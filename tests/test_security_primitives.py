"""Unit tests for rate limiting, idempotency, webhooks, Luhn PAN redaction, and CSV safety."""

from __future__ import annotations

import pytest

from ledger_guard.adapters import InMemoryIdempotencyStore, InMemoryWebhookDedupStore
from ledger_guard.domain import (
    AuthenticationError,
    ConflictError,
    RateLimitExceededError,
    ValidationError,
    WebhookVerificationError,
)
from ledger_guard.security import (
    LOCKOUT_STRIKE_SCHEDULE_SECONDS,
    BoundedMap,
    HmacMultiBucketRateLimiter,
    IdempotencyCoordinator,
    PasswordHasher,
    Redactor,
    TokenService,
    canonical_payload_sha256,
    compute_webhook_signature,
    parse_trusted_proxy_cidrs,
    passes_luhn_checksum,
    resolve_client_ip,
    sanitize_csv_cell,
    serialize_rows_to_csv,
    verify_and_claim_webhook,
)
from ledger_guard.security.rate_limit import normalize_rate_limit_ip
from tests.conftest import TENANT_ALPHA, TENANT_BRAVO


def test_bounded_map_evicts_oldest_entry_preventing_unbounded_growth() -> None:
    bmap: BoundedMap[str, int] = BoundedMap(max_entries=3)
    bmap.set("k1", 1)
    bmap.set("k2", 2)
    bmap.set("k3", 3)
    assert bmap.get("k1") == 1
    bmap.set("k4", 4)
    assert len(bmap) == 3
    assert bmap.get("k2") is None
    assert bmap.get("k1") == 1
    assert bmap.get("k4") == 4


def test_hmac_rate_limiter_scopes_strikes_by_tenant_normalizes_ipv6_and_preserves_ip_bucket() -> (
    None
):
    limiter = HmacMultiBucketRateLimiter(
        b"0123456789abcdef0123456789abcdef",
        principal_limit_per_min=5,
        ip_limit_per_min=60,
        tenant_ip_limit_per_min=120,
    )
    user_email = "finance.ops@alpha.example"
    ip_addr = "198.51.100.42"
    current_time = 1_000.0

    expected_schedule = (60, 300, 900, 3_600, 86_400)
    assert LOCKOUT_STRIKE_SCHEDULE_SECONDS == (60, 300, 900, 3_600, 86_400)

    for expected_lockout in expected_schedule:
        for _ in range(5):
            limiter.check_request(
                client_ip=ip_addr,
                principal_id=user_email,
                tenant_id=str(TENANT_ALPHA),
                now=current_time,
            )
        with pytest.raises(RateLimitExceededError) as exc_info:
            limiter.check_request(
                client_ip=ip_addr,
                principal_id=user_email,
                tenant_id=str(TENANT_ALPHA),
                now=current_time,
            )
        assert exc_info.value.retry_after_seconds == expected_lockout
        assert exc_info.value.bucket == "principal"
        current_time += expected_lockout + 61.0

    # Cross-tenant strike clearing on TENANT_BRAVO never resets TENANT_ALPHA strikes (SEC-02)
    for _ in range(5):
        limiter.check_request(
            client_ip="198.51.100.43",
            principal_id=user_email,
            tenant_id=str(TENANT_ALPHA),
            now=current_time,
        )
    with pytest.raises(RateLimitExceededError):
        limiter.check_request(
            client_ip="198.51.100.43",
            principal_id=user_email,
            tenant_id=str(TENANT_ALPHA),
            now=current_time,
        )
    limiter.clear_principal_on_login(user_email, tenant_id=str(TENANT_BRAVO))
    with pytest.raises(RateLimitExceededError) as still_locked:
        limiter.check_request(
            client_ip="198.51.100.44",
            principal_id=user_email,
            tenant_id=str(TENANT_ALPHA),
            enforce_principal_bucket=False,
            now=current_time,
        )
    assert still_locked.value.bucket == "principal_lockout"

    snapshot = " ".join(limiter.stored_keys_snapshot())
    assert user_email not in snapshot
    assert ip_addr not in snapshot
    assert normalize_rate_limit_ip("2001:db8:abcd:0012::ff01") == "2001:db8:abcd:12::/64"


def test_clear_principal_on_login_preserves_ip_password_spraying_bucket() -> None:
    limiter = HmacMultiBucketRateLimiter(
        b"0123456789abcdef0123456789abcdef",
        principal_limit_per_min=5,
        ip_limit_per_min=10,
    )
    spray_ip = "203.0.113.77"
    t0 = 5_000.0

    for idx in range(9):
        limiter.check_request(
            client_ip=spray_ip,
            principal_id=f"victim.{idx}@alpha.example",
            tenant_id=str(TENANT_ALPHA),
            now=t0,
        )
    limiter.clear_principal_on_login("attacker.owned@alpha.example", tenant_id=str(TENANT_ALPHA))

    limiter.check_request(
        client_ip=spray_ip,
        principal_id="attacker.owned@alpha.example",
        tenant_id=str(TENANT_ALPHA),
        now=t0,
    )
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check_request(
            client_ip=spray_ip,
            principal_id="victim.99@alpha.example",
            tenant_id=str(TENANT_ALPHA),
            now=t0,
        )
    assert exc_info.value.bucket == "ip"


def test_idempotency_prevents_delimiter_collision_nan_and_replays_cleanly() -> None:
    store = InMemoryIdempotencyStore()
    coord = IdempotencyCoordinator(store)
    calls = 0

    def handler() -> tuple[int, dict[str, object]]:
        nonlocal calls
        calls += 1
        return 201, {"order_id": "ord-123", "amount_minor": 5_000}

    first = coord.execute(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="orders:create",
        idempotency_key="idem-key-0001",
        payload={"b": 2, "a": 1},
        handler=handler,
    )
    assert first.replayed is False
    assert calls == 1

    replayed = coord.execute(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="orders:create",
        idempotency_key="idem-key-0001",
        payload={"a": 1, "b": 2},
        handler=handler,
    )
    assert replayed.replayed is True
    assert replayed.body == first.body
    assert calls == 1

    with pytest.raises(ConflictError) as mismatch_err:
        coord.execute(
            tenant_id=TENANT_ALPHA,
            principal_id="rep.one@alpha.example",
            action="orders:create",
            idempotency_key="idem-key-0001",
            payload={"a": 1, "b": 999},
            handler=handler,
        )
    assert mismatch_err.value.code == "IDEMPOTENCY_PAYLOAD_MISMATCH"

    # Delimiter collision protection (SEC-12) & NaN rejection (SEC-21)
    k_a = coord.build_scope_key(
        tenant_id=TENANT_ALPHA,
        principal_id="alice:orders",
        action="create",
        idempotency_key="12345678",
    )
    k_b = coord.build_scope_key(
        tenant_id=TENANT_ALPHA,
        principal_id="alice",
        action="orders:create",
        idempotency_key="12345678",
    )
    assert k_a != k_b

    with pytest.raises(ValidationError):
        canonical_payload_sha256({"val": float("nan")})

    scope = coord.build_scope_key(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="orders:create",
        idempotency_key="idem-inflight-01",
    )
    fp = canonical_payload_sha256({"x": 1})
    store.acquire_or_get(scope, fp)
    with pytest.raises(ConflictError) as inflight_err:
        coord.execute(
            tenant_id=TENANT_ALPHA,
            principal_id="rep.one@alpha.example",
            action="orders:create",
            idempotency_key="idem-inflight-01",
            payload={"x": 1},
            handler=handler,
        )
    assert inflight_err.value.code == "IDEMPOTENCY_IN_FLIGHT"


def test_webhook_context_bound_signature_and_cross_tenant_replay_block() -> None:
    dedup = InMemoryWebhookDedupStore()
    secret = b"whsec_unit_test_secret_32_bytes_!!"
    raw_body = b'{"event": "payment.settled",  "amount_minor": 10000}'
    ts = "1700000100"
    sig_hex = compute_webhook_signature(
        secret,
        ts,
        raw_body,
        provider="stripe",
        tenant_id=TENANT_ALPHA,
        event_id="evt_001",
    )
    sig = f"sha256={sig_hex}"

    first = verify_and_claim_webhook(
        provider="stripe",
        event_id="evt_001",
        tenant_id=TENANT_ALPHA,
        raw_body=raw_body,
        timestamp_header=ts,
        signature_header=sig,
        secret=secret,
        dedup_port=dedup,
        now_epoch=1_700_000_200,
    )
    assert first.is_first_delivery is True

    # Replaying identical signed body onto TENANT_BRAVO fails signature verification (SEC-08)
    with pytest.raises(WebhookVerificationError) as cross_tenant_sig:
        verify_and_claim_webhook(
            provider="stripe",
            event_id="evt_001",
            tenant_id=TENANT_BRAVO,
            raw_body=raw_body,
            timestamp_header=ts,
            signature_header=sig,
            secret=secret,
            dedup_port=dedup,
            now_epoch=1_700_000_202,
        )
    assert cross_tenant_sig.value.code == "WEBHOOK_SIGNATURE_MISMATCH"

    second = verify_and_claim_webhook(
        provider="stripe",
        event_id="evt_001",
        tenant_id=TENANT_ALPHA,
        raw_body=raw_body,
        timestamp_header=ts,
        signature_header=sig,
        secret=secret,
        dedup_port=dedup,
        now_epoch=1_700_000_205,
    )
    assert second.is_first_delivery is False

    # Stale timestamp (> 300s) is rejected
    with pytest.raises(WebhookVerificationError) as stale_err:
        verify_and_claim_webhook(
            provider="stripe",
            event_id="evt_003",
            tenant_id=TENANT_ALPHA,
            raw_body=raw_body,
            timestamp_header=ts,
            signature_header=sig,
            secret=secret,
            dedup_port=dedup,
            now_epoch=1_700_000_405,
        )
    assert stale_err.value.code == "WEBHOOK_TIMESTAMP_EXPIRED"


def test_redactor_scrubs_lg1_quoted_secrets_luhn_pans_and_preserves_shipping() -> None:
    redactor = Redactor(max_cache_entries=16)
    valid_pan = "4532-0151-1283-0366"
    invalid_luhn = "4532-0151-1283-0367"
    assert passes_luhn_checksum("4532015112830366") is True
    assert passes_luhn_checksum("4532015112830367") is False

    synthetic_jwt = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ1c2VyIn0", "c2lnbmF0dXJl"])
    synthetic_lg1 = ".".join(["lg1", "eyJzdWIiOiJhbGljZSJ9", "YWJjZGVmZ2hpamtsbW5vcHFycw"])
    synthetic_stripe_key = "".join(["sk_", "live_", "ABCDEF1234567890"])
    synthetic_bearer = "".join(["super_secret_", "token_999111"])
    synthetic_json_pw = "".join(['"password": "', "Hunter2Pass!", '"'])
    sample = (
        f"Auth: Bearer {synthetic_bearer} "
        f"jwt={synthetic_jwt} "
        f"lg1={synthetic_lg1} "
        f"{synthetic_json_pw} "
        f"key={synthetic_stripe_key} "
        f"url=https://api.alpha.example/cb?token=xyz987&ok=1 "
        f"contact=buyer@customer.example tel=+44 7700 900123 "
        f"card={valid_pan} order_ref={invalid_luhn} "
        f"uuid={TENANT_ALPHA}"
    )
    cleaned = redactor.redact_text(sample)
    assert synthetic_bearer not in cleaned
    assert synthetic_stripe_key not in cleaned
    assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned
    assert synthetic_lg1 not in cleaned
    assert "[REDACTED_LG1_TOKEN]" in cleaned
    assert "Hunter2Pass!" not in cleaned
    assert "xyz987" not in cleaned
    assert "buyer@customer.example" not in cleaned
    assert "900123" not in cleaned
    assert valid_pan not in cleaned
    assert "[REDACTED_PAN]" in cleaned
    assert invalid_luhn in cleaned
    assert str(TENANT_ALPHA) in cleaned

    deep: dict[str, object] = {"a": {"b": {"c": {"d": {"e": {"f": "bottom"}}}}}}
    sanitized_deep = redactor.redact_structure(
        {
            "x-api-key": "raw-val",
            "cardNumber": "4532015112830366",
            "shipping": "next_day",
            "user_pin": "1234",
            "nested": deep,
        }
    )
    assert sanitized_deep["x-api-key"] == "[REDACTED_FIELD]"
    assert sanitized_deep["cardNumber"] == "[REDACTED_FIELD]"
    assert sanitized_deep["user_pin"] == "[REDACTED_FIELD]"
    assert sanitized_deep["shipping"] == "next_day"
    assert sanitized_deep["nested"]["a"]["b"]["c"]["d"] == "[MAX_DEPTH_TRUNCATED]"

    for i in range(40):
        redactor.redact_text(f"log-entry-{i}")
    assert redactor.cache_size == 16


def test_csv_sanitizer_blocks_pipe_unicode_and_embedded_newline_formulas() -> None:
    malicious_cells = (
        "=CMD|' /C calc'!A0",
        "+SUM(A1:A10)",
        "-2+3+cmd",
        "@IMPORTXML(A1,A2)",
        "|calc",
        "\u22121+1",
        "\uff1dSUM(A1:A2)",
        "\uff0b1+1",
        "\uff0d1+1",
        "\uff20SUM(A1)",
        "\uff5ccmd",
        "\t=1+1",
        "   =HYPERLINK(\"https://evil.example\")",
    )
    for cell in malicious_cells:
        sanitized = sanitize_csv_cell(cell)
        assert sanitized.startswith("'"), f"Failed to neutralize {cell!r}"

    multiline = sanitize_csv_cell("Safe note\n=HYPERLINK(\"https://evil.example\")")
    assert "\n" not in multiline
    assert "'=HYPERLINK" in multiline

    csv_text = serialize_rows_to_csv(
        [{"customer_ref": "  \uff1d2+2", "payable_total_minor": 12_500}],
        ["customer_ref", "payable_total_minor"],
    )
    assert "'  \uff1d2+2,12500" in csv_text


def test_trusted_proxy_cidr_resolution_and_token_jti_revocation() -> None:
    with pytest.raises(ValidationError):
        parse_trusted_proxy_cidrs(["*"])

    cidrs = parse_trusted_proxy_cidrs(["10.0.0.0/8"])
    assert (
        resolve_client_ip(
            peer_ip="198.51.100.9",
            x_forwarded_for="1.2.3.4",
            trusted_proxy_cidrs=cidrs,
        )
        == "198.51.100.9"
    )
    assert (
        resolve_client_ip(
            peer_ip="10.0.1.5",
            x_forwarded_for="198.51.100.25, 10.0.2.1",
            trusted_proxy_cidrs=cidrs,
        )
        == "198.51.100.25"
    )
    assert (
        resolve_client_ip(
            peer_ip="unix-socket",
            x_forwarded_for="1.2.3.4",
            trusted_proxy_cidrs=cidrs,
        )
        == "untrusted_peer"
    )

    hasher = PasswordHasher()
    digest = hasher.hash_password("Str0ngPassphrase!2026")
    assert hasher.verify_password("Str0ngPassphrase!2026", digest) is True
    assert hasher.verify_password("WrongPassphrase!2026", digest) is False
    assert hasher.verify_password("Str0ngPassphrase!2026", "scrypt$999999999$8$1$aa$bb") is False

    tokens = TokenService(b"a" * 32)
    tok = tokens.issue_token(
        principal_id="rep.one@alpha.example",
        tenant_id=TENANT_ALPHA,
        now_epoch=1_000,
        ttl_seconds=60,
    )
    claims = tokens.verify_token(tok, now_epoch=1_059)
    assert claims.principal_id == "rep.one@alpha.example"
    assert claims.jti

    tokens.revoke_jti(claims.jti, claims.expires_at)
    with pytest.raises(AuthenticationError) as revoked_exc:
        tokens.verify_token(tok, now_epoch=1_059)
    assert revoked_exc.value.code == "TOKEN_REVOKED"

    with pytest.raises(AuthenticationError):
        tokens.verify_token(tok, now_epoch=1_060)
