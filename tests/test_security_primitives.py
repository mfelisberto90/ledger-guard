"""Unit tests for rate limiting, idempotency, webhooks, Luhn PAN redaction, and CSV safety."""

from __future__ import annotations

import pytest

from ledger_guard.adapters import InMemoryIdempotencyStore, InMemoryWebhookDedupStore
from ledger_guard.domain import (
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
    build_session_cookie_flags,
    compute_webhook_signature,
    parse_trusted_proxy_cidrs,
    passes_luhn_checksum,
    resolve_client_ip,
    sanitize_csv_cell,
    serialize_rows_to_csv,
    verify_and_claim_webhook,
)
from tests.conftest import TENANT_ALPHA


def test_bounded_map_evicts_oldest_entry_preventing_unbounded_growth() -> None:
    bmap: BoundedMap[str, int] = BoundedMap(max_entries=3)
    bmap.set("k1", 1)
    bmap.set("k2", 2)
    bmap.set("k3", 3)
    # Touch k1 so k2 becomes least-recently used
    assert bmap.get("k1") == 1
    bmap.set("k4", 4)
    assert len(bmap) == 3
    assert bmap.get("k2") is None
    assert bmap.get("k1") == 1
    assert bmap.get("k4") == 4


def test_hmac_rate_limiter_never_stores_plain_identifiers_and_escalates_lockouts() -> None:
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
                now=current_time,
            )
        with pytest.raises(RateLimitExceededError) as exc_info:
            limiter.check_request(
                client_ip=ip_addr,
                principal_id=user_email,
                now=current_time,
            )
        assert exc_info.value.retry_after_seconds == expected_lockout
        assert exc_info.value.bucket == "principal"

        # Advance past both 60s window AND active lockout to test next strike tier
        current_time += expected_lockout + 61.0

    # Verify raw identifiers never appear in stored keys
    snapshot = " ".join(limiter.stored_keys_snapshot())
    assert user_email not in snapshot
    assert ip_addr not in snapshot


def test_clear_principal_on_login_preserves_ip_password_spraying_bucket() -> None:
    limiter = HmacMultiBucketRateLimiter(
        b"0123456789abcdef0123456789abcdef",
        principal_limit_per_min=5,
        ip_limit_per_min=10,
    )
    spray_ip = "203.0.113.77"
    t0 = 5_000.0

    # Attacker burns 9 attempts across victims, then logs into controlled account
    for idx in range(9):
        limiter.check_request(
            client_ip=spray_ip,
            principal_id=f"victim.{idx}@alpha.example",
            now=t0,
        )
    limiter.clear_principal_on_login("attacker.owned@alpha.example")

    # 10th IP attempt succeeds, 11th MUST fail on IP bucket despite clear_principal_on_login!
    limiter.check_request(
        client_ip=spray_ip,
        principal_id="attacker.owned@alpha.example",
        now=t0,
    )
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check_request(
            client_ip=spray_ip,
            principal_id="victim.99@alpha.example",
            now=t0,
        )
    assert exc_info.value.bucket == "ip"


def test_idempotency_replays_exact_match_and_rejects_tampered_or_inflight_payload() -> None:
    store = InMemoryIdempotencyStore()
    coord = IdempotencyCoordinator(store)
    calls = 0

    def handler() -> tuple[int, dict[str, object]]:
        nonlocal calls
        calls += 1
        return 201, {"order_id": "ord-123", "amount_minor": 5_000}

    # Key order in dict should not change canonical SHA-256 hash
    first = coord.execute(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="create_order",
        idempotency_key="idem-key-0001",
        payload={"b": 2, "a": 1},
        handler=handler,
    )
    assert first.replayed is False
    assert calls == 1

    replayed = coord.execute(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="create_order",
        idempotency_key="idem-key-0001",
        payload={"a": 1, "b": 2},
        handler=handler,
    )
    assert replayed.replayed is True
    assert replayed.body == first.body
    assert calls == 1

    # Tampered payload with same key -> 409 IDEMPOTENCY_PAYLOAD_MISMATCH
    with pytest.raises(ConflictError) as mismatch_err:
        coord.execute(
            tenant_id=TENANT_ALPHA,
            principal_id="rep.one@alpha.example",
            action="create_order",
            idempotency_key="idem-key-0001",
            payload={"a": 1, "b": 999},
            handler=handler,
        )
    assert mismatch_err.value.code == "IDEMPOTENCY_PAYLOAD_MISMATCH"

    # Simulate in-flight lock -> 409 IDEMPOTENCY_IN_FLIGHT
    scope = coord.build_scope_key(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="create_order",
        idempotency_key="idem-inflight-01",
    )
    from ledger_guard.security import canonical_payload_sha256

    fp = canonical_payload_sha256({"x": 1})
    store.acquire_or_get(scope, fp)
    with pytest.raises(ConflictError) as inflight_err:
        coord.execute(
            tenant_id=TENANT_ALPHA,
            principal_id="rep.one@alpha.example",
            action="create_order",
            idempotency_key="idem-inflight-01",
            payload={"x": 1},
            handler=handler,
        )
    assert inflight_err.value.code == "IDEMPOTENCY_IN_FLIGHT"


def test_webhook_raw_bytes_signature_replay_window_and_atomic_preinsert() -> None:
    dedup = InMemoryWebhookDedupStore()
    secret = b"whsec_unit_test_secret_32_bytes_!!"
    raw_body = b'{"event": "payment.settled",  "amount_minor": 10000}'
    ts = "1700000100"
    sig = f"sha256={compute_webhook_signature(secret, ts, raw_body)}"

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

    # Duplicate delivery with valid signature is atomically recognized as duplicate
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

    # Re-serialized JSON losing whitespace fails raw-bytes HMAC verification
    altered_whitespace = b'{"event":"payment.settled","amount_minor":10000}'
    with pytest.raises(WebhookVerificationError):
        verify_and_claim_webhook(
            provider="stripe",
            event_id="evt_002",
            tenant_id=TENANT_ALPHA,
            raw_body=altered_whitespace,
            timestamp_header=ts,
            signature_header=sig,
            secret=secret,
            dedup_port=dedup,
            now_epoch=1_700_000_200,
        )

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


def test_redactor_scrubs_tokens_jwt_pii_and_luhn_pans_with_bounded_depth() -> None:
    redactor = Redactor(max_cache_entries=16)
    # Standard ISO/IEC 7812 Luhn test PAN: 4532 0151 1283 0366 (valid Luhn)
    valid_pan = "4532-0151-1283-0366"
    invalid_luhn = "4532-0151-1283-0367"
    assert passes_luhn_checksum("4532015112830366") is True
    assert passes_luhn_checksum("4532015112830367") is False

    sample = (
        f"Auth: Bearer super_secret_token_999111 "
        f"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl "
        f"key=sk_live_ABCDEF1234567890 "
        f"url=https://api.alpha.example/cb?token=xyz987&ok=1 "
        f"contact=buyer@customer.example tel=+44 7700 900123 "
        f"card={valid_pan} order_ref={invalid_luhn} "
        f"uuid={TENANT_ALPHA}"
    )
    cleaned = redactor.redact_text(sample)
    assert "super_secret_token_999111" not in cleaned
    assert "sk_live_ABCDEF1234567890" not in cleaned
    assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned
    assert "xyz987" not in cleaned
    assert "buyer@customer.example" not in cleaned
    assert "900123" not in cleaned
    assert valid_pan not in cleaned
    assert "[REDACTED_PAN]" in cleaned
    # Non-Luhn reference and UUID remain readable for operational debugging
    assert invalid_luhn in cleaned
    assert str(TENANT_ALPHA) in cleaned

    # Nested depth > 5 and sensitive dict keys are truncated/redacted
    deep: dict[str, object] = {"a": {"b": {"c": {"d": {"e": {"f": "bottom"}}}}}}
    sanitized_deep = redactor.redact_structure({"api_key": "raw", "nested": deep})
    assert sanitized_deep["api_key"] == "[REDACTED_FIELD]"
    assert (
        sanitized_deep["nested"]["a"]["b"]["c"]["d"] == "[MAX_DEPTH_TRUNCATED]"
    )

    # Bounded memoization cache never exceeds max_cache_entries (16)
    for i in range(40):
        redactor.redact_text(f"log-entry-{i}")
    assert redactor.cache_size == 16


def test_csv_sanitizer_blocks_ascii_leading_whitespace_and_unicode_fullwidth_formulas() -> None:
    malicious_cells = (
        "=CMD|' /C calc'!A0",
        "+SUM(A1:A10)",
        "-2+3+cmd",
        "@IMPORTXML(A1,A2)",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "   =HYPERLINK(\"https://evil.example\")",
        "\uff1dSUM(A1:A2)",
        "\uff0b1+1",
        "\uff0d1+1",
        "\uff20SUM(A1)",
    )
    for cell in malicious_cells:
        sanitized = sanitize_csv_cell(cell)
        assert sanitized.startswith("'"), f"Failed to neutralize {cell!r}"

    csv_text = serialize_rows_to_csv(
        [{"customer_ref": "  \uff1d2+2", "payable_total_minor": 12_500}],
        ["customer_ref", "payable_total_minor"],
    )
    assert "'  \uff1d2+2,12500" in csv_text


def test_cookie_flags_and_trusted_proxy_cidr_resolution() -> None:
    assert build_session_cookie_flags(is_dev=True, request_is_secure=True)["secure"] is False
    assert build_session_cookie_flags(is_dev=False, request_is_secure=False)["secure"] is False
    assert (
        build_session_cookie_flags(
            is_dev=False, request_is_secure=False, x_forwarded_proto="https"
        )["secure"]
        is True
    )
    assert (
        build_session_cookie_flags(
            is_dev=False, request_is_secure=False, force_secure_cookies=True
        )["secure"]
        is True
    )

    with pytest.raises(ValidationError):
        parse_trusted_proxy_cidrs(["*"])

    cidrs = parse_trusted_proxy_cidrs(["10.0.0.0/8"])
    # Untrusted direct peer spoofing X-Forwarded-For is ignored!
    assert (
        resolve_client_ip(
            peer_ip="198.51.100.9",
            x_forwarded_for="1.2.3.4",
            trusted_proxy_cidrs=cidrs,
        )
        == "198.51.100.9"
    )
    # Trusted reverse proxy resolves rightmost non-proxy client IP
    assert (
        resolve_client_ip(
            peer_ip="10.0.1.5",
            x_forwarded_for="198.51.100.25, 10.0.2.1",
            trusted_proxy_cidrs=cidrs,
        )
        == "198.51.100.25"
    )


def test_password_hasher_and_token_expiration() -> None:
    hasher = PasswordHasher()
    digest = hasher.hash_password("Str0ngPassphrase!2026")
    assert hasher.verify_password("Str0ngPassphrase!2026", digest) is True
    assert hasher.verify_password("WrongPassphrase!2026", digest) is False

    tokens = TokenService(b"a" * 32)
    tok = tokens.issue_token(
        principal_id="rep.one@alpha.example",
        tenant_id=TENANT_ALPHA,
        now_epoch=1_000,
        ttl_seconds=60,
    )
    claims = tokens.verify_token(tok, now_epoch=1_059)
    assert claims.principal_id == "rep.one@alpha.example"
    from ledger_guard.domain import AuthenticationError

    with pytest.raises(AuthenticationError):
        tokens.verify_token(tok, now_epoch=1_060)
