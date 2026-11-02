"""Additional edge-case, audit-outbox, granular RBAC, and MCP protocol negative tests."""

from __future__ import annotations

from fractions import Fraction
from uuid import UUID, uuid4

import pytest

from ledger_guard.adapters import InMemoryIdempotencyStore, InMemoryWebhookDedupStore
from ledger_guard.application import OrderLineCommand
from ledger_guard.domain import (
    AuthorizationError,
    CostSnapshot,
    Currency,
    ItemKind,
    LinePricingInput,
    OrderKind,
    PrincipalContext,
    RateLimitExceededError,
    UnitRatio,
    ValidationError,
    WebhookVerificationError,
    price_order_waterfall,
    round_rational_half_even,
)
from ledger_guard.security import (
    HmacMultiBucketRateLimiter,
    IdempotencyCoordinator,
    Redactor,
    compute_webhook_signature,
    verify_and_claim_webhook,
)
from tests.conftest import TENANT_ALPHA, SeededWorld


def test_round_rational_half_even_zero_and_prime_denominators() -> None:
    assert round_rational_half_even(Fraction(0, 7)) == 0
    assert round_rational_half_even(Fraction(1_000_000, 7)) == 142_857
    assert round_rational_half_even(Fraction(-1_000_000, 7)) == -142_857


def test_header_discount_bps_combines_cleanly_with_line_discounts() -> None:
    snap = CostSnapshot("GEAR-1", 5_000, Currency.GBP, UnitRatio(1, 1), 1)
    wf = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="GEAR-1",
                description="Helical Gear",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                quantity=Fraction(1, 1),
                unit_price_minor=10_000,
                unit_ratio=UnitRatio(1, 1),
                manual_discount_bps=1_000,  # 10% -> 9000p
                cost_snapshot=snap,
            )
        ],
        header_discount_bps=1_000,  # 10% of 9000p = 900p -> net 8100p
    )
    assert wf.line_discounts_total_minor == 1_000
    assert wf.header_discount_total_minor == 900
    assert wf.net_goods_total_minor == 8_100
    assert wf.margin_minor == 3_100


def test_zero_net_goods_with_stocked_cost_yields_minus_10000_bps() -> None:
    snap = CostSnapshot("SAMPLE-KIT", 1_500, Currency.GBP, UnitRatio(1, 1), 1)
    wf = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="SAMPLE-KIT",
                description="Sample Kit",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                quantity=Fraction(1, 1),
                unit_price_minor=0,
                unit_ratio=UnitRatio(1, 1),
                cost_snapshot=snap,
            )
        ],
    )
    assert wf.net_goods_total_minor == 0
    assert wf.margin_minor == -1_500
    assert wf.margin_bps == -10_000


def test_unit_ratio_carton_twelve_to_one_multiplies_base_cost_accurately() -> None:
    # Base unit costs 250p; selling a 12-unit carton costs 3000p per carton
    ratio = UnitRatio(12, 1)
    snap = CostSnapshot("CARTON-12", 250, Currency.GBP, ratio, 1)
    wf = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="CARTON-12",
                description="12-Pack Carton",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                quantity=Fraction("5/2"),  # 2.5 cartons = 30 base units = 7500p cost
                unit_price_minor=4_000,
                unit_ratio=ratio,
                cost_snapshot=snap,
            )
        ],
    )
    assert wf.net_goods_total_minor == 10_000
    assert wf.total_cost_minor == 7_500
    assert wf.margin_bps == 2_500


def test_granular_capability_projection_separates_cost_read_from_margin_read(
    world: SeededWorld,
) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    created = world.container.order_service.create_order(
        rep,
        customer_ref="GRANULAR-RBAC",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=10_000)],
    )
    oid = UUID(created["order_id"])

    cost_only = PrincipalContext(
        principal_id="cost.auditor@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="finance_approver",
        capabilities=frozenset({"orders:read", "valuation:cost:read"}),
        is_active=True,
    )
    margin_only = PrincipalContext(
        principal_id="margin.analyst@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="finance_approver",
        capabilities=frozenset({"orders:read", "orders:margin:read"}),
        is_active=True,
    )

    cost_view = world.container.order_service.get_order(cost_only, order_id=oid)
    assert cost_view["total_cost_minor"] == 7_000
    assert "margin_bps" not in cost_view

    margin_view = world.container.order_service.get_order(margin_only, order_id=oid)
    assert margin_view["margin_bps"] == 3_000
    assert "total_cost_minor" not in margin_view


def test_price_increasing_amendment_on_confirmed_order_keeps_confirmed_status(
    world: SeededWorld,
) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    created = world.container.order_service.create_order(
        rep,
        customer_ref="PRICE-UP-01",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=10_000)],
    )
    oid = UUID(created["order_id"])
    lid = UUID(created["lines"][0]["line_id"])
    _ = world.container.order_service.confirm_order(rep, order_id=oid, expected_version=1)

    upgraded = world.container.order_service.amend_order_line(
        rep,
        order_id=oid,
        line_id=lid,
        expected_version=2,
        unit_price_minor=11_500,
    )
    assert upgraded["status"] == "confirmed"
    assert upgraded["pricing_version"] == 1


def test_audit_outbox_records_minimised_events_without_leaking_unit_cost(
    world: SeededWorld,
) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    created = world.container.order_service.create_order(
        rep,
        customer_ref="AUDIT-MIN-01",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=10_000)],
    )
    events = world.container.outbox.list_events(TENANT_ALPHA)
    assert len(events) == 1
    assert events[0].aggregate_id == UUID(created["order_id"])
    assert events[0].event_type == "order.created"
    assert "7000" not in str(events[0].metadata)


def test_in_memory_adapters_fail_closed_on_nil_uuid(world: SeededWorld) -> None:
    nil_uuid = UUID(int=0)
    with pytest.raises(AuthorizationError):
        world.container.orders.list_orders(nil_uuid)
    with pytest.raises(AuthorizationError):
        world.container.catalog.get_catalog_item(nil_uuid, "VALVE-DN50")
    with pytest.raises(AuthorizationError):
        world.container.policies.get_policy(nil_uuid)


def test_rate_limiter_tenant_ip_bucket_enforces_120_per_minute() -> None:
    limiter = HmacMultiBucketRateLimiter(
        b"0123456789abcdef0123456789abcdef",
        ip_limit_per_min=500,
        tenant_ip_limit_per_min=120,
    )
    now = 2_000.0
    for _ in range(120):
        limiter.check_request(
            client_ip="198.51.100.55",
            tenant_id=str(TENANT_ALPHA),
            enforce_principal_bucket=False,
            now=now,
        )
    with pytest.raises(RateLimitExceededError) as err:
        limiter.check_request(
            client_ip="198.51.100.55",
            tenant_id=str(TENANT_ALPHA),
            enforce_principal_bucket=False,
            now=now,
        )
    assert err.value.bucket == "tenant_ip"


def test_idempotency_rejects_short_keys_and_releases_lock_when_handler_raises() -> None:
    store = InMemoryIdempotencyStore()
    coord = IdempotencyCoordinator(store)

    with pytest.raises(ValidationError):
        coord.execute(
            tenant_id=TENANT_ALPHA,
            principal_id="rep.one@alpha.example",
            action="create_order",
            idempotency_key="short",
            payload={"x": 1},
            handler=lambda: (200, {}),
        )

    def failing_handler() -> tuple[int, dict[str, object]]:
        raise ValidationError("Simulated domain failure")

    with pytest.raises(ValidationError):
        coord.execute(
            tenant_id=TENANT_ALPHA,
            principal_id="rep.one@alpha.example",
            action="create_order",
            idempotency_key="idem-release-test-01",
            payload={"x": 1},
            handler=failing_handler,
        )

    # Subsequent retry with same key succeeds because failed in-flight lock was released
    recovered = coord.execute(
        tenant_id=TENANT_ALPHA,
        principal_id="rep.one@alpha.example",
        action="create_order",
        idempotency_key="idem-release-test-01",
        payload={"x": 1},
        handler=lambda: (201, {"recovered": True}),
    )
    assert recovered.status_code == 201
    assert recovered.replayed is False


def test_webhook_rejects_future_timestamp_skew_and_missing_headers() -> None:
    dedup = InMemoryWebhookDedupStore()
    secret = b"whsec_future_skew_test_32_bytes_!"
    raw = b'{"ok":true}'

    with pytest.raises(WebhookVerificationError):
        verify_and_claim_webhook(
            provider="stripe",
            event_id="evt_missing",
            tenant_id=TENANT_ALPHA,
            raw_body=raw,
            timestamp_header=None,
            signature_header=None,
            secret=secret,
            dedup_port=dedup,
        )

    future_ts = "1700001000"
    sig = compute_webhook_signature(secret, future_ts, raw)
    with pytest.raises(WebhookVerificationError):
        verify_and_claim_webhook(
            provider="stripe",
            event_id="evt_future",
            tenant_id=TENANT_ALPHA,
            raw_body=raw,
            timestamp_header=future_ts,
            signature_header=sig,
            secret=secret,
            dedup_port=dedup,
            now_epoch=1_700_000_500,  # 500s skew > 300s ceiling
        )


def test_redactor_truncates_collections_exceeding_50_items() -> None:
    redactor = Redactor()
    oversized_dict = {f"k_{i}": f"val_{i}" for i in range(60)}
    out_dict = redactor.redact_structure(oversized_dict)
    assert out_dict["__truncated_keys__"] is True
    assert len(out_dict) == 51

    oversized_list = list(range(60))
    out_list = redactor.redact_structure(oversized_list)
    assert len(out_list) == 51
    assert out_list[-1] == "[MAX_ITEMS_TRUNCATED]"


def test_mcp_jsonrpc_protocol_error_codes_for_invalid_envelope_and_unknown_method(
    world: SeededWorld,
) -> None:
    headers = {"Authorization": f"Bearer {world.sales_rep_token}"}
    bad_ver = world.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "1.0", "id": 10, "method": "tools/list"},
    )
    assert bad_ver.json()["error"]["code"] == -32600

    unknown_method = world.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 11, "method": "resources/subscribe"},
    )
    assert unknown_method.json()["error"]["code"] == -32601

    unknown_tool = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "drop_database", "arguments": {}},
        },
    )
    assert unknown_tool.json()["error"]["code"] == -32601


def test_mcp_idempotency_replay_and_payload_mismatch_conflict(world: SeededWorld) -> None:
    headers = {"Authorization": f"Bearer {world.sales_rep_token}"}
    args = {
        "idempotency_key": "mcp-idem-0099",
        "customer_ref": "MCP-IDEM-REF",
        "currency": "GBP",
        "lines": [{"sku": "INSTALL-SVC", "quantity": 1}],
    }
    r1 = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "create_order", "arguments": args},
        },
    ).json()["result"]
    assert r1["structuredContent"]["idempotent_replay"] is False

    r2 = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "create_order", "arguments": args},
        },
    ).json()["result"]
    assert r2["structuredContent"]["idempotent_replay"] is True
    assert r2["structuredContent"]["order_id"] == r1["structuredContent"]["order_id"]

    tampered = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "create_order",
                "arguments": {**args, "customer_ref": "MCP-TAMPERED"},
            },
        },
    ).json()["result"]
    assert tampered["isError"] is True
    assert tampered["structuredContent"]["error"]["http_status"] == 409


def test_mcp_unauthenticated_request_rejected_with_http_401(world: SeededWorld) -> None:
    resp = world.client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code == 401


def test_mcp_four_eyes_separation_of_duties_blocks_self_approval(world: SeededWorld) -> None:
    headers = {"Authorization": f"Bearer {world.approver_token}"}
    created = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "create_order",
                "arguments": {
                    "idempotency_key": "mcp-sod-create-01",
                    "customer_ref": "MCP-SOD-REF",
                    "currency": "GBP",
                    "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 7_500}],
                },
            },
        },
    ).json()["result"]["structuredContent"]

    self_approve = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "approve_margin",
                "arguments": {
                    "idempotency_key": "mcp-sod-approve-01",
                    "order_id": created["order_id"],
                    "expected_version": 1,
                    "reason": "Attempting self approval via MCP tool",
                },
            },
        },
    ).json()["result"]
    assert self_approve["isError"] is True
    assert (
        self_approve["structuredContent"]["error"]["code"] == "SEPARATION_OF_DUTIES_VIOLATION"
    )
