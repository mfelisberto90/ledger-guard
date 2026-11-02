"""End-to-end FastAPI HTTP & MCP JSON-RPC security, multi-tenant isolation, and parity tests."""

from __future__ import annotations

import time
from typing import Any

from ledger_guard.security import compute_webhook_signature
from tests.conftest import TENANT_ALPHA, SeededWorld


def _auth(token: str, idem_key: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if idem_key is not None:
        headers["Idempotency-Key"] = idem_key
    return headers


def test_security_headers_and_unique_per_request_csp_nonce(world: SeededWorld) -> None:
    r1 = world.client.get("/healthz")
    r2 = world.client.get("/healthz")
    assert r1.status_code == 200
    csp1 = r1.headers["content-security-policy"]
    csp2 = r2.headers["content-security-policy"]
    assert csp1 != csp2
    assert "'unsafe-inline'" not in csp1
    assert "'unsafe-eval'" not in csp1
    assert "script-src 'self' 'nonce-" in csp1
    assert r1.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains; preload"
    assert r1.headers["cross-origin-opener-policy"] == "same-origin"
    assert r1.headers["cross-origin-resource-policy"] == "same-origin"
    assert r1.headers["x-content-type-options"] == "nosniff"
    assert r1.headers["x-frame-options"] == "DENY"
    assert r1.headers["cache-control"] == "no-store, private"
    assert "server" not in {k.lower() for k in r1.headers}


def test_robots_txt_emits_positive_allow_only_and_zero_cookies(world: SeededWorld) -> None:
    resp = world.client.get("/robots.txt")
    assert resp.status_code == 200
    assert resp.text == "User-agent: *\nAllow: /\n"
    assert "Disallow:" not in resp.text
    assert "set-cookie" not in {k.lower() for k in resp.headers}


def test_cgnat_safe_honeypot_bans_unauthenticated_scanner_while_exempting_authenticated_user(
    world: SeededWorld,
) -> None:
    # Simulate shared carrier CGNAT IP behind trusted proxy 127.0.0.1
    cgnat_headers = {"X-Forwarded-For": "198.51.100.200"}

    # Bad actor on that CGNAT IP probes /.env canary trap -> 403 banned
    trap_resp = world.client.get("/.env", headers=cgnat_headers)
    assert trap_resp.status_code == 403
    assert trap_resp.json()["error"]["code"] == "SCANNER_IP_BANNED"

    # Subsequent unauthenticated request from same CGNAT IP is blocked by 15-min ban
    blocked_unauth = world.client.get(
        "/v1/orders/00000000-0000-4000-8000-000000000001",
        headers=cgnat_headers,
    )
    assert blocked_unauth.status_code == 403
    assert blocked_unauth.json()["error"]["code"] == "SCANNER_IP_BANNED"

    # Legitimate authenticated customer on the EXACT SAME CGNAT IP works uninterrupted!
    auth_cgnat = {
        "X-Forwarded-For": "198.51.100.200",
        **_auth(world.sales_rep_token, "idem-cgnat-order-1"),
    }
    ok_resp = world.client.post(
        "/v1/orders",
        headers=auth_cgnat,
        json={
            "customer_ref": "CGNAT-SAFE-BUYER",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 10_000}],
        },
    )
    assert ok_resp.status_code == 201


def test_offensive_scanner_user_agent_is_banned_while_webhooks_remain_exempt(
    world: SeededWorld,
) -> None:
    scanner_ip = {"X-Forwarded-For": "198.51.100.201", "User-Agent": "sqlmap/1.8.4"}
    r = world.client.get("/v1/orders/00000000-0000-4000-8000-000000000001", headers=scanner_ip)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "SCANNER_IP_BANNED"

    # Signed webhook from that IP still reaches webhook verification cleanly
    raw_body = b'{"type":"invoice.paid"}'
    ts = str(int(time.time()))
    sig = compute_webhook_signature(world.container.webhook_secret, ts, raw_body)
    wh_resp = world.client.post(
        "/v1/webhooks/billing",
        content=raw_body,
        headers={
            "X-Forwarded-For": "198.51.100.201",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Signature": f"sha256={sig}",
            "X-Webhook-Event-Id": "evt_live_901",
            "X-Webhook-Tenant-Id": str(TENANT_ALPHA),
            "Content-Type": "application/json",
        },
    )
    assert wh_resp.status_code == 200
    assert wh_resp.json()["status"] == "processed"


def test_unauthenticated_forged_and_inactive_membership_requests_fail_closed(
    world: SeededWorld,
) -> None:
    r_no_auth = world.client.get("/v1/orders/00000000-0000-4000-8000-000000000001")
    assert r_no_auth.status_code == 401

    r_forged = world.client.get(
        "/v1/orders/00000000-0000-4000-8000-000000000001",
        headers={"Authorization": "Bearer lg1.forged.signature"},
    )
    assert r_forged.status_code == 401

    r_inactive = world.client.get(
        "/v1/orders/00000000-0000-4000-8000-000000000001",
        headers=_auth(world.inactive_token),
    )
    assert r_inactive.status_code == 403
    assert r_inactive.json()["error"]["code"] == "INACTIVE_OR_MISSING_MEMBERSHIP"


def test_bfla_missing_capabilities_return_403_forbidden(world: SeededWorld) -> None:
    # Warehouse principal lacks orders:write and orders:margin:approve
    create_attempt = world.client.post(
        "/v1/orders",
        headers=_auth(world.warehouse_token, "idem-wh-create-01"),
        json={
            "customer_ref": "WH-ATTEMPT",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1}],
        },
    )
    assert create_attempt.status_code == 403
    assert create_attempt.json()["error"]["code"] == "MISSING_CAPABILITY"

    # Sales rep creates sub-floor order, then tries to call approve-margin without capability
    sub_floor = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-rep-subfloor-01"),
        json={
            "customer_ref": "SUBFLOOR-BFLA",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 7_500}],
        },
    ).json()
    approve_attempt = world.client.post(
        f"/v1/orders/{sub_floor['order_id']}/approve-margin",
        headers=_auth(world.second_sales_rep_token, "idem-bfla-approve-01"),
        json={"expected_version": 1, "reason": "Unauthorized approval attempt"},
    )
    assert approve_attempt.status_code == 403
    assert approve_attempt.json()["error"]["code"] == "MISSING_CAPABILITY"


def test_cross_tenant_idor_isolation_returns_404_across_all_endpoints(world: SeededWorld) -> None:
    alpha_order = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-alpha-iso-01"),
        json={
            "customer_ref": "ALPHA-CONFIDENTIAL",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 2}],
        },
    ).json()
    oid = alpha_order["order_id"]
    lid = alpha_order["lines"][0]["line_id"]

    # Tenant Bravo admin attempting to read, confirm, approve, or amend Alpha's order -> 404!
    bravo_get = world.client.get(f"/v1/orders/{oid}", headers=_auth(world.bravo_admin_token))
    assert bravo_get.status_code == 404
    assert (
        world.client.post(
            f"/v1/orders/{oid}/confirm",
            headers=_auth(world.bravo_admin_token, "idem-bravo-conf-01"),
            json={"expected_version": 1},
        ).status_code
        == 404
    )
    assert (
        world.client.post(
            f"/v1/orders/{oid}/approve-margin",
            headers=_auth(world.bravo_admin_token, "idem-bravo-appr-01"),
            json={"expected_version": 1, "reason": "Cross-tenant probe"},
        ).status_code
        == 404
    )
    assert (
        world.client.patch(
            f"/v1/orders/{oid}/lines/{lid}",
            headers=_auth(world.bravo_admin_token, "idem-bravo-amend-01"),
            json={"expected_version": 1, "unit_price_minor": 9_000},
        ).status_code
        == 404
    )


def test_http_idempotency_replay_header_and_409_payload_mismatch(world: SeededWorld) -> None:
    body = {
        "customer_ref": "IDEM-HTTP-01",
        "currency": "GBP",
        "lines": [{"sku": "REAGENT-BTL", "quantity": 3}],
    }
    first = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-http-key-001"),
        json=body,
    )
    assert first.status_code == 201
    assert "x-idempotent-replay" not in {k.lower() for k in first.headers}

    replay = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-http-key-001"),
        json=body,
    )
    assert replay.status_code == 201
    assert replay.headers["x-idempotent-replay"] == "true"
    assert replay.json()["order_id"] == first.json()["order_id"]

    tampered = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-http-key-001"),
        json={**body, "customer_ref": "TAMPERED-REF"},
    )
    assert tampered.status_code == 409
    assert tampered.json()["error"]["code"] == "IDEMPOTENCY_PAYLOAD_MISMATCH"


def test_http_rejects_floating_point_json_and_injected_tenant_id(world: SeededWorld) -> None:
    float_resp = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-float-reject-01"),
        json={
            "customer_ref": "FLOAT-ATTEMPT",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 100.5}],
        },
    )
    assert float_resp.status_code == 422

    extra_tenant_resp = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-extra-tenant-01"),
        json={
            "tenant_id": str(TENANT_ALPHA),
            "customer_ref": "EXTRA-TENANT",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1}],
        },
    )
    assert extra_tenant_resp.status_code == 422


def test_full_http_lifecycle_approval_confirm_and_adverse_amendment_rehold(
    world: SeededWorld,
) -> None:
    # 1. Sales rep creates sub-floor order (£75 vs £70 cost -> 6.67% < 20%, plus £200 freight)
    created = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-lc-create-01"),
        json={
            "customer_ref": "LIFECYCLE-01",
            "currency": "GBP",
            "passthrough_freight_minor": 20_000,
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 7_500}],
        },
    )
    assert created.status_code == 201
    order_data = created.json()
    oid = order_data["order_id"]
    lid = order_data["lines"][0]["line_id"]
    assert order_data["status"] == "pending_approval"
    assert order_data["payable_total_minor"] == 27_500
    assert "total_cost_minor" not in order_data

    # 2. Premature confirmation fails with 422 MARGIN_BELOW_FLOOR_BLOCK
    blocked = world.client.post(
        f"/v1/orders/{oid}/confirm",
        headers=_auth(world.sales_rep_token, "idem-lc-confirm-fail"),
        json={"expected_version": 1},
    )
    assert blocked.status_code == 422
    assert blocked.json()["error"]["code"] == "MARGIN_BELOW_FLOOR_BLOCK"

    # 3. Finance controller approves under four-eyes control
    approved = world.client.post(
        f"/v1/orders/{oid}/approve-margin",
        headers=_auth(world.approver_token, "idem-lc-approve-01"),
        json={"expected_version": 1, "reason": "Approved volume introductory pricing."},
    )
    assert approved.status_code == 200
    assert approved.json()["total_cost_minor"] == 7_000
    assert approved.json()["readiness_gates"][0]["met"] is True

    # 4. Sales rep confirms order (version 2 -> 3)
    confirmed = world.client.post(
        f"/v1/orders/{oid}/confirm",
        headers=_auth(world.sales_rep_token, "idem-lc-confirm-ok"),
        json={"expected_version": 2},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "confirmed"

    # 5. Increasing discount by 500 bps invalidates approval & returns to pending_approval!
    amended = world.client.patch(
        f"/v1/orders/{oid}/lines/{lid}",
        headers=_auth(world.sales_rep_token, "idem-lc-amend-01"),
        json={"expected_version": 3, "manual_discount_bps": 500},
    )
    assert amended.status_code == 200
    assert amended.json()["status"] == "pending_approval"
    assert amended.json()["readiness_gates"][0]["code"] == "MARGIN_BELOW_FLOOR_BLOCK"


def test_login_endpoint_enforces_scrypt_and_progressive_lockout_with_retry_after(
    world: SeededWorld,
) -> None:
    login_ip = {"X-Forwarded-For": "198.51.100.88"}
    ok_login = world.client.post(
        "/v1/auth/login",
        headers=login_ip,
        json={
            "tenant_id": str(TENANT_ALPHA),
            "principal_id": "rep.one@alpha.example",
            "password": "CorrectHorseBattery99!",
        },
    )
    assert ok_login.status_code == 200
    assert ok_login.json()["token_type"] == "bearer"

    # 5 failed logins exhaust principal window, 6th triggers 429 with Retry-After: 60
    for _ in range(5):
        bad = world.client.post(
            "/v1/auth/login",
            headers=login_ip,
            json={
                "tenant_id": str(TENANT_ALPHA),
                "principal_id": "rep.two@alpha.example",
                "password": "WrongPassword123!",
            },
        )
        assert bad.status_code == 401

    locked = world.client.post(
        "/v1/auth/login",
        headers=login_ip,
        json={
            "tenant_id": str(TENANT_ALPHA),
            "principal_id": "rep.two@alpha.example",
            "password": "CorrectHorseBattery99!",
        },
    )
    assert locked.status_code == 429
    assert locked.headers["retry-after"] == "60"


def test_csv_export_endpoint_sanitizes_formulas_and_strips_cost_columns_by_capability(
    world: SeededWorld,
) -> None:
    _ = world.client.post(
        "/v1/orders",
        headers=_auth(world.sales_rep_token, "idem-csv-malicious-01"),
        json={
            "customer_ref": "  \uff1dCMD|' /C calc'!A0",
            "currency": "GBP",
            "lines": [{"sku": "INSTALL-SVC", "quantity": 1}],
        },
    )

    wh_csv = world.client.get(
        "/v1/orders-export.csv", headers=_auth(world.warehouse_token)
    )
    assert wh_csv.status_code == 200
    assert "total_cost_minor" not in wh_csv.text
    assert "margin_bps" not in wh_csv.text
    assert "'\uff1dCMD|' /C calc'!A0" in wh_csv.text

    fin_csv = world.client.get(
        "/v1/orders-export.csv", headers=_auth(world.approver_token)
    )
    assert fin_csv.status_code == 200
    assert "total_cost_minor" in fin_csv.text
    assert "margin_bps" in fin_csv.text


def test_webhook_endpoint_deduplicates_replay_and_runs_handler_strictly_once(
    world: SeededWorld,
) -> None:
    invocations: list[str] = []
    world.container.webhook_handlers.append(
        lambda provider, event_id, _tid, _raw: invocations.append(f"{provider}:{event_id}")
    )
    raw = b'{"invoice_id":"inv_77","paid":true}'
    ts = str(int(time.time()))
    sig = compute_webhook_signature(world.container.webhook_secret, ts, raw)
    headers = {
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Signature": sig,
        "X-Webhook-Event-Id": "evt_dedup_77",
        "X-Webhook-Tenant-Id": str(TENANT_ALPHA),
    }

    r1 = world.client.post("/v1/webhooks/erp_payments", content=raw, headers=headers)
    r2 = world.client.post("/v1/webhooks/erp_payments", content=raw, headers=headers)
    assert r1.status_code == 200
    assert r1.json()["status"] == "processed"
    assert r2.status_code == 200
    assert r2.json()["status"] == "duplicate_ignored"
    assert invocations == ["erp_payments:evt_dedup_77"]


def _mcp_call(
    world: SeededWorld,
    token: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    resp = world.client.post(
        "/mcp",
        headers=_auth(token),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
    )
    assert resp.status_code == 200
    data: dict[str, Any] = resp.json()
    return data["result"]


def test_mcp_server_tools_list_and_full_domain_rbac_parity(world: SeededWorld) -> None:
    # 1. Initialize & list tools
    init_resp = world.client.post(
        "/mcp",
        headers=_auth(world.sales_rep_token),
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
    )
    assert init_resp.status_code == 200
    assert init_resp.json()["result"]["serverInfo"]["name"] == "ledger-guard-mcp"

    list_resp = world.client.post(
        "/mcp",
        headers=_auth(world.sales_rep_token),
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    tool_names = {t["name"] for t in list_resp.json()["result"]["tools"]}
    assert tool_names == {
        "create_order",
        "get_order",
        "confirm_order",
        "approve_margin",
        "amend_order_line",
    }

    # 2. Prompt-injected tenant_id override inside MCP tool arguments is blocked!
    injected = _mcp_call(
        world,
        world.sales_rep_token,
        "get_order",
        {
            "order_id": "00000000-0000-4000-8000-000000000001",
            "tenant_id": "22222222-2222-4222-8222-222222222222",
        },
    )
    assert injected["isError"] is True
    assert injected["structuredContent"]["error"]["code"] == "CLIENT_TENANT_OVERRIDE_FORBIDDEN"

    # 3. MCP create_order by sales rep strips cost/margin identically to HTTP
    created_res = _mcp_call(
        world,
        world.sales_rep_token,
        "create_order",
        {
            "idempotency_key": "mcp-idem-create-01",
            "customer_ref": "MCP-BUYER-01",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": "2", "unit_price_minor": 7_500}],
        },
    )
    assert created_res["isError"] is False
    order = created_res["structuredContent"]
    oid = order["order_id"]
    lid = order["lines"][0]["line_id"]
    assert order["status"] == "pending_approval"
    assert "total_cost_minor" not in order

    # 4. Cross-tenant MCP get_order from Bravo returns ORDER_NOT_FOUND (404)
    cross_tenant = _mcp_call(world, world.bravo_admin_token, "get_order", {"order_id": oid})
    assert cross_tenant["isError"] is True
    assert cross_tenant["structuredContent"]["error"]["http_status"] == 404

    # 5. MCP approve_margin by controller succeeds, then MCP confirm_order confirms,
    #    then MCP amend_order_line lowering price transitions back to pending_approval!
    approved_res = _mcp_call(
        world,
        world.approver_token,
        "approve_margin",
        {
            "idempotency_key": "mcp-idem-approve-01",
            "order_id": oid,
            "expected_version": 1,
            "reason": "MCP finance controller sign-off.",
        },
    )
    assert approved_res["isError"] is False
    assert approved_res["structuredContent"]["total_cost_minor"] == 14_000

    confirmed_res = _mcp_call(
        world,
        world.sales_rep_token,
        "confirm_order",
        {
            "idempotency_key": "mcp-idem-confirm-01",
            "order_id": oid,
            "expected_version": 2,
        },
    )
    assert confirmed_res["isError"] is False
    assert confirmed_res["structuredContent"]["status"] == "confirmed"

    amended_res = _mcp_call(
        world,
        world.sales_rep_token,
        "amend_order_line",
        {
            "idempotency_key": "mcp-idem-amend-01",
            "order_id": oid,
            "line_id": lid,
            "expected_version": 3,
            "unit_price_minor": 7_100,
        },
    )
    assert amended_res["isError"] is False
    assert amended_res["structuredContent"]["status"] == "pending_approval"
