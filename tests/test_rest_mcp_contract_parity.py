"""Contract parity, delegated agent token, control/bidi, and stdio tests for REST & MCP."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from typing import Any

from fastapi.testclient import TestClient

from ledger_guard.api.app import create_sandbox_app
from ledger_guard.application.sandbox import SANDBOX_DEMO_PASSPHRASE, SANDBOX_TENANT_ID
from ledger_guard.domain.margin_gate import PrincipalContext
from ledger_guard.mcp.stdio_cli import serve_stdio_stream
from tests.conftest import TENANT_ALPHA, TENANT_BRAVO, SeededWorld


def test_mcp_protocol_lifecycle_notifications_ping_and_seven_annotated_tools(
    world: SeededWorld,
) -> None:
    headers = world.auth_headers(world.sales_rep_token)

    init_2025 = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}},
        },
    )
    assert init_2025.status_code == 200
    assert init_2025.json()["result"]["protocolVersion"] == "2025-03-26"
    assert init_2025.json()["result"]["serverInfo"]["version"] == "0.3.0"

    init_2024 = world.client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        },
    )
    assert init_2024.status_code == 200
    assert init_2024.json()["result"]["protocolVersion"] == "2024-11-05"

    notif = world.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert notif.status_code == 202
    assert notif.content == b""

    # Non-object JSON on /mcp returns JSON-RPC -32600 rather than FastAPI HTTP 422 (SEC-22)
    non_obj = world.client.post("/mcp", headers=headers, json=[1, 2, 3])
    assert non_obj.status_code == 200
    assert non_obj.json()["error"]["code"] == -32600

    # Malicious object JSON-RPC id is rejected as -32600 (SEC-22)
    bad_id = world.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": {"nested": True}, "method": "ping"},
    )
    assert bad_id.json()["error"]["code"] == -32600

    ping = world.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
    )
    assert ping.status_code == 200
    assert ping.json() == {"jsonrpc": "2.0", "id": 3, "result": {}}

    tools_resp = world.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
    )
    tools = tools_resp.json()["result"]["tools"]
    names = [t["name"] for t in tools]
    assert names == [
        "create_order",
        "get_order",
        "list_orders",
        "confirm_order",
        "approve_margin",
        "amend_order_line",
        "export_orders_csv",
    ]
    for tool in tools:
        ann = tool["annotations"]
        assert isinstance(ann["readOnlyHint"], bool)
        assert ann["destructiveHint"] is False
        assert ann["idempotentHint"] is True
        assert ann["openWorldHint"] is False

    create_schema = tools[0]["inputSchema"]
    sku_prop = create_schema["properties"]["lines"]["items"]["properties"]["sku"]
    assert sku_prop["minLength"] == 1
    assert sku_prop["maxLength"] == 64


def test_unknown_arguments_rejected_identically_on_rest_and_all_seven_mcp_tools(
    world: SeededWorld,
) -> None:
    rest_resp = world.client.post(
        "/v1/orders",
        headers=world.auth_headers(world.sales_rep_token, "idem-extra-rest-01"),
        json={
            "customer_ref": "PO-100",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1}],
            "hallucinated_flag": True,
        },
    )
    assert rest_resp.status_code == 422
    assert rest_resp.json()["error"]["code"] == "REQUEST_VALIDATION_FAILED"

    sample_uuid = "33333333-3333-4333-8333-333333333333"
    tool_payloads: list[tuple[str, dict[str, Any]]] = [
        (
            "create_order",
            {
                "idempotency_key": "idem-mcp-extra-1",
                "customer_ref": "PO-100",
                "currency": "GBP",
                "lines": [{"sku": "VALVE-DN50", "quantity": 1}],
                "bypass_margin": True,
            },
        ),
        ("get_order", {"order_id": sample_uuid, "include_cost": True}),
        ("list_orders", {"limit": 10, "all_tenants": True}),
        (
            "confirm_order",
            {
                "idempotency_key": "idem-mcp-extra-2",
                "order_id": sample_uuid,
                "expected_version": 1,
                "force": True,
            },
        ),
        (
            "approve_margin",
            {
                "idempotency_key": "idem-mcp-extra-3",
                "order_id": sample_uuid,
                "expected_version": 1,
                "reason": "Contractual discount",
                "override_four_eyes": True,
            },
        ),
        (
            "amend_order_line",
            {
                "idempotency_key": "idem-mcp-extra-4",
                "order_id": sample_uuid,
                "line_id": sample_uuid,
                "expected_version": 1,
                "secret_cost_minor": 10,
            },
        ),
        ("export_orders_csv", {"include_supplier_costs": True}),
    ]

    for idx, (tool_name, bad_args) in enumerate(tool_payloads, start=10):
        result = world.mcp_call(world.approver_token, tool_name, bad_args, req_id=idx)
        assert result["isError"] is True
        err = result["structuredContent"]["error"]
        assert err["code"] == "UNKNOWN_TOOL_ARGUMENTS"
        assert err["http_status"] == 422

    nested_tenant = world.mcp_call(
        world.sales_rep_token,
        "create_order",
        {
            "idempotency_key": "idem-nested-tid-01",
            "customer_ref": "PO-NESTED",
            "currency": "GBP",
            "lines": [
                {
                    "sku": "VALVE-DN50",
                    "quantity": 1,
                    "tenant_id": str(TENANT_BRAVO),
                }
            ],
        },
        req_id=99,
    )
    nested_err = nested_tenant["structuredContent"]["error"]
    assert nested_err["code"] == "CLIENT_TENANT_OVERRIDE_FORBIDDEN"
    assert nested_err["http_status"] == 403


def test_list_orders_and_csv_export_parity_across_rest_and_mcp(world: SeededWorld) -> None:
    created = world.client.post(
        "/v1/orders",
        headers=world.auth_headers(world.sales_rep_token, "idem-parity-order-1"),
        json={
            "customer_ref": "=SUM(A1:A2)",
            "currency": "GBP",
            "lines": [{"sku": "REAGENT-BTL", "quantity": 3}],
        },
    )
    assert created.status_code == 201

    rest_list_rep = world.client.get(
        "/v1/orders?limit=10", headers=world.auth_headers(world.sales_rep_token)
    ).json()
    mcp_list_rep = world.mcp_call(world.sales_rep_token, "list_orders", {"limit": 10})[
        "structuredContent"
    ]

    assert rest_list_rep["count"] == 1
    assert mcp_list_rep["count"] == 1
    assert rest_list_rep["items"] == mcp_list_rep["items"]
    assert "total_cost_minor" not in rest_list_rep["items"][0]
    assert "margin_bps" not in rest_list_rep["items"][0]

    # Cross-transport idempotency parity: same key from HTTP replays cleanly over MCP (SEC-20)
    mcp_replay = world.mcp_call(
        world.sales_rep_token,
        "create_order",
        {
            "idempotency_key": "idem-parity-order-1",
            "customer_ref": "=SUM(A1:A2)",
            "currency": "GBP",
            "lines": [{"sku": "REAGENT-BTL", "quantity": 3}],
        },
    )["structuredContent"]
    assert mcp_replay["idempotent_replay"] is True
    assert mcp_replay["order_id"] == created.json()["order_id"]

    rest_csv_rep = world.client.get(
        "/v1/orders-export.csv", headers=world.auth_headers(world.sales_rep_token)
    ).text
    mcp_csv_rep = world.mcp_call(world.sales_rep_token, "export_orders_csv", {})[
        "structuredContent"
    ]

    assert mcp_csv_rep["row_count"] == 1
    assert mcp_csv_rep["csv"] == rest_csv_rep
    assert "total_cost_minor" not in rest_csv_rep
    assert "'=SUM(A1:A2)" in rest_csv_rep

    rest_csv_approver = world.client.get(
        "/v1/orders-export.csv", headers=world.auth_headers(world.approver_token)
    ).text
    mcp_csv_approver = world.mcp_call(world.approver_token, "export_orders_csv", {})[
        "structuredContent"
    ]["csv"]
    assert mcp_csv_approver == rest_csv_approver
    assert "total_cost_minor,margin_minor,margin_bps" in rest_csv_approver


def test_delegated_agent_token_blocks_redelegation_and_reprojects_idempotent_replay(
    world: SeededWorld,
) -> None:
    escalation = world.client.post(
        "/v1/auth/delegate-token",
        headers=world.auth_headers(world.sales_rep_token),
        json={"capabilities": ["orders:read", "valuation:cost:read"], "ttl_seconds": 300},
    )
    assert escalation.status_code == 403
    assert escalation.json()["error"]["code"] == "DELEGATION_SCOPE_ESCALATION"

    # Approver (with valuation:cost:read + orders:margin:read) creates an order first
    owner_created = world.client.post(
        "/v1/orders",
        headers=world.auth_headers(world.approver_token, "idem-replay-leak-check-01"),
        json={
            "customer_ref": "PO-REPLAY-SEC01",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 8_000}],
        },
    )
    assert owner_created.status_code == 201
    assert owner_created.json()["total_cost_minor"] == 7_000

    # Mint attenuated write-only/read token WITHOUT cost or margin capabilities
    delegated_resp = world.client.post(
        "/v1/auth/delegate-token",
        headers=world.auth_headers(world.approver_token),
        json={"capabilities": ["orders:read", "orders:write"], "ttl_seconds": 600},
    )
    assert delegated_resp.status_code == 200
    agent_token = delegated_resp.json()["access_token"]

    # Replaying cached owner Idempotency-Key with attenuated token MUST re-project (SEC-01)
    replayed_under_scp = world.client.post(
        "/v1/orders",
        headers=world.auth_headers(agent_token, "idem-replay-leak-check-01"),
        json={
            "customer_ref": "PO-REPLAY-SEC01",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 8_000}],
        },
    )
    assert replayed_under_scp.status_code == 201
    assert replayed_under_scp.headers["x-idempotent-replay"] == "true"
    assert "total_cost_minor" not in replayed_under_scp.json()
    assert "margin_bps" not in replayed_under_scp.json()

    # Read-only delegated token replaying a write key MUST be blocked with 403 before replay
    read_only_tok = world.client.post(
        "/v1/auth/delegate-token",
        headers=world.auth_headers(world.approver_token),
        json={"capabilities": ["orders:read"], "ttl_seconds": 600},
    ).json()["access_token"]
    blocked_replay = world.client.post(
        "/v1/orders",
        headers=world.auth_headers(read_only_tok, "idem-replay-leak-check-01"),
        json={
            "customer_ref": "PO-REPLAY-SEC01",
            "currency": "GBP",
            "lines": [{"sku": "VALVE-DN50", "quantity": 1, "unit_price_minor": 8_000}],
        },
    )
    assert blocked_replay.status_code == 403
    assert blocked_replay.json()["error"]["code"] == "MISSING_CAPABILITY"

    # Delegated sub-token cannot mint/extend itself via /v1/auth/delegate-token (SEC-04)
    redelegate = world.client.post(
        "/v1/auth/delegate-token",
        headers=world.auth_headers(agent_token),
        json={"capabilities": ["orders:read"], "ttl_seconds": 3_600},
    )
    assert redelegate.status_code == 403
    assert redelegate.json()["error"]["code"] == "DELEGATED_TOKEN_CANNOT_REDELEGATE"

    # Server-side deactivation immediately revokes delegated token access
    world.container.memberships.register_member(
        PrincipalContext(
            principal_id="controller@alpha.example",
            tenant_id=TENANT_ALPHA,
            role="finance_approver",
            capabilities=frozenset({"orders:read"}),
            is_active=False,
        )
    )
    revoked_check = world.client.get(
        f"/v1/orders/{owner_created.json()['order_id']}",
        headers=world.auth_headers(agent_token),
    )
    assert revoked_check.status_code == 403
    assert revoked_check.json()["error"]["code"] == "INACTIVE_OR_MISSING_MEMBERSHIP"


def test_control_and_bidi_override_characters_rejected_and_csp_style_src_attr_present(
    world: SeededWorld,
) -> None:
    health = world.client.get("/healthz")
    assert health.status_code == 200
    assert "style-src-attr 'none'" in health.headers["content-security-policy"]

    for idx, malicious_ref in enumerate(("PO-100\u202eEVIL", "PO-100\x00NULL", "PO-100\nFORGED")):
        resp = world.client.post(
            "/v1/orders",
            headers=world.auth_headers(world.sales_rep_token, f"idem-bidi-check-{idx}"),
            json={
                "customer_ref": malicious_ref,
                "currency": "GBP",
                "lines": [{"sku": "VALVE-DN50", "quantity": 1}],
            },
        )
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "UNSAFE_CONTROL_OR_BIDI_CHAR"


def test_native_stdio_cli_subprocess_framing_bounds_and_sandbox_four_eyes() -> None:
    stdin_lines = "\n".join(
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest-inspector", "version": "1.0.0"},
                    },
                }
            ),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "create_order",
                        "arguments": {
                            "idempotency_key": "stdio-idem-0001",
                            "customer_ref": "PO-STDIO-1",
                            "currency": "GBP",
                            "lines": [{"sku": "REAGENT-BTL", "quantity": 3}],
                        },
                    },
                }
            ),
        ]
    )

    proc = subprocess.run(
        [sys.executable, "-m", "ledger_guard"],
        input=stdin_lines + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert proc.stderr == ""
    frames = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert len(frames) == 3
    assert frames[0]["id"] == 1
    assert frames[0]["result"]["protocolVersion"] == "2025-03-26"
    assert frames[1]["id"] == 2
    assert len(frames[1]["result"]["tools"]) == 7

    created = frames[2]["result"]["structuredContent"]
    assert created["payable_total_minor"] == 1_500
    assert "total_cost_minor" not in created
    assert "margin_bps" not in created

    # Finance approver stdio session can immediately approve the pre-seeded sub-floor order!
    approve_stdin = "\n".join(
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {"name": "list_orders", "arguments": {"limit": 10}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": "approve_margin",
                        "arguments": {
                            "idempotency_key": "stdio-approve-seeded-1",
                            "order_id": "00000000-0000-0000-0000-000000000000",
                            "expected_version": 1,
                            "reason": "Pre-seeded check",
                        },
                    },
                }
            ),
        ]
    )
    approver_out = io.StringIO()
    serve_stdio_stream(
        io.BytesIO(approve_stdin.encode("utf-8")), approver_out, role="finance_approver"
    )
    listed = json.loads(approver_out.getvalue().splitlines()[0])["result"]["structuredContent"]
    assert listed["count"] == 1
    seeded_id = listed["items"][0]["order_id"]

    real_approve_stdin = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "approve_margin",
                "arguments": {
                    "idempotency_key": "stdio-approve-seeded-2",
                    "order_id": seeded_id,
                    "expected_version": 1,
                    "reason": "Approved in finance_approver stdio session",
                },
            },
        }
    ).encode("utf-8")
    approve_out = io.StringIO()
    serve_stdio_stream(io.BytesIO(real_approve_stdin), approve_out, role="finance_approver")
    approved_res = json.loads(approve_out.getvalue().splitlines()[0])["result"]
    assert approved_res["isError"] is False
    gate_code = approved_res["structuredContent"]["readiness_gates"][0]["code"]
    assert gate_code == "MARGIN_EXCEPTION_APPROVED"

    # Reject negative / oversized Content-Length cleanly without hanging or OOM (SEC-06)
    bad_cl_stream = io.BytesIO(b"Content-Length: -1\r\n\r\n")
    bad_out = io.StringIO()
    assert serve_stdio_stream(bad_cl_stream, bad_out) == 0
    assert "-32600" in bad_out.getvalue()

    ping_body = json.dumps({"jsonrpc": "2.0", "id": 77, "method": "ping"}).encode("utf-8")
    cl_stream = io.BytesIO(
        f"Content-Length: {len(ping_body)}\r\n\r\n".encode("ascii") + ping_body
    )
    out_buf = io.StringIO()
    assert serve_stdio_stream(cl_stream, out_buf, role="sales_rep") == 0
    _, json_part = out_buf.getvalue().split("\r\n\r\n", 1)
    assert json.loads(json_part) == {"jsonrpc": "2.0", "id": 77, "result": {}}


def test_create_sandbox_app_allows_immediate_login_and_order_flow() -> None:
    sandbox_client = TestClient(create_sandbox_app())
    login_resp = sandbox_client.post(
        "/v1/auth/login",
        json={
            "tenant_id": str(SANDBOX_TENANT_ID),
            "principal_id": "stdio.sales_rep@sandbox.ledgerguard.local",
            "password": SANDBOX_DEMO_PASSPHRASE,
        },
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    orders_resp = sandbox_client.get(
        "/v1/orders", headers={"Authorization": f"Bearer {token}"}
    )
    assert orders_resp.status_code == 200
    assert orders_resp.json()["count"] == 1
