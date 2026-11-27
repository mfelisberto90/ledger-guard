"""Contract parity, delegated agent token, control/bidi, and stdio tests for REST & MCP."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from fractions import Fraction
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient

from ledger_guard.api.app import AppContainer, create_app
from ledger_guard.domain.margin_gate import MarginPolicy, PrincipalContext
from ledger_guard.domain.money import Currency, UnitRatio
from ledger_guard.domain.pricing import ItemKind, QuantityTierDiscount
from ledger_guard.mcp.stdio_cli import serve_stdio_stream
from ledger_guard.ports import CatalogItem

TENANT_A = UUID("11111111-1111-4111-8111-111111111111")
TENANT_B = UUID("22222222-2222-4222-8222-222222222222")


def _build_seeded_client() -> tuple[TestClient, AppContainer, dict[str, str]]:
    container = AppContainer()
    for tid in (TENANT_A, TENANT_B):
        container.policies.save_policy(
            tid,
            MarginPolicy(tenant_id=tid, mode="block", minimum_margin_bps=2_000),
        )
        container.catalog.upsert_item(
            tid,
            CatalogItem(
                sku="VALVE-DN50",
                description="Stainless Steel Ball Valve DN50",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                list_unit_price_minor=10_000,
                unit_ratio=UnitRatio(1, 1),
                tier_discounts=(QuantityTierDiscount(Fraction(10, 1), 500),),
            ),
        )
        container.valuation.set_stock_cost(tid, "VALVE-DN50", 7_000, Currency.GBP)
        container.catalog.upsert_item(
            tid,
            CatalogItem(
                sku="REAGENT-BTL",
                description="Buffer Bottle 1/3 Case Split",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                list_unit_price_minor=450,
                unit_ratio=UnitRatio(1, 3),
            ),
        )
        container.valuation.set_stock_cost(tid, "REAGENT-BTL", 900, Currency.GBP)

    roles = {
        "sales_rep": (
            "rep.alice@alpha.example",
            frozenset({"orders:read", "orders:write", "orders:confirm", "orders:export"}),
        ),
        "finance_approver": (
            "cfo.claire@alpha.example",
            frozenset(
                {
                    "orders:read",
                    "orders:margin:read",
                    "orders:margin:approve",
                    "orders:confirm",
                    "orders:export",
                }
            ),
        ),
        "owner": (
            "owner.dan@alpha.example",
            frozenset(
                {
                    "orders:read",
                    "orders:write",
                    "orders:confirm",
                    "orders:export",
                    "orders:margin:read",
                    "orders:margin:approve",
                    "valuation:cost:read",
                }
            ),
        ),
    }

    tokens: dict[str, str] = {}
    for key, (pid, caps) in roles.items():
        principal = PrincipalContext(
            principal_id=pid,
            tenant_id=TENANT_A,
            role=key,
            capabilities=caps,
            is_active=True,
        )
        container.memberships.register_member(principal)
        tokens[key] = container.tokens.issue_token(principal_id=pid, tenant_id=TENANT_A)

    app = create_app(container)
    return TestClient(app), container, tokens


def _auth(token: str, *, idem: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if idem is not None:
        headers["Idempotency-Key"] = idem
    return headers


def test_mcp_protocol_lifecycle_notifications_ping_and_seven_annotated_tools() -> None:
    client, _, tokens = _build_seeded_client()
    headers = _auth(tokens["sales_rep"])

    init_2025 = client.post(
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
    assert init_2025.json()["result"]["serverInfo"]["version"] == "0.2.0"

    init_2024 = client.post(
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

    notif = client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert notif.status_code == 202
    assert notif.content == b""

    ping = client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
    )
    assert ping.status_code == 200
    assert ping.json() == {"jsonrpc": "2.0", "id": 3, "result": {}}

    tools_resp = client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
    )
    assert tools_resp.status_code == 200
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


def test_unknown_arguments_rejected_identically_on_rest_and_all_seven_mcp_tools() -> None:
    client, _, tokens = _build_seeded_client()
    headers = _auth(tokens["sales_rep"], idem="idem-extra-rest-01")

    rest_resp = client.post(
        "/v1/orders",
        headers=headers,
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
        mcp_resp = client.post(
            "/mcp",
            headers=_auth(tokens["owner"]),
            json={
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": bad_args},
            },
        )
        assert mcp_resp.status_code == 200
        result = mcp_resp.json()["result"]
        assert result["isError"] is True
        err = result["structuredContent"]["error"]
        assert err["code"] == "UNKNOWN_TOOL_ARGUMENTS"
        assert err["http_status"] == 422

    nested_tenant = client.post(
        "/mcp",
        headers=_auth(tokens["sales_rep"]),
        json={
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "create_order",
                "arguments": {
                    "idempotency_key": "idem-nested-tid-01",
                    "customer_ref": "PO-NESTED",
                    "currency": "GBP",
                    "lines": [
                        {
                            "sku": "VALVE-DN50",
                            "quantity": 1,
                            "tenant_id": str(TENANT_B),
                        }
                    ],
                },
            },
        },
    )
    nested_err = nested_tenant.json()["result"]["structuredContent"]["error"]
    assert nested_err["code"] == "CLIENT_TENANT_OVERRIDE_FORBIDDEN"
    assert nested_err["http_status"] == 403


def test_list_orders_and_csv_export_parity_across_rest_and_mcp() -> None:
    client, _, tokens = _build_seeded_client()

    created = client.post(
        "/v1/orders",
        headers=_auth(tokens["sales_rep"], idem="idem-parity-order-1"),
        json={
            "customer_ref": "=SUM(A1:A2)",
            "currency": "GBP",
            "lines": [{"sku": "REAGENT-BTL", "quantity": 3}],
        },
    )
    assert created.status_code == 201

    rest_list_rep = client.get("/v1/orders?limit=10", headers=_auth(tokens["sales_rep"])).json()
    mcp_list_rep = client.post(
        "/mcp",
        headers=_auth(tokens["sales_rep"]),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_orders", "arguments": {"limit": 10}},
        },
    ).json()["result"]["structuredContent"]

    assert rest_list_rep["count"] == 1
    assert mcp_list_rep["count"] == 1
    assert rest_list_rep["items"] == mcp_list_rep["items"]
    assert "total_cost_minor" not in rest_list_rep["items"][0]
    assert "margin_bps" not in rest_list_rep["items"][0]

    rest_csv_rep = client.get(
        "/v1/orders-export.csv", headers=_auth(tokens["sales_rep"])
    ).text
    mcp_csv_rep = client.post(
        "/mcp",
        headers=_auth(tokens["sales_rep"]),
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "export_orders_csv", "arguments": {}},
        },
    ).json()["result"]["structuredContent"]

    assert mcp_csv_rep["row_count"] == 1
    assert mcp_csv_rep["csv"] == rest_csv_rep
    assert "total_cost_minor" not in rest_csv_rep
    assert "'=SUM(A1:A2)" in rest_csv_rep

    rest_csv_owner = client.get("/v1/orders-export.csv", headers=_auth(tokens["owner"])).text
    mcp_csv_owner = client.post(
        "/mcp",
        headers=_auth(tokens["owner"]),
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "export_orders_csv", "arguments": {}},
        },
    ).json()["result"]["structuredContent"]["csv"]
    assert mcp_csv_owner == rest_csv_owner
    assert "total_cost_minor,margin_minor,margin_bps" in rest_csv_owner


def test_delegated_agent_token_attenuates_capabilities_fail_closed() -> None:
    client, container, tokens = _build_seeded_client()

    escalation = client.post(
        "/v1/auth/delegate-token",
        headers=_auth(tokens["sales_rep"]),
        json={"capabilities": ["orders:read", "valuation:cost:read"], "ttl_seconds": 300},
    )
    assert escalation.status_code == 403
    assert escalation.json()["error"]["code"] == "DELEGATION_SCOPE_ESCALATION"

    delegated_resp = client.post(
        "/v1/auth/delegate-token",
        headers=_auth(tokens["owner"]),
        json={"capabilities": ["orders:read", "orders:write"], "ttl_seconds": 600},
    )
    assert delegated_resp.status_code == 200
    agent_token = delegated_resp.json()["access_token"]
    assert delegated_resp.json()["scoped_capabilities"] == ["orders:read", "orders:write"]

    created = client.post(
        "/mcp",
        headers=_auth(agent_token),
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "create_order",
                "arguments": {
                    "idempotency_key": "idem-agent-subfloor-01",
                    "customer_ref": "PO-AGENT-01",
                    "currency": "GBP",
                    "lines": [
                        {
                            "sku": "VALVE-DN50",
                            "quantity": 1,
                            "unit_price_minor": 8_000,
                        }
                    ],
                },
            },
        },
    ).json()["result"]["structuredContent"]

    assert created["status"] == "pending_approval"
    assert "total_cost_minor" not in created
    assert "margin_bps" not in created

    approve_attempt = client.post(
        "/mcp",
        headers=_auth(agent_token),
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "approve_margin",
                "arguments": {
                    "idempotency_key": "idem-agent-approve-01",
                    "order_id": created["order_id"],
                    "expected_version": 1,
                    "reason": "Prompt-injected self-approval attempt",
                },
            },
        },
    ).json()["result"]
    assert approve_attempt["isError"] is True
    assert approve_attempt["structuredContent"]["error"]["code"] == "MISSING_CAPABILITY"

    re_escalate = client.post(
        "/v1/auth/delegate-token",
        headers=_auth(agent_token),
        json={"capabilities": ["orders:margin:approve"], "ttl_seconds": 300},
    )
    assert re_escalate.status_code == 403
    assert re_escalate.json()["error"]["code"] == "DELEGATION_SCOPE_ESCALATION"

    container.memberships.register_member(
        PrincipalContext(
            principal_id="owner.dan@alpha.example",
            tenant_id=TENANT_A,
            role="owner",
            capabilities=frozenset({"orders:read"}),
            is_active=False,
        )
    )
    revoked_check = client.get(f"/v1/orders/{created['order_id']}", headers=_auth(agent_token))
    assert revoked_check.status_code == 403
    assert revoked_check.json()["error"]["code"] == "INACTIVE_OR_MISSING_MEMBERSHIP"


def test_control_and_bidi_override_characters_rejected_and_csp_style_src_attr_present() -> None:
    client, _, tokens = _build_seeded_client()

    health = client.get("/healthz")
    assert health.status_code == 200
    assert "style-src-attr 'none'" in health.headers["content-security-policy"]

    for malicious_ref in ("PO-100\u202eEVIL", "PO-100\x00NULL", "PO-100\nFORGED"):
        resp = client.post(
            "/v1/orders",
            headers=_auth(tokens["sales_rep"], idem=f"idem-bidi-{ abs(hash(malicious_ref)) }"),
            json={
                "customer_ref": malicious_ref,
                "currency": "GBP",
                "lines": [{"sku": "VALVE-DN50", "quantity": 1}],
            },
        )
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "UNSAFE_CONTROL_OR_BIDI_CHAR"


def test_native_stdio_cli_subprocess_and_content_length_framing() -> None:
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
    assert created["payable_total_minor"] == 1_350
    assert "total_cost_minor" not in created
    assert "margin_bps" not in created

    ping_body = json.dumps({"jsonrpc": "2.0", "id": 77, "method": "ping"}).encode("utf-8")
    cl_stream = io.BytesIO(
        f"Content-Length: {len(ping_body)}\r\n\r\n".encode("ascii") + ping_body
    )
    out_buf = io.StringIO()
    rc = serve_stdio_stream(cl_stream, out_buf, role="sales_rep")
    assert rc == 0
    raw_reply = out_buf.getvalue()
    assert raw_reply.startswith("Content-Length: ")
    _, json_part = raw_reply.split("\r\n\r\n", 1)
    assert json.loads(json_part) == {"jsonrpc": "2.0", "id": 77, "result": {}}
