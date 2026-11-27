"""Shared multi-tenant fixtures for domain, HTTP API, security, and MCP parity tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from ledger_guard.api.app import AppContainer, create_app
from ledger_guard.application.sandbox import seed_catalog_and_policies
from ledger_guard.domain.margin_gate import MarginPolicy, PrincipalContext
from ledger_guard.domain.money import Currency, UnitRatio
from ledger_guard.domain.pricing import ItemKind
from ledger_guard.ports import CatalogItem

TENANT_ALPHA = UUID("11111111-1111-4111-8111-111111111111")
TENANT_BRAVO = UUID("22222222-2222-4222-8222-222222222222")


@dataclass(frozen=True, slots=True)
class SeededWorld:
    """Seeded multi-tenant test world with tokens for distinct RBAC personas."""

    container: AppContainer
    client: TestClient
    sales_rep_token: str
    second_sales_rep_token: str
    approver_token: str
    warehouse_token: str
    inactive_token: str
    bravo_admin_token: str

    @staticmethod
    def auth_headers(token: str, idem_key: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {token}"}
        if idem_key is not None:
            headers["Idempotency-Key"] = idem_key
        return headers

    def mcp_call(
        self,
        token: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        req_id: int = 1,
    ) -> dict[str, Any]:
        resp = self.client.post(
            "/mcp",
            headers=self.auth_headers(token),
            json={
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
        )
        assert resp.status_code == 200
        payload: dict[str, Any] = resp.json()
        result: dict[str, Any] = payload["result"]
        return result


@pytest.fixture
def world() -> SeededWorld:
    container = AppContainer(
        signing_key=b"test-signing-key-32-bytes-minimum!!",
        rate_limit_key=b"test-ratelimit-hmac-key-32-bytes!",
        webhook_secret=b"test-webhook-hmac-secret-32-bytes!",
        trusted_proxy_cidrs=("127.0.0.1/32", "10.0.0.0/8"),
    )

    seed_catalog_and_policies(
        tenant_id=TENANT_ALPHA,
        catalog=container.catalog,
        valuation=container.valuation,
        policies=container.policies,
        minimum_margin_bps=2_000,
    )

    container.policies.save_policy(
        TENANT_BRAVO,
        MarginPolicy(tenant_id=TENANT_BRAVO, mode="block", minimum_margin_bps=1_500),
    )
    container.catalog.upsert_item(
        TENANT_BRAVO,
        CatalogItem(
            sku="VALVE-DN50",
            description="Bravo Tenant Control Valve",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            list_unit_price_minor=12_000,
            unit_ratio=UnitRatio(1, 1),
        ),
    )
    container.valuation.set_stock_cost(TENANT_BRAVO, "VALVE-DN50", 8_000, Currency.GBP)

    pw_hash = container.password_hasher.hash_password("CorrectHorseBattery99!")

    sales_rep = PrincipalContext(
        principal_id="rep.one@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="sales_rep",
        capabilities=frozenset({"orders:read", "orders:write", "orders:confirm", "orders:export"}),
        is_active=True,
    )
    second_rep = PrincipalContext(
        principal_id="rep.two@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="sales_rep",
        capabilities=frozenset({"orders:read", "orders:write", "orders:confirm"}),
        is_active=True,
    )
    approver = PrincipalContext(
        principal_id="controller@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="finance_approver",
        capabilities=frozenset(
            {
                "orders:read",
                "orders:write",
                "orders:confirm",
                "orders:margin:approve",
                "orders:margin:read",
                "valuation:cost:read",
                "orders:export",
            }
        ),
        is_active=True,
    )
    warehouse = PrincipalContext(
        principal_id="dispatch@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="warehouse",
        capabilities=frozenset({"orders:read", "orders:export"}),
        is_active=True,
    )
    inactive_user = PrincipalContext(
        principal_id="former.staff@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="sales_rep",
        capabilities=frozenset({"orders:read", "orders:write"}),
        is_active=False,
    )
    bravo_admin = PrincipalContext(
        principal_id="director@bravo.example",
        tenant_id=TENANT_BRAVO,
        role="owner",
        capabilities=frozenset(
            {
                "orders:read",
                "orders:write",
                "orders:confirm",
                "orders:margin:approve",
                "orders:margin:read",
                "valuation:cost:read",
            }
        ),
        is_active=True,
    )

    for member in (sales_rep, second_rep, approver, warehouse, inactive_user, bravo_admin):
        container.memberships.register_member(member, password_hash=pw_hash)

    app = create_app(container)
    client = TestClient(app, client=("127.0.0.1", 50000))

    return SeededWorld(
        container=container,
        client=client,
        sales_rep_token=container.tokens.issue_token(
            principal_id=sales_rep.principal_id, tenant_id=TENANT_ALPHA
        ),
        second_sales_rep_token=container.tokens.issue_token(
            principal_id=second_rep.principal_id, tenant_id=TENANT_ALPHA
        ),
        approver_token=container.tokens.issue_token(
            principal_id=approver.principal_id, tenant_id=TENANT_ALPHA
        ),
        warehouse_token=container.tokens.issue_token(
            principal_id=warehouse.principal_id, tenant_id=TENANT_ALPHA
        ),
        inactive_token=container.tokens.issue_token(
            principal_id=inactive_user.principal_id, tenant_id=TENANT_ALPHA
        ),
        bravo_admin_token=container.tokens.issue_token(
            principal_id=bravo_admin.principal_id, tenant_id=TENANT_BRAVO
        ),
    )
