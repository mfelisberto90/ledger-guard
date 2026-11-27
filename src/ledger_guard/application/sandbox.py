"""Shared in-memory reference sandbox seeding used across stdio MCP, HTTP sandbox, and tests."""

from __future__ import annotations

from fractions import Fraction
from typing import Any
from uuid import UUID

from ledger_guard.adapters.in_memory import (
    InMemoryCatalogAdapter,
    InMemoryOrderRepository,
    InMemoryPolicyRepository,
    InMemoryValuationAdapter,
)
from ledger_guard.application.order_service import OrderLineCommand, OrderService
from ledger_guard.domain.margin_gate import MarginPolicy, OrderKind, PrincipalContext
from ledger_guard.domain.money import Currency, UnitRatio
from ledger_guard.domain.pricing import ItemKind, QuantityTierDiscount
from ledger_guard.ports import CatalogItem
from ledger_guard.security.auth import MembershipDirectory, PasswordHasher

SANDBOX_TENANT_ID: UUID = UUID("00000000-0000-4000-8000-000000000101")
SANDBOX_PENDING_ORDER_ID: UUID = UUID("00000000-0000-4000-8000-000000000901")
SANDBOX_DEMO_PASSPHRASE: str = "DemoSandboxPass2026!"  # noqa: S105

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "warehouse": frozenset({"orders:read", "orders:export"}),
    "sales_rep": frozenset(
        {"orders:read", "orders:write", "orders:confirm", "orders:export"}
    ),
    "finance_approver": frozenset(
        {
            "orders:read",
            "orders:write",
            "orders:margin:read",
            "orders:margin:approve",
            "orders:confirm",
            "orders:export",
        }
    ),
    "owner": frozenset(
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
}


def seed_catalog_and_policies(
    *,
    tenant_id: UUID,
    catalog: InMemoryCatalogAdapter,
    valuation: InMemoryValuationAdapter,
    policies: InMemoryPolicyRepository,
    minimum_margin_bps: int = 2_000,
) -> None:
    """Seed deterministic reference SKUs (`VALVE-DN50`, `REAGENT-BTL`, `INSTALL-SVC`)."""
    policies.save_policy(
        tenant_id,
        MarginPolicy(
            tenant_id=tenant_id,
            mode="block",
            minimum_margin_bps=minimum_margin_bps,
        ),
    )

    catalog.upsert_item(
        tenant_id,
        CatalogItem(
            sku="VALVE-DN50",
            description="Stainless Steel Ball Valve DN50 PN40",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            list_unit_price_minor=10_000,
            unit_ratio=UnitRatio(1, 1),
            tier_discounts=(
                QuantityTierDiscount(Fraction(10, 1), 500),
                QuantityTierDiscount(Fraction(50, 1), 1_200),
            ),
        ),
    )
    valuation.set_stock_cost(tenant_id, "VALVE-DN50", 7_000, Currency.GBP)

    catalog.upsert_item(
        tenant_id,
        CatalogItem(
            sku="REAGENT-BTL",
            description="Analytical Grade Buffer Bottle (1/3 Case Split)",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            list_unit_price_minor=500,
            unit_ratio=UnitRatio(1, 3),
        ),
    )
    valuation.set_stock_cost(tenant_id, "REAGENT-BTL", 1_000, Currency.GBP)

    catalog.upsert_item(
        tenant_id,
        CatalogItem(
            sku="INSTALL-SVC",
            description="On-Site Commissioning Service Visit",
            item_kind=ItemKind.SERVICE,
            currency=Currency.GBP,
            list_unit_price_minor=25_000,
            unit_ratio=UnitRatio(1, 1),
        ),
    )


def seed_reference_sandbox(
    *,
    catalog: InMemoryCatalogAdapter,
    valuation: InMemoryValuationAdapter,
    policies: InMemoryPolicyRepository,
    memberships: MembershipDirectory,
    orders: InMemoryOrderRepository,
    password_hasher: PasswordHasher | None = None,
    include_password_hashes: bool = False,
    seed_pending_order: bool = False,
) -> tuple[dict[str, PrincipalContext], dict[str, Any] | None]:
    """Populate deterministic sandbox tenant, roles, SKUs, and optional pending order."""
    seed_catalog_and_policies(
        tenant_id=SANDBOX_TENANT_ID,
        catalog=catalog,
        valuation=valuation,
        policies=policies,
    )

    pw_hash = (
        password_hasher.hash_password(SANDBOX_DEMO_PASSPHRASE)
        if include_password_hashes and password_hasher is not None
        else None
    )

    principals: dict[str, PrincipalContext] = {}
    for role_name, caps in ROLE_CAPABILITIES.items():
        principal = PrincipalContext(
            principal_id=f"stdio.{role_name}@sandbox.ledgerguard.local",
            tenant_id=SANDBOX_TENANT_ID,
            role=role_name,
            capabilities=caps,
            is_active=True,
        )
        memberships.register_member(principal, password_hash=pw_hash)
        principals[role_name] = principal

    seeded_order: dict[str, Any] | None = None
    if seed_pending_order:
        service = OrderService(
            catalog=catalog,
            valuation=valuation,
            orders=orders,
            policies=policies,
        )
        seeded_order = service.create_order(
            principals["sales_rep"],
            customer_ref="PO-SANDBOX-SUBFLOOR",
            order_kind=OrderKind.STANDARD,
            currency=Currency.GBP,
            lines=[
                OrderLineCommand(
                    sku="VALVE-DN50",
                    quantity=2,
                    unit_price_minor=7_500,
                )
            ],
            order_id=SANDBOX_PENDING_ORDER_ID,
        )

    return principals, seeded_order
