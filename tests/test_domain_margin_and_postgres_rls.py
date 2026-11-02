"""Tests for margin policy governance, four-eyes SoD, projection, and PostgreSQL FORCE RLS."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from ledger_guard.adapters import PostgresTenantSession
from ledger_guard.application import OrderLineCommand
from ledger_guard.domain import (
    AuthorizationError,
    ConflictError,
    Currency,
    MarginBlockedError,
    MarginPolicy,
    OrderKind,
    OrderStatus,
    PrincipalContext,
    SeparationOfDutiesError,
    ValidationError,
)
from tests.conftest import TENANT_ALPHA, SeededWorld


def test_stock_revaluation_never_retroactively_invalidates_confirmed_order(
    world: SeededWorld,
) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    approver = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "controller@alpha.example"
    )

    created = world.container.order_service.create_order(
        rep,
        customer_ref="ACME-UK-001",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=2, unit_price_minor=10_000)],
    )
    order_uuid = UUID(created["order_id"])
    confirmed = world.container.order_service.confirm_order(
        rep, order_id=order_uuid, expected_version=1
    )
    assert confirmed["status"] == OrderStatus.CONFIRMED.value

    # Warehouse drastically increases live stock cost from £70.00 to £99.00 (1% margin if repriced)
    new_rev = world.container.valuation.set_stock_cost(
        TENANT_ALPHA, "VALVE-DN50", 9_900, Currency.GBP
    )
    assert new_rev == 2

    fetched = world.container.order_service.get_order(approver, order_id=order_uuid)
    assert fetched["status"] == OrderStatus.CONFIRMED.value
    assert fetched["total_cost_minor"] == 14_000
    assert fetched["margin_bps"] == 3_000
    assert fetched["readiness_gates"][0]["met"] is True


def test_exempt_order_kinds_bypass_margin_block_even_at_zero_revenue(
    world: SeededWorld,
) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    for exempt_kind in (
        OrderKind.RETURN,
        OrderKind.CREDIT_MEMO,
        OrderKind.FREE_OF_CHARGE_REPLACEMENT,
        OrderKind.CONSIGNMENT,
    ):
        order = world.container.order_service.create_order(
            rep,
            customer_ref=f"EXEMPT-{exempt_kind.value}",
            order_kind=exempt_kind,
            currency=Currency.GBP,
            lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=0)],
        )
        assert order["status"] == OrderStatus.DRAFT.value
        assert order["readiness_gates"][0]["code"] == "ORDER_KIND_EXEMPT"
        assert order["readiness_gates"][0]["met"] is True


def test_policy_modes_warn_and_off_allow_confirmation_below_target(world: SeededWorld) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )

    world.container.policies.save_policy(
        TENANT_ALPHA,
        MarginPolicy(tenant_id=TENANT_ALPHA, mode="warn", minimum_margin_bps=2_500),
    )
    warned = world.container.order_service.create_order(
        rep,
        customer_ref="WARN-01",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=8_000)],
    )
    assert warned["readiness_gates"][0]["code"] == "MARGIN_BELOW_FLOOR_WARN"
    assert warned["readiness_gates"][0]["met"] is True
    confirmed = world.container.order_service.confirm_order(
        rep, order_id=UUID(warned["order_id"]), expected_version=1
    )
    assert confirmed["status"] == "confirmed"

    world.container.policies.save_policy(
        TENANT_ALPHA,
        MarginPolicy(tenant_id=TENANT_ALPHA, mode="off", minimum_margin_bps=5_000),
    )
    policy_off = world.container.order_service.create_order(
        rep,
        customer_ref="OFF-01",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=7_100)],
    )
    assert policy_off["readiness_gates"][0]["code"] == "MARGIN_POLICY_OFF"


def test_borderline_sub_floor_margin_blocked_by_exact_cross_multiplication(
    world: SeededWorld,
) -> None:
    # Cost = 7000p. Floor = 2000 bps (20.00%). At price = 8749p:
    # Margin = 1749p; 1749 / 8749 = 19.990856...% -> must block!
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    order = world.container.order_service.create_order(
        rep,
        customer_ref="BORDERLINE-1999",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=8_749)],
    )
    assert order["status"] == "pending_approval"
    assert order["readiness_gates"][0]["met"] is False
    with pytest.raises(MarginBlockedError):
        world.container.order_service.confirm_order(
            rep, order_id=UUID(order["order_id"]), expected_version=1
        )


def test_four_eyes_blocks_creator_and_last_amender_even_with_approve_capability(
    world: SeededWorld,
) -> None:
    # Register an admin who has BOTH orders:write AND orders:margin:approve
    dual_principal = PrincipalContext(
        principal_id="director.alpha@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="finance_approver",
        capabilities=frozenset({"orders:read", "orders:write", "orders:margin:approve"}),
        is_active=True,
    )
    world.container.memberships.register_member(dual_principal)

    order = world.container.order_service.create_order(
        dual_principal,
        customer_ref="SELF-APPROVE-ATTEMPT",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=7_500)],
    )
    order_uuid = UUID(order["order_id"])

    # Case-varied PrincipalContext still resolves to same normalized principal_id -> 403 SoD!
    upper_case_self = PrincipalContext(
        principal_id="  DIRECTOR.ALPHA@ALPHA.EXAMPLE ",
        tenant_id=TENANT_ALPHA,
        role="finance_approver",
        capabilities=frozenset({"orders:margin:approve"}),
        is_active=True,
    )
    with pytest.raises(SeparationOfDutiesError):
        world.container.order_service.approve_margin(
            upper_case_self,
            order_id=order_uuid,
            expected_version=1,
            reason="Trying to approve my own discount",
        )


def test_four_eyes_blocks_last_amending_principal_and_requires_non_empty_reason(
    world: SeededWorld,
) -> None:
    rep_one = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    approver = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "controller@alpha.example"
    )

    # Rep one creates healthy order (30% margin) and confirms it
    created = world.container.order_service.create_order(
        rep_one,
        customer_ref="AMEND-SOD-01",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=10_000)],
    )
    order_uuid = UUID(created["order_id"])
    line_uuid = UUID(created["lines"][0]["line_id"])
    confirmed = world.container.order_service.confirm_order(
        rep_one, order_id=order_uuid, expected_version=1
    )
    assert confirmed["status"] == "confirmed"

    # Controller lowers price to £75.00 -> transitions back to pending_approval
    amended = world.container.order_service.amend_order_line(
        approver,
        order_id=order_uuid,
        line_id=line_uuid,
        expected_version=2,
        unit_price_minor=7_500,
    )
    assert amended["status"] == "pending_approval"
    assert amended["last_amended_by"] == "controller@alpha.example"

    # Controller cannot approve their own price-lowering amendment!
    with pytest.raises(SeparationOfDutiesError):
        world.container.order_service.approve_margin(
            approver,
            order_id=order_uuid,
            expected_version=3,
            reason="Approving my own amendment",
        )

    # Distinct approver with blank reason is rejected with ValidationError
    second_approver = PrincipalContext(
        principal_id="cfo@alpha.example",
        tenant_id=TENANT_ALPHA,
        role="finance_approver",
        capabilities=frozenset({"orders:margin:approve", "orders:read"}),
        is_active=True,
    )
    with pytest.raises(ValidationError):
        world.container.order_service.approve_margin(
            second_approver,
            order_id=order_uuid,
            expected_version=3,
            reason="   ",
        )

    approved = world.container.order_service.approve_margin(
        second_approver,
        order_id=order_uuid,
        expected_version=3,
        reason="Approved strategic frame contract alignment.",
    )
    assert len(approved["approvals"]) == 1
    assert approved["readiness_gates"][0]["code"] == "MARGIN_EXCEPTION_APPROVED"


def test_capability_projection_strips_cost_and_margin_for_warehouse_and_sales_rep(
    world: SeededWorld,
) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    warehouse = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "dispatch@alpha.example"
    )
    approver = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "controller@alpha.example"
    )

    created = world.container.order_service.create_order(
        rep,
        customer_ref="PROJECTION-CHECK",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=7_800)],
    )
    order_uuid = UUID(created["order_id"])

    warehouse_view = world.container.order_service.get_order(warehouse, order_id=order_uuid)
    for forbidden_key in ("total_cost_minor", "margin_minor", "margin_bps"):
        assert forbidden_key not in warehouse_view
    for forbidden_line_key in ("unit_cost_minor", "total_cost_minor", "margin_minor", "margin_bps"):
        assert forbidden_line_key not in warehouse_view["lines"][0]
    step_kinds = [s["kind"] for s in warehouse_view["lines"][0]["steps"]]
    assert "STATISTICAL_VALUATION_COST" not in step_kinds
    # Gate is still enforced without leaking cost numbers in remediation!
    gate = warehouse_view["readiness_gates"][0]
    assert gate["met"] is False
    assert "7000" not in gate["remediation"]

    finance_view = world.container.order_service.get_order(approver, order_id=order_uuid)
    assert finance_view["total_cost_minor"] == 7_000
    assert finance_view["margin_minor"] == 800
    assert finance_view["lines"][0]["unit_cost_minor"] == 7_000


def test_optimistic_concurrency_conflict_raises_409_conflict_error(world: SeededWorld) -> None:
    rep = world.container.memberships.resolve_active_principal(
        TENANT_ALPHA, "rep.one@alpha.example"
    )
    created = world.container.order_service.create_order(
        rep,
        customer_ref="OPT-LOCK-01",
        order_kind=OrderKind.STANDARD,
        currency=Currency.GBP,
        lines=[OrderLineCommand(sku="VALVE-DN50", quantity=1, unit_price_minor=10_000)],
    )
    order_uuid = UUID(created["order_id"])
    _ = world.container.order_service.confirm_order(rep, order_id=order_uuid, expected_version=1)

    with pytest.raises(ConflictError) as exc_info:
        world.container.order_service.confirm_order(rep, order_id=order_uuid, expected_version=1)
    assert exc_info.value.code == "OPTIMISTIC_LOCK_CONFLICT"


class _FakeSqlCursor:
    def __init__(self, *, membership_exists: bool) -> None:
        self.membership_exists = membership_exists
        self.executed: list[tuple[str, Sequence[Any] | None]] = []
        self.closed = False

    def execute(self, query: str, params: Sequence[Any] | None = None) -> None:
        self.executed.append((query, params))

    def fetchone(self) -> tuple[Any, ...] | None:
        if self.membership_exists:
            return (1,)
        return None

    def close(self) -> None:
        self.closed = True


class _FakeSqlConnection:
    def __init__(self, *, membership_exists: bool = True) -> None:
        self.membership_exists = membership_exists
        self.cursors: list[_FakeSqlCursor] = []

    def cursor(self) -> _FakeSqlCursor:
        cur = _FakeSqlCursor(membership_exists=self.membership_exists)
        self.cursors.append(cur)
        return cur


def test_postgres_tenant_session_two_stage_rls_and_clean_exit_guard() -> None:
    conn = _FakeSqlConnection(membership_exists=True)
    session = PostgresTenantSession(conn)

    with session.scoped_transaction(
        principal_id="rep.one@alpha.example", tenant_id=TENANT_ALPHA
    ) as cur:
        session.acquire_advisory_lock(cur, "sales_orders")
        assert session.transaction_depth == 1
        assert session.active_tenant_id == TENANT_ALPHA

    session.assert_clean_boundary()
    queries = [q for q, _ in conn.cursors[0].executed]
    assert queries[0] == "BEGIN"
    assert "app.current_user_id" in queries[1]
    assert "FROM tenant_memberships" in queries[2]
    assert "app.current_tenant_id" in queries[3]
    assert "pg_advisory_xact_lock" in queries[4]
    assert queries[5] == "COMMIT"


def test_postgres_tenant_session_rolls_back_and_rejects_missing_membership() -> None:
    conn = _FakeSqlConnection(membership_exists=False)
    session = PostgresTenantSession(conn)

    with (
        pytest.raises(AuthorizationError),
        session.scoped_transaction(principal_id="intruder@alpha.example", tenant_id=TENANT_ALPHA),
    ):
        pass

    session.assert_clean_boundary()
    queries = [q for q, _ in conn.cursors[0].executed]
    assert queries[-1] == "ROLLBACK"
    assert not any("app.current_tenant_id" in q for q in queries)


def test_postgres_tenant_session_blocks_nested_cross_tenant_escalation_and_non_runtime_role() -> (
    None
):
    conn = _FakeSqlConnection(membership_exists=True)
    with pytest.raises(AuthorizationError):
        PostgresTenantSession(conn, runtime_role="postgres")

    session = PostgresTenantSession(conn)
    other_tenant = uuid4()
    with session.scoped_transaction(principal_id="rep@alpha.example", tenant_id=TENANT_ALPHA):
        with pytest.raises(RuntimeError, match="TENANT-ABUSE-02"):
            session.assert_clean_boundary()
        with (
            pytest.raises(AuthorizationError),
            session.scoped_transaction(principal_id="rep@alpha.example", tenant_id=other_tenant),
        ):
            pass
    session.assert_clean_boundary()


def test_sql_migration_enforces_enable_and_force_rls_on_every_table() -> None:
    sql_path = Path(__file__).resolve().parent.parent / "sql" / "001_init_force_rls.sql"
    ddl = sql_path.read_text(encoding="utf-8")
    expected_tables = (
        "tenant_memberships",
        "margin_policies",
        "sales_orders",
        "idempotency_records",
        "processed_webhook_events",
        "audit_outbox",
    )
    assert "NOBYPASSRLS" in ddl
    assert "NULLIF(current_setting('app.current_tenant_id', true), '')::uuid" in ddl
    for table in expected_tables:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" in ddl
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;" in ddl
