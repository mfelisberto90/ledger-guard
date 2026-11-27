"""Empirical PostgreSQL 17 `FORCE ROW LEVEL SECURITY` verification under `app_runtime`."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

import pytest

from ledger_guard.adapters.postgres_rls import PostgresTenantSession
from ledger_guard.domain.errors import AuthorizationError

REPO_ROOT = Path(__file__).resolve().parent.parent
SQL_SCHEMA_PATH = REPO_ROOT / "sql" / "001_init_force_rls.sql"

TENANT_ALPHA = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
TENANT_BRAVO = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
ORDER_ALPHA = UUID("10000000-0000-4000-8000-000000000001")
ORDER_BRAVO = UUID("20000000-0000-4000-8000-000000000002")
OUTBOX_ALPHA = UUID("30000000-0000-4000-8000-000000000003")

_INSERT_SALES_ORDER_SQL = (
    "INSERT INTO sales_orders ("
    "id, tenant_id, customer_ref, order_kind, currency, status, "
    "version, pricing_version, header_discount_bps, header_discount_minor, "
    "net_goods_total_minor, passthrough_freight_minor, "
    "small_order_surcharge_minor, payable_total_minor, total_cost_minor, "
    "margin_minor, margin_bps, created_by, last_amended_by, lines_json"
    ") VALUES ("
    "%s, %s, %s, 'standard', 'GBP', 'draft', 1, 1, "
    "0, 0, %s, %s, 0, %s, 7000, %s, 3000, %s, %s, '[]'::jsonb"
    ")"
)


def _require_pg_dsn() -> str:
    dsn = os.environ.get("LEDGER_GUARD_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip(
            "Set LEDGER_GUARD_TEST_PG_DSN to run live PostgreSQL 17 FORCE RLS verification."
        )
    return dsn


def test_live_postgres17_force_rls_isolation_and_append_only_outbox() -> None:
    dsn = _require_pg_dsn()
    psycopg = pytest.importorskip("psycopg")

    ddl_sql = SQL_SCHEMA_PATH.read_text(encoding="utf-8")

    with psycopg.connect(dsn, autocommit=True) as admin_conn, admin_conn.cursor() as cur:
        cur.execute(ddl_sql)
        cur.execute(
            "TRUNCATE TABLE "
            "audit_outbox, processed_webhook_events, idempotency_records, "
            "sales_orders, margin_policies, tenant_memberships"
        )
        # Include alice as sales_rep in ALPHA and owner in BRAVO (DB-01 cross-tenant OR isolation)
        cur.execute(
            "INSERT INTO tenant_memberships "
            "(tenant_id, principal_id, role, capabilities, is_active) "
            "VALUES (%s, %s, 'sales_rep', ARRAY['orders:read','orders:write'], true), "
            "       (%s, %s, 'owner', ARRAY['orders:read','orders:write'], true), "
            "       (%s, %s, 'owner', ARRAY['orders:read','orders:write'], true), "
            "       (%s, %s, 'sales_rep', ARRAY['orders:read'], false)",
            (
                str(TENANT_ALPHA),
                "alice@alpha.example",
                str(TENANT_ALPHA),
                "owner@alpha.example",
                str(TENANT_BRAVO),
                "alice@alpha.example",
                str(TENANT_ALPHA),
                "suspended@alpha.example",
            ),
        )
        cur.execute(
            _INSERT_SALES_ORDER_SQL,
            (
                str(ORDER_BRAVO),
                str(TENANT_BRAVO),
                "PO-BRAVO-SECRET",
                20_000,
                0,
                20_000,
                13_000,
                "alice@alpha.example",
                "alice@alpha.example",
            ),
        )

    with psycopg.connect(dsn, autocommit=True) as runtime_conn:
        with runtime_conn.cursor() as setup_cur:
            setup_cur.execute("SET ROLE app_runtime")
            setup_cur.execute(
                "SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user"
            )
            role_flags = setup_cur.fetchone()
            assert role_flags == (False, False)

            # 1. Fail-closed zero-row visibility when session GUCs are unset
            setup_cur.execute("SELECT id FROM sales_orders")
            assert setup_cur.fetchall() == []
            setup_cur.execute("SELECT tenant_id FROM tenant_memberships")
            assert setup_cur.fetchall() == []

        session = PostgresTenantSession(runtime_conn, runtime_role="app_runtime")

        # 2. Inactive or cross-tenant principal blocked at Stage A before Stage B
        with (
            pytest.raises(AuthorizationError) as inactive_exc,
            session.scoped_transaction(
                principal_id="suspended@alpha.example",
                tenant_id=TENANT_ALPHA,
            ),
        ):
            pass
        assert inactive_exc.value.code == "INACTIVE_OR_MISSING_MEMBERSHIP"
        session.assert_clean_boundary()

        with (
            pytest.raises(AuthorizationError) as cross_member_exc,
            session.scoped_transaction(
                principal_id="owner@alpha.example",
                tenant_id=TENANT_BRAVO,
            ),
        ):
            pass
        assert cross_member_exc.value.code == "INACTIVE_OR_MISSING_MEMBERSHIP"
        session.assert_clean_boundary()

        # 3. Valid Stage A + Stage B transaction sees strictly TENANT_ALPHA and acquires tenant lock
        with session.scoped_transaction(
            principal_id="alice@alpha.example",
            tenant_id=TENANT_ALPHA,
        ) as cur:
            session.acquire_advisory_lock(cur, "sales_orders")
            # Even though alice is active in BRAVO too, Stage B returns ONLY ALPHA (DB-01)!
            cur.execute("SELECT tenant_id, principal_id FROM tenant_memberships")
            membership_rows = cur.fetchall()
            assert membership_rows == [(TENANT_ALPHA, "alice@alpha.example")]

            cur.execute(
                _INSERT_SALES_ORDER_SQL,
                (
                    str(ORDER_ALPHA),
                    str(TENANT_ALPHA),
                    "PO-ALPHA-1",
                    10_000,
                    500,
                    10_500,
                    3_000,
                    "alice@alpha.example",
                    "alice@alpha.example",
                ),
            )
            cur.execute(
                "INSERT INTO audit_outbox "
                "(id, tenant_id, aggregate_id, actor_principal_id, event_type) "
                "VALUES (%s, %s, %s, %s, 'order.created')",
                (
                    str(OUTBOX_ALPHA),
                    str(TENANT_ALPHA),
                    str(ORDER_ALPHA),
                    "alice@alpha.example",
                ),
            )
            cur.execute("SELECT id, customer_ref FROM sales_orders")
            visible_rows = cur.fetchall()
            assert visible_rows == [(ORDER_ALPHA, "PO-ALPHA-1")]

            # 3b. Cross-tenant acquire_tenant_lock is blocked inside DB function (DB-02)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("SELECT acquire_tenant_lock('sales_orders', %s)", (str(TENANT_BRAVO),))

        session.assert_clean_boundary()

        # 4. Non-owner sales_rep cannot self-elevate to 'owner' or alter margin_policies (DB-01)
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            session.scoped_transaction(
                principal_id="alice@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute(
                "INSERT INTO tenant_memberships "
                "(tenant_id, principal_id, role, capabilities, is_active) "
                "VALUES (%s, 'escalated@alpha.example', 'owner', ARRAY['orders:read'], true)",
                (str(TENANT_ALPHA),),
            )
        session.assert_clean_boundary()

        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            session.scoped_transaction(
                principal_id="alice@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute(
                "INSERT INTO margin_policies (tenant_id, mode, minimum_margin_bps) "
                "VALUES (%s, 'off', 0)",
                (str(TENANT_ALPHA),),
            )
        session.assert_clean_boundary()

        # 5. Final active owner is protected by Last-Owner trigger even under owner session (DB-01)
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            session.scoped_transaction(
                principal_id="owner@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute(
                "DELETE FROM tenant_memberships WHERE tenant_id = %s AND principal_id = %s",
                (str(TENANT_ALPHA), "owner@alpha.example"),
            )
        session.assert_clean_boundary()

        # 6. Cross-tenant INSERT spoof rejected by PostgreSQL WITH CHECK policy
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            session.scoped_transaction(
                principal_id="owner@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute(
                "INSERT INTO margin_policies (tenant_id, mode, minimum_margin_bps) "
                "VALUES (%s, 'off', 0)",
                (str(TENANT_BRAVO),),
            )
        session.assert_clean_boundary()

        # 7. Append-only audit_outbox rejects DELETE and UPDATE by app_runtime
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            session.scoped_transaction(
                principal_id="alice@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute("DELETE FROM audit_outbox WHERE id = %s", (str(OUTBOX_ALPHA),))
        session.assert_clean_boundary()

        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            session.scoped_transaction(
                principal_id="alice@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute(
                "UPDATE audit_outbox SET event_type = 'tampered' WHERE id = %s",
                (str(OUTBOX_ALPHA),),
            )
        session.assert_clean_boundary()

        # 8. SQL arithmetic CHECK constraint blocks inconsistent payable_total_minor
        with (
            pytest.raises(psycopg.errors.CheckViolation),
            session.scoped_transaction(
                principal_id="alice@alpha.example",
                tenant_id=TENANT_ALPHA,
            ) as cur,
        ):
            cur.execute(
                _INSERT_SALES_ORDER_SQL,
                (
                    "40000000-0000-4000-8000-000000000004",
                    str(TENANT_ALPHA),
                    "PO-BAD-SUM",
                    10_000,
                    500,
                    99_999,
                    3_000,
                    "alice@alpha.example",
                    "alice@alpha.example",
                ),
            )
        session.assert_clean_boundary()
