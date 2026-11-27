"""PostgreSQL 17 two-stage transaction-local `FORCE RLS` session and advisory lock adapter."""

from __future__ import annotations

import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any, Protocol
from uuid import UUID

from ledger_guard.domain.errors import AuthorizationError, ValidationError
from ledger_guard.domain.margin_gate import normalize_principal_id


class SqlCursorProtocol(Protocol):
    """PEP 249 / Psycopg-compatible cursor protocol using parameterized bindings."""

    def execute(self, query: str, params: Sequence[Any] | None = None) -> Any: ...

    def fetchone(self) -> tuple[Any, ...] | None: ...

    def fetchall(self) -> Sequence[tuple[Any, ...]]: ...

    def close(self) -> None: ...


class SqlConnectionProtocol(Protocol):
    """Pooled PostgreSQL connection protocol operating under `app_runtime` (`NOBYPASSRLS`)."""

    def cursor(self) -> SqlCursorProtocol: ...


class PostgresTenantSession:
    """Two-stage transaction-local RLS context manager safe for pooled connections."""

    def __init__(
        self,
        connection: SqlConnectionProtocol,
        *,
        runtime_role: str = "app_runtime",
    ) -> None:
        if runtime_role != "app_runtime":
            raise AuthorizationError(
                "Runtime adapter must execute strictly under NOBYPASSRLS role 'app_runtime'."
            )
        self._conn = connection
        self._transaction_depth = 0
        self._active_tenant_id: UUID | None = None
        self._active_principal_id: str | None = None
        self._poisoned = False

    @property
    def transaction_depth(self) -> int:
        return self._transaction_depth

    @property
    def active_tenant_id(self) -> UUID | None:
        return self._active_tenant_id

    @contextmanager
    def scoped_transaction(
        self,
        *,
        principal_id: str,
        tenant_id: UUID,
    ) -> Iterator[SqlCursorProtocol]:
        """Enter a fail-closed two-stage `FORCE RLS` transaction."""
        if not isinstance(tenant_id, UUID) or tenant_id.int == 0:
            raise ValidationError("Verified non-nil tenant UUID is required.")
        normalized_principal = normalize_principal_id(principal_id)

        if self._poisoned:
            raise RuntimeError(
                "TENANT-ABUSE-02: connection boundary was poisoned by a failed rollback."
            )

        if self._transaction_depth > 0:
            if self._active_tenant_id != tenant_id:
                raise AuthorizationError(
                    "Nested cross-tenant context switch inside an active transaction is forbidden.",
                    code="TENANT_SCOPE_ESCALATION",
                )
            if self._active_principal_id != normalized_principal:
                raise AuthorizationError(
                    "Nested cross-principal switch inside an active transaction is forbidden.",
                    code="PRINCIPAL_SCOPE_ESCALATION",
                )
            cursor = self._conn.cursor()
            self._transaction_depth += 1
            try:
                yield cursor
            finally:
                self._transaction_depth -= 1
                cursor.close()
            return

        cursor = self._conn.cursor()
        self._transaction_depth = 1
        self._active_tenant_id = tenant_id
        self._active_principal_id = normalized_principal
        committed = False
        try:
            cursor.execute("BEGIN")
            # Stage A: bind transaction-local principal + target tenant for membership self-check
            cursor.execute(
                "SELECT set_config('app.current_user_id', %s, true), "
                "set_config('app.stage_a_tenant_id', %s, true)",
                (normalized_principal, str(tenant_id)),
            )
            cursor.execute(
                "SELECT role FROM tenant_memberships "
                "WHERE principal_id = %s AND tenant_id = %s AND is_active = true",
                (normalized_principal, str(tenant_id)),
            )
            membership_row = cursor.fetchone()
            if membership_row is None:
                raise AuthorizationError(
                    "Principal does not hold an active membership in the target tenant.",
                    code="INACTIVE_OR_MISSING_MEMBERSHIP",
                )

            db_role = str(membership_row[0]) if len(membership_row) == 1 else "sales_rep"
            # Stage B: bind authoritative tenant_id and membership role for RESTRICTIVE RLS policies
            cursor.execute(
                "SELECT set_config('app.current_tenant_id', %s, true), "
                "set_config('app.current_role', %s, true)",
                (str(tenant_id), db_role),
            )
            yield cursor
            cursor.execute("COMMIT")
            committed = True
        finally:
            try:
                if not committed:
                    active_exc = sys.exc_info()[1]
                    try:
                        cursor.execute("ROLLBACK")
                    except Exception as rollback_err:
                        self._poisoned = True
                        if active_exc is not None:
                            active_exc.add_note(
                                f"Rollback also failed on poisoned connection: {rollback_err}"
                            )
                        else:
                            raise
            finally:
                self._transaction_depth = 0
                self._active_tenant_id = None
                self._active_principal_id = None
                cursor.close()

    def acquire_advisory_lock(self, cursor: SqlCursorProtocol, namespace: str) -> None:
        """Acquire a deterministic transaction-scoped PostgreSQL advisory lock."""
        if self._transaction_depth <= 0 or self._active_tenant_id is None:
            raise AuthorizationError("Advisory lock requires an active scoped RLS transaction.")
        clean_ns = namespace.strip()
        if not clean_ns or len(clean_ns) > 64:
            raise ValidationError("Lock namespace must be 1..64 characters.")
        cursor.execute(
            "SELECT acquire_tenant_lock(%s, %s)",
            (clean_ns, str(self._active_tenant_id)),
        )

    def assert_clean_boundary(self) -> None:
        """Middleware exit invariant (`TENANT-ABUSE-02`): forbid unclosed or poisoned sessions."""
        if (
            self._poisoned
            or self._transaction_depth != 0
            or self._active_tenant_id is not None
            or self._active_principal_id is not None
        ):
            raise RuntimeError(
                "TENANT-ABUSE-02: unclosed or poisoned tenant transaction boundary at exit."
            )
