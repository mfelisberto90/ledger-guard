"""PostgreSQL 17 two-stage transaction-local `FORCE RLS` session and advisory lock adapter."""

from __future__ import annotations

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

    def close(self) -> None: ...


class SqlConnectionProtocol(Protocol):
    """Pooled PostgreSQL connection protocol operating under `app_runtime` (`NOBYPASSRLS`)."""

    def cursor(self) -> SqlCursorProtocol: ...


class PostgresTenantSession:
    """Two-stage transaction-local RLS context manager safe for pooled connections.

    Stage A binds `app.current_user_id` (`is_local = true`) and verifies active
    `tenant_memberships` inside an explicit transaction.
    Stage B binds `app.current_tenant_id` (`is_local = true`) only after membership passes.
    `assert_clean_boundary()` guarantees zero leaked transactions on middleware exit.
    """

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

        if self._transaction_depth > 0:
            if self._active_tenant_id != tenant_id:
                raise AuthorizationError(
                    "Nested cross-tenant context switch inside an active transaction is forbidden.",
                    code="TENANT_SCOPE_ESCALATION",
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
            # Stage A: transaction-local user binding + active membership verification
            cursor.execute(
                "SELECT set_config('app.current_user_id', %s, true)",
                (normalized_principal,),
            )
            cursor.execute(
                "SELECT 1 FROM tenant_memberships "
                "WHERE principal_id = %s AND tenant_id = %s AND is_active = true",
                (normalized_principal, str(tenant_id)),
            )
            membership_row = cursor.fetchone()
            if membership_row is None:
                raise AuthorizationError(
                    "Principal does not hold an active membership in the target tenant.",
                    code="INACTIVE_OR_MISSING_MEMBERSHIP",
                )

            # Stage B: transaction-local tenant binding for FORCE RLS policies
            cursor.execute(
                "SELECT set_config('app.current_tenant_id', %s, true)",
                (str(tenant_id),),
            )
            yield cursor
            cursor.execute("COMMIT")
            committed = True
        finally:
            try:
                if not committed:
                    cursor.execute("ROLLBACK")
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
        lock_key = f"{clean_ns}:{self._active_tenant_id}"
        cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,))

    def assert_clean_boundary(self) -> None:
        """Middleware exit invariant (`TENANT-ABUSE-02`): forbid unclosed transactions."""
        if self._transaction_depth != 0 or self._active_tenant_id is not None:
            raise RuntimeError(
                "TENANT-ABUSE-02: unclosed tenant transaction boundary detected at request exit."
            )
