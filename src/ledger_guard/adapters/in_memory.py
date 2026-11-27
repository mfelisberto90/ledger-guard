"""Fail-closed, bounded, tenant-partitioned in-memory adapters with optimistic concurrency."""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from typing import Any
from uuid import UUID

from ledger_guard.domain.errors import (
    AuthorizationError,
    ConflictError,
    PayloadTooLargeError,
)
from ledger_guard.domain.margin_gate import MarginPolicy, SalesOrder
from ledger_guard.domain.money import Currency, UnitRatio, require_bounded_minor_int
from ledger_guard.domain.pricing import CostSnapshot
from ledger_guard.ports import (
    AuditEvent,
    CatalogItem,
    IdempotencyRecord,
    ValuationContext,
)
from ledger_guard.security.rate_limit import BoundedMap
from ledger_guard.security.webhooks import MAX_WEBHOOK_TIMESTAMP_SKEW_SECONDS

MAX_IN_MEMORY_ORDERS_PER_TENANT: int = 5_000
MAX_IN_MEMORY_OUTBOX_PER_TENANT: int = 5_000
MAX_IN_MEMORY_IDEMPOTENCY_RECORDS: int = 20_000
MAX_IN_MEMORY_WEBHOOK_CLAIMS: int = 20_000
WEBHOOK_DEDUP_TTL_SECONDS: int = 2 * MAX_WEBHOOK_TIMESTAMP_SKEW_SECONDS + 5


def _require_tenant_uuid(tenant_id: UUID) -> UUID:
    if not isinstance(tenant_id, UUID) or tenant_id.int == 0:
        raise AuthorizationError("Fail-closed: non-nil verified tenant UUID is required.")
    return tenant_id


class InMemoryCatalogAdapter:
    """Tenant-partitioned catalog adapter holding zero cost fields."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: dict[tuple[UUID, str], CatalogItem] = {}

    def upsert_item(self, tenant_id: UUID, item: CatalogItem) -> None:
        tid = _require_tenant_uuid(tenant_id)
        with self._lock:
            self._items[(tid, item.sku)] = item

    def get_catalog_item(self, tenant_id: UUID, sku: str) -> CatalogItem | None:
        tid = _require_tenant_uuid(tenant_id)
        with self._lock:
            return self._items.get((tid, sku))


class InMemoryValuationAdapter:
    """Tenant-partitioned inventory valuation ledger supporting revisioned stock revaluations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ledger: dict[tuple[UUID, str], tuple[int, Currency, int]] = {}

    def set_stock_cost(
        self,
        tenant_id: UUID,
        sku: str,
        base_unit_cost_minor: int,
        currency: Currency,
    ) -> int:
        tid = _require_tenant_uuid(tenant_id)
        cost = require_bounded_minor_int(base_unit_cost_minor, "base_unit_cost_minor")
        with self._lock:
            existing = self._ledger.get((tid, sku))
            next_revision = 1 if existing is None else existing[2] + 1
            self._ledger[(tid, sku)] = (cost, currency, next_revision)
            return next_revision

    def get_cost_snapshot(
        self,
        context: ValuationContext,
        sku: str,
        unit_ratio: UnitRatio,
    ) -> CostSnapshot | None:
        tid = _require_tenant_uuid(context.tenant_id)
        if not context.purpose.strip():
            raise AuthorizationError("ValuationContext purpose is required.")
        with self._lock:
            entry = self._ledger.get((tid, sku))
            if entry is None:
                return None
            base_cost_minor, currency, revision = entry
            return CostSnapshot(
                sku=sku,
                base_unit_cost_minor=base_cost_minor,
                currency=currency,
                unit_ratio=unit_ratio,
                valuation_revision=revision,
            )


class InMemoryPolicyRepository:
    """Tenant-partitioned margin policy store with fail-closed `block` default (`2000 bps`)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: dict[UUID, MarginPolicy] = {}

    def get_policy(self, tenant_id: UUID) -> MarginPolicy:
        tid = _require_tenant_uuid(tenant_id)
        with self._lock:
            policy = self._policies.get(tid)
            if policy is None:
                return MarginPolicy(tenant_id=tid, mode="block", minimum_margin_bps=2_000)
            return policy

    def save_policy(self, tenant_id: UUID, policy: MarginPolicy) -> MarginPolicy:
        tid = _require_tenant_uuid(tenant_id)
        if policy.tenant_id != tid:
            raise AuthorizationError("Cross-tenant policy write rejected.")
        with self._lock:
            self._policies[tid] = policy
            return policy


class InMemoryAuditOutbox:
    """Bounded append-only transactional audit outbox partitioned by tenant."""

    def __init__(self, *, max_events_per_tenant: int = MAX_IN_MEMORY_OUTBOX_PER_TENANT) -> None:
        self._lock = threading.RLock()
        self._max_events = max_events_per_tenant
        self._events: dict[UUID, list[AuditEvent]] = {}

    def append_event(self, event: AuditEvent) -> None:
        tid = _require_tenant_uuid(event.tenant_id)
        with self._lock:
            bucket = self._events.setdefault(tid, [])
            if len(bucket) >= self._max_events:
                del bucket[: len(bucket) - self._max_events + 1]
            bucket.append(event)

    def list_events(self, tenant_id: UUID) -> list[AuditEvent]:
        tid = _require_tenant_uuid(tenant_id)
        with self._lock:
            return list(self._events.get(tid, ()))


class InMemoryOrderRepository:
    """Fail-closed bounded tenant-partitioned order repository with optimistic concurrency."""

    def __init__(
        self,
        outbox: InMemoryAuditOutbox,
        *,
        max_orders_per_tenant: int = MAX_IN_MEMORY_ORDERS_PER_TENANT,
    ) -> None:
        self._outbox = outbox
        self._max_orders = max_orders_per_tenant
        self._global_lock = threading.RLock()
        self._tenant_locks: BoundedMap[UUID, threading.RLock] = BoundedMap(max_entries=2_000)
        self._orders: dict[UUID, dict[UUID, SalesOrder]] = {}

    def _lock_for_tenant(self, tenant_id: UUID) -> threading.RLock:
        with self._global_lock:
            lock = self._tenant_locks.get(tenant_id)
            if lock is None:
                lock = threading.RLock()
                self._tenant_locks.set(tenant_id, lock)
            return lock

    def get_by_id(self, tenant_id: UUID, order_id: UUID) -> SalesOrder | None:
        tid = _require_tenant_uuid(tenant_id)
        with self._lock_for_tenant(tid):
            tenant_bucket = self._orders.get(tid)
            if tenant_bucket is None:
                return None
            return tenant_bucket.get(order_id)

    def list_orders(self, tenant_id: UUID, limit: int = 50) -> list[SalesOrder]:
        tid = _require_tenant_uuid(tenant_id)
        bounded_limit = max(1, min(limit, 200))
        with self._lock_for_tenant(tid):
            tenant_bucket = self._orders.get(tid, {})
            return list(tenant_bucket.values())[:bounded_limit]

    def save(
        self,
        tenant_id: UUID,
        order: SalesOrder,
        *,
        expected_version: int | None,
        audit_event: AuditEvent | None = None,
    ) -> SalesOrder:
        tid = _require_tenant_uuid(tenant_id)
        if order.tenant_id != tid:
            raise AuthorizationError("Cross-tenant order persistence rejected.")

        with self._lock_for_tenant(tid):
            bucket = self._orders.setdefault(tid, {})
            existing = bucket.get(order.order_id)

            if existing is None:
                if expected_version not in (None, 0):
                    raise ConflictError(
                        "Cannot apply versioned update to non-existent order.",
                        code="OPTIMISTIC_LOCK_CONFLICT",
                    )
                if len(bucket) >= self._max_orders:
                    raise PayloadTooLargeError(
                        f"Tenant in-memory order store capacity ({self._max_orders}) reached.",
                        code="TENANT_ORDER_CAPACITY_REACHED",
                    )
                persisted = replace(order, version=1)
            else:
                if expected_version is None or expected_version != existing.version:
                    raise ConflictError(
                        f"Optimistic concurrency conflict: expected version {expected_version}, "
                        f"actual version is {existing.version}.",
                        code="OPTIMISTIC_LOCK_CONFLICT",
                        details={
                            "expected_version": expected_version,
                            "actual_version": existing.version,
                        },
                    )
                persisted = replace(order, version=existing.version + 1)

            bucket[persisted.order_id] = persisted
            if audit_event is not None:
                if audit_event.tenant_id != tid:
                    raise AuthorizationError("Cross-tenant outbox event rejected.")
                self._outbox.append_event(audit_event)
            return persisted


class InMemoryIdempotencyStore:
    """Thread-safe bounded atomic idempotency record store."""

    def __init__(self, *, max_entries: int = MAX_IN_MEMORY_IDEMPOTENCY_RECORDS) -> None:
        self._lock = threading.RLock()
        self._records: BoundedMap[str, IdempotencyRecord] = BoundedMap(max_entries=max_entries)

    def acquire_or_get(self, scope_key: str, payload_sha256: str) -> IdempotencyRecord | None:
        with self._lock:
            existing = self._records.get(scope_key)
            if existing is not None:
                return existing
            self._records.set(
                scope_key,
                IdempotencyRecord(
                    payload_sha256=payload_sha256,
                    state="in_flight",
                ),
            )
            return None

    def mark_completed(
        self,
        scope_key: str,
        payload_sha256: str,
        status_code: int,
        response_body: dict[str, Any],
    ) -> None:
        with self._lock:
            self._records.set(
                scope_key,
                IdempotencyRecord(
                    payload_sha256=payload_sha256,
                    state="completed",
                    status_code=status_code,
                    response_body=response_body,
                ),
            )

    def release_in_flight(self, scope_key: str) -> None:
        with self._lock:
            existing = self._records.get(scope_key)
            if existing is not None and existing.state == "in_flight":
                self._records.delete(scope_key)


class InMemoryWebhookDedupStore:
    """Thread-safe bounded atomic `(tenant_id, provider, event_id)` deduplication store."""

    def __init__(
        self,
        *,
        max_entries: int = MAX_IN_MEMORY_WEBHOOK_CLAIMS,
        retention_seconds: int = WEBHOOK_DEDUP_TTL_SECONDS,
    ) -> None:
        self._lock = threading.RLock()
        self._retention_seconds = retention_seconds
        self._claimed: BoundedMap[tuple[UUID, str, str], int] = BoundedMap(max_entries=max_entries)

    def try_claim_event(
        self,
        provider: str,
        event_id: str,
        tenant_id: UUID,
        received_at_epoch: int,
    ) -> bool:
        tid = _require_tenant_uuid(tenant_id)
        key = (tid, provider.strip().lower(), event_id.strip())
        now_epoch = int(time.time()) if received_at_epoch <= 0 else received_at_epoch
        with self._lock:
            existing_ts = self._claimed.get(key)
            if (
                existing_ts is not None
                and (now_epoch - existing_ts) <= self._retention_seconds
            ):
                return False
            self._claimed.set(key, received_at_epoch)
            return True

    def release_event(
        self,
        provider: str,
        event_id: str,
        tenant_id: UUID,
    ) -> None:
        tid = _require_tenant_uuid(tenant_id)
        key = (tid, provider.strip().lower(), event_id.strip())
        with self._lock:
            self._claimed.delete(key)
