"""Hexagonal `Protocol` ports isolating domain logic from storage, catalog, and valuation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID

from ledger_guard.domain.margin_gate import MarginPolicy, SalesOrder
from ledger_guard.domain.money import Currency, UnitRatio
from ledger_guard.domain.pricing import CostSnapshot, ItemKind, QuantityTierDiscount


@dataclass(frozen=True, slots=True)
class CatalogItem:
    """Commercial catalog record intentionally devoid of confidential valuation cost."""

    sku: str
    description: str
    item_kind: ItemKind
    currency: Currency
    list_unit_price_minor: int
    unit_ratio: UnitRatio
    tier_discounts: tuple[QuantityTierDiscount, ...] = ()


@dataclass(frozen=True, slots=True)
class ValuationContext:
    """Internal system valuation capability token confining cost reads to pricing workflows."""

    tenant_id: UUID
    purpose: str


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    """Persisted idempotency state scoped to `(tenant_id, principal_id, action, key)`."""

    scope_key: str
    payload_sha256: str
    state: Literal["in_flight", "completed"]
    status_code: int | None = None
    response_body: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Minimised transactional outbox event containing IDs and state codes (zero raw PII/cost)."""

    event_id: UUID
    tenant_id: UUID
    aggregate_id: UUID
    actor_principal_id: str
    event_type: str
    created_at_utc: str
    metadata: dict[str, Any]


class CatalogPricingPort(Protocol):
    """Port exposing commercial catalog prices without inventory valuation cost."""

    def get_catalog_item(self, tenant_id: UUID, sku: str) -> CatalogItem | None: ...


class InventoryValuationPort(Protocol):
    """Port exposing inventory stock valuation strictly behind `ValuationContext`."""

    def get_cost_snapshot(
        self,
        context: ValuationContext,
        sku: str,
        unit_ratio: UnitRatio,
    ) -> CostSnapshot | None: ...


class OrderRepositoryPort(Protocol):
    """Tenant-isolated order persistence with optimistic concurrency `version` checks."""

    def get_by_id(self, tenant_id: UUID, order_id: UUID) -> SalesOrder | None: ...

    def list_orders(self, tenant_id: UUID, limit: int = 50) -> list[SalesOrder]: ...

    def save(
        self,
        tenant_id: UUID,
        order: SalesOrder,
        *,
        expected_version: int | None,
        audit_event: AuditEvent | None = None,
    ) -> SalesOrder: ...


class PolicyRepositoryPort(Protocol):
    """Tenant-isolated margin policy persistence."""

    def get_policy(self, tenant_id: UUID) -> MarginPolicy: ...

    def save_policy(self, tenant_id: UUID, policy: MarginPolicy) -> MarginPolicy: ...


class IdempotencyPort(Protocol):
    """Atomic payload-bound idempotency lock and replay store."""

    def acquire_or_get(self, scope_key: str, payload_sha256: str) -> IdempotencyRecord | None:
        """Atomically insert an `in_flight` record if absent, or return existing record."""
        ...

    def mark_completed(
        self,
        scope_key: str,
        payload_sha256: str,
        status_code: int,
        response_body: dict[str, Any],
    ) -> None: ...

    def release_in_flight(self, scope_key: str) -> None: ...


class WebhookDedupPort(Protocol):
    """Atomic `INSERT ... ON CONFLICT DO NOTHING` webhook event deduplication port."""

    def try_claim_event(
        self,
        provider: str,
        event_id: str,
        tenant_id: UUID,
        received_at_epoch: int,
    ) -> bool: ...


class AuditOutboxPort(Protocol):
    """Transactional audit trail outbox port."""

    def append_event(self, event: AuditEvent) -> None: ...

    def list_events(self, tenant_id: UUID) -> list[AuditEvent]: ...


__all__ = [
    "AuditEvent",
    "AuditOutboxPort",
    "CatalogItem",
    "CatalogPricingPort",
    "IdempotencyPort",
    "IdempotencyRecord",
    "InventoryValuationPort",
    "OrderRepositoryPort",
    "PolicyRepositoryPort",
    "ValuationContext",
    "WebhookDedupPort",
]
