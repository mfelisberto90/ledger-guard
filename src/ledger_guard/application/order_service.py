"""Hexagonal application service shared identically by FastAPI HTTP and MCP JSON-RPC."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from ledger_guard.domain.errors import NotFoundError, ValidationError
from ledger_guard.domain.margin_gate import (
    OrderKind,
    PrincipalContext,
    SalesOrder,
    apply_order_amendment,
    confirm_sales_order,
    determine_initial_status,
    evaluate_margin_gate,
    project_order_for_principal,
    record_four_eyes_approval,
)
from ledger_guard.domain.money import Currency, parse_rational_quantity
from ledger_guard.domain.pricing import (
    ItemKind,
    LinePricingInput,
    price_order_waterfall,
)
from ledger_guard.ports import (
    AuditEvent,
    CatalogPricingPort,
    InventoryValuationPort,
    OrderRepositoryPort,
    PolicyRepositoryPort,
    ValuationContext,
)
from ledger_guard.security.csv_export import serialize_rows_to_csv


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class OrderLineCommand:
    """Command input for pricing a single line on order creation."""

    sku: str
    quantity: str | int
    unit_price_minor: int | None = None
    manual_discount_bps: int = 0


class OrderService:
    """Application use-case orchestrator enforcing RBAC, valuation isolation, and outbox."""

    def __init__(
        self,
        *,
        catalog: CatalogPricingPort,
        valuation: InventoryValuationPort,
        orders: OrderRepositoryPort,
        policies: PolicyRepositoryPort,
    ) -> None:
        self._catalog = catalog
        self._valuation = valuation
        self._orders = orders
        self._policies = policies

    def create_order(
        self,
        principal: PrincipalContext,
        *,
        customer_ref: str,
        order_kind: OrderKind,
        currency: Currency,
        lines: Sequence[OrderLineCommand],
        header_discount_bps: int = 0,
        header_discount_minor: int = 0,
        passthrough_freight_minor: int = 0,
        small_order_surcharge_minor: int = 0,
    ) -> dict[str, Any]:
        """Create and price a governed sales order inside `principal.tenant_id`."""
        principal.require_capability("orders:write")
        if not lines or len(lines) > 200:
            raise ValidationError("Order must include between 1 and 200 line items.")

        valuation_ctx = ValuationContext(
            tenant_id=principal.tenant_id,
            purpose="create_order_waterfall",
        )
        pricing_inputs: list[LinePricingInput] = []

        for cmd in lines:
            clean_sku = cmd.sku.strip()
            catalog_item = self._catalog.get_catalog_item(principal.tenant_id, clean_sku)
            if catalog_item is None:
                raise NotFoundError(
                    f"Catalog SKU '{clean_sku}' not found in tenant catalog.",
                    code="SKU_NOT_FOUND",
                )

            qty = parse_rational_quantity(cmd.quantity, "quantity")
            unit_price = (
                catalog_item.list_unit_price_minor
                if cmd.unit_price_minor is None
                else cmd.unit_price_minor
            )

            snapshot = None
            if catalog_item.item_kind is ItemKind.STOCKED:
                snapshot = self._valuation.get_cost_snapshot(
                    valuation_ctx,
                    clean_sku,
                    catalog_item.unit_ratio,
                )
                if snapshot is None:
                    raise ValidationError(
                        f"Missing inventory valuation record for stocked SKU '{clean_sku}'.",
                        code="MISSING_VALUATION",
                    )

            pricing_inputs.append(
                LinePricingInput(
                    line_id=uuid4(),
                    sku=catalog_item.sku,
                    description=catalog_item.description,
                    item_kind=catalog_item.item_kind,
                    currency=catalog_item.currency,
                    quantity=qty,
                    unit_price_minor=unit_price,
                    unit_ratio=catalog_item.unit_ratio,
                    manual_discount_bps=cmd.manual_discount_bps,
                    tier_discounts=catalog_item.tier_discounts,
                    cost_snapshot=snapshot,
                )
            )

        waterfall = price_order_waterfall(
            currency=currency,
            lines=pricing_inputs,
            header_discount_bps=header_discount_bps,
            header_discount_minor=header_discount_minor,
            passthrough_freight_minor=passthrough_freight_minor,
            small_order_surcharge_minor=small_order_surcharge_minor,
        )

        policy = self._policies.get_policy(principal.tenant_id)
        initial_status = determine_initial_status(waterfall, policy, order_kind)
        now_iso = _utc_now_iso()
        order_id = uuid4()

        draft_order = SalesOrder(
            order_id=order_id,
            tenant_id=principal.tenant_id,
            customer_ref=customer_ref.strip(),
            order_kind=order_kind,
            status=initial_status,
            version=1,
            pricing_version=1,
            header_discount_bps=header_discount_bps,
            header_discount_minor=header_discount_minor,
            waterfall=waterfall,
            created_by=principal.principal_id,
            last_amended_by=principal.principal_id,
            created_at_utc=now_iso,
            updated_at_utc=now_iso,
        )
        gate = evaluate_margin_gate(draft_order, policy)
        audit = AuditEvent(
            event_id=uuid4(),
            tenant_id=principal.tenant_id,
            aggregate_id=order_id,
            actor_principal_id=principal.principal_id,
            event_type="order.created",
            created_at_utc=now_iso,
            metadata={"status": initial_status.value, "gate_code": gate.code},
        )
        persisted = self._orders.save(
            principal.tenant_id,
            draft_order,
            expected_version=0,
            audit_event=audit,
        )
        return project_order_for_principal(persisted, policy, principal)

    def get_order(self, principal: PrincipalContext, *, order_id: UUID) -> dict[str, Any]:
        """Retrieve a single tenant-isolated order projected to `principal`'s capabilities."""
        principal.require_capability("orders:read")
        order = self._orders.get_by_id(principal.tenant_id, order_id)
        if order is None:
            raise NotFoundError("Order not found.", code="ORDER_NOT_FOUND")
        policy = self._policies.get_policy(principal.tenant_id)
        return project_order_for_principal(order, policy, principal)

    def confirm_order(
        self,
        principal: PrincipalContext,
        *,
        order_id: UUID,
        expected_version: int,
    ) -> dict[str, Any]:
        """Confirm an order when readiness gates pass, checking optimistic `version`."""
        principal.require_capability("orders:confirm")
        order = self._orders.get_by_id(principal.tenant_id, order_id)
        if order is None:
            raise NotFoundError("Order not found.", code="ORDER_NOT_FOUND")
        policy = self._policies.get_policy(principal.tenant_id)
        now_iso = _utc_now_iso()

        confirmed = confirm_sales_order(
            order=order,
            policy=policy,
            confirmed_at_utc=now_iso,
        )
        audit = AuditEvent(
            event_id=uuid4(),
            tenant_id=principal.tenant_id,
            aggregate_id=order_id,
            actor_principal_id=principal.principal_id,
            event_type="order.confirmed",
            created_at_utc=now_iso,
            metadata={"status": confirmed.status.value},
        )
        persisted = self._orders.save(
            principal.tenant_id,
            confirmed,
            expected_version=expected_version,
            audit_event=audit,
        )
        return project_order_for_principal(persisted, policy, principal)

    def approve_margin(
        self,
        principal: PrincipalContext,
        *,
        order_id: UUID,
        expected_version: int,
        reason: str,
    ) -> dict[str, Any]:
        """Record an append-only four-eyes margin exception approval."""
        principal.require_capability("orders:margin:approve")
        order = self._orders.get_by_id(principal.tenant_id, order_id)
        if order is None:
            raise NotFoundError("Order not found.", code="ORDER_NOT_FOUND")
        policy = self._policies.get_policy(principal.tenant_id)
        now_iso = _utc_now_iso()

        approved = record_four_eyes_approval(
            order=order,
            approver=principal,
            reason=reason,
            approved_at_utc=now_iso,
            approval_id=uuid4(),
        )
        audit = AuditEvent(
            event_id=uuid4(),
            tenant_id=principal.tenant_id,
            aggregate_id=order_id,
            actor_principal_id=principal.principal_id,
            event_type="order.margin_approved",
            created_at_utc=now_iso,
            metadata={"pricing_version": approved.pricing_version},
        )
        persisted = self._orders.save(
            principal.tenant_id,
            approved,
            expected_version=expected_version,
            audit_event=audit,
        )
        return project_order_for_principal(persisted, policy, principal)

    def amend_order_line(
        self,
        principal: PrincipalContext,
        *,
        order_id: UUID,
        line_id: UUID,
        expected_version: int,
        quantity: str | int | None = None,
        unit_price_minor: int | None = None,
        manual_discount_bps: int | None = None,
        header_discount_bps: int | None = None,
        header_discount_minor: int | None = None,
    ) -> dict[str, Any]:
        """Amend commercial terms on an order line while preserving captured `CostSnapshot`s."""
        principal.require_capability("orders:write")
        order = self._orders.get_by_id(principal.tenant_id, order_id)
        if order is None:
            raise NotFoundError("Order not found.", code="ORDER_NOT_FOUND")
        policy = self._policies.get_policy(principal.tenant_id)

        target_found = False
        rebuilt_inputs: list[LinePricingInput] = []
        price_lowered_or_disc_increased = False

        for existing_line in order.waterfall.lines:
            catalog_item = self._catalog.get_catalog_item(principal.tenant_id, existing_line.sku)
            tiers = catalog_item.tier_discounts if catalog_item is not None else ()

            if existing_line.line_id == line_id:
                target_found = True
                next_qty = (
                    existing_line.quantity
                    if quantity is None
                    else parse_rational_quantity(quantity, "quantity")
                )
                next_price = (
                    existing_line.unit_price_minor
                    if unit_price_minor is None
                    else unit_price_minor
                )
                next_disc = (
                    existing_line.applied_discount_bps
                    if manual_discount_bps is None
                    else manual_discount_bps
                )
                if next_price < existing_line.unit_price_minor:
                    price_lowered_or_disc_increased = True
                if next_disc > existing_line.applied_discount_bps:
                    price_lowered_or_disc_increased = True

                rebuilt_inputs.append(
                    LinePricingInput(
                        line_id=existing_line.line_id,
                        sku=existing_line.sku,
                        description=existing_line.description,
                        item_kind=existing_line.item_kind,
                        currency=order.currency,
                        quantity=next_qty,
                        unit_price_minor=next_price,
                        unit_ratio=existing_line.unit_ratio,
                        manual_discount_bps=next_disc,
                        tier_discounts=tiers,
                        cost_snapshot=existing_line.cost_snapshot,
                    )
                )
            else:
                rebuilt_inputs.append(
                    LinePricingInput(
                        line_id=existing_line.line_id,
                        sku=existing_line.sku,
                        description=existing_line.description,
                        item_kind=existing_line.item_kind,
                        currency=order.currency,
                        quantity=existing_line.quantity,
                        unit_price_minor=existing_line.unit_price_minor,
                        unit_ratio=existing_line.unit_ratio,
                        manual_discount_bps=existing_line.applied_discount_bps,
                        tier_discounts=tiers,
                        cost_snapshot=existing_line.cost_snapshot,
                    )
                )

        if not target_found:
            raise NotFoundError("Order line not found on target order.", code="LINE_NOT_FOUND")

        next_hdr_bps = (
            order.header_discount_bps if header_discount_bps is None else header_discount_bps
        )
        next_hdr_minor = (
            order.header_discount_minor
            if header_discount_minor is None
            else header_discount_minor
        )
        if next_hdr_bps > order.header_discount_bps or next_hdr_minor > order.header_discount_minor:
            price_lowered_or_disc_increased = True

        new_waterfall = price_order_waterfall(
            currency=order.currency,
            lines=rebuilt_inputs,
            header_discount_bps=next_hdr_bps,
            header_discount_minor=next_hdr_minor,
            passthrough_freight_minor=order.waterfall.passthrough_freight_minor,
            small_order_surcharge_minor=order.waterfall.small_order_surcharge_minor,
        )
        if new_waterfall.margin_bps < order.waterfall.margin_bps:
            price_lowered_or_disc_increased = True

        now_iso = _utc_now_iso()
        amended = apply_order_amendment(
            order=order,
            new_waterfall=new_waterfall,
            new_header_discount_bps=next_hdr_bps,
            new_header_discount_minor=next_hdr_minor,
            policy=policy,
            amended_by=principal,
            amended_at_utc=now_iso,
            adverse_commercial_change=price_lowered_or_disc_increased,
        )
        gate = evaluate_margin_gate(amended, policy)
        audit = AuditEvent(
            event_id=uuid4(),
            tenant_id=principal.tenant_id,
            aggregate_id=order_id,
            actor_principal_id=principal.principal_id,
            event_type="order.line_amended",
            created_at_utc=now_iso,
            metadata={"status": amended.status.value, "gate_code": gate.code},
        )
        persisted = self._orders.save(
            principal.tenant_id,
            amended,
            expected_version=expected_version,
            audit_event=audit,
        )
        return project_order_for_principal(persisted, policy, principal)

    def export_orders_csv(self, principal: PrincipalContext) -> str:
        """Export tenant orders to formula-sanitized CSV respecting cost/margin RBAC."""
        principal.require_capability("orders:export")
        policy = self._policies.get_policy(principal.tenant_id)
        orders = self._orders.list_orders(principal.tenant_id, limit=200)
        projected_rows = [
            project_order_for_principal(order, policy, principal) for order in orders
        ]
        columns = [
            "order_id",
            "customer_ref",
            "order_kind",
            "currency",
            "status",
            "net_goods_total_minor",
            "passthrough_freight_minor",
            "small_order_surcharge_minor",
            "payable_total_minor",
        ]
        if principal.has_capability("valuation:cost:read"):
            columns.append("total_cost_minor")
        if principal.has_capability("orders:margin:read"):
            columns.extend(["margin_minor", "margin_bps"])
        return serialize_rows_to_csv(projected_rows, columns)
