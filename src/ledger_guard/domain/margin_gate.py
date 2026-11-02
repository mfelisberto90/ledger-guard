"""Margin policy governance, four-eyes separation of duties, and capability-based projection."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from ledger_guard.domain.errors import (
    AuthorizationError,
    MarginBlockedError,
    SeparationOfDutiesError,
    ValidationError,
)
from ledger_guard.domain.money import Currency, require_strict_int
from ledger_guard.domain.pricing import (
    ConditionStepKind,
    PricedOrderLine,
    PricedOrderWaterfall,
)

PolicyMode = Literal["off", "warn", "block"]


class OrderKind(StrEnum):
    """Commercial order classifications, including statutory/operational exemptions."""

    STANDARD = "standard"
    RETURN = "return"
    CREDIT_MEMO = "credit_memo"
    FREE_OF_CHARGE_REPLACEMENT = "free_of_charge_replacement"
    CONSIGNMENT = "consignment"


DEFAULT_EXEMPT_ORDER_KINDS: frozenset[OrderKind] = frozenset(
    {
        OrderKind.RETURN,
        OrderKind.CREDIT_MEMO,
        OrderKind.FREE_OF_CHARGE_REPLACEMENT,
        OrderKind.CONSIGNMENT,
    }
)


class OrderStatus(StrEnum):
    """Lifecycle states of a governed commercial order."""

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    CONFIRMED = "confirmed"


def normalize_principal_id(raw_principal_id: str) -> str:
    """Canonicalize principal identifiers so case/whitespace tricks never bypass four-eyes."""
    normalized = raw_principal_id.strip().lower()
    if not normalized or len(normalized) > 128:
        raise ValidationError("Principal identifier must be between 1 and 128 characters.")
    return normalized


@dataclass(frozen=True, slots=True)
class PrincipalContext:
    """Server-verified principal identity, active membership, and explicit capabilities."""

    principal_id: str
    tenant_id: UUID
    role: str
    capabilities: frozenset[str]
    is_active: bool

    def __post_init__(self) -> None:
        normalized = normalize_principal_id(self.principal_id)
        object.__setattr__(self, "principal_id", normalized)
        if not isinstance(self.is_active, bool):
            raise ValidationError("is_active must be a strict boolean.")

    def has_capability(self, capability: str) -> bool:
        """Fail-closed capability check requiring active tenant membership."""
        if not self.is_active:
            return False
        return capability in self.capabilities

    def require_capability(self, capability: str) -> None:
        """Raise `AuthorizationError` (`403`) when active membership or capability is absent."""
        if not self.is_active:
            raise AuthorizationError(
                "Tenant membership is inactive.", code="INACTIVE_MEMBERSHIP"
            )
        if capability not in self.capabilities:
            raise AuthorizationError(
                f"Principal lacks required capability '{capability}'.",
                code="MISSING_CAPABILITY",
                details={"required_capability": capability},
            )


@dataclass(frozen=True, slots=True)
class MarginPolicy:
    """Per-tenant margin floor configuration."""

    tenant_id: UUID
    mode: PolicyMode = "block"
    minimum_margin_bps: int = 2_000
    exempt_order_kinds: frozenset[OrderKind] = DEFAULT_EXEMPT_ORDER_KINDS

    def __post_init__(self) -> None:
        if self.mode not in ("off", "warn", "block"):
            raise ValidationError("Policy mode must be 'off', 'warn', or 'block'.")
        bps = require_strict_int(self.minimum_margin_bps, "minimum_margin_bps")
        if bps < -10_000 or bps > 10_000:
            raise ValidationError("minimum_margin_bps must be between -10000 and 10000.")


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """Immutable, append-only four-eyes margin exception approval."""

    approval_id: UUID
    approver_principal_id: str
    reason: str
    approved_at_utc: str
    approved_pricing_version: int
    approved_margin_bps: int
    approved_net_goods_minor: int

    def __post_init__(self) -> None:
        normalized = normalize_principal_id(self.approver_principal_id)
        object.__setattr__(self, "approver_principal_id", normalized)
        cleaned_reason = self.reason.strip()
        if not cleaned_reason or len(cleaned_reason) > 1_000:
            raise ValidationError(
                "Margin approval requires a non-empty reason (1..1000 characters).",
                code="APPROVAL_REASON_REQUIRED",
            )
        object.__setattr__(self, "reason", cleaned_reason)


@dataclass(frozen=True, slots=True)
class ReadinessGate:
    """Structured readiness gate contract safe for capability-stripped callers."""

    gate: str
    met: bool
    code: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "met": self.met,
            "code": self.code,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class SalesOrder:
    """Aggregate root for a multi-tenant governed commercial order."""

    order_id: UUID
    tenant_id: UUID
    customer_ref: str
    order_kind: OrderKind
    status: OrderStatus
    version: int
    pricing_version: int
    header_discount_bps: int
    header_discount_minor: int
    waterfall: PricedOrderWaterfall
    created_by: str
    last_amended_by: str
    created_at_utc: str
    updated_at_utc: str
    approvals: tuple[ApprovalRecord, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_by", normalize_principal_id(self.created_by))
        object.__setattr__(self, "last_amended_by", normalize_principal_id(self.last_amended_by))
        if not self.customer_ref.strip() or len(self.customer_ref) > 128:
            raise ValidationError("customer_ref must be between 1 and 128 characters.")
        if self.version < 1 or self.pricing_version < 1:
            raise ValidationError("Order version and pricing_version must be >= 1.")

    @property
    def currency(self) -> Currency:
        return self.waterfall.currency

    @property
    def active_approval(self) -> ApprovalRecord | None:
        """Return an approval covering the current `pricing_version`, if present."""
        for record in reversed(self.approvals):
            if record.approved_pricing_version == self.pricing_version:
                return record
        return None


def is_margin_floor_satisfied(waterfall: PricedOrderWaterfall, minimum_margin_bps: int) -> bool:
    """Exact integer cross-multiplication check (`margin / net_goods >= min_bps / 10_000`).

    Avoids binary floating-point rounding and prevents borderline sub-floor margins
    (e.g. `19.996%` against a `20.00%` floor) from slipping past early rounding.
    """
    net_goods = waterfall.net_goods_total_minor
    if net_goods > 0:
        return waterfall.margin_minor * 10_000 >= minimum_margin_bps * net_goods
    if waterfall.total_cost_minor > 0:
        return False
    return minimum_margin_bps <= 0


def evaluate_margin_gate(order: SalesOrder, policy: MarginPolicy) -> ReadinessGate:
    """Evaluate the `margin_floor` readiness gate without leaking confidential cost figures."""
    if policy.mode == "off":
        return ReadinessGate(
            gate="margin_floor",
            met=True,
            code="MARGIN_POLICY_OFF",
            remediation="No action required; tenant margin policy is disabled.",
        )

    if order.order_kind in policy.exempt_order_kinds:
        return ReadinessGate(
            gate="margin_floor",
            met=True,
            code="ORDER_KIND_EXEMPT",
            remediation="No action required; order classification is exempt from margin floor.",
        )

    if order.active_approval is not None:
        return ReadinessGate(
            gate="margin_floor",
            met=True,
            code="MARGIN_EXCEPTION_APPROVED",
            remediation="Margin exception approved under four-eyes control.",
        )

    if is_margin_floor_satisfied(order.waterfall, policy.minimum_margin_bps):
        return ReadinessGate(
            gate="margin_floor",
            met=True,
            code="MARGIN_FLOOR_MET",
            remediation="Order meets tenant minimum margin threshold.",
        )

    if policy.mode == "warn":
        return ReadinessGate(
            gate="margin_floor",
            met=True,
            code="MARGIN_BELOW_FLOOR_WARN",
            remediation=(
                "Order margin is below advisory target; review commercial pricing before dispatch."
            ),
        )

    return ReadinessGate(
        gate="margin_floor",
        met=False,
        code="MARGIN_BELOW_FLOOR_BLOCK",
        remediation=(
            "Increase selling price, reduce commercial discount, or request four-eyes "
            "approval from an authorised margin approver."
        ),
    )


def determine_initial_status(
    waterfall: PricedOrderWaterfall,
    policy: MarginPolicy,
    order_kind: OrderKind,
) -> OrderStatus:
    """Place newly created sub-floor orders under `pending_approval` when policy blocks."""
    if (
        policy.mode == "block"
        and order_kind not in policy.exempt_order_kinds
        and not is_margin_floor_satisfied(waterfall, policy.minimum_margin_bps)
    ):
        return OrderStatus.PENDING_APPROVAL
    return OrderStatus.DRAFT


def record_four_eyes_approval(
    *,
    order: SalesOrder,
    approver: PrincipalContext,
    reason: str,
    approved_at_utc: str,
    approval_id: UUID,
) -> SalesOrder:
    """Append an `ApprovalRecord` enforcing `orders:margin:approve` and four-eyes separation."""
    approver.require_capability("orders:margin:approve")
    if approver.tenant_id != order.tenant_id:
        raise AuthorizationError("Cross-tenant approval attempt rejected.")

    if approver.principal_id in {order.created_by, order.last_amended_by}:
        raise SeparationOfDutiesError(
            "Four-eyes separation of duties violation: approver must be distinct from "
            "both order creator and last amending principal."
        )

    record = ApprovalRecord(
        approval_id=approval_id,
        approver_principal_id=approver.principal_id,
        reason=reason,
        approved_at_utc=approved_at_utc,
        approved_pricing_version=order.pricing_version,
        approved_margin_bps=order.waterfall.margin_bps,
        approved_net_goods_minor=order.waterfall.net_goods_total_minor,
    )
    return replace(
        order,
        approvals=(*order.approvals, record),
        updated_at_utc=approved_at_utc,
    )


def confirm_sales_order(
    *,
    order: SalesOrder,
    policy: MarginPolicy,
    confirmed_at_utc: str,
) -> SalesOrder:
    """Confirm an order only when all readiness gates evaluate to `met=True`."""
    gate = evaluate_margin_gate(order, policy)
    if not gate.met:
        raise MarginBlockedError(
            "Order confirmation blocked by unmet margin readiness gate.",
            code=gate.code,
            details={"readiness_gates": [gate.to_dict()]},
        )
    return replace(
        order,
        status=OrderStatus.CONFIRMED,
        updated_at_utc=confirmed_at_utc,
    )


def apply_order_amendment(
    *,
    order: SalesOrder,
    new_waterfall: PricedOrderWaterfall,
    new_header_discount_bps: int,
    new_header_discount_minor: int,
    policy: MarginPolicy,
    amended_by: PrincipalContext,
    amended_at_utc: str,
    adverse_commercial_change: bool,
) -> SalesOrder:
    """Re-evaluate margin governance after an order line or header commercial amendment.

    Price-lowering or discount-increasing amendments increment `pricing_version`
    (requiring fresh approval if below floor) and automatically transition `confirmed`
    orders back to `pending_approval` when the margin floor is breached.
    """
    next_pricing_version = (
        order.pricing_version + 1 if adverse_commercial_change else order.pricing_version
    )
    candidate = replace(
        order,
        pricing_version=next_pricing_version,
        header_discount_bps=new_header_discount_bps,
        header_discount_minor=new_header_discount_minor,
        waterfall=new_waterfall,
        last_amended_by=amended_by.principal_id,
        updated_at_utc=amended_at_utc,
    )
    gate = evaluate_margin_gate(candidate, policy)
    if not gate.met:
        return replace(candidate, status=OrderStatus.PENDING_APPROVAL)
    return candidate


def _project_line(
    line: PricedOrderLine,
    *,
    can_read_cost: bool,
    can_read_margin: bool,
) -> dict[str, Any]:
    steps_out = [
        {
            "kind": step.kind.value,
            "amount_minor": step.amount_minor,
            "is_statistical": step.is_statistical,
        }
        for step in line.steps
        if can_read_cost or step.kind is not ConditionStepKind.STATISTICAL_VALUATION_COST
    ]
    projected: dict[str, Any] = {
        "line_id": str(line.line_id),
        "sku": line.sku,
        "description": line.description,
        "item_kind": line.item_kind.value,
        "quantity": str(line.quantity),
        "unit_ratio": {
            "numerator": line.unit_ratio.numerator,
            "denominator": line.unit_ratio.denominator,
        },
        "unit_price_minor": line.unit_price_minor,
        "applied_discount_bps": line.applied_discount_bps,
        "gross_minor": line.gross_minor,
        "quantity_discount_minor": line.quantity_discount_minor,
        "header_discount_spread_minor": line.header_discount_spread_minor,
        "net_goods_minor": line.net_goods_minor,
        "steps": steps_out,
    }
    if can_read_cost:
        projected["unit_cost_minor"] = line.unit_cost_minor
        projected["total_cost_minor"] = line.total_cost_minor
    if can_read_margin:
        projected["margin_minor"] = line.margin_minor
        projected["margin_bps"] = line.margin_bps
    return projected


def project_order_for_principal(
    order: SalesOrder,
    policy: MarginPolicy,
    principal: PrincipalContext,
) -> dict[str, Any]:
    """Capability-based order representation stripping cost/margin for unprivileged roles.

    Principals lacking `valuation:cost:read` never see `unit_cost_minor`,
    `total_cost_minor`, or `STATISTICAL_VALUATION_COST` steps. Principals lacking
    `orders:margin:read` never see `margin_minor`, `margin_bps`, or `approved_margin_bps`.
    Readiness gate outcome (`{gate, met, code, remediation}`) remains visible so sales
    and warehouse staff know whether approval is required without leaking cost!
    """
    can_read_cost = principal.has_capability("valuation:cost:read")
    can_read_margin = principal.has_capability("orders:margin:read")
    gate = evaluate_margin_gate(order, policy)

    approvals_out: list[dict[str, Any]] = []
    for record in order.approvals:
        entry: dict[str, Any] = {
            "approval_id": str(record.approval_id),
            "approver_principal_id": record.approver_principal_id,
            "reason": record.reason,
            "approved_at_utc": record.approved_at_utc,
            "approved_pricing_version": record.approved_pricing_version,
        }
        if can_read_margin:
            entry["approved_margin_bps"] = record.approved_margin_bps
        approvals_out.append(entry)

    payload: dict[str, Any] = {
        "order_id": str(order.order_id),
        "tenant_id": str(order.tenant_id),
        "customer_ref": order.customer_ref,
        "order_kind": order.order_kind.value,
        "currency": order.currency.value,
        "status": order.status.value,
        "version": order.version,
        "pricing_version": order.pricing_version,
        "header_discount_bps": order.header_discount_bps,
        "header_discount_minor": order.header_discount_minor,
        "gross_goods_total_minor": order.waterfall.gross_goods_total_minor,
        "line_discounts_total_minor": order.waterfall.line_discounts_total_minor,
        "header_discount_total_minor": order.waterfall.header_discount_total_minor,
        "net_goods_total_minor": order.waterfall.net_goods_total_minor,
        "passthrough_freight_minor": order.waterfall.passthrough_freight_minor,
        "small_order_surcharge_minor": order.waterfall.small_order_surcharge_minor,
        "payable_total_minor": order.waterfall.payable_total_minor,
        "created_by": order.created_by,
        "last_amended_by": order.last_amended_by,
        "created_at_utc": order.created_at_utc,
        "updated_at_utc": order.updated_at_utc,
        "readiness_gates": [gate.to_dict()],
        "approvals": approvals_out,
        "lines": [
            _project_line(
                ln,
                can_read_cost=can_read_cost,
                can_read_margin=can_read_margin,
            )
            for ln in order.waterfall.lines
        ],
    }
    if can_read_cost:
        payload["total_cost_minor"] = order.waterfall.total_cost_minor
    if can_read_margin:
        payload["margin_minor"] = order.waterfall.margin_minor
        payload["margin_bps"] = order.waterfall.margin_bps
    return payload
