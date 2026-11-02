"""Deterministic commercial condition waterfall and immutable inventory cost snapshots."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from fractions import Fraction
from uuid import UUID

from ledger_guard.domain.errors import CurrencyMismatchError, ValidationError
from ledger_guard.domain.money import (
    Currency,
    UnitRatio,
    parse_rational_quantity,
    require_strict_int,
    round_rational_half_even,
)


class ConditionStepKind(StrEnum):
    """Canonical pricing condition steps in deterministic execution order."""

    BASE_PRICE = "BASE_PRICE"
    QUANTITY_DISCOUNT = "QUANTITY_DISCOUNT"
    HEADER_DISCOUNT_SPREAD = "HEADER_DISCOUNT_SPREAD"
    PASSTHROUGH_FREIGHT = "PASSTHROUGH_FREIGHT"
    SMALL_ORDER_SURCHARGE = "SMALL_ORDER_SURCHARGE"
    STATISTICAL_VALUATION_COST = "STATISTICAL_VALUATION_COST"


class ItemKind(StrEnum):
    """Distinguishes physical stocked SKUs from non-stocked professional/service lines."""

    STOCKED = "stocked"
    SERVICE = "service"


@dataclass(frozen=True, slots=True)
class QuantityTierDiscount:
    """Automatic tier discount triggered when selling quantity meets `min_quantity`."""

    min_quantity: Fraction
    discount_bps: int

    def __post_init__(self) -> None:
        if self.min_quantity <= 0:
            raise ValidationError("Quantity tier min_quantity must be positive.")
        bps = require_strict_int(self.discount_bps, "discount_bps")
        if bps < 0 or bps > 10_000:
            raise ValidationError("Quantity tier discount_bps must be between 0 and 10000.")


@dataclass(frozen=True, slots=True)
class CostSnapshot:
    """Immutable valuation snapshot captured at line pricing time.

    Subsequent warehouse stock revaluations in the inventory ledger never mutate or
    retroactively invalidate orders that have already captured their `CostSnapshot`.
    """

    sku: str
    base_unit_cost_minor: int
    currency: Currency
    unit_ratio: UnitRatio
    valuation_revision: int

    def __post_init__(self) -> None:
        cost = require_strict_int(self.base_unit_cost_minor, "base_unit_cost_minor")
        rev = require_strict_int(self.valuation_revision, "valuation_revision")
        if cost < 0:
            raise ValidationError("Snapshot base_unit_cost_minor cannot be negative.")
        if rev < 1:
            raise ValidationError("Snapshot valuation_revision must be >= 1.")


@dataclass(frozen=True, slots=True)
class ConditionStep:
    """Single auditable condition step emitted by the pricing waterfall."""

    kind: ConditionStepKind
    amount_minor: int
    is_statistical: bool


@dataclass(frozen=True, slots=True)
class LinePricingInput:
    """Validated commercial line input entering the deterministic waterfall."""

    line_id: UUID
    sku: str
    description: str
    item_kind: ItemKind
    currency: Currency
    quantity: Fraction
    unit_price_minor: int
    unit_ratio: UnitRatio
    manual_discount_bps: int = 0
    tier_discounts: tuple[QuantityTierDiscount, ...] = ()
    cost_snapshot: CostSnapshot | None = None

    def __post_init__(self) -> None:
        if not self.sku.strip() or len(self.sku) > 64:
            raise ValidationError("SKU must be between 1 and 64 characters.")
        if not self.description.strip() or len(self.description) > 255:
            raise ValidationError("Line description must be between 1 and 255 characters.")
        parse_rational_quantity(self.quantity, "quantity")
        price = require_strict_int(self.unit_price_minor, "unit_price_minor")
        if price < 0:
            raise ValidationError("unit_price_minor cannot be negative.")
        bps = require_strict_int(self.manual_discount_bps, "manual_discount_bps")
        if bps < 0 or bps > 10_000:
            raise ValidationError("manual_discount_bps must be between 0 and 10000.")
        if self.item_kind is ItemKind.STOCKED and self.cost_snapshot is None:
            raise ValidationError(
                f"Stocked SKU '{self.sku}' requires an immutable inventory CostSnapshot."
            )
        if self.cost_snapshot is not None and self.cost_snapshot.currency != self.currency:
            raise CurrencyMismatchError(
                f"SKU '{self.sku}' valuation currency ({self.cost_snapshot.currency.value}) "
                f"does not match order currency ({self.currency.value})."
            )


@dataclass(frozen=True, slots=True)
class PricedOrderLine:
    """Immutable priced order line with net-goods, statistical cost, and step trace."""

    line_id: UUID
    sku: str
    description: str
    item_kind: ItemKind
    quantity: Fraction
    unit_ratio: UnitRatio
    unit_price_minor: int
    applied_discount_bps: int
    gross_minor: int
    quantity_discount_minor: int
    header_discount_spread_minor: int
    net_goods_minor: int
    unit_cost_minor: int
    total_cost_minor: int
    margin_minor: int
    margin_bps: int
    cost_snapshot: CostSnapshot | None
    steps: tuple[ConditionStep, ...]


@dataclass(frozen=True, slots=True)
class PricedOrderWaterfall:
    """Complete order waterfall output separating margin-basis goods from pass-through charges."""

    currency: Currency
    lines: tuple[PricedOrderLine, ...]
    gross_goods_total_minor: int
    line_discounts_total_minor: int
    header_discount_total_minor: int
    net_goods_total_minor: int
    passthrough_freight_minor: int
    small_order_surcharge_minor: int
    payable_total_minor: int
    total_cost_minor: int
    margin_minor: int
    margin_bps: int
    header_steps: tuple[ConditionStep, ...]


def compute_margin_bps(margin_minor: int, net_goods_minor: int, total_cost_minor: int) -> int:
    """Compute gross margin in basis points (`100 bps = 1.00%`) using `ROUND_HALF_EVEN`."""
    if net_goods_minor > 0:
        return round_rational_half_even(Fraction(margin_minor * 10_000, net_goods_minor))
    if total_cost_minor > 0:
        return -10_000
    return 0


def _allocate_proportional_minor(total_to_spread: int, weights: Sequence[int]) -> list[int]:
    """Allocate `total_to_spread` across `weights` proportionally with zero penny drift."""
    count = len(weights)
    if count == 0 or total_to_spread == 0:
        return [0] * count
    weight_sum = sum(weights)
    if weight_sum <= 0:
        return [0] * count

    floors: list[int] = []
    remainders: list[tuple[Fraction, int, int]] = []
    for idx, weight in enumerate(weights):
        exact = Fraction(total_to_spread * weight, weight_sum)
        floor_val = exact.numerator // exact.denominator
        floors.append(floor_val)
        remainders.append((exact - floor_val, weight, -idx))

    remaining = total_to_spread - sum(floors)
    ranked_indices = sorted(
        range(count),
        key=lambda i: remainders[i],
        reverse=True,
    )
    for idx in ranked_indices[:remaining]:
        floors[idx] += 1
    return floors


def resolve_effective_line_discount_bps(
    quantity: Fraction,
    manual_discount_bps: int,
    tiers: Sequence[QuantityTierDiscount],
) -> int:
    """Pick the highest qualifying tier discount or explicit manual line discount."""
    tier_bps = 0
    for tier in tiers:
        if quantity >= tier.min_quantity and tier.discount_bps > tier_bps:
            tier_bps = tier.discount_bps
    return max(manual_discount_bps, tier_bps)


def price_order_waterfall(
    *,
    currency: Currency,
    lines: Sequence[LinePricingInput],
    header_discount_bps: int = 0,
    header_discount_minor: int = 0,
    passthrough_freight_minor: int = 0,
    small_order_surcharge_minor: int = 0,
) -> PricedOrderWaterfall:
    """Execute the six-step commercial pricing waterfall with exact `Fraction` arithmetic.

    Crucially, `passthrough_freight_minor` and `small_order_surcharge_minor` increase
    `payable_total_minor` billed to the buyer, yet are strictly excluded from
    `net_goods_total_minor` and gross margin basis.
    """
    if not lines or len(lines) > 200:
        raise ValidationError("Order must contain between 1 and 200 lines.")

    hdr_bps = require_strict_int(header_discount_bps, "header_discount_bps")
    hdr_minor = require_strict_int(header_discount_minor, "header_discount_minor")
    freight = require_strict_int(passthrough_freight_minor, "passthrough_freight_minor")
    surcharge = require_strict_int(small_order_surcharge_minor, "small_order_surcharge_minor")

    if hdr_bps < 0 or hdr_bps > 10_000:
        raise ValidationError("header_discount_bps must be between 0 and 10000.")
    if hdr_minor < 0:
        raise ValidationError("header_discount_minor cannot be negative.")
    if freight < 0:
        raise ValidationError("passthrough_freight_minor cannot be negative.")
    if surcharge < 0:
        raise ValidationError("small_order_surcharge_minor cannot be negative.")

    gross_list: list[int] = []
    qty_disc_list: list[int] = []
    applied_bps_list: list[int] = []
    after_line_disc_list: list[int] = []

    for item in lines:
        if item.currency != currency:
            raise CurrencyMismatchError(
                f"Line SKU '{item.sku}' currency ({item.currency.value}) mismatches "
                f"order currency ({currency.value})."
            )
        gross = round_rational_half_even(item.quantity * Fraction(item.unit_price_minor, 1))
        eff_bps = resolve_effective_line_discount_bps(
            item.quantity, item.manual_discount_bps, item.tier_discounts
        )
        qty_disc = round_rational_half_even(Fraction(gross * eff_bps, 10_000))
        after_line = gross - qty_disc

        gross_list.append(gross)
        qty_disc_list.append(qty_disc)
        applied_bps_list.append(eff_bps)
        after_line_disc_list.append(after_line)

    subtotal_after_line = sum(after_line_disc_list)
    bps_header_disc = round_rational_half_even(Fraction(subtotal_after_line * hdr_bps, 10_000))
    total_header_discount = bps_header_disc + hdr_minor
    if total_header_discount > subtotal_after_line:
        raise ValidationError(
            "Combined header discount exceeds post-line-discount goods subtotal."
        )

    spread_allocations = _allocate_proportional_minor(total_header_discount, after_line_disc_list)

    priced_lines: list[PricedOrderLine] = []
    for idx, item in enumerate(lines):
        gross = gross_list[idx]
        qty_disc = qty_disc_list[idx]
        spread_disc = spread_allocations[idx]
        net_goods = after_line_disc_list[idx] - spread_disc

        if item.cost_snapshot is not None:
            exact_selling_cost = item.cost_snapshot.unit_ratio.exact_selling_unit_cost(
                item.cost_snapshot.base_unit_cost_minor
            )
            unit_cost_minor = round_rational_half_even(exact_selling_cost)
            total_cost_minor = round_rational_half_even(item.quantity * exact_selling_cost)
        else:
            unit_cost_minor = 0
            total_cost_minor = 0

        line_margin_minor = net_goods - total_cost_minor
        line_margin_bps = compute_margin_bps(line_margin_minor, net_goods, total_cost_minor)

        steps: list[ConditionStep] = [
            ConditionStep(ConditionStepKind.BASE_PRICE, gross, is_statistical=False),
            ConditionStep(ConditionStepKind.QUANTITY_DISCOUNT, -qty_disc, is_statistical=False),
            ConditionStep(
                ConditionStepKind.HEADER_DISCOUNT_SPREAD, -spread_disc, is_statistical=False
            ),
            ConditionStep(
                ConditionStepKind.STATISTICAL_VALUATION_COST,
                total_cost_minor,
                is_statistical=True,
            ),
        ]

        priced_lines.append(
            PricedOrderLine(
                line_id=item.line_id,
                sku=item.sku,
                description=item.description,
                item_kind=item.item_kind,
                quantity=item.quantity,
                unit_ratio=item.unit_ratio,
                unit_price_minor=item.unit_price_minor,
                applied_discount_bps=applied_bps_list[idx],
                gross_minor=gross,
                quantity_discount_minor=qty_disc,
                header_discount_spread_minor=spread_disc,
                net_goods_minor=net_goods,
                unit_cost_minor=unit_cost_minor,
                total_cost_minor=total_cost_minor,
                margin_minor=line_margin_minor,
                margin_bps=line_margin_bps,
                cost_snapshot=item.cost_snapshot,
                steps=tuple(steps),
            )
        )

    net_goods_total = sum(ln.net_goods_minor for ln in priced_lines)
    total_cost = sum(ln.total_cost_minor for ln in priced_lines)
    margin_total = net_goods_total - total_cost
    order_margin_bps = compute_margin_bps(margin_total, net_goods_total, total_cost)
    payable_total = net_goods_total + freight + surcharge

    header_steps = (
        ConditionStep(ConditionStepKind.PASSTHROUGH_FREIGHT, freight, is_statistical=False),
        ConditionStep(ConditionStepKind.SMALL_ORDER_SURCHARGE, surcharge, is_statistical=False),
    )

    return PricedOrderWaterfall(
        currency=currency,
        lines=tuple(priced_lines),
        gross_goods_total_minor=sum(gross_list),
        line_discounts_total_minor=sum(qty_disc_list),
        header_discount_total_minor=total_header_discount,
        net_goods_total_minor=net_goods_total,
        passthrough_freight_minor=freight,
        small_order_surcharge_minor=surcharge,
        payable_total_minor=payable_total,
        total_cost_minor=total_cost,
        margin_minor=margin_total,
        margin_bps=order_margin_bps,
        header_steps=header_steps,
    )
