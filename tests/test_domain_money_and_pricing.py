"""Unit tests for exact rational `Fraction` money, UoM conversion, and condition waterfall."""

from __future__ import annotations

from fractions import Fraction
from uuid import uuid4

import pytest

from ledger_guard.domain import (
    ConditionStepKind,
    CostSnapshot,
    Currency,
    CurrencyMismatchError,
    ItemKind,
    LinePricingInput,
    MinorAmount,
    QuantityTierDiscount,
    UnitRatio,
    ValidationError,
    parse_rational_quantity,
    price_order_waterfall,
    round_rational_half_even,
)


def test_round_rational_half_even_bankers_ties() -> None:
    assert round_rational_half_even(Fraction(5, 2)) == 2
    assert round_rational_half_even(Fraction(7, 2)) == 4
    assert round_rational_half_even(Fraction(-5, 2)) == -2
    assert round_rational_half_even(Fraction(-7, 2)) == -4
    assert round_rational_half_even(Fraction(100, 3)) == 33
    assert round_rational_half_even(Fraction(200, 3)) == 67


def test_minor_amount_rejects_boolean_and_non_integer() -> None:
    with pytest.raises(ValidationError):
        MinorAmount(True, Currency.GBP)
    with pytest.raises(ValidationError):
        MinorAmount(12.5, Currency.GBP)  # type: ignore[arg-type]


def test_minor_amount_addition_and_subtraction_same_currency() -> None:
    a = MinorAmount(1_250, Currency.GBP)
    b = MinorAmount(750, Currency.GBP)
    assert (a + b).amount_minor == 2_000
    assert (a - b).amount_minor == 500
    assert MinorAmount.zero(Currency.JPY).currency.minor_exponent == 0
    assert Currency.GBP.minor_exponent == 2


def test_minor_amount_rejects_cross_currency_without_fx() -> None:
    gbp = MinorAmount(1_000, Currency.GBP)
    eur = MinorAmount(1_000, Currency.EUR)
    with pytest.raises(CurrencyMismatchError):
        _ = gbp + eur
    with pytest.raises(CurrencyMismatchError):
        _ = gbp - eur


def test_unit_ratio_non_terminating_one_third_preserves_exact_case_cost() -> None:
    # A 3-pack case costs £10.00 (1000p); selling 3 single bottles (1/3 case each) must equal 1000p
    ratio = UnitRatio(1, 3)
    snapshot = CostSnapshot(
        sku="REAGENT-BTL",
        base_unit_cost_minor=1_000,
        currency=Currency.GBP,
        unit_ratio=ratio,
        valuation_revision=1,
    )
    waterfall = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="REAGENT-BTL",
                description="Single Bottle",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                quantity=Fraction(3, 1),
                unit_price_minor=500,
                unit_ratio=ratio,
                cost_snapshot=snapshot,
            )
        ],
    )
    assert waterfall.lines[0].unit_cost_minor == 333
    assert waterfall.lines[0].total_cost_minor == 1_000
    assert waterfall.net_goods_total_minor == 1_500
    assert waterfall.margin_minor == 500
    assert waterfall.margin_bps == 3_333


def test_unit_ratio_rejects_zero_or_negative_components() -> None:
    with pytest.raises(ValidationError):
        UnitRatio(0, 3)
    with pytest.raises(ValidationError):
        UnitRatio(1, -2)
    assert UnitRatio(12, 1).to_base_quantity(Fraction(5, 2)) == Fraction(30, 1)


def test_parse_rational_quantity_accepts_fraction_strings_and_rejects_zero_or_float() -> None:
    assert parse_rational_quantity("7/3") == Fraction(7, 3)
    assert parse_rational_quantity(4) == Fraction(4, 1)
    with pytest.raises(ValidationError):
        parse_rational_quantity(0)
    with pytest.raises(ValidationError):
        parse_rational_quantity("-3/2")
    with pytest.raises(ValidationError):
        parse_rational_quantity(1.5)  # type: ignore[arg-type]


def test_header_discount_spread_allocates_penny_remainders_without_drift() -> None:
    snap = CostSnapshot("SKU-A", 50, Currency.GBP, UnitRatio(1, 1), 1)
    lines = [
        LinePricingInput(
            line_id=uuid4(),
            sku=f"SKU-{idx}",
            description=f"Item {idx}",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            quantity=Fraction(1, 1),
            unit_price_minor=100,
            unit_ratio=UnitRatio(1, 1),
            cost_snapshot=snap,
        )
        for idx in range(3)
    ]
    wf = price_order_waterfall(currency=Currency.GBP, lines=lines, header_discount_minor=10)
    spreads = [ln.header_discount_spread_minor for ln in wf.lines]
    assert spreads == [4, 3, 3]
    assert sum(spreads) == 10
    assert wf.net_goods_total_minor == 290


def test_passthrough_freight_and_surcharge_excluded_from_margin_basis() -> None:
    # Goods sold for £100.00, costing £85.00 -> 15.00% (1500 bps) margin.
    # Adding £500.00 pass-through freight and £25.00 small-order surcharge raises payable total
    # to £625.00, yet margin_minor MUST stay £15.00 (1500 bps), never inflated by freight!
    snap = CostSnapshot("PUMP-1", 8_500, Currency.GBP, UnitRatio(1, 1), 1)
    wf = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="PUMP-1",
                description="Industrial Pump",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                quantity=Fraction(1, 1),
                unit_price_minor=10_000,
                unit_ratio=UnitRatio(1, 1),
                cost_snapshot=snap,
            )
        ],
        passthrough_freight_minor=50_000,
        small_order_surcharge_minor=2_500,
    )
    assert wf.net_goods_total_minor == 10_000
    assert wf.payable_total_minor == 62_500
    assert wf.total_cost_minor == 8_500
    assert wf.margin_minor == 1_500
    assert wf.margin_bps == 1_500
    header_kinds = [step.kind for step in wf.header_steps]
    assert header_kinds == [
        ConditionStepKind.PASSTHROUGH_FREIGHT,
        ConditionStepKind.SMALL_ORDER_SURCHARGE,
    ]


def test_quantity_tier_discount_applies_automatically_when_threshold_reached() -> None:
    snap = CostSnapshot("BOLT-M8", 60, Currency.GBP, UnitRatio(1, 1), 1)
    tiers = (
        QuantityTierDiscount(min_quantity=Fraction(10, 1), discount_bps=500),
        QuantityTierDiscount(min_quantity=Fraction(50, 1), discount_bps=1_200),
    )
    wf = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="BOLT-M8",
                description="M8 Bolt",
                item_kind=ItemKind.STOCKED,
                currency=Currency.GBP,
                quantity=Fraction(50, 1),
                unit_price_minor=100,
                unit_ratio=UnitRatio(1, 1),
                tier_discounts=tiers,
                cost_snapshot=snap,
            )
        ],
    )
    assert wf.lines[0].applied_discount_bps == 1_200
    assert wf.lines[0].gross_minor == 5_000
    assert wf.lines[0].quantity_discount_minor == 600
    assert wf.net_goods_total_minor == 4_400


def test_non_stocked_service_line_prices_cleanly_without_cost_snapshot() -> None:
    wf = price_order_waterfall(
        currency=Currency.GBP,
        lines=[
            LinePricingInput(
                line_id=uuid4(),
                sku="INSTALL-SVC",
                description="Commissioning Service",
                item_kind=ItemKind.SERVICE,
                currency=Currency.GBP,
                quantity=Fraction(2, 1),
                unit_price_minor=15_000,
                unit_ratio=UnitRatio(1, 1),
                cost_snapshot=None,
            )
        ],
    )
    assert wf.net_goods_total_minor == 30_000
    assert wf.total_cost_minor == 0
    assert wf.margin_minor == 30_000
    assert wf.margin_bps == 10_000


def test_stocked_line_without_cost_snapshot_is_rejected() -> None:
    with pytest.raises(ValidationError):
        LinePricingInput(
            line_id=uuid4(),
            sku="STOCKED-NO-COST",
            description="Unvalued Stock Item",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            quantity=Fraction(1, 1),
            unit_price_minor=1_000,
            unit_ratio=UnitRatio(1, 1),
            cost_snapshot=None,
        )


def test_stocked_line_currency_mismatch_between_price_and_cost_is_rejected() -> None:
    eur_snap = CostSnapshot("VALVE-EUR", 700, Currency.EUR, UnitRatio(1, 1), 1)
    with pytest.raises(CurrencyMismatchError):
        LinePricingInput(
            line_id=uuid4(),
            sku="VALVE-EUR",
            description="Valve",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            quantity=Fraction(1, 1),
            unit_price_minor=1_000,
            unit_ratio=UnitRatio(1, 1),
            cost_snapshot=eur_snap,
        )


def test_excessive_header_discount_exceeding_subtotal_is_rejected() -> None:
    snap = CostSnapshot("VALVE", 500, Currency.GBP, UnitRatio(1, 1), 1)
    line = LinePricingInput(
        line_id=uuid4(),
        sku="VALVE",
        description="Valve",
        item_kind=ItemKind.STOCKED,
        currency=Currency.GBP,
        quantity=Fraction(1, 1),
        unit_price_minor=1_000,
        unit_ratio=UnitRatio(1, 1),
        cost_snapshot=snap,
    )
    with pytest.raises(ValidationError):
        price_order_waterfall(currency=Currency.GBP, lines=[line], header_discount_minor=1_001)
