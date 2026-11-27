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
    QuantityTierDiscount,
    UnitRatio,
    ValidationError,
    price_order_waterfall,
    round_rational_half_even,
)
from ledger_guard.domain.money import (
    MAX_LINE_QUANTITY,
    MAX_MINOR_AMOUNT,
    parse_rational_quantity,
    require_bounded_minor_int,
)
from ledger_guard.domain.pricing import compute_margin_bps


def test_round_rational_half_even_bankers_ties() -> None:
    assert round_rational_half_even(Fraction(5, 2)) == 2
    assert round_rational_half_even(Fraction(7, 2)) == 4
    assert round_rational_half_even(Fraction(-5, 2)) == -2
    assert round_rational_half_even(Fraction(-7, 2)) == -4
    assert round_rational_half_even(Fraction(100, 3)) == 33
    assert round_rational_half_even(Fraction(200, 3)) == 67


def test_require_bounded_minor_int_rejects_booleans_and_bigint_overflow() -> None:
    with pytest.raises(ValidationError) as bool_exc:
        require_bounded_minor_int(True, "unit_price_minor")
    assert bool_exc.value.code == "NON_INTEGER_AMOUNT"

    with pytest.raises(ValidationError) as overflow_exc:
        require_bounded_minor_int(MAX_MINOR_AMOUNT + 1, "unit_price_minor")
    assert overflow_exc.value.code == "AMOUNT_OUT_OF_BOUNDS"


def test_unit_ratio_non_terminating_one_third_preserves_exact_case_cost() -> None:
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


def test_unit_ratio_rejects_zero_negative_or_unbounded_components() -> None:
    with pytest.raises(ValidationError):
        UnitRatio(0, 3)
    with pytest.raises(ValidationError):
        UnitRatio(1, -2)
    with pytest.raises(ValidationError):
        UnitRatio(MAX_LINE_QUANTITY + 1, 1)


def test_parse_rational_quantity_blocks_scientific_notation_poison_pills_and_unicode() -> None:
    assert parse_rational_quantity("7/3") == Fraction(7, 3)
    assert parse_rational_quantity(4) == Fraction(4, 1)

    for malicious in (
        0,
        -1,
        "-3/2",
        "1e5000",
        "1e99999999",
        "1e9999999999999999999999999",
        "1/" + "9" * 20,
        "1_000/3",
        "١٢٣/٤",
        1.5,
        Fraction(1, 2_000_000),
        MAX_LINE_QUANTITY + 1,
    ):
        with pytest.raises(ValidationError):
            parse_rational_quantity(malicious)  # type: ignore[arg-type]


def test_zero_rounded_paid_line_and_clamped_negative_margin_bps() -> None:
    snap = CostSnapshot("MICRO-1", 50, Currency.GBP, UnitRatio(1, 1), 1)
    with pytest.raises(ValidationError) as exc_info:
        price_order_waterfall(
            currency=Currency.GBP,
            lines=[
                LinePricingInput(
                    line_id=uuid4(),
                    sku="MICRO-1",
                    description="Micro fractional line",
                    item_kind=ItemKind.STOCKED,
                    currency=Currency.GBP,
                    quantity=Fraction(1, 10),
                    unit_price_minor=1,
                    unit_ratio=UnitRatio(1, 1),
                    cost_snapshot=snap,
                )
            ],
        )
    assert exc_info.value.code == "ZERO_ROUNDED_LINE_GROSS"

    # Low positive net_goods with higher cost clamps to -10_000 bps (matches SQL CHECK)
    assert compute_margin_bps(-6_000, 1_000, 7_000) == -10_000


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
