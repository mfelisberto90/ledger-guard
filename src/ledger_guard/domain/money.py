"""Exact integer minor-unit money and rational unit-of-measure (UoM) conversions.

Zero I/O, zero imprecise binary representations: every intermediate calculation runs in
`fractions.Fraction` and settles to integer minor units (`pence` / `cents`) via exact
Euclidean `ROUND_HALF_EVEN` (banker's rounding).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from fractions import Fraction

from ledger_guard.domain.errors import CurrencyMismatchError, ValidationError


class Currency(StrEnum):
    """Supported ISO 4217 currencies with minor-unit precision."""

    GBP = "GBP"
    EUR = "EUR"
    USD = "USD"
    BRL = "BRL"
    JPY = "JPY"

    @property
    def minor_exponent(self) -> int:
        if self is Currency.JPY:
            return 0
        return 2


def require_strict_int(value: object, field_name: str) -> int:
    """Validate that `value` is a genuine Python `int` (explicitly rejecting `bool`)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(
            f"Field '{field_name}' must be an exact integer (minor units); non-integer rejected.",
            code="NON_INTEGER_AMOUNT",
        )
    return value


def parse_rational_quantity(value: Fraction | int | str, field_name: str = "quantity") -> Fraction:
    """Parse an exact positive rational quantity without binary floating-point conversion."""
    if isinstance(value, bool):
        raise ValidationError(f"Field '{field_name}' cannot be a boolean.")
    if isinstance(value, Fraction):
        rational = value
    elif isinstance(value, int):
        rational = Fraction(value, 1)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 64:
            raise ValidationError(f"Field '{field_name}' must be a bounded non-empty rational.")
        try:
            rational = Fraction(cleaned)
        except (ValueError, ZeroDivisionError) as exc:
            raise ValidationError(
                f"Field '{field_name}' is not a valid rational quantity."
            ) from exc
    else:
        raise ValidationError(
            f"Field '{field_name}' must be int, Fraction, or rational string."
        )

    if rational <= 0:
        raise ValidationError(f"Field '{field_name}' must be strictly greater than zero.")
    return rational


def round_rational_half_even(value: Fraction) -> int:
    """Round an exact `Fraction` to the nearest integer using `ROUND_HALF_EVEN`."""
    numerator = value.numerator
    denominator = value.denominator
    sign = -1 if numerator < 0 else 1
    quotient, remainder = divmod(abs(numerator), denominator)
    twice_remainder = 2 * remainder
    if twice_remainder < denominator:
        rounded = quotient
    elif twice_remainder > denominator:
        rounded = quotient + 1
    else:
        rounded = quotient if (quotient % 2 == 0) else (quotient + 1)
    return sign * rounded


@dataclass(frozen=True, slots=True)
class MinorAmount:
    """Immutable monetary value in integer minor units (`pence`, `cents`, `yen`)."""

    amount_minor: int
    currency: Currency

    def __post_init__(self) -> None:
        require_strict_int(self.amount_minor, "amount_minor")
        if not isinstance(self.currency, Currency):
            raise ValidationError("Invalid currency enum instance.")

    def _assert_same_currency(self, other: MinorAmount) -> None:
        if self.currency != other.currency:
            raise CurrencyMismatchError(
                f"Cannot combine {self.currency.value} and {other.currency.value} without "
                "an explicit treasury FX rate snapshot."
            )

    def __add__(self, other: MinorAmount) -> MinorAmount:
        self._assert_same_currency(other)
        return MinorAmount(self.amount_minor + other.amount_minor, self.currency)

    def __sub__(self, other: MinorAmount) -> MinorAmount:
        self._assert_same_currency(other)
        return MinorAmount(self.amount_minor - other.amount_minor, self.currency)

    @classmethod
    def zero(cls, currency: Currency) -> MinorAmount:
        return cls(0, currency)


@dataclass(frozen=True, slots=True)
class UnitRatio:
    """Exact rational conversion between selling unit of measure and base stock unit.

    `numerator / denominator` expresses how many base stock units equal 1 selling line unit.
    Example:
      - Selling 1 single bottle from a 3-bottle case -> `UnitRatio(1, 3)`
      - Selling 1 outer carton containing 12 base units -> `UnitRatio(12, 1)`
    """

    numerator: int
    denominator: int = 1

    def __post_init__(self) -> None:
        num = require_strict_int(self.numerator, "unit_ratio.numerator")
        den = require_strict_int(self.denominator, "unit_ratio.denominator")
        if num <= 0 or den <= 0:
            raise ValidationError("UnitRatio numerator and denominator must be positive integers.")

    @property
    def as_fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)

    def to_base_quantity(self, selling_quantity: Fraction | int) -> Fraction:
        """Convert selling line quantity to exact base stock units without premature rounding."""
        qty = parse_rational_quantity(selling_quantity, "selling_quantity")
        return qty * self.as_fraction

    def exact_selling_unit_cost(self, base_unit_cost_minor: int) -> Fraction:
        """Compute exact rational selling-unit cost in minor units from base stock cost."""
        cost = require_strict_int(base_unit_cost_minor, "base_unit_cost_minor")
        if cost < 0:
            raise ValidationError("Base unit cost cannot be negative.")
        return Fraction(cost, 1) * self.as_fraction
