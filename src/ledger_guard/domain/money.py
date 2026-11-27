"""Exact integer minor-unit money, bounded inputs, and rational unit-of-measure (UoM).

Zero I/O, zero imprecise binary representations: every intermediate calculation runs in
`fractions.Fraction` and settles to integer minor units (`pence` / `cents`) via exact
Euclidean `ROUND_HALF_EVEN` (banker's rounding).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from fractions import Fraction

from ledger_guard.domain.errors import ValidationError

MAX_MINOR_AMOUNT: int = 10_000_000_000_000  # £100B per unit/surcharge; SQL BIGINT & IEEE safe
MAX_ORDER_TOTAL_MINOR: int = 9_000_000_000_000_000  # Below JS MAX_SAFE_INTEGER (9.007e15) & BIGINT
MAX_LINE_QUANTITY: int = 1_000_000_000
MAX_QUANTITY_DENOMINATOR: int = 1_000_000
MAX_INT32: int = 2_147_483_647

_BIDI_AND_INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x061C,  # ARABIC LETTER MARK
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)

_STRICT_RATIONAL_RE = re.compile(r"\A([0-9]{1,10})(?:/([1-9][0-9]{0,6}))?\Z")


def validate_safe_text(value: str, field_name: str, *, max_length: int) -> str:
    """Validate bounded text, rejecting ASCII control, Unicode Bidi, and surrogate characters."""
    if not isinstance(value, str):
        raise ValidationError(f"Field '{field_name}' must be a string.")
    for ch in value:
        codepoint = ord(ch)
        if (
            codepoint < 0x20
            or codepoint == 0x7F
            or (0xD800 <= codepoint <= 0xDFFF)
            or codepoint in _BIDI_AND_INVISIBLE_CODEPOINTS
        ):
            raise ValidationError(
                f"Field '{field_name}' contains prohibited control or bidirectional characters.",
                code="UNSAFE_CONTROL_OR_BIDI_CHAR",
            )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length:
        raise ValidationError(
            f"Field '{field_name}' must be between 1 and {max_length} characters."
        )
    return cleaned


class Currency(StrEnum):
    """Supported ISO 4217 currencies."""

    GBP = "GBP"
    EUR = "EUR"
    USD = "USD"
    BRL = "BRL"
    JPY = "JPY"


def require_strict_int(value: object, field_name: str) -> int:
    """Validate that `value` is a genuine Python `int` (explicitly rejecting `bool`)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(
            f"Field '{field_name}' must be an exact integer (minor units); non-integer rejected.",
            code="NON_INTEGER_AMOUNT",
        )
    return value


def require_bounded_minor_int(
    value: object,
    field_name: str,
    *,
    min_value: int = 0,
    max_value: int = MAX_MINOR_AMOUNT,
) -> int:
    """Validate strict integer inside `[min_value, max_value]` (prevents BIGINT/JSON overflow)."""
    parsed = require_strict_int(value, field_name)
    if parsed < min_value or parsed > max_value:
        raise ValidationError(
            f"Field '{field_name}' must be between {min_value} and {max_value}.",
            code="AMOUNT_OUT_OF_BOUNDS",
        )
    return parsed


def parse_rational_quantity(value: Fraction | int | str, field_name: str = "quantity") -> Fraction:
    """Parse an exact positive rational quantity without float or scientific-notation DoS."""
    if isinstance(value, bool):
        raise ValidationError(f"Field '{field_name}' cannot be a boolean.")
    if isinstance(value, Fraction):
        require_strict_int(value.numerator, f"{field_name}.numerator")
        require_strict_int(value.denominator, f"{field_name}.denominator")
        rational = value
    elif isinstance(value, int):
        rational = Fraction(value, 1)
    elif isinstance(value, str):
        cleaned = validate_safe_text(value, field_name, max_length=32)
        match = _STRICT_RATIONAL_RE.fullmatch(cleaned)
        if match is None:
            raise ValidationError(
                f"Field '{field_name}' must be a positive ASCII integer or 'num/den' rational."
            )
        num_s, den_s = match.group(1), match.group(2)
        rational = Fraction(int(num_s), int(den_s) if den_s is not None else 1)
    else:
        raise ValidationError(
            f"Field '{field_name}' must be int, Fraction, or rational string."
        )

    if rational <= 0:
        raise ValidationError(f"Field '{field_name}' must be strictly greater than zero.")
    if rational.denominator > MAX_QUANTITY_DENOMINATOR:
        raise ValidationError(
            f"Field '{field_name}' denominator exceeds max {MAX_QUANTITY_DENOMINATOR}."
        )
    if rational > MAX_LINE_QUANTITY:
        raise ValidationError(
            f"Field '{field_name}' exceeds max line quantity {MAX_LINE_QUANTITY}."
        )
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
        require_bounded_minor_int(
            self.numerator,
            "unit_ratio.numerator",
            min_value=1,
            max_value=MAX_LINE_QUANTITY,
        )
        require_bounded_minor_int(
            self.denominator,
            "unit_ratio.denominator",
            min_value=1,
            max_value=MAX_QUANTITY_DENOMINATOR,
        )

    @property
    def as_fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)

    def exact_selling_unit_cost(self, base_unit_cost_minor: int) -> Fraction:
        """Compute exact rational selling-unit cost in minor units from base stock cost."""
        cost = require_bounded_minor_int(base_unit_cost_minor, "base_unit_cost_minor")
        return Fraction(cost, 1) * self.as_fraction
