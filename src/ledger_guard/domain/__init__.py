"""Pure domain model exports for LedgerGuard."""

from __future__ import annotations

from ledger_guard.domain.errors import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    CurrencyMismatchError,
    DomainError,
    MarginBlockedError,
    NotFoundError,
    PayloadTooLargeError,
    RateLimitExceededError,
    SeparationOfDutiesError,
    ValidationError,
    WebhookVerificationError,
)
from ledger_guard.domain.margin_gate import (
    MarginPolicy,
    OrderKind,
    OrderStatus,
    PrincipalContext,
    SalesOrder,
    is_margin_floor_satisfied,
    normalize_principal_id,
    project_order_for_principal,
)
from ledger_guard.domain.money import (
    Currency,
    UnitRatio,
    parse_rational_quantity,
    round_rational_half_even,
)
from ledger_guard.domain.pricing import (
    ConditionStepKind,
    CostSnapshot,
    ItemKind,
    LinePricingInput,
    QuantityTierDiscount,
    price_order_waterfall,
)

__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ConditionStepKind",
    "ConflictError",
    "CostSnapshot",
    "Currency",
    "CurrencyMismatchError",
    "DomainError",
    "ItemKind",
    "LinePricingInput",
    "MarginBlockedError",
    "MarginPolicy",
    "NotFoundError",
    "OrderKind",
    "OrderStatus",
    "PayloadTooLargeError",
    "PrincipalContext",
    "QuantityTierDiscount",
    "RateLimitExceededError",
    "SalesOrder",
    "SeparationOfDutiesError",
    "UnitRatio",
    "ValidationError",
    "WebhookVerificationError",
    "is_margin_floor_satisfied",
    "normalize_principal_id",
    "parse_rational_quantity",
    "price_order_waterfall",
    "project_order_for_principal",
    "round_rational_half_even",
]
