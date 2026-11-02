"""Domain and security exception hierarchy with structured machine-readable error codes."""

from __future__ import annotations

from typing import Any


class DomainError(Exception):
    """Base error for deterministic domain and security boundary violations."""

    code: str = "DOMAIN_ERROR"
    http_status: int = 400

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.details: dict[str, Any] = details if details is not None else {}


class ValidationError(DomainError):
    """Raised when bounded input, arithmetic, or domain invariants fail validation."""

    code = "VALIDATION_ERROR"
    http_status = 422


class CurrencyMismatchError(ValidationError):
    """Raised when combining amounts or costs denominated in distinct ISO currencies."""

    code = "CURRENCY_MISMATCH"
    http_status = 422


class AuthenticationError(DomainError):
    """Raised when credentials or bearer tokens are missing, expired, or forged."""

    code = "UNAUTHENTICATED"
    http_status = 401


class AuthorizationError(DomainError):
    """Raised when an authenticated principal lacks capability or active membership."""

    code = "FORBIDDEN"
    http_status = 403


class SeparationOfDutiesError(AuthorizationError):
    """Raised when a principal attempts four-eyes margin approval on their own order."""

    code = "SEPARATION_OF_DUTIES_VIOLATION"
    http_status = 403


class NotFoundError(DomainError):
    """Raised when an aggregate does not exist within the caller's verified tenant."""

    code = "NOT_FOUND"
    http_status = 404


class ConflictError(DomainError):
    """Raised on optimistic concurrency version mismatch or idempotency conflict."""

    code = "CONFLICT"
    http_status = 409


class MarginBlockedError(DomainError):
    """Raised when order confirmation is blocked by an unmet margin readiness gate."""

    code = "MARGIN_BELOW_FLOOR_BLOCK"
    http_status = 422


class RateLimitExceededError(DomainError):
    """Raised when an HMAC multi-bucket rate limiter quota or strike lockout is exceeded."""

    code = "RATE_LIMITED"
    http_status = 429

    def __init__(self, message: str, *, retry_after_seconds: int, bucket: str) -> None:
        super().__init__(
            message,
            code="RATE_LIMITED",
            details={"retry_after_seconds": retry_after_seconds, "bucket": bucket},
        )
        self.retry_after_seconds = retry_after_seconds
        self.bucket = bucket


class ScannerBannedError(AuthorizationError):
    """Raised when an unauthenticated scanner or canary trap IP is temporarily banned."""

    code = "SCANNER_IP_BANNED"
    http_status = 403


class WebhookVerificationError(AuthenticationError):
    """Raised when a webhook signature fails constant-time verification or exceeds 300s skew."""

    code = "WEBHOOK_VERIFICATION_FAILED"
    http_status = 401
