"""Raw-bytes context-bound HMAC-SHA256 webhook verification (`<= 300s`) and anti-replay."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass
from uuid import UUID

from ledger_guard.domain.errors import ValidationError, WebhookVerificationError
from ledger_guard.domain.money import validate_safe_text
from ledger_guard.ports import WebhookDedupPort

MAX_WEBHOOK_TIMESTAMP_SKEW_SECONDS: int = 300
_PROVIDER_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class WebhookClaimResult:
    """Result of verifying a signed webhook and claiming its `event_id`."""

    provider: str
    event_id: str
    is_first_delivery: bool


def normalize_webhook_provider(provider: str) -> str:
    """Validate and canonicalize webhook provider slug (`1..64` ASCII slug)."""
    cleaned = validate_safe_text(provider, "provider", max_length=64).lower()
    if _PROVIDER_RE.fullmatch(cleaned) is None:
        raise ValidationError(
            "Webhook provider must be 1..64 lowercase [a-z0-9_-] characters.",
            code="INVALID_WEBHOOK_PROVIDER",
        )
    return cleaned


def compute_webhook_signature(
    secret: bytes,
    timestamp: str,
    raw_body: bytes,
    *,
    provider: str,
    tenant_id: UUID | str,
    event_id: str,
) -> str:
    """Compute context-bound `HMAC-SHA256(secret, provider.tenant.event.ts.raw_body)`."""
    if len(secret) < 16:
        raise ValidationError("Webhook signing secret must be at least 16 bytes.")
    clean_provider = normalize_webhook_provider(provider)
    clean_event = validate_safe_text(event_id, "event_id", max_length=128)
    clean_ts = timestamp.strip()
    header_prefix = f"{clean_provider}.{tenant_id}.{clean_event}.{clean_ts}.".encode()
    return hmac.new(secret, header_prefix + raw_body, hashlib.sha256).hexdigest()


def verify_and_claim_webhook(
    *,
    provider: str,
    event_id: str,
    tenant_id: UUID,
    raw_body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    secret: bytes,
    dedup_port: WebhookDedupPort,
    now_epoch: int | None = None,
) -> WebhookClaimResult:
    """Verify context-bound raw-bytes HMAC signature, enforce 300s window, and claim event."""
    if len(secret) < 16:
        raise ValidationError("Webhook signing secret must be at least 16 bytes.")
    clean_provider = normalize_webhook_provider(provider)
    clean_event_id = validate_safe_text(event_id, "event_id", max_length=128)
    if not timestamp_header or not signature_header:
        raise WebhookVerificationError("Missing webhook signature or timestamp header.")

    clean_ts = timestamp_header.strip()
    try:
        parsed_ts = int(clean_ts)
    except ValueError as exc:
        raise WebhookVerificationError("Malformed webhook timestamp header.") from exc

    now = int(time.time()) if now_epoch is None else now_epoch
    if abs(now - parsed_ts) > MAX_WEBHOOK_TIMESTAMP_SKEW_SECONDS:
        raise WebhookVerificationError(
            "Webhook timestamp outside allowed 300-second anti-replay window.",
            code="WEBHOOK_TIMESTAMP_EXPIRED",
        )

    provided_sig = signature_header.strip()
    if provided_sig.startswith("sha256="):
        provided_sig = provided_sig[len("sha256=") :]

    expected_sig = compute_webhook_signature(
        secret,
        clean_ts,
        raw_body,
        provider=clean_provider,
        tenant_id=tenant_id,
        event_id=clean_event_id,
    )
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise WebhookVerificationError(
            "Webhook HMAC-SHA256 signature mismatch.",
            code="WEBHOOK_SIGNATURE_MISMATCH",
        )

    claimed = dedup_port.try_claim_event(
        provider=clean_provider,
        event_id=clean_event_id,
        tenant_id=tenant_id,
        received_at_epoch=now,
    )
    return WebhookClaimResult(
        provider=clean_provider,
        event_id=clean_event_id,
        is_first_delivery=claimed,
    )
