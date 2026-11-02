"""Raw-bytes HMAC-SHA256 webhook verification (`<= 300s`) and TOCTOU pre-insertion."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from uuid import UUID

from ledger_guard.domain.errors import ValidationError, WebhookVerificationError
from ledger_guard.ports import WebhookDedupPort

MAX_WEBHOOK_TIMESTAMP_SKEW_SECONDS: int = 300


@dataclass(frozen=True, slots=True)
class WebhookClaimResult:
    """Result of verifying a signed webhook and claiming its `event_id`."""

    provider: str
    event_id: str
    is_first_delivery: bool


def compute_webhook_signature(secret: bytes, timestamp: str, raw_body: bytes) -> str:
    """Compute canonical `HMAC-SHA256(secret, f'{timestamp}.' + raw_body)` hex digest."""
    if len(secret) < 16:
        raise ValidationError("Webhook signing secret must be at least 16 bytes.")
    signed_message = timestamp.encode("ascii") + b"." + raw_body
    return hmac.new(secret, signed_message, hashlib.sha256).hexdigest()


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
    """Verify raw-bytes HMAC signature, enforce 300s window, and pre-insert `event_id`."""
    if len(secret) < 16:
        raise ValidationError("Webhook signing secret must be at least 16 bytes.")
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

    expected_sig = compute_webhook_signature(secret, clean_ts, raw_body)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise WebhookVerificationError(
            "Webhook HMAC-SHA256 signature mismatch.",
            code="WEBHOOK_SIGNATURE_MISMATCH",
        )

    clean_provider = provider.strip().lower()
    clean_event_id = event_id.strip()
    if not clean_provider or not clean_event_id or len(clean_event_id) > 128:
        raise ValidationError("Webhook provider and bounded event_id are required.")

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
