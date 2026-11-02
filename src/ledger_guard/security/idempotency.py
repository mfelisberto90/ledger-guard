"""Payload-bound SHA-256 idempotency coordinator (`409` on mismatch or concurrent lock)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ledger_guard.domain.errors import ConflictError, ValidationError
from ledger_guard.domain.margin_gate import normalize_principal_id
from ledger_guard.ports import IdempotencyPort

_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")


def validate_idempotency_key(raw_key: str | None) -> str:
    """Validate that `Idempotency-Key` is present and bounded (8..128 URL-safe chars)."""
    if raw_key is None:
        raise ValidationError(
            "Missing required 'Idempotency-Key' header for state-mutating request.",
            code="IDEMPOTENCY_KEY_REQUIRED",
        )
    cleaned = raw_key.strip()
    if not _IDEMPOTENCY_KEY_RE.fullmatch(cleaned):
        raise ValidationError(
            "Idempotency-Key must be 8..128 characters matching [A-Za-z0-9_.:-].",
            code="INVALID_IDEMPOTENCY_KEY",
        )
    return cleaned


def canonical_payload_sha256(payload: Mapping[str, Any]) -> str:
    """Compute a deterministic key-sorted JSON SHA-256 digest."""
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class IdempotencyOutcome:
    """Outcome of executing or replaying an idempotent mutation."""

    status_code: int
    body: dict[str, Any]
    replayed: bool


class IdempotencyCoordinator:
    """Scopes every idempotency record to `(tenant_id, principal_id, action, key)`."""

    def __init__(self, store: IdempotencyPort) -> None:
        self._store = store

    @staticmethod
    def build_scope_key(
        *,
        tenant_id: UUID,
        principal_id: str,
        action: str,
        idempotency_key: str,
    ) -> str:
        clean_key = validate_idempotency_key(idempotency_key)
        norm_principal = normalize_principal_id(principal_id)
        return f"idempotency:{tenant_id}:{norm_principal}:{action}:{clean_key}"

    def execute(
        self,
        *,
        tenant_id: UUID,
        principal_id: str,
        action: str,
        idempotency_key: str | None,
        payload: Mapping[str, Any],
        handler: Callable[[], tuple[int, dict[str, Any]]],
    ) -> IdempotencyOutcome:
        """Atomically execute `handler` once or replay cached response on exact hash match."""
        clean_key = validate_idempotency_key(idempotency_key)
        scope_key = self.build_scope_key(
            tenant_id=tenant_id,
            principal_id=principal_id,
            action=action,
            idempotency_key=clean_key,
        )
        fingerprint = canonical_payload_sha256(payload)

        existing = self._store.acquire_or_get(scope_key, fingerprint)
        if existing is not None:
            if existing.payload_sha256 != fingerprint:
                raise ConflictError(
                    "Idempotency-Key was already used with a different request payload.",
                    code="IDEMPOTENCY_PAYLOAD_MISMATCH",
                )
            if existing.state == "in_flight":
                raise ConflictError(
                    "Concurrent request with identical Idempotency-Key is currently in flight.",
                    code="IDEMPOTENCY_IN_FLIGHT",
                )
            if existing.status_code is None or existing.response_body is None:
                raise ConflictError(
                    "Corrupted idempotency state detected.",
                    code="IDEMPOTENCY_STATE_INVALID",
                )
            return IdempotencyOutcome(
                status_code=existing.status_code,
                body=existing.response_body,
                replayed=True,
            )

        try:
            status_code, response_body = handler()
        except Exception:
            self._store.release_in_flight(scope_key)
            raise

        self._store.mark_completed(scope_key, fingerprint, status_code, response_body)
        return IdempotencyOutcome(
            status_code=status_code,
            body=response_body,
            replayed=False,
        )
