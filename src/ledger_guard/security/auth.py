"""Authentication, scrypt password hashing, HMAC bearer tokens, and cookie hygiene."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ledger_guard.domain.errors import AuthenticationError, AuthorizationError, ValidationError
from ledger_guard.domain.margin_gate import PrincipalContext, normalize_principal_id


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * ((4 - (len(encoded) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise AuthenticationError("Malformed token encoding.") from exc


class PasswordHasher:
    """Memory-hard `scrypt` password/PIN hasher with constant-time `compare_digest`."""

    def __init__(self, *, n: int = 16_384, r: int = 8, p: int = 1) -> None:
        self._n = n
        self._r = r
        self._p = p

    def hash_password(self, plain_password: str) -> str:
        if len(plain_password) < 8 or len(plain_password) > 256:
            raise ValidationError("Password length must be between 8 and 256 characters.")
        salt = secrets.token_bytes(16)
        derived = hashlib.scrypt(
            plain_password.encode("utf-8"),
            salt=salt,
            n=self._n,
            r=self._r,
            p=self._p,
            dklen=32,
        )
        return (
            f"scrypt${self._n}${self._r}${self._p}$"
            f"{_b64url_encode(salt)}${_b64url_encode(derived)}"
        )

    def verify_password(self, plain_password: str, encoded_hash: str) -> bool:
        if not plain_password or len(plain_password) > 256:
            return False
        parts = encoded_hash.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        try:
            n_val = int(parts[1])
            r_val = int(parts[2])
            p_val = int(parts[3])
            salt = _b64url_decode(parts[4])
            expected = _b64url_decode(parts[5])
        except (ValueError, AuthenticationError):
            return False
        candidate = hashlib.scrypt(
            plain_password.encode("utf-8"),
            salt=salt,
            n=n_val,
            r=r_val,
            p=p_val,
            dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)


@dataclass(frozen=True, slots=True)
class VerifiedTokenClaims:
    """Server-verified bearer token claims."""

    principal_id: str
    tenant_id: UUID
    issued_at: int
    expires_at: int


class TokenService:
    """HMAC-SHA256 stateless token signer/verifier (`lg1.<claims>.<sig>`)."""

    def __init__(self, signing_key: bytes, *, default_ttl_seconds: int = 3_600) -> None:
        if len(signing_key) < 32:
            raise ValidationError("Token signing key must be at least 32 bytes.")
        self._key = signing_key
        self._default_ttl = default_ttl_seconds

    def issue_token(
        self,
        *,
        principal_id: str,
        tenant_id: UUID,
        now_epoch: int | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        now = int(time.time()) if now_epoch is None else now_epoch
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        payload = {
            "sub": normalize_principal_id(principal_id),
            "tid": str(tenant_id),
            "iat": now,
            "exp": now + ttl,
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded_payload = _b64url_encode(payload_bytes)
        sig = hmac.new(self._key, encoded_payload.encode("ascii"), hashlib.sha256).digest()
        return f"lg1.{encoded_payload}.{_b64url_encode(sig)}"

    def verify_token(self, token: str, *, now_epoch: int | None = None) -> VerifiedTokenClaims:
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != "lg1":
            raise AuthenticationError("Unrecognised bearer token format.")
        encoded_payload, encoded_sig = parts[1], parts[2]
        expected_sig = hmac.new(
            self._key,
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        provided_sig = _b64url_decode(encoded_sig)
        if not hmac.compare_digest(expected_sig, provided_sig):
            raise AuthenticationError("Bearer token signature verification failed.")

        try:
            raw_obj: dict[str, Any] = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
            sub = str(raw_obj["sub"])
            tid = UUID(str(raw_obj["tid"]))
            iat = int(raw_obj["iat"])
            exp = int(raw_obj["exp"])
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AuthenticationError("Invalid bearer token claims payload.") from exc

        now = int(time.time()) if now_epoch is None else now_epoch
        if now >= exp:
            raise AuthenticationError("Bearer token has expired.", code="TOKEN_EXPIRED")

        return VerifiedTokenClaims(
            principal_id=normalize_principal_id(sub),
            tenant_id=tid,
            issued_at=iat,
            expires_at=exp,
        )


@dataclass(frozen=True, slots=True)
class StoredCredentialRecord:
    """Server-side membership and password hash record."""

    principal: PrincipalContext
    password_hash: str | None = None


class MembershipDirectory:
    """Authoritative server-side membership directory (never trusts client claims alone)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[tuple[UUID, str], StoredCredentialRecord] = {}

    def register_member(
        self,
        principal: PrincipalContext,
        *,
        password_hash: str | None = None,
    ) -> None:
        with self._lock:
            self._records[(principal.tenant_id, principal.principal_id)] = StoredCredentialRecord(
                principal=principal,
                password_hash=password_hash,
            )

    def resolve_active_principal(self, tenant_id: UUID, principal_id: str) -> PrincipalContext:
        normalized = normalize_principal_id(principal_id)
        with self._lock:
            record = self._records.get((tenant_id, normalized))
        if record is None or not record.principal.is_active:
            raise AuthorizationError(
                "Active tenant membership not found for authenticated principal.",
                code="INACTIVE_OR_MISSING_MEMBERSHIP",
            )
        return record.principal

    def get_credential_record(
        self,
        tenant_id: UUID,
        principal_id: str,
    ) -> StoredCredentialRecord | None:
        normalized = normalize_principal_id(principal_id)
        with self._lock:
            return self._records.get((tenant_id, normalized))


def build_session_cookie_flags(
    *,
    is_dev: bool,
    request_is_secure: bool,
    x_forwarded_proto: str | None = None,
    force_secure_cookies: bool = False,
) -> dict[str, Any]:
    """Derive fail-safe cookie flags preserving local HTTP tests while enforcing HTTPS in prod."""
    forwarded_https = (x_forwarded_proto or "").strip().lower() == "https"
    secure_flag = (not is_dev) and (
        request_is_secure or forwarded_https or force_secure_cookies
    )
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": secure_flag,
    }
