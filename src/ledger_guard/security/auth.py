"""Authentication, scrypt password hashing, and HMAC bearer tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ledger_guard.domain.errors import AuthenticationError, AuthorizationError, ValidationError
from ledger_guard.domain.margin_gate import PrincipalContext, normalize_principal_id
from ledger_guard.domain.money import require_strict_int, validate_safe_text
from ledger_guard.security.rate_limit import BoundedMap

MAX_TOKEN_LENGTH: int = 4_096
MAX_TOKEN_TTL_SECONDS: int = 86_400
MAX_CLOCK_SKEW_SECONDS: int = 60
_SCRYPT_MAXMEM: int = 67_108_864


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * ((4 - (len(encoded) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise AuthenticationError("Malformed token encoding.") from exc


class PasswordHasher:
    """Memory-hard `scrypt` password/PIN hasher with constant-time timing hygiene."""

    def __init__(self, *, n: int = 16_384, r: int = 8, p: int = 1) -> None:
        self._n = n
        self._r = r
        self._p = p
        self._dummy_hash = self.hash_password("LedgerGuardDummyConstantTimeCheck!0")

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
            maxmem=_SCRYPT_MAXMEM,
        )
        return (
            f"scrypt${self._n}${self._r}${self._p}$"
            f"{_b64url_encode(salt)}${_b64url_encode(derived)}"
        )

    def verify_dummy(self, plain_password: str) -> bool:
        """Burn constant `scrypt` verification time when a login account does not exist."""
        self.verify_password(plain_password or "dummy-padding-check", self._dummy_hash)
        return False

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
            if (
                n_val < 4_096
                or n_val > 65_536
                or (n_val & (n_val - 1)) != 0
                or r_val < 1
                or r_val > 16
                or p_val < 1
                or p_val > 4
            ):
                return False
            salt = _b64url_decode(parts[4])
            expected = _b64url_decode(parts[5])
            if len(salt) != 16 or len(expected) != 32:
                return False
            candidate = hashlib.scrypt(
                plain_password.encode("utf-8"),
                salt=salt,
                n=n_val,
                r=r_val,
                p=p_val,
                dklen=32,
                maxmem=_SCRYPT_MAXMEM,
            )
        except (ValueError, MemoryError, AuthenticationError):
            return False
        return hmac.compare_digest(candidate, expected)


@dataclass(frozen=True, slots=True)
class VerifiedTokenClaims:
    """Server-verified bearer token claims with optional delegated capability scope."""

    principal_id: str
    tenant_id: UUID
    issued_at: int
    expires_at: int
    jti: str
    scoped_capabilities: frozenset[str] | None = None


class TokenService:
    """HMAC-SHA256 stateless token signer/verifier with `jti` revocation (`lg1.<claims>.<sig>`)."""

    def __init__(
        self,
        signing_key: bytes,
        *,
        default_ttl_seconds: int = 3_600,
        max_revoked_jtis: int = 10_000,
    ) -> None:
        if len(signing_key) < 32:
            raise ValidationError("Token signing key must be at least 32 bytes.")
        self._key = signing_key
        self._default_ttl = default_ttl_seconds
        self._revoked_jtis: BoundedMap[str, int] = BoundedMap(max_entries=max_revoked_jtis)

    def revoke_jti(self, jti: str, expires_at: int = 0) -> None:
        clean_jti = validate_safe_text(jti, "jti", max_length=64)
        self._revoked_jtis.set(clean_jti, expires_at)

    def issue_token(
        self,
        *,
        principal_id: str,
        tenant_id: UUID,
        now_epoch: int | None = None,
        ttl_seconds: int | None = None,
        scoped_capabilities: Collection[str] | None = None,
    ) -> str:
        now = int(time.time()) if now_epoch is None else require_strict_int(now_epoch, "now_epoch")
        ttl = (
            self._default_ttl
            if ttl_seconds is None
            else require_strict_int(ttl_seconds, "ttl_seconds")
        )
        if ttl <= 0 or ttl > MAX_TOKEN_TTL_SECONDS:
            raise ValidationError(
                f"Token ttl_seconds must be between 1 and {MAX_TOKEN_TTL_SECONDS}."
            )

        payload: dict[str, Any] = {
            "sub": normalize_principal_id(principal_id),
            "tid": str(tenant_id),
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_hex(8),
        }
        if scoped_capabilities is not None:
            normalized_scp = sorted(
                {
                    validate_safe_text(cap, "scoped_capability", max_length=64)
                    for cap in scoped_capabilities
                }
            )
            if not normalized_scp:
                raise ValidationError(
                    "Delegated token scoped_capabilities must contain at least one capability."
                )
            payload["scp"] = normalized_scp

        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded_payload = _b64url_encode(payload_bytes)
        sig = hmac.new(self._key, encoded_payload.encode("ascii"), hashlib.sha256).digest()
        return f"lg1.{encoded_payload}.{_b64url_encode(sig)}"

    def verify_token(self, token: str, *, now_epoch: int | None = None) -> VerifiedTokenClaims:
        stripped = token.strip()
        if not stripped or len(stripped) > MAX_TOKEN_LENGTH:
            raise AuthenticationError("Unrecognised or oversized bearer token.")
        parts = stripped.split(".")
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
            raw_obj = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
            if not isinstance(raw_obj, dict):
                raise ValueError("Token payload must be an object.")
            sub = normalize_principal_id(str(raw_obj["sub"]))
            tid = UUID(str(raw_obj["tid"]))
            raw_iat = raw_obj["iat"]
            raw_exp = raw_obj["exp"]
            if (
                isinstance(raw_iat, bool)
                or isinstance(raw_exp, bool)
                or not isinstance(raw_iat, int)
                or not isinstance(raw_exp, int)
            ):
                raise ValueError("Token iat/exp must be strict integers.")
            jti = str(raw_obj.get("jti", ""))
            parsed_scp: frozenset[str] | None = None
            if "scp" in raw_obj:
                raw_scp = raw_obj["scp"]
                if not isinstance(raw_scp, list) or not raw_scp:
                    raise ValueError("Invalid scp claim list.")
                validated_items: set[str] = set()
                for item in raw_scp:
                    if not isinstance(item, str):
                        raise ValueError("Non-string capability in scp claim.")
                    validated_items.add(validate_safe_text(item, "scp", max_length=64))
                parsed_scp = frozenset(validated_items)
        except (KeyError, ValueError, TypeError, ValidationError, json.JSONDecodeError) as exc:
            raise AuthenticationError("Invalid bearer token claims payload.") from exc

        now = int(time.time()) if now_epoch is None else now_epoch
        if raw_exp <= raw_iat or (raw_exp - raw_iat) > MAX_TOKEN_TTL_SECONDS:
            raise AuthenticationError("Invalid bearer token lifetime window.")
        if raw_iat > now + MAX_CLOCK_SKEW_SECONDS:
            raise AuthenticationError("Bearer token issued in the future.")
        if now >= raw_exp:
            raise AuthenticationError("Bearer token has expired.", code="TOKEN_EXPIRED")
        if jti and self._revoked_jtis.get(jti) is not None:
            raise AuthenticationError("Bearer token has been revoked.", code="TOKEN_REVOKED")

        return VerifiedTokenClaims(
            principal_id=sub,
            tenant_id=tid,
            issued_at=raw_iat,
            expires_at=raw_exp,
            jti=jti,
            scoped_capabilities=parsed_scp,
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

    def resolve_scoped_principal(
        self,
        tenant_id: UUID,
        principal_id: str,
        scoped_capabilities: frozenset[str] | None = None,
    ) -> PrincipalContext:
        """Intersect active membership capabilities with delegated token scopes fail-closed."""
        member = self.resolve_active_principal(tenant_id, principal_id)
        if scoped_capabilities is None:
            return member
        effective_capabilities = member.capabilities & scoped_capabilities
        return PrincipalContext(
            principal_id=member.principal_id,
            tenant_id=member.tenant_id,
            role=member.role,
            capabilities=effective_capabilities,
            is_active=member.is_active,
        )

    def get_credential_record(
        self,
        tenant_id: UUID,
        principal_id: str,
    ) -> StoredCredentialRecord | None:
        normalized = normalize_principal_id(principal_id)
        with self._lock:
            return self._records.get((tenant_id, normalized))
