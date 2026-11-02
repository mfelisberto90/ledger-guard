"""Bounded in-memory LRU/FIFO map and HMAC-SHA256 multi-bucket rate limiter."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from ledger_guard.domain.errors import RateLimitExceededError, ValidationError
from ledger_guard.domain.margin_gate import normalize_principal_id

LOCKOUT_STRIKE_SCHEDULE_SECONDS: tuple[int, ...] = (60, 300, 900, 3_600, 86_400)
STRIKE_RETENTION_SECONDS: int = 86_400


class BoundedMap[K, V]:
    """Fixed-capacity thread-safe dictionary preventing memory-exhaustion DoS."""

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            raise ValidationError("BoundedMap max_entries must be >= 1.")
        self._max_entries = max_entries
        self._lock = threading.RLock()
        self._data: OrderedDict[K, V] = OrderedDict()

    @property
    def max_entries(self) -> int:
        return self._max_entries

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def get(self, key: K) -> V | None:
        with self._lock:
            if key not in self._data:
                return None
            self._data.move_to_end(key)
            return self._data[key]

    def set(self, key: K, value: V) -> None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self._data[key] = value
                return
            if len(self._data) >= self._max_entries:
                self._data.popitem(last=False)
            self._data[key] = value

    def delete(self, key: K) -> None:
        with self._lock:
            self._data.pop(key, None)

    def keys_snapshot(self) -> list[K]:
        with self._lock:
            return list(self._data.keys())


@dataclass(slots=True)
class _WindowCounter:
    count: int
    reset_at: float


@dataclass(slots=True)
class _StrikeState:
    strikes: int
    locked_until: float
    expires_at: float


class HmacMultiBucketRateLimiter:
    """Multi-bucket HMAC-SHA256 rate limiter with progressive principal strike lockouts.

    - Keys are hashed with `HMAC-SHA256(secret_key, raw)` so plain emails, user IDs,
      and client IPs are never stored in memory or cache snapshots.
    - Buckets:
        * `principal`: default `5 / 60s` + progressive lockout (`60s..86400s`)
        * `ip`: default `60 / 60s`
        * `tenant_ip`: default `120 / 60s`
    - `clear_principal_on_login` resets ONLY the principal & strike buckets, strictly
      preserving the `ip` bucket to block distributed-account password spraying (`AUTH-ABUSE-02`).
    """

    def __init__(
        self,
        secret_key: bytes,
        *,
        principal_limit_per_min: int = 5,
        ip_limit_per_min: int = 60,
        tenant_ip_limit_per_min: int = 120,
        max_entries: int = 10_000,
    ) -> None:
        if len(secret_key) < 16:
            raise ValidationError("Rate limiter HMAC key must be at least 16 bytes.")
        self._key = secret_key
        self._principal_limit = principal_limit_per_min
        self._ip_limit = ip_limit_per_min
        self._tenant_ip_limit = tenant_ip_limit_per_min
        self._lock = threading.RLock()
        self._windows: BoundedMap[str, _WindowCounter] = BoundedMap(max_entries=max_entries)
        self._strikes: BoundedMap[str, _StrikeState] = BoundedMap(max_entries=max_entries)

    def derive_bucket_key(self, prefix: str, raw_identifier: str) -> str:
        digest = hmac.new(
            self._key,
            raw_identifier.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{prefix}_{digest}"

    def stored_keys_snapshot(self) -> list[str]:
        return self._windows.keys_snapshot() + self._strikes.keys_snapshot()

    def _consume_window(
        self,
        bucket_key: str,
        limit: int,
        window_seconds: int,
        now: float,
    ) -> tuple[bool, int]:
        counter = self._windows.get(bucket_key)
        if counter is None or now >= counter.reset_at:
            self._windows.set(bucket_key, _WindowCounter(count=1, reset_at=now + window_seconds))
            return True, 0
        if counter.count >= limit:
            retry_after = max(1, int(counter.reset_at - now + 0.999))
            return False, retry_after
        counter.count += 1
        self._windows.set(bucket_key, counter)
        return True, 0

    def check_request(
        self,
        *,
        client_ip: str,
        principal_id: str | None = None,
        tenant_id: str | None = None,
        enforce_principal_bucket: bool = True,
        now: float | None = None,
    ) -> None:
        """Evaluate applicable rate-limit buckets in canonical order."""
        ts = time.monotonic() if now is None else now
        clean_ip = client_ip.strip() or "unknown_ip"

        with self._lock:
            # 1. Check active strike lockout on principal first
            if enforce_principal_bucket and principal_id is not None:
                norm_principal = normalize_principal_id(principal_id)
                strike_key = self.derive_bucket_key("rl_strikes", norm_principal)
                strike_state = self._strikes.get(strike_key)
                if strike_state is not None:
                    if ts >= strike_state.expires_at:
                        self._strikes.delete(strike_key)
                    elif ts < strike_state.locked_until:
                        retry_after = max(1, int(strike_state.locked_until - ts + 0.999))
                        raise RateLimitExceededError(
                            "Principal temporarily locked out due to repeated rate-limit strikes.",
                            retry_after_seconds=retry_after,
                            bucket="principal_lockout",
                        )

            # 2. Check IP bucket (60/min)
            ip_key = self.derive_bucket_key("rl_ip", clean_ip)
            ip_ok, ip_retry = self._consume_window(ip_key, self._ip_limit, 60, ts)
            if not ip_ok:
                raise RateLimitExceededError(
                    "IP request rate limit exceeded.",
                    retry_after_seconds=ip_retry,
                    bucket="ip",
                )

            # 3. Check Tenant+IP bucket (120/min)
            if tenant_id is not None:
                t_ip_key = self.derive_bucket_key("rl_tenant_ip", f"{tenant_id}:{clean_ip}")
                tip_ok, tip_retry = self._consume_window(
                    t_ip_key, self._tenant_ip_limit, 60, ts
                )
                if not tip_ok:
                    raise RateLimitExceededError(
                        "Tenant IP request rate limit exceeded.",
                        retry_after_seconds=tip_retry,
                        bucket="tenant_ip",
                    )

            # 4. Check Principal bucket (5/min) + escalate exponential strike lockout
            if enforce_principal_bucket and principal_id is not None:
                norm_principal = normalize_principal_id(principal_id)
                p_key = self.derive_bucket_key("rl_principal", norm_principal)
                p_ok, _ = self._consume_window(p_key, self._principal_limit, 60, ts)
                if not p_ok:
                    strike_key = self.derive_bucket_key("rl_strikes", norm_principal)
                    existing = self._strikes.get(strike_key)
                    if existing is None or ts >= existing.expires_at:
                        next_strikes = 1
                    else:
                        next_strikes = existing.strikes + 1
                    schedule_idx = min(
                        next_strikes - 1, len(LOCKOUT_STRIKE_SCHEDULE_SECONDS) - 1
                    )
                    lockout_secs = LOCKOUT_STRIKE_SCHEDULE_SECONDS[schedule_idx]
                    self._strikes.set(
                        strike_key,
                        _StrikeState(
                            strikes=next_strikes,
                            locked_until=ts + lockout_secs,
                            expires_at=ts + STRIKE_RETENTION_SECONDS,
                        ),
                    )
                    raise RateLimitExceededError(
                        "Principal rate limit exceeded; progressive lockout engaged.",
                        retry_after_seconds=lockout_secs,
                        bucket="principal",
                    )

    def clear_principal_on_login(self, principal_id: str) -> None:
        """Reset principal & strike counters after valid login while preserving IP bucket."""
        norm_principal = normalize_principal_id(principal_id)
        with self._lock:
            self._windows.delete(self.derive_bucket_key("rl_principal", norm_principal))
            self._strikes.delete(self.derive_bucket_key("rl_strikes", norm_principal))
