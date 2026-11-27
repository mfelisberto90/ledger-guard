"""Bounded in-memory LRU/FIFO map and HMAC-SHA256 multi-bucket rate limiter."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
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

    def values_snapshot(self) -> list[V]:
        with self._lock:
            return list(self._data.values())


@dataclass(slots=True)
class _WindowCounter:
    count: int
    reset_at: float


@dataclass(slots=True)
class _StrikeState:
    strikes: int
    locked_until: float
    expires_at: float


def normalize_rate_limit_ip(client_ip: str) -> str:
    """Normalize client IPs, grouping IPv6 addresses by `/64` prefix to block subnet evasion."""
    clean_ip = client_ip.strip()
    if not clean_ip:
        return "unknown_ip"
    try:
        parsed = ipaddress.ip_address(clean_ip)
    except ValueError:
        return clean_ip
    if parsed.version == 6:
        net = ipaddress.ip_network(f"{parsed}/64", strict=False)
        return str(net)
    return str(parsed)


class HmacMultiBucketRateLimiter:
    """Multi-bucket HMAC-SHA256 rate limiter with tenant-scoped progressive lockouts."""

    def __init__(
        self,
        secret_key: bytes,
        *,
        principal_limit_per_min: int = 5,
        authenticated_principal_limit_per_min: int = 120,
        ip_limit_per_min: int = 60,
        tenant_ip_limit_per_min: int = 120,
        tenant_limit_per_min: int = 240,
        max_entries: int = 10_000,
    ) -> None:
        if len(secret_key) < 16:
            raise ValidationError("Rate limiter HMAC key must be at least 16 bytes.")
        self._key = secret_key
        self._principal_limit = principal_limit_per_min
        self._auth_principal_limit = authenticated_principal_limit_per_min
        self._ip_limit = ip_limit_per_min
        self._tenant_ip_limit = tenant_ip_limit_per_min
        self._tenant_limit = tenant_limit_per_min
        self._lock = threading.RLock()
        self._ip_windows: BoundedMap[str, _WindowCounter] = BoundedMap(max_entries=max_entries)
        self._tenant_windows: BoundedMap[str, _WindowCounter] = BoundedMap(max_entries=max_entries)
        self._principal_windows: BoundedMap[str, _WindowCounter] = BoundedMap(
            max_entries=max_entries
        )
        self._strikes: BoundedMap[str, _StrikeState] = BoundedMap(max_entries=max_entries)

    def derive_bucket_key(self, prefix: str, raw_identifier: str) -> str:
        digest = hmac.new(
            self._key,
            raw_identifier.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{prefix}_{digest}"

    @staticmethod
    def _principal_scope(tenant_id: str | None, principal_id: str) -> str:
        norm_principal = normalize_principal_id(principal_id)
        scope_tid = tenant_id.strip().lower() if tenant_id else "global"
        return f"{scope_tid}:{norm_principal}"

    def stored_keys_snapshot(self) -> list[str]:
        with self._lock:
            return (
                self._ip_windows.keys_snapshot()
                + self._tenant_windows.keys_snapshot()
                + self._principal_windows.keys_snapshot()
                + self._strikes.keys_snapshot()
            )

    @staticmethod
    def _consume_window(
        bucket_map: BoundedMap[str, _WindowCounter],
        bucket_key: str,
        limit: int,
        window_seconds: int,
        now: float,
    ) -> tuple[bool, int]:
        counter = bucket_map.get(bucket_key)
        if counter is None or now >= counter.reset_at:
            bucket_map.set(bucket_key, _WindowCounter(count=1, reset_at=now + window_seconds))
            return True, 0
        if counter.count >= limit:
            retry_after = max(1, int(counter.reset_at - now + 0.999))
            return False, retry_after
        counter.count += 1
        bucket_map.set(bucket_key, counter)
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
        """Evaluate applicable rate-limit buckets in fail-closed order."""
        ts = time.monotonic() if now is None else now
        clean_ip = normalize_rate_limit_ip(client_ip)

        with self._lock:
            # 1. Always enforce active strike lockout for any identified principal
            if principal_id is not None:
                p_scope = self._principal_scope(tenant_id, principal_id)
                strike_key = self.derive_bucket_key("rl_strikes", p_scope)
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
            ip_ok, ip_retry = self._consume_window(
                self._ip_windows, ip_key, self._ip_limit, 60, ts
            )
            if not ip_ok:
                raise RateLimitExceededError(
                    "IP request rate limit exceeded.",
                    retry_after_seconds=ip_retry,
                    bucket="ip",
                )

            # 3. Check Tenant+IP and Tenant-wide buckets
            if tenant_id is not None:
                t_ip_key = self.derive_bucket_key("rl_tenant_ip", f"{tenant_id}:{clean_ip}")
                tip_ok, tip_retry = self._consume_window(
                    self._tenant_windows, t_ip_key, self._tenant_ip_limit, 60, ts
                )
                if not tip_ok:
                    raise RateLimitExceededError(
                        "Tenant IP request rate limit exceeded.",
                        retry_after_seconds=tip_retry,
                        bucket="tenant_ip",
                    )

                t_key = self.derive_bucket_key("rl_tenant", tenant_id)
                t_ok, t_retry = self._consume_window(
                    self._tenant_windows, t_key, self._tenant_limit, 60, ts
                )
                if not t_ok:
                    raise RateLimitExceededError(
                        "Tenant request rate limit exceeded.",
                        retry_after_seconds=t_retry,
                        bucket="tenant",
                    )

            # 4. Check Principal bucket (strict login 5/min + strike escalation, or auth quota)
            if principal_id is not None:
                p_scope = self._principal_scope(tenant_id, principal_id)
                if enforce_principal_bucket:
                    p_key = self.derive_bucket_key("rl_principal", p_scope)
                    p_ok, _ = self._consume_window(
                        self._principal_windows, p_key, self._principal_limit, 60, ts
                    )
                    if not p_ok:
                        strike_key = self.derive_bucket_key("rl_strikes", p_scope)
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
                else:
                    auth_p_key = self.derive_bucket_key("rl_auth_principal", p_scope)
                    auth_ok, auth_retry = self._consume_window(
                        self._principal_windows, auth_p_key, self._auth_principal_limit, 60, ts
                    )
                    if not auth_ok:
                        raise RateLimitExceededError(
                            "Authenticated principal rate limit exceeded.",
                            retry_after_seconds=auth_retry,
                            bucket="principal",
                        )

    def clear_principal_on_login(
        self,
        principal_id: str,
        *,
        tenant_id: str | None = None,
    ) -> None:
        """Reset tenant-scoped principal & strike counters while preserving IP spray bucket."""
        p_scope = self._principal_scope(tenant_id, principal_id)
        with self._lock:
            self._principal_windows.delete(self.derive_bucket_key("rl_principal", p_scope))
            self._strikes.delete(self.derive_bucket_key("rl_strikes", p_scope))
