"""Bounded recursive PII, secret token, JWT, and Luhn-validated PAN log/error redactor."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from ledger_guard.security.rate_limit import BoundedMap

MAX_REDACTION_DEPTH: int = 5
MAX_COLLECTION_ITEMS: int = 50
MAX_MEMO_CACHE_ENTRIES: int = 1_000

_SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "pin",
    "nino",
    "sort_code",
    "account_number",
    "iban",
    "share_code",
    "cvv",
    "card_number",
)

_BEARER_BASIC_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|token|secret|api_key|access_token|refresh_token|pin|nino|"
    r"sort_code|account_number|iban|share_code|cvv)\s*([=:])\s*([^\s,&;\"']+)"
)
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|api_key|secret|access_token|phone|password)=)([^&#\s]+)"
)
_PREFIXED_SECRET_RE = re.compile(
    r"\b(?:sk_live|sk_test|pk_live|pk_test|rk_live|rk_test|whsec|ghp|github_pat|"
    r"xoxb|api_key|sec_key)_[A-Za-z0-9_-]{8,}\b"
)
# Standalone 32..64 hex strings not bordered by UUID hyphens
_HEX_SECRET_RE = re.compile(r"(?<![0-9A-Fa-f-])\b[0-9A-Fa-f]{32,64}\b(?![0-9A-Fa-f-])")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UK_INTL_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}|07\d{3}[\s-]?\d{6})(?!\d)"
)
_CANDIDATE_PAN_RE = re.compile(r"(?<![\dA-Za-z-])(?:\d[ -]?){12,18}\d(?![\dA-Za-z-])")


def passes_luhn_checksum(digits: str) -> bool:
    """Verify whether a 13..19 digit ASCII string satisfies the ISO/IEC 7812 Luhn check."""
    if len(digits) < 13 or len(digits) > 19 or not digits.isdigit():
        return False
    # Reject all-zero strings
    if all(ch == "0" for ch in digits):
        return False

    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        val = ord(ch) - 48
        if idx % 2 == 1:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return (total % 10) == 0


def _replace_luhn_pan(match: re.Match[str]) -> str:
    raw = match.group(0)
    digits_only = "".join(ch for ch in raw if ch.isdigit())
    if passes_luhn_checksum(digits_only):
        return "[REDACTED_PAN]"
    return raw


class Redactor:
    """Bounded recursive string and structured payload sanitizer."""

    def __init__(self, *, max_cache_entries: int = MAX_MEMO_CACHE_ENTRIES) -> None:
        self._cache: BoundedMap[str, str] = BoundedMap(max_entries=max_cache_entries)

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def redact_text(self, value: str) -> str:
        """Apply ordered redaction rules with bounded LRU memoization (`<= 1000` entries)."""
        clean = value.encode("utf-8", "replace").decode("utf-8")
        cached = self._cache.get(clean)
        if cached is not None:
            return cached

        out = _BEARER_BASIC_RE.sub(r"\1 [REDACTED_TOKEN]", clean)
        out = _JWT_RE.sub("[REDACTED_JWT]", out)
        out = _KV_SECRET_RE.sub(r"\1\2[REDACTED_SECRET]", out)
        out = _QUERY_SECRET_RE.sub(r"\1[REDACTED_QUERY]", out)
        out = _PREFIXED_SECRET_RE.sub("[REDACTED_SECRET]", out)
        out = _HEX_SECRET_RE.sub("[REDACTED_HEX]", out)
        out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
        # Run Luhn PAN detection before phone matching so 16-digit card numbers become REDACTED_PAN
        out = _CANDIDATE_PAN_RE.sub(_replace_luhn_pan, out)
        out = _UK_INTL_PHONE_RE.sub("[REDACTED_PHONE]", out)

        self._cache.set(clean, out)
        return out

    def redact_structure(self, data: Any, *, _depth: int = 0) -> Any:
        """Recursively sanitize dicts/sequences enforcing max depth 5 and max 50 items."""
        if _depth >= MAX_REDACTION_DEPTH:
            return "[MAX_DEPTH_TRUNCATED]"

        if isinstance(data, str):
            return self.redact_text(data)

        if isinstance(data, (int, bool)) or data is None:
            return data

        if isinstance(data, Mapping):
            sanitized_map: dict[str, Any] = {}
            for idx, (raw_k, raw_v) in enumerate(data.items()):
                if idx >= MAX_COLLECTION_ITEMS:
                    sanitized_map["__truncated_keys__"] = True
                    break
                key_str = str(raw_k)
                lower_key = key_str.lower()
                if any(marker in lower_key for marker in _SENSITIVE_KEY_SUBSTRINGS):
                    sanitized_map[key_str] = "[REDACTED_FIELD]"
                else:
                    sanitized_map[key_str] = self.redact_structure(raw_v, _depth=_depth + 1)
            return sanitized_map

        if isinstance(data, Sequence) and not isinstance(data, (bytes, bytearray)):
            sanitized_list: list[Any] = []
            for idx, elem in enumerate(data):
                if idx >= MAX_COLLECTION_ITEMS:
                    sanitized_list.append("[MAX_ITEMS_TRUNCATED]")
                    break
                sanitized_list.append(self.redact_structure(elem, _depth=_depth + 1))
            return sanitized_list

        return self.redact_text(str(data))
