"""Pure ASGI `A+` security headers, per-request CSP nonce, and CGNAT-safe honeypot guard."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from typing import Any

from ledger_guard.domain.errors import AuthenticationError, AuthorizationError, ValidationError
from ledger_guard.security.auth import MembershipDirectory, TokenService
from ledger_guard.security.rate_limit import BoundedMap

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

ROBOTS_TXT_CONTENT: str = "User-agent: *\nAllow: /\n"
SCANNER_BAN_SECONDS: int = 900

CANARY_TRAP_PATHS: frozenset[str] = frozenset(
    {
        "/.env",
        "/.git/config",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/actuator/env",
    }
)

OFFENSIVE_SCANNER_SIGNATURES: tuple[str, ...] = (
    "sqlmap",
    "nikto",
    "nuclei",
    "acunetix",
    "nessus",
    "masscan",
    "zgrab",
    "dirbuster",
    "gobuster",
    "ffuf",
    "feroxbuster",
    "wpscan",
    "havij",
)

STRIPPED_RESPONSE_HEADERS: frozenset[bytes] = frozenset(
    {
        b"server",
        b"x-powered-by",
        b"x-generator",
        b"x-aspnet-version",
    }
)


def generate_csp_nonce() -> str:
    """Generate a fresh 18-byte (144-bit) cryptographic base64 nonce per HTTP request."""
    return base64.b64encode(secrets.token_bytes(18)).decode("ascii")


def build_csp_header(nonce: str) -> str:
    """Construct strict Mozilla Observatory `A+` Content-Security-Policy header."""
    return (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data:; "
        f"media-src 'self' data: blob:; "
        f"font-src 'self' data:; "
        f"frame-src 'self'; "
        f"connect-src 'self'; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none'"
    )


def parse_trusted_proxy_cidrs(cidrs: Sequence[str]) -> tuple[IPNetwork, ...]:
    """Parse explicit trusted proxy CIDR blocks, rejecting wildcard `*`."""
    parsed: list[IPNetwork] = []
    for raw in cidrs:
        cleaned = raw.strip()
        if cleaned == "*" or not cleaned:
            raise ValidationError("Wildcard or empty trusted proxy CIDR is forbidden.")
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise ValidationError(f"Invalid trusted proxy CIDR '{cleaned}'.") from exc
        parsed.append(net)
    return tuple(parsed)


def resolve_client_ip(
    *,
    peer_ip: str,
    x_forwarded_for: str | None,
    trusted_proxy_cidrs: Sequence[IPNetwork],
) -> str:
    """Honor `X-Forwarded-For` strictly when direct peer IP matches `trusted_proxy_cidrs`."""
    clean_peer = peer_ip.strip() or "127.0.0.1"
    try:
        peer_addr = ipaddress.ip_address(clean_peer)
    except ValueError:
        return "127.0.0.1"

    is_trusted_proxy = any(peer_addr in cidr for cidr in trusted_proxy_cidrs)
    if not is_trusted_proxy or not x_forwarded_for:
        return str(peer_addr)

    hops = [part.strip() for part in x_forwarded_for.split(",") if part.strip()]
    for candidate in reversed(hops):
        try:
            cand_addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not any(cand_addr in cidr for cidr in trusted_proxy_cidrs):
            return str(cand_addr)
    return str(peer_addr)


class CgnatSafeScannerGuard:
    """15-minute honeypot & offensive UA ban exempting authenticated principals & webhooks."""

    def __init__(self, secret_key: bytes, *, max_entries: int = 10_000) -> None:
        if len(secret_key) < 16:
            raise ValidationError("Scanner guard HMAC key must be at least 16 bytes.")
        self._key = secret_key
        self._banned_until: BoundedMap[str, float] = BoundedMap(max_entries=max_entries)

    def _ip_digest(self, client_ip: str) -> str:
        return hmac.new(self._key, client_ip.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def is_exempt_route(path: str) -> bool:
        return path in {"/robots.txt", "/healthz"} or path.startswith("/v1/webhooks/")

    def evaluate(
        self,
        *,
        path: str,
        user_agent: str,
        client_ip: str,
        is_authenticated_principal: bool,
        now: float | None = None,
    ) -> bool:
        """Return `True` if request is allowed, `False` if blocked by scanner guard."""
        if self.is_exempt_route(path) or is_authenticated_principal:
            return True

        ts = time.monotonic() if now is None else now
        digest = self._ip_digest(client_ip)

        banned_until = self._banned_until.get(digest)
        if banned_until is not None and ts < banned_until:
            return False

        normalized_path = path.rstrip("/") or "/"
        lower_ua = user_agent.lower()
        triggered_trap = normalized_path in CANARY_TRAP_PATHS or path in CANARY_TRAP_PATHS
        triggered_ua = any(sig in lower_ua for sig in OFFENSIVE_SCANNER_SIGNATURES)

        if triggered_trap or triggered_ua:
            self._banned_until.set(digest, ts + SCANNER_BAN_SECONDS)
            return False

        return True


def _extract_header_map(raw_headers: Sequence[tuple[bytes, bytes]]) -> dict[bytes, str]:
    extracted: dict[bytes, str] = {}
    for k, v in raw_headers:
        lower_k = k.lower()
        if lower_k not in extracted:
            extracted[lower_k] = v.decode("latin-1")
    return extracted


def _build_security_headers(path: str, nonce: str) -> list[tuple[bytes, bytes]]:
    headers: list[tuple[bytes, bytes]] = [
        (b"content-security-policy", build_csp_header(nonce).encode("ascii")),
        (
            b"strict-transport-security",
            b"max-age=31536000; includeSubDomains; preload",
        ),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"cross-origin-resource-policy", b"same-origin"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"x-permitted-cross-domain-policies", b"none"),
        (b"referrer-policy", b"strict-origin-when-cross-origin"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
        (b"cache-control", b"no-store, private"),
    ]
    if path != "/robots.txt":
        headers.append((b"x-robots-tag", b"noindex, nofollow, noarchive"))
    return headers


class SecurityDefenseMiddleware:
    """Pure ASGI edge defence middleware preserving raw request streams for webhooks."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        scanner_guard: CgnatSafeScannerGuard,
        token_service: TokenService,
        memberships: MembershipDirectory,
        trusted_proxy_cidrs: Sequence[IPNetwork] = (),
    ) -> None:
        self._app = app
        self._scanner_guard = scanner_guard
        self._token_service = token_service
        self._memberships = memberships
        self._trusted_proxies = tuple(trusted_proxy_cidrs)

    def _has_verified_principal(self, auth_header: str | None) -> bool:
        if not auth_header:
            return False
        parts = auth_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        try:
            claims = self._token_service.verify_token(parts[1])
            self._memberships.resolve_active_principal(claims.tenant_id, claims.principal_id)
            return True
        except (AuthenticationError, AuthorizationError):
            return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        path = str(scope.get("path", "/"))
        raw_headers: Sequence[tuple[bytes, bytes]] = scope.get("headers", ())
        header_map = _extract_header_map(raw_headers)

        client_tuple = scope.get("client")
        peer_ip = str(client_tuple[0]) if client_tuple else "127.0.0.1"
        client_ip = resolve_client_ip(
            peer_ip=peer_ip,
            x_forwarded_for=header_map.get(b"x-forwarded-for"),
            trusted_proxy_cidrs=self._trusted_proxies,
        )

        nonce = generate_csp_nonce()
        state: dict[str, Any] = scope.setdefault("state", {})
        state["csp_nonce"] = nonce
        state["client_ip"] = client_ip

        is_authenticated = self._has_verified_principal(header_map.get(b"authorization"))
        allowed = self._scanner_guard.evaluate(
            path=path,
            user_agent=header_map.get(b"user-agent", ""),
            client_ip=client_ip,
            is_authenticated_principal=is_authenticated,
        )

        if not allowed:
            body_bytes = json.dumps(
                {
                    "error": {
                        "code": "SCANNER_IP_BANNED",
                        "message": "Request blocked by edge scanner defence.",
                    }
                }
            ).encode("utf-8")
            sec_headers = _build_security_headers(path, nonce)
            sec_headers.extend(
                [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode("ascii")),
                ]
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": sec_headers,
                }
            )
            await send({"type": "http.response.body", "body": body_bytes})
            return

        stateless_public_endpoint = path in {"/robots.txt", "/healthz"}

        async def send_with_hardened_headers(message: Message) -> None:
            if message.get("type") == "http.response.start":
                existing_headers: Sequence[tuple[bytes, bytes]] = message.get("headers", ())
                filtered: list[tuple[bytes, bytes]] = []
                present_names: set[bytes] = set()
                for h_name, h_val in existing_headers:
                    lower_name = h_name.lower()
                    if lower_name in STRIPPED_RESPONSE_HEADERS:
                        continue
                    if stateless_public_endpoint and lower_name == b"set-cookie":
                        continue
                    filtered.append((h_name, h_val))
                    present_names.add(lower_name)

                for sec_name, sec_val in _build_security_headers(path, nonce):
                    if sec_name not in present_names:
                        filtered.append((sec_name, sec_val))
                message["headers"] = filtered
            await send(message)

        await self._app(scope, receive, send_with_hardened_headers)
