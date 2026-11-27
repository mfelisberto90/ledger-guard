# Security policy and threat model

## Reporting a vulnerability

Please do **not** open public GitHub issues for suspected security vulnerabilities. Use [GitHub Private Vulnerability Reporting](https://github.com/mfelisberto90/ledger-guard/security/advisories/new) on this repository so we can validate, patch, and coordinate disclosure safely.

We aim to acknowledge reports within 48 hours and publish a regression test alongside every security fix.

## Supported versions

| Version | Python runtime | Supported |
| :--- | :--- | :--- |
| `0.2.x` | Python 3.12+ | Yes |
| `0.1.x` | Python 3.12+ | Security fixes only |

## Trust boundaries and abuse cases

LedgerGuard treats every inbound HTTP caller, browser client, webhook sender, and MCP-connected AI agent as untrusted until verified server-side:

1. **Cross-tenant IDOR & prompt injection**: Tenant scope (`tenant_id`) is resolved strictly from verified server tokens and active `tenant_memberships`, backed by PostgreSQL 17 `ENABLE` + `FORCE ROW LEVEL SECURITY` under a `NOBYPASSRLS` runtime role (`app_runtime`). Any client-supplied `tenant_id` in HTTP payloads or MCP tool arguments is rejected (`CLIENT_TENANT_OVERRIDE_FORBIDDEN`), unknown MCP arguments fail closed (`UNKNOWN_TOOL_ARGUMENTS`), and cross-tenant UUID lookups return `404`.
2. **Least-privilege agent token delegation (`POST /v1/auth/delegate-token`)**: Principals connecting AI agents can mint short-lived (`60..3600s`) attenuated `lg1` tokens carrying an explicit `scp` capability list. Every request computes `member.capabilities & token.scp` fail-closed so an agent token can never escalate beyond live server-side membership permissions.
3. **Confidential valuation leakage**: Commercial catalog reads (`CatalogPricingPort`) contain zero supplier cost columns. `project_order_for_principal` strips `unit_cost_minor`, `total_cost_minor`, `margin_minor`, `margin_bps`, and statistical cost steps whenever a principal lacks `valuation:cost:read` or `orders:margin:read`, while still enforcing `margin_floor` server-side.
4. **Four-eyes separation of duties (`orders:margin:approve`)**: Margin approvals normalise `principal_id` (`strip().lower()`) and block self-approval by either `order.created_by` or `order.last_amended_by`. Lowering unit prices or increasing discounts on a confirmed order increments `pricing_version` and returns sub-floor orders to `pending_approval`.
5. **Control character & Unicode Bidi spoofing**: `validate_safe_text` rejects ASCII control bytes (`< 0x20`, `0x7F`) and invisible bidirectional override codepoints (`U+202A..U+202E`, `U+2066..U+2069`, `U+200E`, `U+200F`, `U+061C`) across `customer_ref`, `sku`, `description`, `principal_id`, and `reason`.
6. **Password spraying, replay & edge defences**: `HmacMultiBucketRateLimiter` hashes identifiers with `HMAC-SHA256` inside fixed-capacity `BoundedMap` structures (`10,000` max keys) and preserves the `ip` (`60/min`) bucket across logins. State mutations enforce `SHA-256` payload-bound idempotency (`409` on mismatch) and optimistic `expected_version` checks. Pure ASGI middleware emits per-request 18-byte CSP nonces with `style-src-attr 'none'`, CGNAT-safe honeypots, Unicode full-width CSV formula guards, and recursive Luhn PAN redaction.

## Data classification tiers

| Tier | Examples in LedgerGuard | Handling standard |
| :--- | :--- | :--- |
| `public` | `/robots.txt` (`Allow: /` only), `/healthz`, `stdio` demo SKUs | Zero `Set-Cookie` headers, zero internal path `Disallow:` leaks |
| `internal` | Order status, readiness gate codes, SKU codes, `scp` scope list | Tenant-scoped via `FORCE RLS`, `Cache-Control: no-store, private` |
| `personal` | Normalised `principal_id`, client IP | Hashed with `HMAC-SHA256` in rate-limit/scanner buckets; redacted in logs |
| `sensitive` | `unit_cost_minor`, `total_cost_minor`, `margin_bps` | Stripped unless principal holds `valuation:cost:read` / `orders:margin:read` |
| `highly_sensitive` | Password hashes (`scrypt`), signing keys, webhook secrets, Luhn PANs | Constant-time `hmac.compare_digest`; never logged or returned |

## Automated CI invariant gate

Every pull request runs `scripts/security-lint.py --self-test` (9 architectural and SQL `FORCE RLS` rules + SARIF 2.1.0 output), `pip-audit`, `ruff`, `mypy --strict`, native `stdio` MCP handshake checks, and `pytest` against a live `postgres:17-alpine` service container under `SET ROLE app_runtime`.
