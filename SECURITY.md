# Security Policy & Threat Model

## Reporting a Vulnerability

Please do **not** open public GitHub issues for suspected security vulnerabilities. Use [GitHub Private Vulnerability Reporting](https://github.com/mfelisberto90/ledger-guard/security/advisories/new) on this repository so we can validate, patch, and coordinate disclosure safely.

We aim to acknowledge reports within 48 hours and publish a regression test alongside every security fix.

## Supported Versions

| Version | Python Runtime | Supported |
| :--- | :--- | :--- |
| `0.1.x` | Python 3.12+ | Yes |

## Trust Boundaries & Abuse Cases

LedgerGuard treats every inbound HTTP caller, browser client, webhook sender, and MCP-connected AI agent as untrusted until verified server-side:

1. **Cross-Tenant IDOR & Prompt Injection**: Tenant scope (`tenant_id`) is resolved strictly from verified server tokens and active `tenant_memberships`, backed by PostgreSQL 17 `ENABLE` + `FORCE ROW LEVEL SECURITY` under a `NOBYPASSRLS` runtime role (`app_runtime`). Any client-supplied `tenant_id` in HTTP payloads or MCP tool arguments is rejected, and cross-tenant UUID lookups fail closed with `404`.
2. **Confidential Valuation Leakage**: Commercial catalog reads (`CatalogPricingPort`) contain zero supplier cost columns. `project_order_for_principal` strips `unit_cost_minor`, `total_cost_minor`, `margin_minor`, `margin_bps`, and statistical cost steps whenever a principal lacks `valuation:cost:read` or `orders:margin:read`, while still enforcing `margin_floor` server-side.
3. **Four-Eyes Separation of Duties (`orders:margin:approve`)**: Margin approvals normalise `principal_id` (`strip().lower()`) and block self-approval by either `order.created_by` or `order.last_amended_by`. Lowering unit prices or increasing discounts on a confirmed order increments `pricing_version` and returns sub-floor orders to `pending_approval`.
4. **Password Spraying & Memory DoS**: `HmacMultiBucketRateLimiter` hashes identifiers with `HMAC-SHA256` inside fixed-capacity `BoundedMap` structures (`10,000` max keys). Valid logins clear `principal` strike counters while preserving the `ip` (`60/min`) bucket so attackers cannot reset IP quotas by logging into their own account.
5. **Replay & Concurrency Races**: State mutations require a bounded `Idempotency-Key` hashed with canonical key-sorted `SHA-256` (`409` on mismatch or in-flight collision) and optimistic concurrency `expected_version` checks. Webhooks verify raw request bytes via `hmac.compare_digest`, reject timestamps outside `300s`, and atomically claim `(provider, event_id)` before running handlers.
6. **CGNAT Collateral Lockouts, Formula Injection & Log Leaks**: Canary traps (`/.env`, `/wp-admin`) and scanner User-Agents (`sqlmap`, `nuclei`, `nikto`, `ffuf`) trigger 15-minute IP bans while exempting verified authenticated sessions and signed webhooks. CSV exports prefix ASCII and Unicode full-width formula triggers (`=`, `+`, `-`, `@`, `\uff1d`, `\uff0b`, `\uff0d`, `\uff20`) with `'`, and diagnostic logs pass through a bounded recursive Luhn PAN, JWT, and secret redactor.

## Data Classification Tiers

| Tier | Examples in LedgerGuard | Handling Standard |
| :--- | :--- | :--- |
| `public` | `/robots.txt` (`Allow: /` only), `/healthz` | Zero `Set-Cookie` headers, zero internal path `Disallow:` leaks |
| `internal` | Order status, readiness gate codes, SKU codes | Tenant-scoped via `FORCE RLS`, `Cache-Control: no-store, private` |
| `personal` | Normalized `principal_id`, client IP | Hashed with `HMAC-SHA256` in rate-limit/scanner buckets; redacted in logs |
| `sensitive` | `unit_cost_minor`, `total_cost_minor`, `margin_bps` | Stripped unless principal holds `valuation:cost:read` / `orders:margin:read` |
| `highly_sensitive` | Password hashes (`scrypt`), signing keys, webhook secrets, Luhn PANs | Constant-time `hmac.compare_digest`; never logged or returned |

## Automated CI Invariant Gate

Every pull request runs `python3 scripts/security-lint.py` alongside `ruff`, `mypy --strict`, and `pytest` to block privileged runtime DB roles, client-supplied tenant authority, fail-open boolean defaults, wildcard proxy trust, raw SQL string interpolation, `robots.txt` recon leaks, tautological test assertions, and binary `float` usage inside `src/ledger_guard/domain/`.
