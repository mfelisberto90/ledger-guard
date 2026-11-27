# Security policy and threat model

## Reporting a vulnerability

Please do **not** open public GitHub issues for suspected security vulnerabilities. Use [GitHub Private Vulnerability Reporting](https://github.com/mfelisberto90/ledger-guard/security/advisories/new) on this repository so we can validate, patch, and coordinate disclosure safely.

We aim to acknowledge reports within 48 hours and publish a regression test alongside every security fix.

## Supported versions

| Version | Python runtime | Supported |
| :--- | :--- | :--- |
| `0.3.x` | Python 3.12+ | Yes |
| `0.2.x` | Python 3.12+ | Security fixes only |

## Trust boundaries and abuse cases

LedgerGuard treats every inbound HTTP caller, browser client, webhook sender, and MCP-connected AI agent as untrusted until verified server-side:

1. **Cross-tenant IDOR, prompt injection & replay projection**: Tenant scope (`tenant_id`) is resolved strictly from verified server tokens and active `tenant_memberships`, backed by PostgreSQL 17 `ENABLE` + `FORCE ROW LEVEL SECURITY` under a `NOBYPASSRLS` runtime role (`app_runtime`), with `tenant_memberships` Stage-A/B separation, `owner`-gated mutations, and a Last-Owner trigger. RBAC runs before idempotency replay and cached order responses re-project through `project_order_for_principal` for the caller's live capabilities.
2. **Least-privilege agent token delegation (`POST /v1/auth/delegate-token`)**: Principals connecting AI agents can mint short-lived (`60..3600s`) attenuated `lg1` tokens carrying `scp` and `jti` claims. Every request intersects `member.capabilities & token.scp` fail-closed, checks revoked `jti` entries, and blocks delegated sub-tokens from re-delegating or extending their own TTL.
3. **Confidential valuation & math DoS prevention**: Commercial catalog reads (`CatalogPricingPort`) contain zero supplier cost columns. Rational quantities match strict ASCII regex `\A[0-9]{1,10}(?:/[1-9][0-9]{0,6})?\Z` (banning scientific-notation CPU/RAM DoS such as `1e5000`), monetary values enforce `BIGINT`-safe bounds, and `compute_margin_bps` clamps safely to `-10000..10000`.
4. **Four-eyes separation of duties (`orders:margin:approve`)**: Margin approvals normalise `principal_id`, track `amended_by_history` across all order participants to block amender-washing, preserve captured `manual_discount_bps` and `tier_discounts` separately, and invalidate prior approvals if adverse changes or sub-floor exposure expansion occur.
5. **Edge DoS, header spoofing, rate limiting & redaction**: `SecurityDefenseMiddleware` enforces `413` streaming body caps (`256 KiB` / `1 MiB`), joins multi-header `X-Forwarded-For` per RFC 9110, rejects duplicate `Authorization` headers, binds webhooks cleanly across `(provider, tenant_id, event_id, timestamp)` with rollback on handler failure, isolates rate-limit buckets per `(tenant_id, principal_id)` and `/64` IPv6 subnet, runs `scrypt` via `run_in_threadpool` with dummy hashing, redacts `lg1.*` and quoted JSON secrets, and neutralises pipe `|` and multiline CSV formula triggers.

## Data classification tiers

| Tier | Examples in LedgerGuard | Handling standard |
| :--- | :--- | :--- |
| `public` | `/robots.txt` (`Allow: /` only), `/healthz`, `stdio` demo SKUs | Zero `Set-Cookie` headers, zero internal path `Disallow:` leaks |
| `internal` | Order status, readiness gate codes, SKU codes, `scp`, `jti` | Tenant-scoped via `FORCE RLS`, `Cache-Control: no-store, private` |
| `personal` | Normalised `principal_id`, client IP | Hashed with `HMAC-SHA256` per tenant in rate-limit buckets; redacted in logs |
| `sensitive` | `unit_cost_minor`, `total_cost_minor`, `margin_bps` | Stripped unless principal holds `valuation:cost:read` / `orders:margin:read` |
| `highly_sensitive` | Password hashes (`scrypt`), signing keys, webhook secrets, Luhn PANs | Constant-time checks; never logged or returned |

## Automated CI invariant gate

Every pull request runs `scripts/security-lint.py --self-test` (9 regex, Python AST float/division, and nested-comment SQL `FORCE RLS` rules + SARIF artifact), `pip-audit --strict --skip-editable`, `ruff`, `mypy --strict`, SHA-pinned GitHub Actions, digest-pinned `postgres:17-alpine` live RLS tests under `SET ROLE app_runtime`, and bounded `stdio` MCP handshake checks.
