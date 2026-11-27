# Changelog

All notable changes to LedgerGuard are documented in this file.

## [0.3.0] - 2026-11-27

### Added
- Shared single-source Pydantic contract registry (`ledger_guard.application.schemas`) generating both FastAPI request validation and MCP `MCP_TOOLS_SPEC` JSON Schemas with `validate_mcp_arguments`.
- Shared in-memory reference sandbox seeder (`ledger_guard.application.sandbox`) wiring `create_sandbox_app` for immediate Uvicorn startup and pre-seeding one `pending_approval` sub-floor order in `stdio` so `approve_margin` can be exercised directly.
- Weekly `.github/dependabot.yml` automation and `[project.optional-dependencies] postgres` / `[tool.hatch.build.targets.sdist]` packaging metadata in `pyproject.toml`.

### Security
- Rejected scientific-notation and unbounded rational quantity strings (`DOM-01`) with strict ASCII integer/rational parsing, capped monetary `BIGINT` bounds (`DOM-02`), clamped `compute_margin_bps` (`DOM-03`), preserved `manual_discount_bps` + `tier_discounts` across amendments (`DOM-04`), and tracked full `amended_by_history` + `approved_net_goods_minor` ceilings (`DOM-05`).
- Enforced RBAC before idempotency replay with live caller re-projection (`SEC-01`), tenant-scoped rate-limit/strike buckets with pre-auth IP quotas (`SEC-02`/`SEC-07`), RFC 9110 multi-header `X-Forwarded-For` joining + duplicate `Authorization` blocking (`SEC-03`), sub-token re-delegation bans + `jti` revocation (`SEC-04`/`SEC-15`), HTTP `413` streaming body caps (`SEC-05`), and bounded `stdio` framing (`SEC-06`).
- Context-bound webhook HMAC signatures over `provider.tenant_id.event_id.timestamp.raw_body` with handler-error claim release (`SEC-08`/`SEC-13`), threadpool constant-time `scrypt` login verification (`SEC-10`), canonical JSON idempotency keys (`SEC-12`), `lg1.*` + quoted JSON redaction (`SEC-09`), and pipe/multiline CSV formula guards (`SEC-19`).
- Tightened `sql/001_init_force_rls.sql` Stage-A/B `tenant_memberships` isolation (`DB-01`), `owner`-gated membership/policy writes, Last-Owner trigger, `principal_id` RLS on `idempotency_records`, tenant-validated `acquire_tenant_lock`, and `ROLLBACK` poison tracking in `PostgresTenantSession` (`DB-03`).
- Upgraded `scripts/security-lint.py` (`SEC-LINT-008` AST float/division scan, `app_migrator` detection, nested SQL comment stripping) and pinned SHA/digest references in `.github/workflows/ci.yml`; removed unclaimed PyPI entry from `server.json` (`SUP-01`) and tightened dependency floor versions (`h11>=0.16.0`, `starlette>=1.3.1`, `anyio>=4.14.2`, `httpx2>=2.12.0`).

### Removed
- Eliminated ~700+ lines of redundant manual MCP JSON Schema builders, duplicate test fixtures, unused `__all__` re-exports, dead symbols (`ScannerBannedError`, `AuditOutboxPort`, `MinorAmount`, `build_session_cookie_flags`, `ledger_guard.mcp.__main__`), and unused `httpx` dev dependency.

## [0.2.0] - 2026-11-27

### Added
- Native Model Context Protocol `stdio` server (`ledger-guard-mcp`), `list_orders` / `export_orders_csv` REST+MCP parity, delegated `scp` agent tokens, control/Unicode Bidi guard, `SEC-LINT-009` + SARIF, `pip-audit`, and live `postgres:17-alpine` CI verification.

## [0.1.0] - 2026-11-02

### Added
- Initial clean-room Python 3.12 hexagonal pricing waterfall (`fractions.Fraction` UoM ratios, `ROUND_HALF_EVEN` integer minor units, immutable `CostSnapshot`), four-eyes margin gate, capability-based view projection, FastAPI + HTTP `/mcp` server, and PostgreSQL 17 `FORCE RLS` DDL.
