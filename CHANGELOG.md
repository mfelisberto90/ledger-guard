# Changelog

All notable changes to LedgerGuard are documented in this file.

## [0.2.0] - 2026-11-27

### Added
- Native Model Context Protocol `stdio` server (`ledger-guard-mcp`, `ledger-guard`, `python -m ledger_guard`) running an isolated least-privilege in-memory sandbox (`sales_rep` default) with newline-delimited and `Content-Length` JSON-RPC 2.0 support.
- Official MCP Registry `server.json` manifest and full MCP `2025-03-26` / `2024-11-05` lifecycle handlers (`initialize`, `notifications/initialized`, `ping`, `tools/list` with tool `annotations`).
- 1:1 REST and MCP tool parity across 7 operations, adding `list_orders` (`GET /v1/orders`) and `export_orders_csv` on MCP.
- Attenuated agent token delegation (`POST /v1/auth/delegate-token`) signing explicit `scp` capability subsets intersected fail-closed (`member.capabilities & token.scp`) on every request.
- Domain-level ASCII control character and Unicode Bidi override blocker (`UNSAFE_CONTROL_OR_BIDI_CHAR`) across `customer_ref`, `sku`, `description`, `principal_id`, and `reason`.
- Rule `SEC-LINT-009` (comment-stripped SQL `ENABLE` + `FORCE ROW LEVEL SECURITY` verification), `--self-test`, and `--sarif` 2.1.0 export in `scripts/security-lint.py`.
- Live `postgres:17-alpine` CI verification (`tests/test_postgres17_live_rls.py`) proving fail-closed zero-row visibility, cross-tenant `WITH CHECK` enforcement, and append-only `audit_outbox` privileges under `SET ROLE app_runtime`.
- `PRIVACY.md` documenting zero telemetry and local-only sandbox execution.

### Security
- Closed controller argument drift on MCP: all 7 MCP tools now reject unknown or hallucinated arguments with `UNKNOWN_TOOL_ARGUMENTS` (`422`), matching FastAPI `ConfigDict(extra="forbid")`.
- Added `style-src-attr 'none'` to per-request Content-Security-Policy headers in `SecurityDefenseMiddleware`.
- Added `pip-audit` CVE scanning and `DeprecationWarning` promotion to errors in pytest.

## [0.1.0] - 2026-11-02

### Added
- Initial clean-room Python 3.12 hexagonal pricing waterfall (`fractions.Fraction` UoM ratios, `ROUND_HALF_EVEN` integer minor units, immutable `CostSnapshot`), four-eyes margin gate, capability-based view projection, FastAPI + HTTP `/mcp` server, and PostgreSQL 17 `FORCE RLS` DDL (`sql/001_init_force_rls.sql`).
