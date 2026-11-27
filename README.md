# LedgerGuard

[![CI](https://github.com/mfelisberto90/ledger-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mfelisberto90/ledger-guard/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-green.svg)](./LICENSE)
[![M8ven Score](https://m8ven.ai/badge/mcp/mfelisberto90-ledger-guard-b5gzoa?v=303cad183b11d1fa0d6c188eb82283f7)](https://m8ven.ai/mcp/mfelisberto90/ledger-guard)

Binary floats wreck commercial ledgers fast. If you round a 3-bottle case split (`1/3` unit ratio) one step too early, you'll leak a penny on every single order, and if your AI tool endpoints return raw ORM rows, you'll hand confidential supplier buy prices to staff who shouldn't ever see them.

I've built **LedgerGuard** (`v0.2.0`) as my clean-room Python 3.12 reference architecture for B2B order pricing, four-eyes margin governance, and multi-tenant API security. You won't find binary `float` anywhere inside `src/ledger_guard/domain/`. Every quantity, unit-of-measure ratio, and discount allocation stays in exact `fractions.Fraction` maths until we settle into integer minor units (`pence`, `cents`, `yen`) with Euclidean `ROUND_HALF_EVEN`. Because our FastAPI routes, our `POST /mcp` JSON-RPC endpoint, and our native `ledger-guard-mcp` `stdio` server all call the same `OrderService`, your web apps and your AI agents obey identical RBAC, idempotency, and tenant rules.

## Why I built it this way

Most pricing demos bolt margin checks onto browser code. That doesn't survive your first week with a real B2B sales desk.

Say your sales rep adds £500.00 of pass-through carrier freight onto a loss-making valve order. If your engine folds freight into product revenue, it'll mask a sub-floor discount and wave the order straight past your 20.00% (`2000 bps`) floor. Or suppose your warehouse team revalues stock on Tuesday afternoon: orders you've already confirmed on Monday morning shouldn't fail retroactive checks because a query read a mutable valuation table. We lock down both rules in pure Python 3.12 domain code with zero I/O imports. You capture an immutable `CostSnapshot` when you price each stocked line, and we bill freight and surcharges inside `payable_total_minor` while keeping `net_goods_total_minor` clean.

```mermaid
flowchart LR
    STDIO["MCP Clients (stdio: ledger-guard-mcp)"] --> MCP["McpToolServer (7 tools, strict args)"]
    HTTP_MCP["POST /mcp (JSON-RPC 2.0)"] --> MW["SecurityDefenseMiddleware (CSP Nonce, Honeypot)"]
    REST["FastAPI /v1/* (7 routes)"] --> MW
    MW --> AUTH["TokenService (Scoped Agent Tokens: member ∩ scp)"]
    AUTH --> MCP
    AUTH --> APP["OrderService + IdempotencyCoordinator"]
    MCP --> APP
    APP --> DOM["Pure Domain Core (Fraction UoM, Control/Bidi Guard, Four-Eyes)"]
    APP --> DB["PostgreSQL 17 FORCE RLS (Verified live under app_runtime)"]
```

## How our defences fit together

When you price an order, we run six waterfall steps in strict sequence: `BASE_PRICE`, `QUANTITY_DISCOUNT`, penny-exact `HEADER_DISCOUNT_SPREAD`, `PASSTHROUGH_FREIGHT`, `SMALL_ORDER_SURCHARGE`, and `STATISTICAL_VALUATION_COST`. If your tenant policy is set to `block`, sub-floor orders land in `pending_approval`. You can't approve an order you've created or last amended yourself, even if you vary letter casing on your `principal_id`, and every approval records a mandatory reason in an append-only `ApprovalRecord`. Drop a unit price or raise a discount on a confirmed order and we'll bump `pricing_version` and put your order right back into `pending_approval`.

Your standard sales reps and warehouse staff don't need supplier buy costs to do their jobs. Whenever your caller lacks `valuation:cost:read` or `orders:margin:read`, `project_order_for_principal` strips `unit_cost_minor`, `total_cost_minor`, `margin_minor`, `margin_bps`, and statistical cost steps before we serialise HTTP JSON, MCP payloads, or CSV exports. They'll still see `{gate, met, code, remediation}` so they know what's blocking confirmation without seeing your buy prices. And if you're connecting an AI agent on behalf of a finance director, you don't hand over full credentials: call `POST /v1/auth/delegate-token` to mint a short-lived `lg1` token restricted to `["orders:read", "orders:write"]`. We compute `member.capabilities & token.scp` on every request, so a prompt-injected agent can't escalate to `orders:margin:approve` or `valuation:cost:read`.

In `sql/001_init_force_rls.sql`, we split `app_migrator` from `app_runtime` (`NOBYPASSRLS`) and enforce `ENABLE` and `FORCE ROW LEVEL SECURITY` across all 6 tables with `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`. Our GitHub Actions CI boots a live `postgres:17-alpine` container and proves under `SET ROLE app_runtime` that unset context returns zero rows, cross-tenant `INSERT` attempts fail `WITH CHECK`, and `audit_outbox` rejects `UPDATE` and `DELETE`. At the ASGI edge, you get a fresh 18-byte base64 CSP `nonce` with `style-src-attr 'none'`, ASCII control and Unicode Bidi (`U+202E`) input blocking, `BoundedMap` `HMAC-SHA256` rate limiting (keeping your `ip` 60/min password-spraying bucket intact after login), `SHA-256` payload-bound idempotency, CGNAT-safe honeypots, and Luhn PAN log redaction.

## Run the MCP server over stdio

You don't need external databases or environment secrets to try our MCP server. Connect Claude Desktop, Cursor, or your MCP inspector straight to `ledger-guard-mcp` over `stdio`. Out of the box, we boot an isolated in-memory sandbox for you, seeded with sample B2B SKUs (`VALVE-DN50`, `REAGENT-BTL`, `INSTALL-SVC`) under our least-privilege `sales_rep` role:

```json
{
  "mcpServers": {
    "ledger-guard": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mfelisberto90/ledger-guard", "ledger-guard-mcp"]
    }
  }
}
```

If you'd like to test our JSON-RPC 2.0 `stdio` handshake (`initialize` -> `notifications/initialized` -> `tools/list`) from your shell, you'll get clean newline-delimited responses right away:

```bash
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"local","version":"1.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | uv run ledger-guard-mcp
```

## REST and MCP contract parity

Every route we've exposed on FastAPI has a matching MCP tool (`create_order`, `get_order`, `list_orders`, `confirm_order`, `approve_margin`, `amend_order_line`, and `export_orders_csv`) with identical bounds and projection rules. We bind `tenant_id` strictly from your verified `Authorization: Bearer` token on HTTP or your sandbox membership on `stdio`. If a caller or prompt-injected model smuggles `tenant_id` into a JSON body or MCP tool call, we'll block it (`422` on HTTP and `CLIENT_TENANT_OVERRIDE_FORBIDDEN` on MCP). Pass any unknown or hallucinated argument to any of our 7 MCP tools and you'll get `UNKNOWN_TOOL_ARGUMENTS` (`422`), matching FastAPI's `ConfigDict(extra="forbid")`.

## Quickstart and local PostgreSQL 17 checks

Install Python 3.12+ and [`uv`](https://docs.astral.sh/uv/), sync our locked environment, and run every gate we enforce in CI right on your machine:

```bash
uv sync --frozen --dev

uv run ruff check src tests scripts
uv run mypy --strict src
uv run python3 scripts/security-lint.py --self-test
uv run pip-audit
uv run pytest -v
```

If you'd like to run our live PostgreSQL 17 `FORCE ROW LEVEL SECURITY` suite (`tests/test_postgres17_live_rls.py`) locally with Docker:

```bash
docker run --rm -d --name lg-pg17 -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:17-alpine
LEDGER_GUARD_TEST_PG_DSN="postgresql://postgres:postgres@127.0.0.1:55432/postgres" uv run pytest -v
docker stop lg-pg17
```

If you'd like to start our FastAPI + HTTP MCP server locally with Uvicorn, you're one command away:

```bash
uv run uvicorn ledger_guard.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

## Repository layout

```text
src/ledger_guard/
  domain/        Pure Python 3.12 pricing, Fraction UoM, text guard, margin gate & projection
  ports/         Protocol interfaces isolating catalog pricing from valuation & storage
  adapters/      Fail-closed in-memory store + PostgreSQL 17 2-stage FORCE RLS session
  security/      scrypt auth, delegated scp tokens, HMAC rate limiter, idempotency, ASGI CSP
  application/   Shared OrderService orchestrating all 7 HTTP and MCP operations
  api/           FastAPI routes (/v1/orders, /v1/auth/delegate-token, /v1/webhooks, /mcp)
  mcp/           MCP JSON-RPC 2.0 server (2025-03-26) + native stdio CLI (stdio_cli.py)
sql/             001_init_force_rls.sql PostgreSQL 17 DDL (app_migrator vs app_runtime)
scripts/         security-lint.py enforcing 9 architectural/SQL invariants + SARIF 2.1.0
server.json      Model Context Protocol Registry manifest
tests/           72 unit, boundary, concurrency, IDOR/BFLA, parity & live PG17 RLS tests
```

## Security, privacy, and licence

Read [SECURITY.md](./SECURITY.md) if you're auditing our threat model or reporting a vulnerability, [PRIVACY.md](./PRIVACY.md) for our zero-telemetry guarantee, and [CHANGELOG.md](./CHANGELOG.md) for version notes. Released under the [MIT Licence](./LICENSE) by Murilo Felisberto in Edinburgh, Scotland, UK.
