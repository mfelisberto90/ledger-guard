"""Native Model Context Protocol `stdio` JSON-RPC 2.0 server entrypoint.

Runs an isolated in-memory B2B ledger sandbox by default under least-privilege role
`sales_rep` (zero supplier cost or margin disclosure, zero network sockets, zero external
environment secrets required) so MCP clients, Claude Desktop, Cursor, and automated MCP
verifiers can inspect and exercise all 7 tools over standard input/output.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from fractions import Fraction
from typing import BinaryIO, TextIO
from uuid import UUID

from ledger_guard.api.app import AppContainer
from ledger_guard.domain.margin_gate import MarginPolicy, PrincipalContext
from ledger_guard.domain.money import Currency, UnitRatio
from ledger_guard.domain.pricing import ItemKind, QuantityTierDiscount
from ledger_guard.mcp.server import SERVER_VERSION
from ledger_guard.ports import CatalogItem

SANDBOX_TENANT_ID: UUID = UUID("00000000-0000-4000-8000-000000000101")

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "warehouse": frozenset({"orders:read"}),
    "sales_rep": frozenset(
        {"orders:read", "orders:write", "orders:confirm", "orders:export"}
    ),
    "finance_approver": frozenset(
        {
            "orders:read",
            "orders:margin:read",
            "orders:margin:approve",
            "orders:confirm",
            "orders:export",
        }
    ),
    "owner": frozenset(
        {
            "orders:read",
            "orders:write",
            "orders:confirm",
            "orders:export",
            "orders:margin:read",
            "orders:margin:approve",
            "valuation:cost:read",
        }
    ),
}


def build_sandbox_container() -> tuple[AppContainer, dict[str, PrincipalContext]]:
    """Construct a deterministic, zero-I/O in-memory sandbox seeded with sample B2B SKUs."""
    container = AppContainer()
    container.policies.save_policy(
        SANDBOX_TENANT_ID,
        MarginPolicy(
            tenant_id=SANDBOX_TENANT_ID,
            mode="block",
            minimum_margin_bps=2_000,
        ),
    )

    container.catalog.upsert_item(
        SANDBOX_TENANT_ID,
        CatalogItem(
            sku="VALVE-DN50",
            description="Stainless Steel Ball Valve DN50 PN40",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            list_unit_price_minor=10_000,
            unit_ratio=UnitRatio(1, 1),
            tier_discounts=(QuantityTierDiscount(Fraction(10, 1), 500),),
        ),
    )
    container.valuation.set_stock_cost(
        SANDBOX_TENANT_ID,
        "VALVE-DN50",
        7_000,
        Currency.GBP,
    )

    container.catalog.upsert_item(
        SANDBOX_TENANT_ID,
        CatalogItem(
            sku="REAGENT-BTL",
            description="Analytical Grade Buffer Bottle (1/3 Case Split)",
            item_kind=ItemKind.STOCKED,
            currency=Currency.GBP,
            list_unit_price_minor=450,
            unit_ratio=UnitRatio(1, 3),
        ),
    )
    container.valuation.set_stock_cost(
        SANDBOX_TENANT_ID,
        "REAGENT-BTL",
        900,
        Currency.GBP,
    )

    container.catalog.upsert_item(
        SANDBOX_TENANT_ID,
        CatalogItem(
            sku="INSTALL-SVC",
            description="On-Site Commissioning Service Visit",
            item_kind=ItemKind.SERVICE,
            currency=Currency.GBP,
            list_unit_price_minor=25_000,
            unit_ratio=UnitRatio(1, 1),
        ),
    )

    principals: dict[str, PrincipalContext] = {}
    for role_name, caps in ROLE_CAPABILITIES.items():
        principal = PrincipalContext(
            principal_id=f"stdio.{role_name}@sandbox.ledgerguard.local",
            tenant_id=SANDBOX_TENANT_ID,
            role=role_name,
            capabilities=caps,
            is_active=True,
        )
        container.memberships.register_member(principal)
        principals[role_name] = principal

    return container, principals


def _write_response(
    stdout: TextIO,
    payload: dict[str, object],
    *,
    use_content_length: bool,
) -> None:
    encoded = json.dumps(payload, separators=(",", ":"))
    if use_content_length:
        byte_len = len(encoded.encode("utf-8"))
        stdout.write(f"Content-Length: {byte_len}\r\n\r\n{encoded}")
    else:
        stdout.write(f"{encoded}\n")
    stdout.flush()


def serve_stdio_stream(
    stdin_bytes: BinaryIO,
    stdout_text: TextIO,
    *,
    role: str = "sales_rep",
) -> int:
    """Process MCP JSON-RPC 2.0 frames over `stdio` (newline JSON and Content-Length)."""
    container, principals = build_sandbox_container()
    principal = principals[role]

    while True:
        first_line = stdin_bytes.readline()
        if not first_line:
            break

        stripped = first_line.strip()
        if not stripped:
            continue

        use_content_length = False
        if stripped.lower().startswith(b"content-length:"):
            use_content_length = True
            try:
                length_val = int(stripped.split(b":", 1)[1].strip().decode("ascii"))
            except ValueError:
                _write_response(
                    stdout_text,
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Invalid Content-Length header."},
                    },
                    use_content_length=True,
                )
                continue

            while True:
                header_line = stdin_bytes.readline()
                if not header_line or header_line in (b"\r\n", b"\n"):
                    break
            raw_body = stdin_bytes.read(length_val)
            if not raw_body:
                break
        else:
            raw_body = stripped

        try:
            decoded_obj = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _write_response(
                stdout_text,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error: invalid JSON payload."},
                },
                use_content_length=use_content_length,
            )
            continue

        if not isinstance(decoded_obj, dict):
            _write_response(
                stdout_text,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: JSON object expected."},
                },
                use_content_length=use_content_length,
            )
            continue

        response = container.mcp_server.handle_jsonrpc(principal, decoded_obj)
        if response is not None:
            _write_response(
                stdout_text,
                response,
                use_content_length=use_content_length,
            )

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `ledger-guard-mcp` / `python -m ledger_guard`."""
    parser = argparse.ArgumentParser(
        prog="ledger-guard-mcp",
        description="LedgerGuard Model Context Protocol (MCP) stdio JSON-RPC 2.0 server.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ledger-guard-mcp {SERVER_VERSION}",
    )
    parser.add_argument(
        "--role",
        choices=sorted(ROLE_CAPABILITIES.keys()),
        default="sales_rep",
        help="Sandbox principal role preset (defaults to least-privilege 'sales_rep').",
    )
    parsed = parser.parse_args(argv)
    return serve_stdio_stream(sys.stdin.buffer, sys.stdout, role=str(parsed.role))


if __name__ == "__main__":
    raise SystemExit(main())
