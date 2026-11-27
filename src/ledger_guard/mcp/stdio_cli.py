"""Native Model Context Protocol `stdio` JSON-RPC 2.0 server entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import BinaryIO, TextIO

from ledger_guard import __version__ as SERVER_VERSION
from ledger_guard.adapters.in_memory import (
    InMemoryAuditOutbox,
    InMemoryCatalogAdapter,
    InMemoryIdempotencyStore,
    InMemoryOrderRepository,
    InMemoryPolicyRepository,
    InMemoryValuationAdapter,
)
from ledger_guard.application.order_service import OrderService
from ledger_guard.application.sandbox import ROLE_CAPABILITIES, seed_reference_sandbox
from ledger_guard.domain.margin_gate import PrincipalContext
from ledger_guard.mcp.server import McpToolServer
from ledger_guard.security.auth import MembershipDirectory
from ledger_guard.security.idempotency import IdempotencyCoordinator
from ledger_guard.security.redaction import Redactor

MAX_STDIO_FRAME_BYTES: int = 1_048_576
MAX_STDIO_HEADER_LINES: int = 32


def build_stdio_mcp_server(
    *,
    seed_pending_order: bool = True,
) -> tuple[McpToolServer, dict[str, PrincipalContext], dict[str, object] | None]:
    """Construct an isolated, zero-HTTP-import in-memory MCP tool server and sandbox."""
    catalog = InMemoryCatalogAdapter()
    valuation = InMemoryValuationAdapter()
    policies = InMemoryPolicyRepository()
    outbox = InMemoryAuditOutbox()
    orders = InMemoryOrderRepository(outbox)
    idempotency_store = InMemoryIdempotencyStore()
    memberships = MembershipDirectory()
    redactor = Redactor()

    order_service = OrderService(
        catalog=catalog,
        valuation=valuation,
        orders=orders,
        policies=policies,
    )
    mcp_server = McpToolServer(
        order_service=order_service,
        idempotency=IdempotencyCoordinator(idempotency_store),
        redactor=redactor,
    )
    principals, pending_order = seed_reference_sandbox(
        catalog=catalog,
        valuation=valuation,
        policies=policies,
        memberships=memberships,
        orders=orders,
        seed_pending_order=seed_pending_order,
    )
    return mcp_server, principals, pending_order


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


def _read_exact_bytes(stream: BinaryIO, count: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve_stdio_stream(
    stdin_bytes: BinaryIO,
    stdout_text: TextIO,
    *,
    role: str = "sales_rep",
    seed_pending_order: bool = True,
) -> int:
    """Process bounded MCP JSON-RPC 2.0 frames over `stdio`."""
    mcp_server, principals, _ = build_stdio_mcp_server(seed_pending_order=seed_pending_order)
    principal = principals[role]
    max_line_read = MAX_STDIO_FRAME_BYTES + 1

    while True:
        first_line = stdin_bytes.readline(max_line_read)
        if not first_line:
            break
        if len(first_line) > MAX_STDIO_FRAME_BYTES and not first_line.endswith(b"\n"):
            _write_response(
                stdout_text,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: frame exceeds maximum allowed size.",
                    },
                },
                use_content_length=False,
            )
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

            header_count = 0
            header_limit_exceeded = False
            while True:
                header_line = stdin_bytes.readline(max_line_read)
                header_count += 1
                if not header_line or header_line in (b"\r\n", b"\n"):
                    break
                if header_count >= MAX_STDIO_HEADER_LINES or len(header_line) > 8_192:
                    header_limit_exceeded = True
                    break

            if header_limit_exceeded or length_val <= 0 or length_val > MAX_STDIO_FRAME_BYTES:
                _write_response(
                    stdout_text,
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32600,
                            "message": (
                                "Invalid Request: Content-Length must be in "
                                f"1..{MAX_STDIO_FRAME_BYTES}."
                            ),
                        },
                    },
                    use_content_length=True,
                )
                if length_val > MAX_STDIO_FRAME_BYTES or length_val < 0:
                    break
                continue

            raw_body = _read_exact_bytes(stdin_bytes, length_val)
            if raw_body is None:
                break
        else:
            raw_body = stripped

        try:
            decoded_obj = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
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

        try:
            response = mcp_server.handle_jsonrpc(principal, decoded_obj)
        except Exception:
            err_id = (
                decoded_obj.get("id")
                if isinstance(decoded_obj.get("id"), (int, str))
                else None
            )
            response = {
                "jsonrpc": "2.0",
                "id": err_id,
                "error": {"code": -32603, "message": "Internal JSON-RPC execution error."},
            }

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
