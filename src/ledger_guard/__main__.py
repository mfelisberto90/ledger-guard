"""Package CLI entrypoint delegating `python -m ledger_guard` to the MCP stdio server."""

from __future__ import annotations

from ledger_guard.mcp.stdio_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
