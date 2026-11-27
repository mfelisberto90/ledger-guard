"""LedgerGuard: hexagonal commercial order pricing, margin governance, and multi-tenant security."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("ledger-guard")
except PackageNotFoundError:  # pragma: no cover - source tree fallback
    __version__ = "0.3.0"

__all__ = ["__version__"]
