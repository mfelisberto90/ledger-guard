#!/usr/bin/env python3
"""Security & Financial Invariant Linter for LedgerGuard.

Adapted from the Enterprise App Security Blueprint (`enterprise-app-security-blueprint`).
Executed in CI via `python3 scripts/security-lint.py`.

Enforces architectural invariants that generic SAST tools miss:
1. SEC-LINT-001: Privileged/migrator/backup DB credentials or connections used in runtime layers.
2. SEC-LINT-002: Trusting client-supplied tenant_id / agency_id / org_id directly into auth state.
3. SEC-LINT-003: Fail-open null-coalescing on security/authority booleans (`is_active or True`).
4. SEC-LINT-004: Wildcard trusted proxy (`*`) or `unsafe-eval` / `unsafe-inline` in script-src CSP.
5. SEC-LINT-005: Raw string interpolation inside SQL queries.
6. SEC-LINT-006: Internal recon path leaks via `Disallow: /admin|/platform|/internal` in robots.txt.
7. SEC-LINT-007: Tautological placeholder assertions in test suites (`assert True`).
8. SEC-LINT-008: Binary float usage in financial domain layer (`src/ledger_guard/domain`).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parent.parent

SOURCE_EXTENSIONS = {".py", ".sql"}
IGNORE_DIRS = {
    "node_modules",
    "vendor",
    "target",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


class LintRule(TypedDict, total=False):
    id: str
    description: str
    pattern: str
    scope: str
    allow_marker: str


BANNED_RULES: list[LintRule] = [
    {
        "id": "SEC-LINT-001",
        "description": "Privileged migrator/backup DB connection used in runtime code",
        "pattern": (
            r"(?:pgsql_bootstrap|pgsql_migrator|pgsql_backup|"
            r"DATABASE_MIGRATOR_URL|db_superuser)"
        ),
        "scope": "src",
        "allow_marker": "RLS BYPASS JUSTIFICATION",
    },
    {
        "id": "SEC-LINT-002",
        "description": "Client request tenant/org parameter trusted directly as session authority",
        "pattern": (
            r"session(?:\(\))?.*(?:selected_tenant_id|current_tenant_id)"
            r".*(?:request|req)\.(?:input|body|query|get)"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-003",
        "description": "Fail-open default on authority flag is prohibited (must fail closed)",
        "pattern": (
            r"\b(?:is_active|is_admin|is_owner|has_access|is_verified|authorized)"
            r"\s*(?:\?\?|\|\||\bor\b)\s*(?:true|True|1)\b"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-004",
        "description": "Unsafe wildcard proxy trust or unsafe-inline/unsafe-eval in CSP",
        "pattern": (
            r"(?:['\"]unsafe-eval['\"]|script-src[^;\n]*['\"]unsafe-inline['\"]"
            r"|trust\s+proxy['\"]?\s*,\s*true|trustedProxies\s*\(\s*at:\s*'\*')"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-005",
        "description": "Dynamic interpolation in raw SQL execution; use parameterized bindings",
        "pattern": r"(?:\.queryRawUnsafe|\.execute\s*\(\s*f[\"'])",
        "scope": "src",
    },
    {
        "id": "SEC-LINT-006",
        "description": "Disallow internal path leak in robots.txt (use positive Allow rules)",
        "pattern": r"Disallow:\s*/(?:admin|platform|internal|agency|portal|dashboard)",
        "scope": "src",
    },
    {
        "id": "SEC-LINT-007",
        "description": "Tautological placeholder test assertion prohibited",
        "pattern": r"(?:expect\(\s*true\s*\)\.toBe\(\s*true\s*\)|\bassert\s+True\b)",
        "scope": "tests",
    },
    {
        "id": "SEC-LINT-008",
        "description": "Binary float prohibited in financial domain; use Fraction & minor ints",
        "pattern": r"\bfloat\b",
        "scope": "domain",
    },
]


def iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_EXTENSIONS:
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.name in {"security-lint.py", "security_invariant_lint_template.py"}:
            continue
        yield path


def scan(root: Path) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    compiled = [(rule, re.compile(rule["pattern"], re.MULTILINE)) for rule in BANNED_RULES]

    for file_path in iter_files(root):
        rel = file_path.relative_to(root).as_posix()
        is_test = rel.startswith("tests/") or ".test." in rel
        is_src = rel.startswith("src/")
        is_domain = rel.startswith("src/ledger_guard/domain/")
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for rule, regex in compiled:
            scope = rule.get("scope", "src")
            if scope == "tests" and not is_test:
                continue
            if scope == "src" and not is_src:
                continue
            if scope == "domain" and not is_domain:
                continue

            for match in regex.finditer(content):
                marker = rule.get("allow_marker")
                if marker:
                    prev_lines = content[: match.start()].splitlines()[-15:]
                    if any(marker in ln for ln in prev_lines):
                        continue
                line_no = content[: match.start()].count("\n") + 1
                violations.append(
                    {
                        "id": rule["id"],
                        "description": rule["description"],
                        "file": rel,
                        "line": line_no,
                        "snippet": match.group(0).strip()[:140],
                    }
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="LedgerGuard Security Invariant Linter")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    violations = scan(args.root.resolve())
    if not violations:
        print("PASS: All 8 security and financial invariant lint rules satisfied (0 violations).")
        return 0

    print(f"FAIL: Found {len(violations)} security invariant violation(s):\n")
    for item in violations:
        print(f"[{item['id']}] {item['file']}:{item['line']} - {item['description']}")
        print(f"  Match: {item['snippet']}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
