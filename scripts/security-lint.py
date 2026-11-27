#!/usr/bin/env python3
"""Security & Financial Invariant Linter for LedgerGuard.

Adapted from the Enterprise App Security Blueprint (`enterprise-app-security-blueprint`).
Executed in CI via `python3 scripts/security-lint.py --self-test` and `--sarif`.

Enforces architectural invariants that generic SAST tools miss:
1. SEC-LINT-001: Privileged/migrator/backup DB credentials or connections used in runtime layers.
2. SEC-LINT-002: Trusting client-supplied tenant_id / agency_id / org_id directly into auth state.
3. SEC-LINT-003: Fail-open null-coalescing on security/authority booleans (`is_active or True`).
4. SEC-LINT-004: Wildcard trusted proxy (`*`) or `unsafe-eval` / `unsafe-inline` in script-src CSP.
5. SEC-LINT-005: Raw string interpolation inside SQL queries.
6. SEC-LINT-006: Internal recon path leaks via `Disallow: /admin|/platform|/internal` in robots.txt.
7. SEC-LINT-007: Tautological placeholder assertions in test suites (`assert True`).
8. SEC-LINT-008: Binary float usage in financial domain layer (`src/ledger_guard/domain`).
9. SEC-LINT-009: SQL table declared without both ENABLE and FORCE ROW LEVEL SECURITY.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypedDict

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

SQL_RLS_RULE_META: dict[str, str] = {
    "id": "SEC-LINT-009",
    "description": "SQL table declared without both ENABLE and FORCE ROW LEVEL SECURITY",
}

_SQL_COMMENT_RE = re.compile(r"--[^\n]*|/\*[\s\S]*?\*/")
_CREATE_TABLE_RE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-zA-Z_][\w]*\.)?([a-zA-Z_][\w]*)\b",
    re.IGNORECASE,
)


def strip_sql_comments_preserving_newlines(sql_text: str) -> str:
    """Replace SQL comments with whitespace while keeping line numbers aligned."""

    def _blank(match: re.Match[str]) -> str:
        raw = match.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in raw)

    return _SQL_COMMENT_RE.sub(_blank, sql_text)


def scan_sql_rls_invariants(file_path: Path, rel_path: str, content: str) -> list[dict[str, Any]]:
    """Verify every `CREATE TABLE` in `sql/*.sql` has ENABLE + FORCE ROW LEVEL SECURITY."""
    del file_path
    stripped = strip_sql_comments_preserving_newlines(content)
    violations: list[dict[str, Any]] = []

    for match in _CREATE_TABLE_RE.finditer(stripped):
        table_name = match.group(1)
        line_no = stripped[: match.start()].count("\n") + 1
        enable_re = re.compile(
            rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"
            rf"(?:[a-zA-Z_][\w]*\.)?{re.escape(table_name)}\s+"
            rf"ENABLE\s+ROW\s+LEVEL\s+SECURITY\b",
            re.IGNORECASE,
        )
        force_re = re.compile(
            rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"
            rf"(?:[a-zA-Z_][\w]*\.)?{re.escape(table_name)}\s+"
            rf"FORCE\s+ROW\s+LEVEL\s+SECURITY\b",
            re.IGNORECASE,
        )
        has_enable = enable_re.search(stripped) is not None
        has_force = force_re.search(stripped) is not None
        if not (has_enable and has_force):
            missing_parts: list[str] = []
            if not has_enable:
                missing_parts.append("ENABLE ROW LEVEL SECURITY")
            if not has_force:
                missing_parts.append("FORCE ROW LEVEL SECURITY")
            violations.append(
                {
                    "id": SQL_RLS_RULE_META["id"],
                    "description": (
                        f"{SQL_RLS_RULE_META['description']} "
                        f"(table '{table_name}' missing {', '.join(missing_parts)})"
                    ),
                    "file": rel_path,
                    "line": line_no,
                    "snippet": match.group(0).strip()[:140],
                }
            )
    return violations


def iter_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_EXTENSIONS:
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.name in {"security-lint.py", "security_invariant_lint_template.py"}:
            continue
        yield path


def scan(root: Path) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    compiled = [(rule, re.compile(rule["pattern"], re.MULTILINE)) for rule in BANNED_RULES]

    for file_path in iter_files(root):
        rel = file_path.relative_to(root).as_posix()
        is_test = rel.startswith("tests/") or ".test." in rel
        is_src = rel.startswith("src/")
        is_domain = rel.startswith("src/ledger_guard/domain/")
        is_sql = rel.startswith("sql/") and file_path.suffix == ".sql"
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if is_sql:
            violations.extend(scan_sql_rls_invariants(file_path, rel, content))

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


def build_sarif_report(violations: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 report for GitHub Code Scanning / CI artifacts."""
    all_rules = [
        {"id": r["id"], "shortDescription": {"text": r["description"]}} for r in BANNED_RULES
    ]
    all_rules.append(
        {
            "id": SQL_RLS_RULE_META["id"],
            "shortDescription": {"text": SQL_RLS_RULE_META["description"]},
        }
    )
    results = [
        {
            "ruleId": str(item["id"]),
            "level": "error",
            "message": {"text": str(item["description"])},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(item["file"])},
                        "region": {"startLine": int(item["line"])},
                    }
                }
            ],
        }
        for item in violations
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ledger-guard-security-lint",
                        "version": "0.2.0",
                        "rules": all_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def run_self_test() -> int:
    """Verify all 9 lint rules catch negative fixtures while passing clean code."""
    with tempfile.TemporaryDirectory(prefix="lg-lint-selftest-") as tmp_dir:
        tmp_root = Path(tmp_dir)
        (tmp_root / "src" / "ledger_guard" / "domain").mkdir(parents=True)
        (tmp_root / "tests").mkdir(parents=True)
        (tmp_root / "sql").mkdir(parents=True)

        bad_src = "\n".join(
            [
                "dsn = DATABASE_MIGRATOR_URL",
                "session['current_tenant_id'] = request.body('tenant_id')",
                "flag = user.is_active or True",
                "csp = \"script-src 'self' 'unsafe-inline'\"",
                'cur.execute(f"SELECT * FROM orders WHERE id = {oid}")',
                'robots = "Disallow: /admin"',
            ]
        )
        (tmp_root / "src" / "bad_runtime.py").write_text(bad_src, encoding="utf-8")
        (tmp_root / "src" / "ledger_guard" / "domain" / "bad_math.py").write_text(
            "x = float(10)\n",
            encoding="utf-8",
        )
        (tmp_root / "tests" / "test_bad.py").write_text(
            "def test_placeholder():\n    assert True\n",
            encoding="utf-8",
        )
        (tmp_root / "sql" / "001_bad.sql").write_text(
            "-- ALTER TABLE naked_orders FORCE ROW LEVEL SECURITY;\n"
            "CREATE TABLE naked_orders (id UUID PRIMARY KEY, tenant_id UUID NOT NULL);\n"
            "ALTER TABLE naked_orders ENABLE ROW LEVEL SECURITY;\n",
            encoding="utf-8",
        )

        found = scan(tmp_root)
        triggered_ids = {str(v["id"]) for v in found}
        expected_ids = {f"SEC-LINT-00{i}" for i in range(1, 10)}
        missing = sorted(expected_ids - triggered_ids)
        if missing:
            print(f"SELF-TEST FAIL: Rules failed to trigger: {', '.join(missing)}")
            return 1

    repo_violations = scan(ROOT)
    if repo_violations:
        print(f"SELF-TEST FAIL: Repository has {len(repo_violations)} active violation(s).")
        return 1

    print("SELF-TEST PASS: All 9 security/financial lint rules verified (negative + repo clean).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="LedgerGuard Security Invariant Linter")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--self-test", action="store_true", help="Run negative rule self-tests.")
    parser.add_argument("--sarif", type=Path, default=None, help="Optional SARIF 2.1.0 output.")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    violations = scan(args.root.resolve())
    if args.sarif is not None:
        sarif_doc = build_sarif_report(violations)
        args.sarif.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")

    if not violations:
        print("PASS: All 9 security and financial invariant lint rules satisfied (0 violations).")
        return 0

    print(f"FAIL: Found {len(violations)} security invariant violation(s):\n")
    for item in violations:
        print(f"[{item['id']}] {item['file']}:{item['line']} - {item['description']}")
        print(f"  Match: {item['snippet']}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
