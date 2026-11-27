#!/usr/bin/env python3
"""Security & Financial Invariant Linter for LedgerGuard (`AST` + regex + SQL RLS).

Executed in CI via `python3 scripts/security-lint.py --self-test` and `--sarif`.

Enforces architectural invariants that generic SAST tools miss:
1. SEC-LINT-001: Privileged/migrator/BYPASSRLS roles used in runtime Python code.
2. SEC-LINT-002: Trusting client-supplied tenant_id directly into session/GUC authority.
3. SEC-LINT-003: Fail-open defaults on authority booleans (`is_active or True`, `.get(..., True)`).
4. SEC-LINT-004: Wildcard proxy/CORS trust (`*`) or `'unsafe-inline'`/`'unsafe-eval'` in CSP.
5. SEC-LINT-005: Dynamic string interpolation in raw SQL `.execute()`/`.executemany()`.
6. SEC-LINT-006: Internal recon path leaks via `Disallow: /admin|/platform|/internal`.
7. SEC-LINT-007: Tautological placeholder assertions in test suites (`assert True`).
8. SEC-LINT-008: AST check forbidding `float` literals, `float()`, and `/` division in domain/app.
9. SEC-LINT-009: SQL tables missing ENABLE + FORCE RLS (or stripped by DISABLE/NO FORCE RLS).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypedDict

ROOT = Path(__file__).resolve().parent.parent

SOURCE_EXTENSIONS = {".py", ".sql", ".txt"}
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
        "description": "Privileged migrator/backup/BYPASSRLS DB credential or role in runtime code",
        "pattern": (
            r"(?:app_migrator|pgsql_migrator|pgsql_backup|"
            r"DATABASE_MIGRATOR_URL|db_superuser|\bBYPASSRLS\b)"
        ),
        "scope": "src",
        "allow_marker": "# RLS BYPASS JUSTIFICATION:",
    },
    {
        "id": "SEC-LINT-002",
        "description": "Client request tenant parameter trusted directly as session/GUC authority",
        "pattern": (
            r"(?:current_tenant_id|selected_tenant_id)[\s\S]{0,120}"
            r"(?:request\.(?:headers|query_params|cookies|path_params)|payload\.tenant_id)"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-003",
        "description": "Fail-open default on authority flag is prohibited (must fail closed)",
        "pattern": (
            r"(?:\b(?:is_active|is_admin|is_owner|has_access|is_verified|authorized)"
            r"\s*\bor\b\s*(?:True|1)\b"
            r"|\.(?:get|setdefault)\s*\(\s*['\"]"
            r"(?:is_active|is_admin|is_owner|has_access|is_verified|authorized)"
            r"['\"]\s*,\s*(?:True|1)\b"
            r"|getattr\s*\([^,]+,\s*['\"]"
            r"(?:is_active|is_admin|is_owner|has_access|is_verified|authorized)"
            r"['\"]\s*,\s*(?:True|1)\b)"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-004",
        "description": "Wildcard proxy/CORS trust or unsafe-inline/unsafe-eval in CSP",
        "pattern": (
            r"(?:['\"]unsafe-eval['\"]"
            r"|(?:default-src|script-src|style-src)[^;\n]*['\"]unsafe-inline['\"]"
            r"|trusted_proxy_cidrs\s*=\s*[\[(][^)\]]*['\"]\*['\"]"
            r"|allowed_hosts\s*=\s*\[?\s*['\"]\*['\"]"
            r"|allow_origins\s*=\s*\[?\s*['\"]\*['\"])"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-005",
        "description": "Dynamic interpolation in raw SQL execution; use parameterized bindings",
        "pattern": (
            r"\.(?:execute|executemany|exec_driver_sql)\s*\(\s*"
            r"(?:[rRfFbBuU]*[fF][\"']|[^)]*(?:\.format\s*\(|\s%\s|\s\+\s))"
        ),
        "scope": "src",
    },
    {
        "id": "SEC-LINT-006",
        "description": "Disallow internal path leak in robots.txt (use positive Allow rules)",
        "pattern": r"Disallow:\s*/(?:admin|platform|internal|agency|portal|dashboard)",
        "scope": "all",
    },
    {
        "id": "SEC-LINT-007",
        "description": "Tautological placeholder test assertion prohibited",
        "pattern": r"\bassert\s*\(?\s*(?:True|not\s+False|1\s*==\s*1)\b",
        "scope": "tests",
    },
]

AST_FLOAT_RULE_META: dict[str, str] = {
    "id": "SEC-LINT-008",
    "description": (
        "Binary float literal, float(), or true-division `/` prohibited in domain/application"
    ),
}

SQL_RLS_RULE_META: dict[str, str] = {
    "id": "SEC-LINT-009",
    "description": "SQL table declared without active ENABLE + FORCE ROW LEVEL SECURITY",
}

_CREATE_TABLE_RE = re.compile(
    r"\bCREATE\s+(?:(?:GLOBAL|LOCAL)\s+)?(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+|FOREIGN\s+)?TABLE\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:\"[^\"]+\"|[a-zA-Z_][\w]*)\.)?"
    r"(?:\"([^\"]+)\"|([a-zA-Z_][\w]*)\b)",
    re.IGNORECASE,
)


def strip_sql_comments_and_strings(sql_text: str) -> str:
    """Strip nested `/* ... */` / `-- ...` comments and `'...'` literals, preserving lines."""
    out: list[str] = []
    i = 0
    n = len(sql_text)
    block_depth = 0

    while i < n:
        ch = sql_text[i]
        nxt = sql_text[i + 1] if i + 1 < n else ""

        if block_depth > 0:
            if ch == "/" and nxt == "*":
                block_depth += 1
                out.extend((" ", " "))
                i += 2
            elif ch == "*" and nxt == "/":
                block_depth -= 1
                out.extend((" ", " "))
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue

        if ch == "/" and nxt == "*":
            block_depth = 1
            out.extend((" ", " "))
            i += 2
            continue

        if ch == "-" and nxt == "-":
            while i < n and sql_text[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if ch == "'":
            out.append("'")
            i += 1
            while i < n:
                sc = sql_text[i]
                if sc == "'" and i + 1 < n and sql_text[i + 1] == "'":
                    out.extend((" ", " "))
                    i += 2
                    continue
                if sc == "'":
                    out.append("'")
                    i += 1
                    break
                out.append("\n" if sc == "\n" else " ")
                i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def scan_sql_rls_invariants(rel_path: str, content: str) -> list[dict[str, Any]]:
    """Verify every SQL table has ENABLE + FORCE RLS and is never weakened."""
    stripped = strip_sql_comments_and_strings(content)
    violations: list[dict[str, Any]] = []

    for match in _CREATE_TABLE_RE.finditer(stripped):
        table_name = match.group(1) or match.group(2)
        line_no = stripped[: match.start()].count("\n") + 1
        table_ref = rf"(?:(?:\"[^\"]+\"|[a-zA-Z_][\w]*)\.)?\"?{re.escape(table_name)}\"?"

        enable_re = re.compile(
            rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{table_ref}\s+"
            rf"ENABLE\s+ROW\s+LEVEL\s+SECURITY\b",
            re.IGNORECASE,
        )
        force_re = re.compile(
            rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{table_ref}\s+"
            rf"FORCE\s+ROW\s+LEVEL\s+SECURITY\b",
            re.IGNORECASE,
        )
        weaken_re = re.compile(
            rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{table_ref}\s+"
            rf"(?:DISABLE|NO\s+FORCE)\s+ROW\s+LEVEL\s+SECURITY\b",
            re.IGNORECASE,
        )

        missing_parts: list[str] = []
        if enable_re.search(stripped) is None:
            missing_parts.append("ENABLE ROW LEVEL SECURITY")
        if force_re.search(stripped) is None:
            missing_parts.append("FORCE ROW LEVEL SECURITY")
        if weaken_re.search(stripped) is not None:
            missing_parts.append("weakened by DISABLE/NO FORCE ROW LEVEL SECURITY")

        if missing_parts:
            violations.append(
                {
                    "id": SQL_RLS_RULE_META["id"],
                    "description": (
                        f"{SQL_RLS_RULE_META['description']} "
                        f"(table '{table_name}': {', '.join(missing_parts)})"
                    ),
                    "file": rel_path,
                    "line": line_no,
                    "snippet": match.group(0).strip()[:140],
                }
            )
    return violations


def scan_python_ast_invariants(rel_path: str, content: str) -> list[dict[str, Any]]:
    """Enforce zero binary `float` literals, `float()`, or `/` division via Python AST."""
    violations: list[dict[str, Any]] = []
    try:
        tree = ast.parse(content, filename=rel_path)
    except SyntaxError:
        return violations

    for node in ast.walk(tree):
        hit_snippet: str | None = None
        if isinstance(node, ast.Constant) and isinstance(node.value, float):
            hit_snippet = repr(node.value)
        elif isinstance(node, ast.Name) and node.id == "float":
            hit_snippet = "float"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            hit_snippet = "true division (/)"

        if hit_snippet is not None:
            violations.append(
                {
                    "id": AST_FLOAT_RULE_META["id"],
                    "description": AST_FLOAT_RULE_META["description"],
                    "file": rel_path,
                    "line": getattr(node, "lineno", 1),
                    "snippet": hit_snippet,
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
        is_domain_or_app = rel.startswith("src/ledger_guard/domain/") or rel.startswith(
            "src/ledger_guard/application/"
        )
        is_sql = file_path.suffix == ".sql"
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if is_sql:
            violations.extend(scan_sql_rls_invariants(rel, content))

        if is_domain_or_app and file_path.suffix == ".py":
            violations.extend(scan_python_ast_invariants(rel, content))

        lines = content.splitlines()
        for rule, regex in compiled:
            scope = rule.get("scope", "src")
            if scope == "tests" and not is_test:
                continue
            if scope == "src" and not (is_src and file_path.suffix == ".py"):
                continue

            for match in regex.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                marker = rule.get("allow_marker")
                if marker and 1 <= line_no <= len(lines):
                    cur_line = lines[line_no - 1]
                    prev_line = lines[line_no - 2] if line_no >= 2 else ""
                    if marker in cur_line or marker in prev_line:
                        continue
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
    """Build a SARIF 2.1.0 report for CI archiving and security scanning."""
    all_rules = [
        {"id": r["id"], "shortDescription": {"text": r["description"]}} for r in BANNED_RULES
    ]
    all_rules.append(
        {
            "id": AST_FLOAT_RULE_META["id"],
            "shortDescription": {"text": AST_FLOAT_RULE_META["description"]},
        }
    )
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
                        "version": "0.3.0",
                        "rules": all_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def run_self_test() -> int:
    """Verify all 9 lint rules catch adversarial fixtures while passing the clean repo."""
    with tempfile.TemporaryDirectory(prefix="lg-lint-selftest-") as tmp_dir:
        tmp_root = Path(tmp_dir)
        (tmp_root / "src" / "ledger_guard" / "domain").mkdir(parents=True)
        (tmp_root / "src" / "ledger_guard" / "application").mkdir(parents=True)
        (tmp_root / "tests").mkdir(parents=True)
        (tmp_root / "sql").mkdir(parents=True)

        bad_src = "\n".join(
            [
                'role_name = "app_migrator"',
                "current_tenant_id = request.headers.get('X-Tenant')",
                'active = payload.get("is_active", True)',
                "csp = \"style-src 'self' 'unsafe-inline'\"",
                'cur.execute(rf"SELECT * FROM orders WHERE id = {oid}")',
            ]
        )
        (tmp_root / "src" / "bad_runtime.py").write_text(bad_src, encoding="utf-8")
        (tmp_root / "robots.txt").write_text("Disallow: /admin\n", encoding="utf-8")
        (tmp_root / "src" / "ledger_guard" / "domain" / "bad_math.py").write_text(
            "price_ratio = 1.5\nhalf = 1 / 2\n",
            encoding="utf-8",
        )
        (tmp_root / "tests" / "test_bad.py").write_text(
            "def test_placeholder():\n    assert(True)\n",
            encoding="utf-8",
        )
        (tmp_root / "sql" / "001_bad.sql").write_text(
            "/* outer /* inner */ ALTER TABLE \"naked_orders\" FORCE ROW LEVEL SECURITY; */\n"
            'CREATE UNLOGGED TABLE "naked_orders" (id UUID PRIMARY KEY, tenant_id UUID NOT NULL);\n'
            'ALTER TABLE "naked_orders" ENABLE ROW LEVEL SECURITY;\n'
            "SELECT 'ALTER TABLE \"naked_orders\" FORCE ROW LEVEL SECURITY';\n",
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
        print(f"SELF-TEST FAIL: Repository has {len(repo_violations)} active violation(s):")
        for item in repo_violations:
            print(f"  [{item['id']}] {item['file']}:{item['line']} - {item['snippet']}")
        return 1

    print("SELF-TEST PASS: All 9 security/AST/SQL lint rules verified (negative + repo clean).")
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
