"""CSV export serializer neutralizing ASCII and Unicode full-width formula injection."""

from __future__ import annotations

import csv
import io
from collections.abc import Mapping, Sequence

_DANGEROUS_FORMULA_PREFIXES: frozenset[str] = frozenset(
    {
        "=",
        "+",
        "-",
        "@",
        "\t",
        "\r",
        "\n",
        "\uff1d",  # U+FF1D full-width equals sign
        "\uff0b",  # U+FF0B full-width plus sign
        "\uff0d",  # U+FF0D full-width hyphen-minus
        "\uff20",  # U+FF20 full-width commercial at
    }
)


def sanitize_csv_cell(value: object) -> str:
    """Neutralize spreadsheet formula triggers, including after leading whitespace."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)

    text = str(value)
    if not text:
        return ""

    if text[0] in _DANGEROUS_FORMULA_PREFIXES:
        return f"'{text}"

    stripped = text.lstrip()
    if stripped and stripped[0] in _DANGEROUS_FORMULA_PREFIXES:
        return f"'{text}"

    return text


def serialize_rows_to_csv(
    rows: Sequence[Mapping[str, object]],
    fieldnames: Sequence[str],
) -> str:
    """Serialize projected records into RFC 4180 CSV with formula-injection protection."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([sanitize_csv_cell(col) for col in fieldnames])
    for row in rows:
        writer.writerow([sanitize_csv_cell(row.get(col, "")) for col in fieldnames])
    return buffer.getvalue()
