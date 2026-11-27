"""Shared Pydantic request/tool schemas and MCP schema generator (REST + MCP single source)."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt
from pydantic import ValidationError as PydanticValidationError

from ledger_guard.domain.errors import AuthorizationError, ValidationError
from ledger_guard.domain.margin_gate import OrderKind
from ledger_guard.domain.money import MAX_INT32, MAX_MINOR_AMOUNT, Currency

_INT_BOUND_FIELDS: frozenset[str] = frozenset(
    {
        "unit_price_minor",
        "manual_discount_bps",
        "header_discount_bps",
        "header_discount_minor",
        "passthrough_freight_minor",
        "small_order_surcharge_minor",
        "expected_version",
        "limit",
        "ttl_seconds",
    }
)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    principal_id: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class DelegateTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capabilities: list[str] = Field(min_length=1, max_length=32)
    ttl_seconds: StrictInt = Field(default=900, ge=60, le=3_600)


class CreateOrderLinePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sku: str = Field(min_length=1, max_length=64, description="Catalog SKU identifier.")
    quantity: StrictInt | str = Field(
        description="Positive integer or exact rational string (e.g. '3/2')."
    )
    unit_price_minor: StrictInt | None = Field(
        default=None,
        ge=0,
        le=MAX_MINOR_AMOUNT,
        description="Optional selling unit price override in minor units.",
    )
    manual_discount_bps: StrictInt = Field(
        default=0,
        ge=0,
        le=10_000,
        description="Optional manual line discount in basis points.",
    )


class CreateOrderPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_ref: str = Field(
        min_length=1,
        max_length=128,
        description="Buyer purchase order reference or account code.",
    )
    order_kind: OrderKind = Field(
        default=OrderKind.STANDARD,
        description="Commercial order classification.",
    )
    currency: Currency = Field(description="ISO 4217 currency code.")
    header_discount_bps: StrictInt = Field(
        default=0,
        ge=0,
        le=10_000,
        description="Proportional header discount in basis points (100 bps = 1%).",
    )
    header_discount_minor: StrictInt = Field(
        default=0,
        ge=0,
        le=MAX_MINOR_AMOUNT,
        description="Fixed header discount in integer minor currency units.",
    )
    passthrough_freight_minor: StrictInt = Field(
        default=0,
        ge=0,
        le=MAX_MINOR_AMOUNT,
        description="Pass-through carrier freight in minor units (excluded from margin basis).",
    )
    small_order_surcharge_minor: StrictInt = Field(
        default=0,
        ge=0,
        le=MAX_MINOR_AMOUNT,
        description="Small-order surcharge in minor units (excluded from margin basis).",
    )
    lines: list[CreateOrderLinePayload] = Field(
        min_length=1,
        max_length=200,
        description="Commercial order lines to price.",
    )


class ConfirmOrderPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(
        ge=1,
        le=MAX_INT32,
        description="Optimistic concurrency aggregate version.",
    )


class ApproveMarginPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(
        ge=1,
        le=MAX_INT32,
        description="Optimistic concurrency aggregate version.",
    )
    reason: str = Field(
        min_length=1,
        max_length=1_000,
        description="Commercial justification recorded in the audit trail.",
    )


class AmendOrderLinePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(
        ge=1,
        le=MAX_INT32,
        description="Optimistic concurrency aggregate version.",
    )
    quantity: StrictInt | str | None = Field(
        default=None,
        description="Updated positive integer or rational quantity string.",
    )
    unit_price_minor: StrictInt | None = Field(
        default=None,
        ge=0,
        le=MAX_MINOR_AMOUNT,
        description="Updated selling unit price in minor units.",
    )
    manual_discount_bps: StrictInt | None = Field(
        default=None,
        ge=0,
        le=10_000,
        description="Updated manual line discount in basis points.",
    )
    header_discount_bps: StrictInt | None = Field(
        default=None,
        ge=0,
        le=10_000,
        description="Updated proportional header discount in basis points.",
    )
    header_discount_minor: StrictInt | None = Field(
        default=None,
        ge=0,
        le=MAX_MINOR_AMOUNT,
        description="Updated fixed header discount in minor units.",
    )


class CreateOrderToolArgs(CreateOrderPayload):
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        description="Unique client mutation key bound to payload SHA-256.",
    )


class GetOrderToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order_id: UUID = Field(description="Target order UUID within the caller's tenant.")


class ListOrdersToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: StrictInt = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of orders to return (1..200).",
    )


class ConfirmOrderToolArgs(ConfirmOrderPayload):
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        description="Unique client mutation key bound to payload SHA-256.",
    )
    order_id: UUID = Field(description="Target order UUID to confirm.")


class ApproveMarginToolArgs(ApproveMarginPayload):
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        description="Unique client mutation key bound to payload SHA-256.",
    )
    order_id: UUID = Field(description="Target order UUID awaiting margin exception approval.")


class AmendOrderLineToolArgs(AmendOrderLinePayload):
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        description="Unique client mutation key bound to payload SHA-256.",
    )
    order_id: UUID = Field(description="Target order UUID.")
    line_id: UUID = Field(description="Target line UUID on the order.")


class ExportOrdersCsvToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _inline_json_schema_node(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, list):
        return [_inline_json_schema_node(item, defs) for item in node]
    if not isinstance(node, dict):
        return node

    out: dict[str, Any] = {}
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        def_name = ref[len("#/$defs/") :]
        resolved = _inline_json_schema_node(deepcopy(defs[def_name]), defs)
        if isinstance(resolved, dict):
            out.update(resolved)

    for key, val in node.items():
        if key in {"$ref", "$defs", "title"}:
            continue
        if key == "anyOf" and isinstance(val, list):
            non_null = [v for v in val if not (isinstance(v, dict) and v.get("type") == "null")]
            if len(non_null) == 1:
                resolved = _inline_json_schema_node(non_null[0], defs)
                if isinstance(resolved, dict):
                    out.update(resolved)
                continue
            types = [v["type"] for v in non_null if isinstance(v, dict) and "type" in v]
            if len(types) == len(non_null) and types:
                out["type"] = types
                continue
        out[key] = _inline_json_schema_node(val, defs)
    return out


def pydantic_to_mcp_input_schema(model_cls: type[BaseModel]) -> dict[str, Any]:
    """Generate a self-contained JSON Schema from a Pydantic model for MCP `tools/list`."""
    raw = model_cls.model_json_schema()
    defs = raw.pop("$defs", {})
    schema = _inline_json_schema_node(raw, defs)
    if isinstance(schema, dict):
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})
        schema["additionalProperties"] = False
        return schema
    return {"type": "object", "additionalProperties": False, "properties": {}}


def _find_tenant_override(obj: object) -> bool:
    if isinstance(obj, Mapping):
        if "tenant_id" in obj:
            return True
        return any(_find_tenant_override(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_find_tenant_override(item) for item in obj)
    return False


def validate_mcp_arguments[T: BaseModel](model_cls: type[T], args: Mapping[str, Any]) -> T:
    """Validate MCP tool arguments using shared Pydantic contracts (`extra="forbid"`)."""
    if _find_tenant_override(args):
        raise AuthorizationError(
            "Client-supplied tenant_id is forbidden; tenant scope is bound server-side.",
            code="CLIENT_TENANT_OVERRIDE_FORBIDDEN",
        )
    try:
        return model_cls.model_validate(dict(args))
    except PydanticValidationError as exc:
        errors = exc.errors(include_input=False)
        extra_fields = [
            ".".join(str(part) for part in err["loc"])
            for err in errors
            if err.get("type") == "extra_forbidden"
        ]
        if extra_fields:
            raise ValidationError(
                f"Unknown argument(s): {', '.join(sorted(extra_fields))}.",
                code="UNKNOWN_TOOL_ARGUMENTS",
                details={"unknown_arguments": sorted(extra_fields)},
            ) from exc

        for err in errors:
            loc = err.get("loc", ())
            last_loc = str(loc[-1]) if loc else ""
            err_type = str(err.get("type", ""))
            if last_loc in _INT_BOUND_FIELDS and (
                err_type.startswith("int") or err_type == "bool_parsing"
            ):
                raise ValidationError(
                    f"Field '{last_loc}' must be an exact integer.",
                    code="NON_INTEGER_AMOUNT",
                ) from exc

        summary = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in errors[:3])
        raise ValidationError(f"Tool arguments failed bounded validation: {summary}") from exc
