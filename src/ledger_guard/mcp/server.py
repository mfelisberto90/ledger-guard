"""Model Context Protocol (MCP) JSON-RPC 2.0 tool server sharing `OrderService`."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from ledger_guard.application.order_service import OrderLineCommand, OrderService
from ledger_guard.domain.errors import AuthorizationError, DomainError, ValidationError
from ledger_guard.domain.margin_gate import OrderKind, PrincipalContext
from ledger_guard.domain.money import Currency, require_strict_int
from ledger_guard.security.idempotency import IdempotencyCoordinator
from ledger_guard.security.redaction import Redactor

SERVER_VERSION: str = "0.2.0"
DEFAULT_MCP_PROTOCOL_VERSION: str = "2025-03-26"
SUPPORTED_MCP_PROTOCOL_VERSIONS: frozenset[str] = frozenset(
    {
        "2025-06-18",
        "2025-03-26",
        "2024-11-05",
    }
)

_CREATE_ORDER_KEYS: frozenset[str] = frozenset(
    {
        "idempotency_key",
        "customer_ref",
        "order_kind",
        "currency",
        "header_discount_bps",
        "header_discount_minor",
        "passthrough_freight_minor",
        "small_order_surcharge_minor",
        "lines",
    }
)
_CREATE_ORDER_LINE_KEYS: frozenset[str] = frozenset(
    {
        "sku",
        "quantity",
        "unit_price_minor",
        "manual_discount_bps",
    }
)
_GET_ORDER_KEYS: frozenset[str] = frozenset({"order_id"})
_LIST_ORDERS_KEYS: frozenset[str] = frozenset({"limit"})
_CONFIRM_ORDER_KEYS: frozenset[str] = frozenset(
    {"idempotency_key", "order_id", "expected_version"}
)
_APPROVE_MARGIN_KEYS: frozenset[str] = frozenset(
    {"idempotency_key", "order_id", "expected_version", "reason"}
)
_AMEND_ORDER_LINE_KEYS: frozenset[str] = frozenset(
    {
        "idempotency_key",
        "order_id",
        "line_id",
        "expected_version",
        "quantity",
        "unit_price_minor",
        "manual_discount_bps",
        "header_discount_bps",
        "header_discount_minor",
    }
)
_EXPORT_ORDERS_CSV_KEYS: frozenset[str] = frozenset()

MCP_TOOLS_SPEC: tuple[dict[str, Any], ...] = (
    {
        "name": "create_order",
        "title": "Create Governed Order",
        "description": (
            "Price and create a tenant-scoped B2B sales order using exact Fraction UoM "
            "arithmetic, immutable inventory CostSnapshots, and margin-floor governance. "
            "Requires capability 'orders:write'."
        ),
        "annotations": {
            "title": "Create Governed Order",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "customer_ref", "currency", "lines"],
            "properties": {
                "idempotency_key": {
                    "type": "string",
                    "minLength": 8,
                    "maxLength": 128,
                    "description": "Unique client mutation key bound to payload SHA-256.",
                },
                "customer_ref": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "description": "Buyer purchase order reference or account code.",
                },
                "order_kind": {
                    "type": "string",
                    "enum": [k.value for k in OrderKind],
                    "default": "standard",
                    "description": "Commercial order classification.",
                },
                "currency": {
                    "type": "string",
                    "enum": [c.value for c in Currency],
                    "description": "ISO 4217 currency code.",
                },
                "header_discount_bps": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10000,
                    "description": "Proportional header discount in basis points (100 bps = 1%).",
                },
                "header_discount_minor": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Fixed header discount in integer minor currency units.",
                },
                "passthrough_freight_minor": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "Pass-through carrier freight in minor units "
                        "(excluded from margin basis)."
                    ),
                },
                "small_order_surcharge_minor": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "Small-order surcharge in minor units (excluded from margin basis)."
                    ),
                },
                "lines": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 200,
                    "description": "Commercial order lines to price.",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["sku", "quantity"],
                        "properties": {
                            "sku": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 64,
                                "description": "Catalog SKU identifier.",
                            },
                            "quantity": {
                                "type": ["integer", "string"],
                                "description": (
                                    "Positive integer or exact rational string (e.g. '3/2')."
                                ),
                            },
                            "unit_price_minor": {
                                "type": "integer",
                                "minimum": 0,
                                "description": (
                                    "Optional selling unit price override in minor units."
                                ),
                            },
                            "manual_discount_bps": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 10000,
                                "description": "Optional manual line discount in basis points.",
                            },
                        },
                    },
                },
            },
        },
    },
    {
        "name": "get_order",
        "title": "Get Order",
        "description": (
            "Fetch a single tenant-scoped sales order with capability-projected cost and "
            "margin fields. Requires capability 'orders:read'."
        ),
        "annotations": {
            "title": "Get Order",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["order_id"],
            "properties": {
                "order_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Target order UUID within the caller's tenant.",
                },
            },
        },
    },
    {
        "name": "list_orders",
        "title": "List Orders",
        "description": (
            "List recent tenant-scoped sales orders with capability-projected cost and "
            "margin fields stripped according to caller permissions. Requires 'orders:read'."
        ),
        "annotations": {
            "title": "List Orders",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                    "description": "Maximum number of orders to return (1..200).",
                },
            },
        },
    },
    {
        "name": "confirm_order",
        "title": "Confirm Order",
        "description": (
            "Confirm a governed sales order when all readiness gates evaluate to met=true. "
            "Requires capability 'orders:confirm' and matching optimistic expected_version."
        ),
        "annotations": {
            "title": "Confirm Order",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "order_id", "expected_version"],
            "properties": {
                "idempotency_key": {
                    "type": "string",
                    "minLength": 8,
                    "maxLength": 128,
                    "description": "Unique client mutation key bound to payload SHA-256.",
                },
                "order_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Target order UUID to confirm.",
                },
                "expected_version": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Optimistic concurrency aggregate version.",
                },
            },
        },
    },
    {
        "name": "approve_margin",
        "title": "Approve Margin Exception",
        "description": (
            "Record an append-only four-eyes margin exception approval with mandatory reason. "
            "Approver must hold 'orders:margin:approve' and be distinct from creator/amender."
        ),
        "annotations": {
            "title": "Approve Margin Exception",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "order_id", "expected_version", "reason"],
            "properties": {
                "idempotency_key": {
                    "type": "string",
                    "minLength": 8,
                    "maxLength": 128,
                    "description": "Unique client mutation key bound to payload SHA-256.",
                },
                "order_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Target order UUID awaiting margin exception approval.",
                },
                "expected_version": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Optimistic concurrency aggregate version.",
                },
                "reason": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1000,
                    "description": "Commercial justification recorded in the audit trail.",
                },
            },
        },
    },
    {
        "name": "amend_order_line",
        "title": "Amend Order Line",
        "description": (
            "Amend commercial pricing or quantity on an existing order line while preserving "
            "immutable CostSnapshots and re-evaluating margin floor gates. Requires 'orders:write'."
        ),
        "annotations": {
            "title": "Amend Order Line",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "order_id", "line_id", "expected_version"],
            "properties": {
                "idempotency_key": {
                    "type": "string",
                    "minLength": 8,
                    "maxLength": 128,
                    "description": "Unique client mutation key bound to payload SHA-256.",
                },
                "order_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Target order UUID.",
                },
                "line_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Target line UUID on the order.",
                },
                "expected_version": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Optimistic concurrency aggregate version.",
                },
                "quantity": {
                    "type": ["integer", "string"],
                    "description": "Updated positive integer or rational quantity string.",
                },
                "unit_price_minor": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Updated selling unit price in minor units.",
                },
                "manual_discount_bps": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10000,
                    "description": "Updated manual line discount in basis points.",
                },
                "header_discount_bps": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10000,
                    "description": "Updated proportional header discount in basis points.",
                },
                "header_discount_minor": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Updated fixed header discount in minor units.",
                },
            },
        },
    },
    {
        "name": "export_orders_csv",
        "title": "Export Orders CSV",
        "description": (
            "Export tenant orders as formula-injection-sanitized CSV with cost and margin "
            "columns gated by 'valuation:cost:read' and 'orders:margin:read'. "
            "Requires 'orders:export'."
        ),
        "annotations": {
            "title": "Export Orders CSV",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
    },
)


def _parse_uuid_arg(raw: object, field_name: str) -> UUID:
    if not isinstance(raw, str):
        raise ValidationError(f"Field '{field_name}' must be a UUID string.")
    try:
        return UUID(raw.strip())
    except ValueError as exc:
        raise ValidationError(f"Field '{field_name}' is not a valid UUID.") from exc


def _require_str_arg(args: Mapping[str, Any], field_name: str) -> str:
    raw = args.get(field_name)
    if not isinstance(raw, str):
        raise ValidationError(f"Field '{field_name}' must be a string.")
    return raw


def _reject_client_tenant_override(args: Mapping[str, Any]) -> None:
    if "tenant_id" in args:
        raise AuthorizationError(
            "Client-supplied tenant_id is forbidden; tenant scope is bound server-side.",
            code="CLIENT_TENANT_OVERRIDE_FORBIDDEN",
        )


def _validate_allowed_keys(
    args: Mapping[str, Any],
    allowed_keys: frozenset[str],
    context: str,
) -> None:
    _reject_client_tenant_override(args)
    unknown = sorted(set(args.keys()) - allowed_keys)
    if unknown:
        raise ValidationError(
            f"Unknown argument(s) for {context}: {', '.join(unknown)}.",
            code="UNKNOWN_TOOL_ARGUMENTS",
            details={"unknown_arguments": unknown},
        )


class McpToolServer:
    """MCP JSON-RPC 2.0 dispatcher enforcing identical RBAC, idempotency, and projection."""

    def __init__(
        self,
        *,
        order_service: OrderService,
        idempotency: IdempotencyCoordinator,
        redactor: Redactor,
    ) -> None:
        self._orders = order_service
        self._idempotency = idempotency
        self._redactor = redactor

    def handle_jsonrpc(
        self,
        principal: PrincipalContext,
        rpc_request: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Handle an MCP JSON-RPC 2.0 request or notification (`None` for notifications)."""
        is_notification = "id" not in rpc_request
        req_id = rpc_request.get("id")
        if rpc_request.get("jsonrpc") != "2.0":
            return self._rpc_error(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'.")

        method = rpc_request.get("method")
        if not isinstance(method, str) or not method:
            return self._rpc_error(req_id, -32600, "Invalid Request: method string required.")

        if is_notification or method.startswith("notifications/"):
            return None

        if method == "initialize":
            params = rpc_request.get("params")
            requested_version = (
                params.get("protocolVersion") if isinstance(params, Mapping) else None
            )
            negotiated_version = (
                requested_version
                if isinstance(requested_version, str)
                and requested_version in SUPPORTED_MCP_PROTOCOL_VERSIONS
                else DEFAULT_MCP_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated_version,
                    "serverInfo": {"name": "ledger-guard-mcp", "version": SERVER_VERSION},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }

        if method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {},
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": list(MCP_TOOLS_SPEC)},
            }

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": []},
            }

        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"prompts": []},
            }

        if method == "tools/call":
            params = rpc_request.get("params")
            if not isinstance(params, Mapping):
                return self._rpc_error(req_id, -32602, "Invalid params: object expected.")
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, Mapping):
                return self._rpc_error(
                    req_id, -32602, "Invalid params: tool name and arguments map required."
                )
            return self._dispatch_tool(req_id, principal, tool_name, arguments)

        return self._rpc_error(req_id, -32601, f"Method '{method}' not supported.")

    def _dispatch_tool(
        self,
        req_id: Any,
        principal: PrincipalContext,
        tool_name: str,
        args: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            _reject_client_tenant_override(args)

            if tool_name == "get_order":
                _validate_allowed_keys(args, _GET_ORDER_KEYS, "get_order")
                order_id = _parse_uuid_arg(args.get("order_id"), "order_id")
                result_payload = self._orders.get_order(principal, order_id=order_id)
                return self._tool_success(req_id, result_payload, replayed=False)

            if tool_name == "list_orders":
                _validate_allowed_keys(args, _LIST_ORDERS_KEYS, "list_orders")
                raw_limit = args.get("limit", 50)
                limit = require_strict_int(raw_limit, "limit")
                result_payload = self._orders.list_orders(principal, limit=limit)
                return self._tool_success(req_id, result_payload, replayed=False)

            if tool_name == "export_orders_csv":
                _validate_allowed_keys(args, _EXPORT_ORDERS_CSV_KEYS, "export_orders_csv")
                csv_text = self._orders.export_orders_csv(principal)
                line_count = max(0, len(csv_text.splitlines()) - 1)
                return self._tool_success(
                    req_id,
                    {"csv": csv_text, "row_count": line_count},
                    replayed=False,
                )

            if tool_name == "create_order":
                _validate_allowed_keys(args, _CREATE_ORDER_KEYS, "create_order")
                idem_key = _require_str_arg(args, "idempotency_key")
                outcome = self._idempotency.execute(
                    tenant_id=principal.tenant_id,
                    principal_id=principal.principal_id,
                    action="mcp:create_order",
                    idempotency_key=idem_key,
                    payload=dict(args),
                    handler=lambda: (201, self._exec_create_order(principal, args)),
                )
                return self._tool_success(req_id, outcome.body, replayed=outcome.replayed)

            if tool_name == "confirm_order":
                _validate_allowed_keys(args, _CONFIRM_ORDER_KEYS, "confirm_order")
                idem_key = _require_str_arg(args, "idempotency_key")
                order_id = _parse_uuid_arg(args.get("order_id"), "order_id")
                exp_ver = require_strict_int(args.get("expected_version"), "expected_version")
                outcome = self._idempotency.execute(
                    tenant_id=principal.tenant_id,
                    principal_id=principal.principal_id,
                    action=f"mcp:confirm_order:{order_id}",
                    idempotency_key=idem_key,
                    payload=dict(args),
                    handler=lambda: (
                        200,
                        self._orders.confirm_order(
                            principal, order_id=order_id, expected_version=exp_ver
                        ),
                    ),
                )
                return self._tool_success(req_id, outcome.body, replayed=outcome.replayed)

            if tool_name == "approve_margin":
                _validate_allowed_keys(args, _APPROVE_MARGIN_KEYS, "approve_margin")
                idem_key = _require_str_arg(args, "idempotency_key")
                order_id = _parse_uuid_arg(args.get("order_id"), "order_id")
                exp_ver = require_strict_int(args.get("expected_version"), "expected_version")
                reason = _require_str_arg(args, "reason")
                outcome = self._idempotency.execute(
                    tenant_id=principal.tenant_id,
                    principal_id=principal.principal_id,
                    action=f"mcp:approve_margin:{order_id}",
                    idempotency_key=idem_key,
                    payload=dict(args),
                    handler=lambda: (
                        200,
                        self._orders.approve_margin(
                            principal,
                            order_id=order_id,
                            expected_version=exp_ver,
                            reason=reason,
                        ),
                    ),
                )
                return self._tool_success(req_id, outcome.body, replayed=outcome.replayed)

            if tool_name == "amend_order_line":
                _validate_allowed_keys(args, _AMEND_ORDER_LINE_KEYS, "amend_order_line")
                idem_key = _require_str_arg(args, "idempotency_key")
                order_id = _parse_uuid_arg(args.get("order_id"), "order_id")
                line_id = _parse_uuid_arg(args.get("line_id"), "line_id")
                exp_ver = require_strict_int(args.get("expected_version"), "expected_version")
                outcome = self._idempotency.execute(
                    tenant_id=principal.tenant_id,
                    principal_id=principal.principal_id,
                    action=f"mcp:amend_order_line:{order_id}:{line_id}",
                    idempotency_key=idem_key,
                    payload=dict(args),
                    handler=lambda: (
                        200,
                        self._exec_amend_line(principal, order_id, line_id, exp_ver, args),
                    ),
                )
                return self._tool_success(req_id, outcome.body, replayed=outcome.replayed)

            return self._rpc_error(req_id, -32601, f"Unknown MCP tool '{tool_name}'.")
        except DomainError as err:
            safe_error = {
                "code": err.code,
                "http_status": err.http_status,
                "message": self._redactor.redact_text(err.message),
                "details": self._redactor.redact_structure(err.details),
            }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": safe_error})}],
                    "structuredContent": {"error": safe_error},
                    "isError": True,
                },
            }

    def _exec_create_order(
        self,
        principal: PrincipalContext,
        args: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw_lines = args.get("lines")
        if not isinstance(raw_lines, list) or not raw_lines:
            raise ValidationError("MCP create_order requires a non-empty 'lines' array.")

        commands: list[OrderLineCommand] = []
        for idx, entry in enumerate(raw_lines):
            if not isinstance(entry, Mapping):
                raise ValidationError("Each line entry must be an object.")
            _validate_allowed_keys(entry, _CREATE_ORDER_LINE_KEYS, f"create_order.lines[{idx}]")
            sku = _require_str_arg(entry, "sku")
            raw_qty = entry.get("quantity")
            if not isinstance(raw_qty, (int, str)) or isinstance(raw_qty, bool):
                raise ValidationError("Line quantity must be integer or rational string.")
            raw_price = entry.get("unit_price_minor")
            unit_price = (
                None if raw_price is None else require_strict_int(raw_price, "unit_price_minor")
            )
            disc_bps = require_strict_int(
                entry.get("manual_discount_bps", 0), "manual_discount_bps"
            )
            commands.append(
                OrderLineCommand(
                    sku=sku,
                    quantity=raw_qty,
                    unit_price_minor=unit_price,
                    manual_discount_bps=disc_bps,
                )
            )

        raw_currency = _require_str_arg(args, "currency")
        try:
            currency = Currency(raw_currency)
        except ValueError as exc:
            raise ValidationError("Unsupported currency code.") from exc

        raw_order_kind = args.get("order_kind", "standard")
        if not isinstance(raw_order_kind, str):
            raise ValidationError("Field 'order_kind' must be a string.")
        try:
            order_kind = OrderKind(raw_order_kind)
        except ValueError as exc:
            raise ValidationError("Unsupported order_kind classification.") from exc

        customer_ref = _require_str_arg(args, "customer_ref")

        return self._orders.create_order(
            principal,
            customer_ref=customer_ref,
            order_kind=order_kind,
            currency=currency,
            lines=commands,
            header_discount_bps=require_strict_int(
                args.get("header_discount_bps", 0), "header_discount_bps"
            ),
            header_discount_minor=require_strict_int(
                args.get("header_discount_minor", 0), "header_discount_minor"
            ),
            passthrough_freight_minor=require_strict_int(
                args.get("passthrough_freight_minor", 0), "passthrough_freight_minor"
            ),
            small_order_surcharge_minor=require_strict_int(
                args.get("small_order_surcharge_minor", 0), "small_order_surcharge_minor"
            ),
        )

    def _exec_amend_line(
        self,
        principal: PrincipalContext,
        order_id: UUID,
        line_id: UUID,
        expected_version: int,
        args: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw_qty = args.get("quantity")
        if raw_qty is not None and (
            not isinstance(raw_qty, (int, str)) or isinstance(raw_qty, bool)
        ):
            raise ValidationError("quantity must be integer or rational string.")

        raw_price = args.get("unit_price_minor")
        unit_price = (
            None if raw_price is None else require_strict_int(raw_price, "unit_price_minor")
        )
        raw_disc = args.get("manual_discount_bps")
        manual_disc = (
            None if raw_disc is None else require_strict_int(raw_disc, "manual_discount_bps")
        )
        raw_hdr_bps = args.get("header_discount_bps")
        hdr_bps = (
            None
            if raw_hdr_bps is None
            else require_strict_int(raw_hdr_bps, "header_discount_bps")
        )
        raw_hdr_minor = args.get("header_discount_minor")
        hdr_minor = (
            None
            if raw_hdr_minor is None
            else require_strict_int(raw_hdr_minor, "header_discount_minor")
        )

        return self._orders.amend_order_line(
            principal,
            order_id=order_id,
            line_id=line_id,
            expected_version=expected_version,
            quantity=raw_qty,
            unit_price_minor=unit_price,
            manual_discount_bps=manual_disc,
            header_discount_bps=hdr_bps,
            header_discount_minor=hdr_minor,
        )

    @staticmethod
    def _tool_success(
        req_id: Any,
        payload: dict[str, Any],
        *,
        replayed: bool,
    ) -> dict[str, Any]:
        envelope = dict(payload)
        envelope["idempotent_replay"] = replayed
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(envelope)}],
                "structuredContent": envelope,
                "isError": False,
            },
        }

    def _rpc_error(self, req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": self._redactor.redact_text(message),
            },
        }
