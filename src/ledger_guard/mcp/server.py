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

MCP_TOOLS_SPEC: tuple[dict[str, Any], ...] = (
    {
        "name": "create_order",
        "description": (
            "Price and create a commercial order using exact Fraction UoM arithmetic "
            "and tenant margin-floor governance."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "customer_ref", "currency", "lines"],
            "properties": {
                "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 128},
                "customer_ref": {"type": "string", "minLength": 1, "maxLength": 128},
                "order_kind": {
                    "type": "string",
                    "enum": [k.value for k in OrderKind],
                    "default": "standard",
                },
                "currency": {"type": "string", "enum": [c.value for c in Currency]},
                "header_discount_bps": {"type": "integer", "minimum": 0, "maximum": 10000},
                "header_discount_minor": {"type": "integer", "minimum": 0},
                "passthrough_freight_minor": {"type": "integer", "minimum": 0},
                "small_order_surcharge_minor": {"type": "integer", "minimum": 0},
                "lines": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 200,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["sku", "quantity"],
                        "properties": {
                            "sku": {"type": "string"},
                            "quantity": {"type": ["integer", "string"]},
                            "unit_price_minor": {"type": "integer", "minimum": 0},
                            "manual_discount_bps": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 10000,
                            },
                        },
                    },
                },
            },
        },
    },
    {
        "name": "get_order",
        "description": "Fetch a tenant-scoped order with capability-projected cost/margin fields.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["order_id"],
            "properties": {
                "order_id": {"type": "string", "format": "uuid"},
            },
        },
    },
    {
        "name": "confirm_order",
        "description": "Confirm an order when readiness gates evaluate to met=true.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "order_id", "expected_version"],
            "properties": {
                "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 128},
                "order_id": {"type": "string", "format": "uuid"},
                "expected_version": {"type": "integer", "minimum": 1},
            },
        },
    },
    {
        "name": "approve_margin",
        "description": "Record a four-eyes margin exception approval with mandatory reason.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "order_id", "expected_version", "reason"],
            "properties": {
                "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 128},
                "order_id": {"type": "string", "format": "uuid"},
                "expected_version": {"type": "integer", "minimum": 1},
                "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
            },
        },
    },
    {
        "name": "amend_order_line",
        "description": "Amend order line commercial pricing and re-evaluate margin floor gates.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["idempotency_key", "order_id", "line_id", "expected_version"],
            "properties": {
                "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 128},
                "order_id": {"type": "string", "format": "uuid"},
                "line_id": {"type": "string", "format": "uuid"},
                "expected_version": {"type": "integer", "minimum": 1},
                "quantity": {"type": ["integer", "string"]},
                "unit_price_minor": {"type": "integer", "minimum": 0},
                "manual_discount_bps": {"type": "integer", "minimum": 0, "maximum": 10000},
                "header_discount_bps": {"type": "integer", "minimum": 0, "maximum": 10000},
                "header_discount_minor": {"type": "integer", "minimum": 0},
            },
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


def _reject_client_tenant_override(args: Mapping[str, Any]) -> None:
    if "tenant_id" in args:
        raise AuthorizationError(
            "Client-supplied tenant_id is forbidden; tenant scope is bound server-side.",
            code="CLIENT_TENANT_OVERRIDE_FORBIDDEN",
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
    ) -> dict[str, Any]:
        """Handle an authenticated MCP JSON-RPC 2.0 request."""
        req_id = rpc_request.get("id")
        if rpc_request.get("jsonrpc") != "2.0":
            return self._rpc_error(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'.")

        method = rpc_request.get("method")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "ledger-guard-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": list(MCP_TOOLS_SPEC)},
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
                order_id = _parse_uuid_arg(args.get("order_id"), "order_id")
                result_payload = self._orders.get_order(principal, order_id=order_id)
                return self._tool_success(req_id, result_payload, replayed=False)

            if tool_name == "create_order":
                idem_key = str(args.get("idempotency_key", ""))
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
                idem_key = str(args.get("idempotency_key", ""))
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
                idem_key = str(args.get("idempotency_key", ""))
                order_id = _parse_uuid_arg(args.get("order_id"), "order_id")
                exp_ver = require_strict_int(args.get("expected_version"), "expected_version")
                reason = str(args.get("reason", ""))
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
                idem_key = str(args.get("idempotency_key", ""))
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
        for entry in raw_lines:
            if not isinstance(entry, Mapping):
                raise ValidationError("Each line entry must be an object.")
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
                    sku=str(entry.get("sku", "")),
                    quantity=raw_qty,
                    unit_price_minor=unit_price,
                    manual_discount_bps=disc_bps,
                )
            )

        try:
            currency = Currency(str(args.get("currency", "")))
        except ValueError as exc:
            raise ValidationError("Unsupported currency code.") from exc

        try:
            order_kind = OrderKind(str(args.get("order_kind", "standard")))
        except ValueError as exc:
            raise ValidationError("Unsupported order_kind classification.") from exc

        return self._orders.create_order(
            principal,
            customer_ref=str(args.get("customer_ref", "")),
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
