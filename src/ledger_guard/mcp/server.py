"""Model Context Protocol (MCP) JSON-RPC 2.0 tool server sharing `OrderService`."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from ledger_guard import __version__ as SERVER_VERSION
from ledger_guard.application.order_service import OrderLineCommand, OrderService
from ledger_guard.application.schemas import (
    AmendOrderLineToolArgs,
    ApproveMarginToolArgs,
    ConfirmOrderToolArgs,
    CreateOrderToolArgs,
    ExportOrdersCsvToolArgs,
    GetOrderToolArgs,
    ListOrdersToolArgs,
    pydantic_to_mcp_input_schema,
    validate_mcp_arguments,
)
from ledger_guard.domain.errors import DomainError
from ledger_guard.domain.margin_gate import PrincipalContext
from ledger_guard.security.idempotency import IdempotencyCoordinator
from ledger_guard.security.redaction import Redactor

DEFAULT_MCP_PROTOCOL_VERSION: str = "2025-03-26"
SUPPORTED_MCP_PROTOCOL_VERSIONS: frozenset[str] = frozenset(
    {
        "2025-06-18",
        "2025-03-26",
        "2024-11-05",
    }
)


@dataclass(frozen=True, slots=True)
class _ToolDescriptor:
    name: str
    title: str
    description: str
    read_only: bool
    model: type[BaseModel]
    required_capability: str
    is_idempotent_mutation: bool = False


_TOOL_REGISTRY: tuple[_ToolDescriptor, ...] = (
    _ToolDescriptor(
        name="create_order",
        title="Create Governed Order",
        description=(
            "Price and create a tenant-scoped B2B sales order using exact Fraction UoM "
            "arithmetic, immutable inventory CostSnapshots, and margin-floor governance. "
            "Requires capability 'orders:write'."
        ),
        read_only=False,
        model=CreateOrderToolArgs,
        required_capability="orders:write",
        is_idempotent_mutation=True,
    ),
    _ToolDescriptor(
        name="get_order",
        title="Get Order",
        description=(
            "Fetch a single tenant-scoped sales order with capability-projected cost and "
            "margin fields. Requires capability 'orders:read'."
        ),
        read_only=True,
        model=GetOrderToolArgs,
        required_capability="orders:read",
    ),
    _ToolDescriptor(
        name="list_orders",
        title="List Orders",
        description=(
            "List recent tenant-scoped sales orders with capability-projected cost and "
            "margin fields stripped according to caller permissions. Requires 'orders:read'."
        ),
        read_only=True,
        model=ListOrdersToolArgs,
        required_capability="orders:read",
    ),
    _ToolDescriptor(
        name="confirm_order",
        title="Confirm Order",
        description=(
            "Confirm a governed sales order when all readiness gates evaluate to met=true. "
            "Requires capability 'orders:confirm' and matching optimistic expected_version."
        ),
        read_only=False,
        model=ConfirmOrderToolArgs,
        required_capability="orders:confirm",
        is_idempotent_mutation=True,
    ),
    _ToolDescriptor(
        name="approve_margin",
        title="Approve Margin Exception",
        description=(
            "Record an append-only four-eyes margin exception approval with mandatory reason. "
            "Approver must hold 'orders:margin:approve' and be distinct from creator/amenders."
        ),
        read_only=False,
        model=ApproveMarginToolArgs,
        required_capability="orders:margin:approve",
        is_idempotent_mutation=True,
    ),
    _ToolDescriptor(
        name="amend_order_line",
        title="Amend Order Line",
        description=(
            "Amend commercial pricing or quantity on an existing order line while preserving "
            "immutable CostSnapshots and re-evaluating margin floor gates. Requires 'orders:write'."
        ),
        read_only=False,
        model=AmendOrderLineToolArgs,
        required_capability="orders:write",
        is_idempotent_mutation=True,
    ),
    _ToolDescriptor(
        name="export_orders_csv",
        title="Export Orders CSV",
        description=(
            "Export tenant orders as formula-injection-sanitized CSV with cost and margin "
            "columns gated by 'valuation:cost:read' and 'orders:margin:read'. "
            "Requires 'orders:export'."
        ),
        read_only=True,
        model=ExportOrdersCsvToolArgs,
        required_capability="orders:export",
    ),
)

_TOOLS_BY_NAME: dict[str, _ToolDescriptor] = {item.name: item for item in _TOOL_REGISTRY}

MCP_TOOLS_SPEC: tuple[dict[str, Any], ...] = tuple(
    {
        "name": desc.name,
        "title": desc.title,
        "description": desc.description,
        "annotations": {
            "title": desc.title,
            "readOnlyHint": desc.read_only,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": pydantic_to_mcp_input_schema(desc.model),
    }
    for desc in _TOOL_REGISTRY
)


def _is_valid_jsonrpc_id(raw_id: object) -> bool:
    if raw_id is None:
        return True
    if isinstance(raw_id, bool):
        return False
    if isinstance(raw_id, int):
        return True
    if isinstance(raw_id, str):
        return len(raw_id) <= 128
    return False


class McpToolServer:
    """MCP JSON-RPC 2.0 dispatcher sharing Pydantic contracts and `OrderService`."""

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
        has_id = "id" in rpc_request
        req_id = rpc_request.get("id")
        if has_id and not _is_valid_jsonrpc_id(req_id):
            return self._rpc_error(None, -32600, "Invalid Request: invalid JSON-RPC 'id'.")

        if rpc_request.get("jsonrpc") != "2.0":
            return self._rpc_error(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'.")

        method = rpc_request.get("method")
        if not isinstance(method, str) or not method:
            return self._rpc_error(req_id, -32600, "Invalid Request: method string required.")

        if method.startswith("notifications/"):
            if has_id:
                return self._rpc_error(req_id, -32600, "Notifications must not contain 'id'.")
            return None

        if not has_id:
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
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": list(MCP_TOOLS_SPEC)}}

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

    def _run_idempotent_order_mutation(
        self,
        *,
        req_id: Any,
        principal: PrincipalContext,
        action: str,
        idempotency_key: str,
        payload: dict[str, Any],
        status_code: int,
        executor: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        outcome = self._idempotency.execute(
            tenant_id=principal.tenant_id,
            principal_id=principal.principal_id,
            action=action,
            idempotency_key=idempotency_key,
            payload=payload,
            handler=lambda: (status_code, executor()),
        )
        body = outcome.body
        if outcome.replayed and "order_id" in body:
            from uuid import UUID

            order, policy = self._orders._get_order_and_policy(
                principal, UUID(str(body["order_id"]))
            )
            from ledger_guard.domain.margin_gate import project_order_for_principal

            body = project_order_for_principal(order, policy, principal)
        return self._tool_success(req_id, body, replayed=outcome.replayed)

    def _dispatch_tool(
        self,
        req_id: Any,
        principal: PrincipalContext,
        tool_name: str,
        args: Mapping[str, Any],
    ) -> dict[str, Any]:
        desc = _TOOLS_BY_NAME.get(tool_name)
        if desc is None:
            return self._rpc_error(req_id, -32601, f"Unknown MCP tool '{tool_name}'.")

        try:
            validated = validate_mcp_arguments(desc.model, args)
            principal.require_capability(desc.required_capability)

            if isinstance(validated, GetOrderToolArgs):
                return self._tool_success(
                    req_id,
                    self._orders.get_order(principal, order_id=validated.order_id),
                    replayed=False,
                )

            if isinstance(validated, ListOrdersToolArgs):
                return self._tool_success(
                    req_id,
                    self._orders.list_orders(principal, limit=validated.limit),
                    replayed=False,
                )

            if isinstance(validated, ExportOrdersCsvToolArgs):
                csv_text = self._orders.export_orders_csv(principal)
                row_count = max(0, len(csv_text.splitlines()) - 1)
                return self._tool_success(
                    req_id,
                    {"csv": csv_text, "row_count": row_count},
                    replayed=False,
                )

            if isinstance(validated, CreateOrderToolArgs):
                commands = [
                    OrderLineCommand(
                        sku=ln.sku,
                        quantity=ln.quantity,
                        unit_price_minor=ln.unit_price_minor,
                        manual_discount_bps=ln.manual_discount_bps,
                    )
                    for ln in validated.lines
                ]
                canonical_payload = validated.model_dump(
                    mode="json", exclude={"idempotency_key"}
                )
                return self._run_idempotent_order_mutation(
                    req_id=req_id,
                    principal=principal,
                    action="orders:create",
                    idempotency_key=validated.idempotency_key,
                    payload=canonical_payload,
                    status_code=201,
                    executor=lambda: self._orders.create_order(
                        principal,
                        customer_ref=validated.customer_ref,
                        order_kind=validated.order_kind,
                        currency=validated.currency,
                        lines=commands,
                        header_discount_bps=validated.header_discount_bps,
                        header_discount_minor=validated.header_discount_minor,
                        passthrough_freight_minor=validated.passthrough_freight_minor,
                        small_order_surcharge_minor=validated.small_order_surcharge_minor,
                    ),
                )

            if isinstance(validated, ConfirmOrderToolArgs):
                canonical_payload = validated.model_dump(
                    mode="json", exclude={"idempotency_key", "order_id"}
                )
                return self._run_idempotent_order_mutation(
                    req_id=req_id,
                    principal=principal,
                    action=f"orders:confirm:{validated.order_id}",
                    idempotency_key=validated.idempotency_key,
                    payload=canonical_payload,
                    status_code=200,
                    executor=lambda: self._orders.confirm_order(
                        principal,
                        order_id=validated.order_id,
                        expected_version=validated.expected_version,
                    ),
                )

            if isinstance(validated, ApproveMarginToolArgs):
                canonical_payload = validated.model_dump(
                    mode="json", exclude={"idempotency_key", "order_id"}
                )
                return self._run_idempotent_order_mutation(
                    req_id=req_id,
                    principal=principal,
                    action=f"orders:approve_margin:{validated.order_id}",
                    idempotency_key=validated.idempotency_key,
                    payload=canonical_payload,
                    status_code=200,
                    executor=lambda: self._orders.approve_margin(
                        principal,
                        order_id=validated.order_id,
                        expected_version=validated.expected_version,
                        reason=validated.reason,
                    ),
                )

            if isinstance(validated, AmendOrderLineToolArgs):
                canonical_payload = validated.model_dump(
                    mode="json",
                    exclude={"idempotency_key", "order_id", "line_id"},
                    exclude_none=True,
                )
                return self._run_idempotent_order_mutation(
                    req_id=req_id,
                    principal=principal,
                    action=f"orders:amend_line:{validated.order_id}:{validated.line_id}",
                    idempotency_key=validated.idempotency_key,
                    payload=canonical_payload,
                    status_code=200,
                    executor=lambda: self._orders.amend_order_line(
                        principal,
                        order_id=validated.order_id,
                        line_id=validated.line_id,
                        expected_version=validated.expected_version,
                        quantity=validated.quantity,
                        unit_price_minor=validated.unit_price_minor,
                        manual_discount_bps=validated.manual_discount_bps,
                        header_discount_bps=validated.header_discount_bps,
                        header_discount_minor=validated.header_discount_minor,
                    ),
                )

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
