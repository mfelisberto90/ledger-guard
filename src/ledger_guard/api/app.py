"""FastAPI HTTP transport and MCP JSON-RPC mount with OWASP ASVS L2 defence pipeline."""

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from ledger_guard.adapters.in_memory import (
    InMemoryAuditOutbox,
    InMemoryCatalogAdapter,
    InMemoryIdempotencyStore,
    InMemoryOrderRepository,
    InMemoryPolicyRepository,
    InMemoryValuationAdapter,
    InMemoryWebhookDedupStore,
)
from ledger_guard.application.order_service import OrderLineCommand, OrderService
from ledger_guard.domain.errors import (
    AuthenticationError,
    DomainError,
    RateLimitExceededError,
)
from ledger_guard.domain.margin_gate import OrderKind, PrincipalContext
from ledger_guard.domain.money import Currency
from ledger_guard.mcp.server import McpToolServer
from ledger_guard.ports import AuditEvent
from ledger_guard.security.auth import MembershipDirectory, PasswordHasher, TokenService
from ledger_guard.security.idempotency import IdempotencyCoordinator
from ledger_guard.security.middleware import (
    ROBOTS_TXT_CONTENT,
    CgnatSafeScannerGuard,
    SecurityDefenseMiddleware,
    parse_trusted_proxy_cidrs,
)
from ledger_guard.security.rate_limit import HmacMultiBucketRateLimiter
from ledger_guard.security.redaction import Redactor
from ledger_guard.security.webhooks import verify_and_claim_webhook


@dataclass(slots=True)
class AppContainer:
    """Dependency container wiring hexagonal ports, adapters, and security controls."""

    signing_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    rate_limit_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    webhook_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    trusted_proxy_cidrs: tuple[str, ...] = ("127.0.0.1/32", "::1/128")

    catalog: InMemoryCatalogAdapter = field(default_factory=InMemoryCatalogAdapter)
    valuation: InMemoryValuationAdapter = field(default_factory=InMemoryValuationAdapter)
    policies: InMemoryPolicyRepository = field(default_factory=InMemoryPolicyRepository)
    outbox: InMemoryAuditOutbox = field(default_factory=InMemoryAuditOutbox)
    idempotency_store: InMemoryIdempotencyStore = field(default_factory=InMemoryIdempotencyStore)
    webhook_dedup: InMemoryWebhookDedupStore = field(default_factory=InMemoryWebhookDedupStore)
    memberships: MembershipDirectory = field(default_factory=MembershipDirectory)
    password_hasher: PasswordHasher = field(default_factory=PasswordHasher)
    redactor: Redactor = field(default_factory=Redactor)
    webhook_handlers: list[Callable[[str, str, UUID, bytes], None]] = field(default_factory=list)

    orders: InMemoryOrderRepository = field(init=False)
    tokens: TokenService = field(init=False)
    rate_limiter: HmacMultiBucketRateLimiter = field(init=False)
    scanner_guard: CgnatSafeScannerGuard = field(init=False)
    idempotency: IdempotencyCoordinator = field(init=False)
    order_service: OrderService = field(init=False)
    mcp_server: McpToolServer = field(init=False)

    def __post_init__(self) -> None:
        self.orders = InMemoryOrderRepository(self.outbox)
        self.tokens = TokenService(self.signing_key)
        self.rate_limiter = HmacMultiBucketRateLimiter(self.rate_limit_key)
        self.scanner_guard = CgnatSafeScannerGuard(self.rate_limit_key)
        self.idempotency = IdempotencyCoordinator(self.idempotency_store)
        self.order_service = OrderService(
            catalog=self.catalog,
            valuation=self.valuation,
            orders=self.orders,
            policies=self.policies,
        )
        self.mcp_server = McpToolServer(
            order_service=self.order_service,
            idempotency=self.idempotency,
            redactor=self.redactor,
        )


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    principal_id: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class CreateOrderLinePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sku: str = Field(min_length=1, max_length=64)
    quantity: StrictInt | str
    unit_price_minor: StrictInt | None = Field(default=None, ge=0)
    manual_discount_bps: StrictInt = Field(default=0, ge=0, le=10_000)


class CreateOrderPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_ref: str = Field(min_length=1, max_length=128)
    order_kind: OrderKind = OrderKind.STANDARD
    currency: Currency
    header_discount_bps: StrictInt = Field(default=0, ge=0, le=10_000)
    header_discount_minor: StrictInt = Field(default=0, ge=0)
    passthrough_freight_minor: StrictInt = Field(default=0, ge=0)
    small_order_surcharge_minor: StrictInt = Field(default=0, ge=0)
    lines: list[CreateOrderLinePayload] = Field(min_length=1, max_length=200)


class ConfirmOrderPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(ge=1)


class ApproveMarginPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1_000)


class AmendOrderLinePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(ge=1)
    quantity: StrictInt | str | None = None
    unit_price_minor: StrictInt | None = Field(default=None, ge=0)
    manual_discount_bps: StrictInt | None = Field(default=None, ge=0, le=10_000)
    header_discount_bps: StrictInt | None = Field(default=None, ge=0, le=10_000)
    header_discount_minor: StrictInt | None = Field(default=None, ge=0)


def _client_ip_from_request(request: Request) -> str:
    state_ip = getattr(request.state, "client_ip", None)
    if isinstance(state_ip, str) and state_ip:
        return state_ip
    if request.client is not None:
        return request.client.host
    return "127.0.0.1"


def create_app(container: AppContainer | None = None) -> FastAPI:
    """Create the hardened FastAPI + MCP application instance."""
    deps = AppContainer() if container is None else container
    parsed_cidrs = parse_trusted_proxy_cidrs(deps.trusted_proxy_cidrs)

    app = FastAPI(
        title="LedgerGuard API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.container = deps

    app.add_middleware(
        SecurityDefenseMiddleware,
        scanner_guard=deps.scanner_guard,
        token_service=deps.tokens,
        memberships=deps.memberships,
        trusted_proxy_cidrs=parsed_cidrs,
    )

    @app.exception_handler(DomainError)
    async def handle_domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimitExceededError):
            headers["Retry-After"] = str(exc.retry_after_seconds)
        body = {
            "error": {
                "code": exc.code,
                "message": deps.redactor.redact_text(exc.message),
                "details": deps.redactor.redact_structure(exc.details),
            }
        }
        return JSONResponse(status_code=exc.http_status, content=body, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        sanitized_errors = deps.redactor.redact_structure(exc.errors())
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "REQUEST_VALIDATION_FAILED",
                    "message": "Request payload failed bounded schema validation.",
                    "details": {"issues": sanitized_errors},
                }
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected server error occurred.",
                    "details": {},
                }
            },
        )

    def require_authenticated_principal(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> PrincipalContext:
        if not authorization:
            raise AuthenticationError("Missing Authorization Bearer header.")
        parts = authorization.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationError("Authorization header must use Bearer scheme.")

        claims = deps.tokens.verify_token(parts[1])
        principal = deps.memberships.resolve_active_principal(
            claims.tenant_id, claims.principal_id
        )
        deps.rate_limiter.check_request(
            client_ip=_client_ip_from_request(request),
            principal_id=principal.principal_id,
            tenant_id=str(principal.tenant_id),
            enforce_principal_bucket=False,
        )
        return principal

    @app.get("/robots.txt", include_in_schema=False)
    async def robots_txt() -> PlainTextResponse:
        return PlainTextResponse(content=ROBOTS_TXT_CONTENT, media_type="text/plain")

    @app.get("/healthz", include_in_schema=False)
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/auth/login")
    async def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
        client_ip = _client_ip_from_request(request)
        deps.rate_limiter.check_request(
            client_ip=client_ip,
            principal_id=payload.principal_id,
            tenant_id=str(payload.tenant_id),
            enforce_principal_bucket=True,
        )
        record = deps.memberships.get_credential_record(payload.tenant_id, payload.principal_id)
        if (
            record is None
            or not record.principal.is_active
            or record.password_hash is None
            or not deps.password_hasher.verify_password(payload.password, record.password_hash)
        ):
            raise AuthenticationError("Invalid credentials.", code="INVALID_CREDENTIALS")

        # Reset principal strike counter on valid login while preserving IP spray bucket!
        deps.rate_limiter.clear_principal_on_login(record.principal.principal_id)
        access_token = deps.tokens.issue_token(
            principal_id=record.principal.principal_id,
            tenant_id=record.principal.tenant_id,
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "tenant_id": str(record.principal.tenant_id),
        }

    @app.post("/v1/orders")
    async def create_order_endpoint(
        payload: CreateOrderPayload,
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        raw_dict = payload.model_dump(mode="json")
        commands = [
            OrderLineCommand(
                sku=ln.sku,
                quantity=ln.quantity,
                unit_price_minor=ln.unit_price_minor,
                manual_discount_bps=ln.manual_discount_bps,
            )
            for ln in payload.lines
        ]
        outcome = deps.idempotency.execute(
            tenant_id=principal.tenant_id,
            principal_id=principal.principal_id,
            action="http:create_order",
            idempotency_key=idempotency_key,
            payload=raw_dict,
            handler=lambda: (
                201,
                deps.order_service.create_order(
                    principal,
                    customer_ref=payload.customer_ref,
                    order_kind=payload.order_kind,
                    currency=payload.currency,
                    lines=commands,
                    header_discount_bps=payload.header_discount_bps,
                    header_discount_minor=payload.header_discount_minor,
                    passthrough_freight_minor=payload.passthrough_freight_minor,
                    small_order_surcharge_minor=payload.small_order_surcharge_minor,
                ),
            ),
        )
        headers = {"X-Idempotent-Replay": "true"} if outcome.replayed else {}
        return JSONResponse(
            status_code=outcome.status_code,
            content=outcome.body,
            headers=headers,
        )

    @app.get("/v1/orders/{order_id}")
    async def get_order_endpoint(
        order_id: UUID,
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
    ) -> dict[str, Any]:
        return deps.order_service.get_order(principal, order_id=order_id)

    @app.post("/v1/orders/{order_id}/confirm")
    async def confirm_order_endpoint(
        order_id: UUID,
        payload: ConfirmOrderPayload,
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        outcome = deps.idempotency.execute(
            tenant_id=principal.tenant_id,
            principal_id=principal.principal_id,
            action=f"http:confirm_order:{order_id}",
            idempotency_key=idempotency_key,
            payload=payload.model_dump(mode="json"),
            handler=lambda: (
                200,
                deps.order_service.confirm_order(
                    principal,
                    order_id=order_id,
                    expected_version=payload.expected_version,
                ),
            ),
        )
        headers = {"X-Idempotent-Replay": "true"} if outcome.replayed else {}
        return JSONResponse(
            status_code=outcome.status_code,
            content=outcome.body,
            headers=headers,
        )

    @app.post("/v1/orders/{order_id}/approve-margin")
    async def approve_margin_endpoint(
        order_id: UUID,
        payload: ApproveMarginPayload,
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        outcome = deps.idempotency.execute(
            tenant_id=principal.tenant_id,
            principal_id=principal.principal_id,
            action=f"http:approve_margin:{order_id}",
            idempotency_key=idempotency_key,
            payload=payload.model_dump(mode="json"),
            handler=lambda: (
                200,
                deps.order_service.approve_margin(
                    principal,
                    order_id=order_id,
                    expected_version=payload.expected_version,
                    reason=payload.reason,
                ),
            ),
        )
        headers = {"X-Idempotent-Replay": "true"} if outcome.replayed else {}
        return JSONResponse(
            status_code=outcome.status_code,
            content=outcome.body,
            headers=headers,
        )

    @app.patch("/v1/orders/{order_id}/lines/{line_id}")
    async def amend_order_line_endpoint(
        order_id: UUID,
        line_id: UUID,
        payload: AmendOrderLinePayload,
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        outcome = deps.idempotency.execute(
            tenant_id=principal.tenant_id,
            principal_id=principal.principal_id,
            action=f"http:amend_line:{order_id}:{line_id}",
            idempotency_key=idempotency_key,
            payload=payload.model_dump(mode="json", exclude_none=True),
            handler=lambda: (
                200,
                deps.order_service.amend_order_line(
                    principal,
                    order_id=order_id,
                    line_id=line_id,
                    expected_version=payload.expected_version,
                    quantity=payload.quantity,
                    unit_price_minor=payload.unit_price_minor,
                    manual_discount_bps=payload.manual_discount_bps,
                    header_discount_bps=payload.header_discount_bps,
                    header_discount_minor=payload.header_discount_minor,
                ),
            ),
        )
        headers = {"X-Idempotent-Replay": "true"} if outcome.replayed else {}
        return JSONResponse(
            status_code=outcome.status_code,
            content=outcome.body,
            headers=headers,
        )

    @app.get("/v1/orders-export.csv")
    async def export_orders_csv_endpoint(
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
    ) -> Response:
        csv_body = deps.order_service.export_orders_csv(principal)
        return Response(
            content=csv_body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="orders-export.csv"'},
        )

    @app.post("/v1/webhooks/{provider}")
    async def receive_webhook_endpoint(
        provider: str,
        request: Request,
        x_webhook_timestamp: Annotated[str | None, Header()] = None,
        x_webhook_signature: Annotated[str | None, Header()] = None,
        x_webhook_event_id: Annotated[str | None, Header()] = None,
        x_webhook_tenant_id: Annotated[UUID | None, Header()] = None,
    ) -> dict[str, Any]:
        raw_bytes = await request.body()
        if x_webhook_tenant_id is None or x_webhook_event_id is None:
            raise AuthenticationError("Missing webhook tenant or event identifier header.")

        claim = verify_and_claim_webhook(
            provider=provider,
            event_id=x_webhook_event_id,
            tenant_id=x_webhook_tenant_id,
            raw_body=raw_bytes,
            timestamp_header=x_webhook_timestamp,
            signature_header=x_webhook_signature,
            secret=deps.webhook_secret,
            dedup_port=deps.webhook_dedup,
        )
        if not claim.is_first_delivery:
            return {"status": "duplicate_ignored", "event_id": claim.event_id}

        for callback in deps.webhook_handlers:
            callback(claim.provider, claim.event_id, x_webhook_tenant_id, raw_bytes)

        deps.outbox.append_event(
            AuditEvent(
                event_id=uuid4(),
                tenant_id=x_webhook_tenant_id,
                aggregate_id=uuid4(),
                actor_principal_id=f"webhook:{claim.provider}",
                event_type="webhook.processed",
                created_at_utc=datetime.now(UTC).isoformat(),
                metadata={"webhook_event_id": claim.event_id},
            )
        )
        return {"status": "processed", "event_id": claim.event_id}

    @app.post("/mcp")
    async def mcp_jsonrpc_endpoint(
        rpc_body: dict[str, Any],
        principal: Annotated[PrincipalContext, Depends(require_authenticated_principal)],
    ) -> dict[str, Any]:
        return deps.mcp_server.handle_jsonrpc(principal, rpc_body)

    return app
