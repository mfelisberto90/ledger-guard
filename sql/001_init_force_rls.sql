-- =============================================================================
-- LedgerGuard: PostgreSQL 17 Multi-Tenant Schema & Fail-Closed FORCE RLS DDL
-- =============================================================================
-- Role Topology:
--   1. app_migrator : Owns schema objects and runs DDL migrations only.
--                     Strictly blocked from application runtime pools.
--   2. app_runtime  : NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS.
--                     Subject to ENABLE + FORCE ROW LEVEL SECURITY on all tables.
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_migrator') THEN
        CREATE ROLE app_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
        CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
    END IF;
END
$$;

-- Helper function for deterministic transaction-scoped tenant locks (enforces current_tenant_id)
CREATE OR REPLACE FUNCTION acquire_tenant_lock(lock_namespace TEXT, tenant_uuid UUID)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    active_tenant UUID;
BEGIN
    active_tenant := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
    IF active_tenant IS NULL OR tenant_uuid IS DISTINCT FROM active_tenant THEN
        RAISE EXCEPTION 'TENANT_LOCK_SCOPE_VIOLATION: lock tenant does not match session tenant'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(lock_namespace || ':' || tenant_uuid::text, 0));
END;
$$;

-- 1. Tenant Memberships (Stage A bootstrap & Last-Owner invariant source of truth)
CREATE TABLE IF NOT EXISTS tenant_memberships (
    tenant_id       UUID        NOT NULL,
    principal_id    TEXT        NOT NULL CHECK (
        char_length(principal_id) BETWEEN 1 AND 128
        AND principal_id = lower(btrim(principal_id))
    ),
    role            TEXT        NOT NULL CHECK (role IN ('owner', 'finance_approver', 'sales_rep', 'warehouse')),
    capabilities    TEXT[]      NOT NULL DEFAULT '{}'::text[],
    is_active       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, principal_id)
);

ALTER TABLE tenant_memberships OWNER TO app_migrator;
ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships FORCE ROW LEVEL SECURITY;

-- Enforce Stage-A vs Stage-B separation + zero cross-tenant OR leak (`DB-01`)
DROP POLICY IF EXISTS tenant_memberships_stage_a_self_check ON tenant_memberships;
CREATE POLICY tenant_memberships_stage_a_self_check ON tenant_memberships
    FOR SELECT
    USING (
        (
            NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
            AND tenant_id = NULLIF(current_setting('app.stage_a_tenant_id', true), '')::uuid
            AND principal_id = NULLIF(current_setting('app.current_user_id', true), '')
            AND is_active = true
        )
        OR (
            tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            AND (
                principal_id = NULLIF(current_setting('app.current_user_id', true), '')
                OR NULLIF(current_setting('app.current_role', true), '') = 'owner'
            )
        )
    );

DROP POLICY IF EXISTS tenant_memberships_tenant_mutation ON tenant_memberships;
DROP POLICY IF EXISTS tenant_memberships_owner_insert ON tenant_memberships;
DROP POLICY IF EXISTS tenant_memberships_owner_update ON tenant_memberships;
DROP POLICY IF EXISTS tenant_memberships_owner_delete ON tenant_memberships;

CREATE POLICY tenant_memberships_owner_insert ON tenant_memberships
    FOR INSERT
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND NULLIF(current_setting('app.current_role', true), '') = 'owner'
    );

CREATE POLICY tenant_memberships_owner_update ON tenant_memberships
    FOR UPDATE
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND NULLIF(current_setting('app.current_role', true), '') = 'owner'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND NULLIF(current_setting('app.current_role', true), '') = 'owner'
    );

CREATE POLICY tenant_memberships_owner_delete ON tenant_memberships
    FOR DELETE
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND NULLIF(current_setting('app.current_role', true), '') = 'owner'
    );

-- Last-Owner Protection Trigger (forbids demoting/deactivating/deleting final active owner)
CREATE OR REPLACE FUNCTION enforce_last_active_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    remaining_owners INTEGER;
BEGIN
    IF OLD.role = 'owner' AND OLD.is_active = true THEN
        IF TG_OP = 'DELETE' OR NEW.role <> 'owner' OR NEW.is_active = false THEN
            SELECT count(*) INTO remaining_owners
            FROM tenant_memberships
            WHERE tenant_id = OLD.tenant_id
              AND role = 'owner'
              AND is_active = true
              AND principal_id <> OLD.principal_id;
            IF remaining_owners = 0 THEN
                RAISE EXCEPTION 'LAST_OWNER_PROTECTED: cannot remove or demote final active owner'
                    USING ERRCODE = '42501';
            END IF;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_tenant_memberships_last_owner ON tenant_memberships;
CREATE TRIGGER trg_tenant_memberships_last_owner
    BEFORE UPDATE OR DELETE ON tenant_memberships
    FOR EACH ROW
    EXECUTE FUNCTION enforce_last_active_owner();

-- 2. Tenant Margin Policies
CREATE TABLE IF NOT EXISTS margin_policies (
    tenant_id           UUID        PRIMARY KEY,
    mode                TEXT        NOT NULL CHECK (mode IN ('off', 'warn', 'block')),
    minimum_margin_bps  INTEGER     NOT NULL CHECK (minimum_margin_bps BETWEEN -10000 AND 10000),
    exempt_order_kinds  TEXT[]      NOT NULL DEFAULT ARRAY['return', 'credit_memo', 'free_of_charge_replacement', 'consignment'],
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE margin_policies OWNER TO app_migrator;
ALTER TABLE margin_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE margin_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS margin_policies_tenant_isolation ON margin_policies;
DROP POLICY IF EXISTS margin_policies_tenant_select ON margin_policies;
DROP POLICY IF EXISTS margin_policies_owner_mutation ON margin_policies;

CREATE POLICY margin_policies_tenant_select ON margin_policies
    FOR SELECT
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

CREATE POLICY margin_policies_owner_mutation ON margin_policies
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND NULLIF(current_setting('app.current_role', true), '') = 'owner'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND NULLIF(current_setting('app.current_role', true), '') = 'owner'
    );

-- 3. Governed Sales Orders (integer minor units + optimistic concurrency version)
CREATE TABLE IF NOT EXISTS sales_orders (
    id                          UUID        PRIMARY KEY,
    tenant_id                   UUID        NOT NULL,
    customer_ref                TEXT        NOT NULL CHECK (char_length(customer_ref) BETWEEN 1 AND 128),
    order_kind                  TEXT        NOT NULL CHECK (order_kind IN ('standard', 'return', 'credit_memo', 'free_of_charge_replacement', 'consignment')),
    currency                    TEXT        NOT NULL CHECK (currency IN ('GBP', 'EUR', 'USD', 'BRL', 'JPY')),
    status                      TEXT        NOT NULL CHECK (status IN ('draft', 'pending_approval', 'confirmed')),
    version                     INTEGER     NOT NULL CHECK (version >= 1),
    pricing_version             INTEGER     NOT NULL CHECK (pricing_version >= 1),
    header_discount_bps         INTEGER     NOT NULL CHECK (header_discount_bps BETWEEN 0 AND 10000),
    header_discount_minor       BIGINT      NOT NULL CHECK (header_discount_minor >= 0),
    gross_goods_total_minor     BIGINT      NOT NULL DEFAULT 0 CHECK (gross_goods_total_minor >= 0),
    line_discounts_total_minor  BIGINT      NOT NULL DEFAULT 0 CHECK (line_discounts_total_minor >= 0),
    header_discount_total_minor BIGINT      NOT NULL DEFAULT 0 CHECK (header_discount_total_minor >= 0),
    net_goods_total_minor       BIGINT      NOT NULL CHECK (net_goods_total_minor >= 0),
    passthrough_freight_minor   BIGINT      NOT NULL CHECK (passthrough_freight_minor >= 0),
    small_order_surcharge_minor BIGINT      NOT NULL CHECK (small_order_surcharge_minor >= 0),
    payable_total_minor         BIGINT      NOT NULL CHECK (
        payable_total_minor = net_goods_total_minor + passthrough_freight_minor + small_order_surcharge_minor
    ),
    total_cost_minor            BIGINT      NOT NULL CHECK (total_cost_minor >= 0),
    margin_minor                BIGINT      NOT NULL CHECK (margin_minor = net_goods_total_minor - total_cost_minor),
    margin_bps                  INTEGER     NOT NULL CHECK (margin_bps BETWEEN -10000 AND 10000),
    created_by                  TEXT        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    last_amended_by             TEXT        NOT NULL CHECK (char_length(last_amended_by) BETWEEN 1 AND 128),
    lines_json                  JSONB       NOT NULL CHECK (
        jsonb_typeof(lines_json) = 'array' AND octet_length(lines_json::text) <= 262144
    ),
    approvals_json              JSONB       NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(approvals_json) = 'array' AND octet_length(approvals_json::text) <= 65536
    ),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, id)
);

ALTER TABLE sales_orders OWNER TO app_migrator;
ALTER TABLE sales_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE sales_orders FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sales_orders_tenant_isolation ON sales_orders;
CREATE POLICY sales_orders_tenant_isolation ON sales_orders
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

CREATE INDEX IF NOT EXISTS idx_sales_orders_tenant_created
    ON sales_orders (tenant_id, created_at DESC, id DESC);

-- 4. Payload-Bound Idempotency Ledger (scoped to both tenant_id AND current_user_id)
CREATE TABLE IF NOT EXISTS idempotency_records (
    tenant_id       UUID        NOT NULL,
    principal_id    TEXT        NOT NULL CHECK (char_length(principal_id) BETWEEN 1 AND 128),
    action          TEXT        NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    idempotency_key TEXT        NOT NULL CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
    payload_sha256  TEXT        NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    state           TEXT        NOT NULL CHECK (state IN ('in_flight', 'completed')),
    status_code     INTEGER,
    response_json   JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, principal_id, action, idempotency_key),
    CHECK (
        (state = 'in_flight' AND status_code IS NULL AND response_json IS NULL)
        OR (state = 'completed' AND status_code BETWEEN 200 AND 599 AND response_json IS NOT NULL)
    )
);

ALTER TABLE idempotency_records OWNER TO app_migrator;
ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS idempotency_records_tenant_isolation ON idempotency_records;
CREATE POLICY idempotency_records_tenant_isolation ON idempotency_records
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND principal_id = NULLIF(current_setting('app.current_user_id', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        AND principal_id = NULLIF(current_setting('app.current_user_id', true), '')
    );

CREATE INDEX IF NOT EXISTS idx_idempotency_records_created
    ON idempotency_records (created_at);

-- 5. Atomic Webhook Anti-Replay Pre-Insertion Table (tenant-scoped composite PK)
CREATE TABLE IF NOT EXISTS processed_webhook_events (
    provider        TEXT        NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 64),
    event_id        TEXT        NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 128),
    tenant_id       UUID        NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider, event_id)
);

ALTER TABLE processed_webhook_events OWNER TO app_migrator;
ALTER TABLE processed_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE processed_webhook_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS processed_webhook_events_tenant_isolation ON processed_webhook_events;
CREATE POLICY processed_webhook_events_tenant_isolation ON processed_webhook_events
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

CREATE INDEX IF NOT EXISTS idx_processed_webhooks_tenant_received
    ON processed_webhook_events (tenant_id, received_at DESC);

-- 6. Minimised Append-Only Transactional Audit Outbox
CREATE TABLE IF NOT EXISTS audit_outbox (
    id                  UUID        PRIMARY KEY,
    tenant_id           UUID        NOT NULL,
    aggregate_id        UUID        NOT NULL,
    actor_principal_id  TEXT        NOT NULL CHECK (char_length(actor_principal_id) BETWEEN 1 AND 128),
    event_type          TEXT        NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 64),
    metadata_json       JSONB       NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(metadata_json) = 'object' AND octet_length(metadata_json::text) <= 16384
    ),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at        TIMESTAMPTZ
);

ALTER TABLE audit_outbox OWNER TO app_migrator;
ALTER TABLE audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_outbox_tenant_isolation ON audit_outbox;
CREATE POLICY audit_outbox_tenant_isolation ON audit_outbox
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

CREATE INDEX IF NOT EXISTS idx_audit_outbox_tenant_created
    ON audit_outbox (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_outbox_unpublished
    ON audit_outbox (created_at) WHERE published_at IS NULL;

-- Least-privilege grants to app_runtime (audit_outbox is strictly append/read: no UPDATE/DELETE)
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    tenant_memberships,
    margin_policies,
    sales_orders,
    idempotency_records
TO app_runtime;
GRANT SELECT, INSERT ON
    processed_webhook_events,
    audit_outbox
TO app_runtime;
GRANT EXECUTE ON FUNCTION acquire_tenant_lock(TEXT, UUID) TO app_runtime;
