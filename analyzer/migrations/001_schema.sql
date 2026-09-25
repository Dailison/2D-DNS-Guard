-- 2D DNS Analyzer — schema inicial.
-- Convenções:
--   * Tudo que é dado de cliente tem tenant_id (dados de tenants nunca se misturam).
--   * `domains`/`fqdns` são inteligência GLOBAL sobre nomes públicos (reaproveitada
--     entre tenants para não reclassificar o mesmo domínio N vezes).
--   * query_agg é particionada por mês (bucket) -> retenção barata (DROP partição).

-- Categorias de classificação (tabela, para permitir novas categorias depois)
CREATE TABLE categories (
    code        text PRIMARY KEY,
    label       text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_threat   boolean NOT NULL DEFAULT false,
    sort_order  int NOT NULL DEFAULT 0
);

-- Clientes (empresas) monitorados
CREATE TABLE tenants (
    id           serial PRIMARY KEY,
    slug         text UNIQUE NOT NULL,
    name         text NOT NULL,
    active       boolean NOT NULL DEFAULT true,
    auto_created boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Redes de cada tenant (IP do cliente -> tenant por maior prefixo)
CREATE TABLE tenant_networks (
    id          serial PRIMARY KEY,
    tenant_id   int NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cidr        cidr NOT NULL UNIQUE,
    description text NOT NULL DEFAULT ''
);
CREATE INDEX tenant_networks_cidr_gist ON tenant_networks USING gist (cidr inet_ops);

-- Computadores/IPs de cada tenant
CREATE TABLE clients (
    id         bigserial PRIMARY KEY,
    tenant_id  int NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ip         inet NOT NULL,
    label      text,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    UNIQUE (tenant_id, ip)
);

-- Domínio registrável (eTLD+1, com sufixos privados da PSL: user.github.io é
-- a unidade, não github.io). Inteligência global + classificação BASE.
CREATE TABLE domains (
    id                 bigserial PRIMARY KEY,
    name               text UNIQUE NOT NULL,
    kind               text NOT NULL DEFAULT 'public',   -- public | internal | reverse | ip | invalid
    tld                text NOT NULL DEFAULT '',
    features           jsonb NOT NULL DEFAULT '{}',
    popularity_rank    int,
    registered_at      date,
    ti_hits            jsonb NOT NULL DEFAULT '[]',
    ti_signature       text NOT NULL DEFAULT '',
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    total_queries      bigint NOT NULL DEFAULT 0,
    -- classificação base (sem dados de tenant específico)
    classification     text REFERENCES categories(code),
    risk_score         smallint,
    work_score         smallint,
    confidence         real,
    topic              text,
    reasons            jsonb NOT NULL DEFAULT '[]',
    evidence           jsonb NOT NULL DEFAULT '[]',
    recommended_action text,
    classified_by      text,          -- internal | catalog | rules | llm | manual
    model              text,
    locked             boolean NOT NULL DEFAULT false,   -- classificação manual global
    analyzed_at        timestamptz,
    needs_analysis     boolean NOT NULL DEFAULT true,
    llm_pending        boolean NOT NULL DEFAULT false,   -- classificado só por regras; aguardando IA
    evidence_hash      text NOT NULL DEFAULT '',         -- IA só reprocessa se evidências relevantes mudarem
    claimed_at         timestamptz,                      -- trava leve do classificador
    llm_attempts       int NOT NULL DEFAULT 0,
    last_error         text
);
CREATE INDEX domains_needs_analysis ON domains (last_seen DESC) WHERE needs_analysis;
CREATE INDEX domains_llm_pending ON domains (total_queries DESC) WHERE llm_pending;
CREATE INDEX domains_classification ON domains (classification);

-- FQDNs observados (nível onde se detecta DGA/entropia e onde batem as listas)
CREATE TABLE fqdns (
    id         bigserial PRIMARY KEY,
    name       text UNIQUE NOT NULL,
    domain_id  bigint NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    candidates text[] NOT NULL DEFAULT '{}',   -- fqdn ... até o registrável (p/ casar listas)
    features   jsonb NOT NULL DEFAULT '{}',
    first_seen timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX fqdns_domain ON fqdns (domain_id);

-- Consultas agregadas por hora (particionada por mês)
CREATE TABLE query_agg (
    tenant_id  int NOT NULL,
    client_id  bigint NOT NULL,
    domain_id  bigint NOT NULL,
    fqdn_id    bigint NOT NULL,
    bucket     timestamptz NOT NULL,     -- início da hora (UTC)
    queries    int NOT NULL,
    blocked    int NOT NULL DEFAULT 0,
    nxdomain   int NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, client_id, fqdn_id, bucket)
) PARTITION BY RANGE (bucket);
-- (partições mensais são criadas pelo coletor: query_agg_YYYYMM)

-- Resumo cliente x domínio (sem tempo): "quem acessou", novidades por cliente
CREATE TABLE client_domains (
    tenant_id  int NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id  bigint NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id  bigint NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    queries    bigint NOT NULL DEFAULT 0,
    blocked    bigint NOT NULL DEFAULT 0,
    nxdomain   bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, client_id, domain_id)
);
CREATE INDEX client_domains_domain ON client_domains (tenant_id, domain_id);
CREATE INDEX client_domains_first ON client_domains (tenant_id, first_seen);

-- Visão do tenant sobre o domínio + override manual por tenant
CREATE TABLE tenant_domains (
    tenant_id               int NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id               bigint NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    first_seen              timestamptz NOT NULL,
    last_seen               timestamptz NOT NULL,
    total_queries           bigint NOT NULL DEFAULT 0,
    clients_count           int NOT NULL DEFAULT 0,
    override_classification text REFERENCES categories(code),
    override_work_score     smallint,
    override_note           text,
    override_by             text,
    override_at             timestamptz,
    PRIMARY KEY (tenant_id, domain_id)
);
CREATE INDEX tenant_domains_last ON tenant_domains (tenant_id, last_seen DESC);

-- Fontes de Threat Intelligence (configuráveis na tabela)
CREATE TABLE ti_sources (
    id            serial PRIMARY KEY,
    name          text UNIQUE NOT NULL,
    label         text NOT NULL,
    kind          text NOT NULL,          -- hosts | adblock | plain | tld_adblock
    url           text NOT NULL,
    threat        text NOT NULL,          -- malware | c2 | phishing | threat | badware | dyndns | bypass | abused_tld
    confidence    text NOT NULL,          -- high | medium | low
    weight        smallint NOT NULL,      -- pontos de risco de um acerto exato
    enabled       boolean NOT NULL DEFAULT true,
    refresh_hours int NOT NULL DEFAULT 12,
    license_note  text NOT NULL DEFAULT '',
    last_fetch    timestamptz,
    last_status   text,
    entries       int
);

CREATE TABLE ti_indicators (
    source_id  int NOT NULL REFERENCES ti_sources(id) ON DELETE CASCADE,
    domain     text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, domain)
);
CREATE INDEX ti_indicators_domain ON ti_indicators (domain);

-- Falsos positivos marcados pelo operador (source_id NULL = todas as fontes)
CREATE TABLE ti_suppressions (
    id         serial PRIMARY KEY,
    domain     text NOT NULL,
    source_id  int REFERENCES ti_sources(id) ON DELETE CASCADE,
    note       text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ti_suppressions_uq ON ti_suppressions (domain, COALESCE(source_id, 0));

-- Popularidade (Tranco top 1M)
CREATE TABLE popularity (
    domain text PRIMARY KEY,
    rank   int NOT NULL
);

-- Cache de consultas externas (RDAP etc.)
CREATE TABLE lookup_cache (
    kind       text NOT NULL,
    key        text NOT NULL,
    ok         boolean NOT NULL,
    value      jsonb,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key)
);

-- Histórico de classificações (base global: tenant_id NULL; override: tenant_id)
CREATE TABLE classification_history (
    id             bigserial PRIMARY KEY,
    domain_id      bigint NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    tenant_id      int REFERENCES tenants(id) ON DELETE CASCADE,
    classification text,
    risk_score     smallint,
    work_score     smallint,
    confidence     real,
    topic          text,
    reasons        jsonb,
    evidence       jsonb,
    source         text,
    model          text,
    note           text,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX classification_history_domain ON classification_history (domain_id, created_at DESC);

-- Alertas (somente análise; nada é bloqueado automaticamente)
CREATE TABLE alerts (
    id         bigserial PRIMARY KEY,
    tenant_id  int NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind       text NOT NULL,
    severity   text NOT NULL,           -- low | medium | high | critical
    client_id  bigint REFERENCES clients(id) ON DELETE SET NULL,
    domain_id  bigint REFERENCES domains(id) ON DELETE SET NULL,
    title      text NOT NULL,
    details    jsonb NOT NULL DEFAULT '{}',
    dedup_key  text NOT NULL,
    status     text NOT NULL DEFAULT 'open',   -- open | ack | closed
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    ack_by     text,
    UNIQUE (tenant_id, dedup_key)
);
CREATE INDEX alerts_tenant_status ON alerts (tenant_id, status, created_at DESC);

-- Histórico das execuções (coleta, TI, classificação, comportamento)
CREATE TABLE analysis_runs (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    ok          boolean,
    stats       jsonb NOT NULL DEFAULT '{}',
    error       text
);
CREATE INDEX analysis_runs_kind ON analysis_runs (kind, started_at DESC);

-- Estado da ingestão (cursor etc.)
CREATE TABLE ingest_state (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Classificação efetiva por tenant: override do tenant > classificação base.
CREATE VIEW v_tenant_domains AS
SELECT td.tenant_id,
       d.id AS domain_id,
       d.name,
       d.kind,
       d.topic,
       COALESCE(td.override_classification, d.classification) AS classification,
       CASE WHEN td.override_classification IS NOT NULL
            THEN COALESCE(td.override_work_score, d.work_score)
            ELSE d.work_score END AS work_score,
       d.risk_score,
       d.confidence,
       d.recommended_action,
       d.classified_by,
       (td.override_classification IS NOT NULL) AS overridden,
       td.first_seen,
       td.last_seen,
       td.total_queries,
       td.clients_count,
       d.popularity_rank,
       d.ti_hits,
       d.analyzed_at,
       d.llm_pending
FROM tenant_domains td
JOIN domains d ON d.id = td.domain_id;
