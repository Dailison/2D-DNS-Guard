-- Feed em tempo real da classificação (tela "IA ao vivo" do portal).
-- kind: llm_start | llm_done | llm_error | llm_unavailable | rules_batch
CREATE TABLE IF NOT EXISTS ai_events (
    id             bigserial PRIMARY KEY,
    kind           text NOT NULL,
    domain_id      bigint,
    name           text,
    classification text,
    risk           smallint,
    work           smallint,
    seconds        real,
    detail         text,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_events_created ON ai_events (created_at DESC);
