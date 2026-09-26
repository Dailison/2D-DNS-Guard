-- Plano de confiabilidade, fase 2.1: o console guarda aqui o config do Advanced Blocking (o que leu)
-- ANTES de cada gravação no Technitium. Mantém os 100 mais recentes.
CREATE TABLE IF NOT EXISTS technitium_config_backups (
    id        bigserial PRIMARY KEY,
    taken_at  timestamptz NOT NULL DEFAULT now(),
    taken_by  text,
    motivo    text,
    config    jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS technitium_config_backups_at ON technitium_config_backups (taken_at DESC);
