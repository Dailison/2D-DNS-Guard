-- Plano de confiabilidade, fase 4.2: auditoria PERMANENTE de tudo o que entra e sai das listas (ai_events
-- some em 7 dias). Gatilho no banco: nenhum ponto de gravação escapa (código, migração, psql). Quem/por quê
-- vêm de set_config('dnsguard.por'/'dnsguard.motivo', ..., true) na transação (listas.contexto); sem isso,
-- a entrada usa o added_by.
CREATE TABLE IF NOT EXISTS list_audit (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    domain    text NOT NULL,
    category  text NOT NULL,
    acao      text NOT NULL CHECK (acao IN ('add', 'remove')),
    por       text,
    motivo    text
);
CREATE INDEX IF NOT EXISTS list_audit_domain ON list_audit (domain, at DESC);
CREATE INDEX IF NOT EXISTS list_audit_category ON list_audit (category, at DESC);

CREATE OR REPLACE FUNCTION audita_category_lists() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  por text := nullif(current_setting('dnsguard.por', true), '');
  motivo text := nullif(current_setting('dnsguard.motivo', true), '');
BEGIN
  IF TG_OP IN ('DELETE', 'UPDATE') THEN
    INSERT INTO list_audit (domain, category, acao, por, motivo) VALUES (OLD.domain, OLD.category, 'remove', coalesce(por, '?'), motivo);
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    INSERT INTO list_audit (domain, category, acao, por, motivo) VALUES (NEW.domain, NEW.category, 'add', coalesce(por, NEW.added_by, '?'), motivo);
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS category_lists_audit ON category_lists;
CREATE TRIGGER category_lists_audit AFTER INSERT OR DELETE OR UPDATE ON category_lists
  FOR EACH ROW EXECUTE FUNCTION audita_category_lists();
