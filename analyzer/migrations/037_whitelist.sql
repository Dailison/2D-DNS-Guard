-- Whitelists por categoria (pedido do usuário 2026-09-26): o que a IA (validada pela IA online) considerou
-- trabalho com certeza, os protegidos do catálogo e o que uma pessoa liberou. Publicadas em
-- /whitelist/<cat>.txt e assinadas por TODOS os grupos (allowListUrls: vencem qualquer bloqueio).
-- Auditoria na mesma list_audit (category = 'wl:<cat>').
CREATE TABLE IF NOT EXISTS whitelist_domains (
    category  text NOT NULL,
    domain    text NOT NULL,
    added_by  text,
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (category, domain)
);
CREATE INDEX IF NOT EXISTS whitelist_domains_domain ON whitelist_domains (domain);

CREATE OR REPLACE FUNCTION audita_whitelist() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  por text := nullif(current_setting('dnsguard.por', true), '');
  motivo text := nullif(current_setting('dnsguard.motivo', true), '');
BEGIN
  IF TG_OP IN ('DELETE', 'UPDATE') THEN
    INSERT INTO list_audit (domain, category, acao, por, motivo) VALUES (OLD.domain, 'wl:' || OLD.category, 'remove', coalesce(por, '?'), motivo);
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    INSERT INTO list_audit (domain, category, acao, por, motivo) VALUES (NEW.domain, 'wl:' || NEW.category, 'add', coalesce(por, NEW.added_by, '?'), motivo);
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS whitelist_domains_audit ON whitelist_domains;
CREATE TRIGGER whitelist_domains_audit AFTER INSERT OR DELETE OR UPDATE ON whitelist_domains
  FOR EACH ROW EXECUTE FUNCTION audita_whitelist();

-- Sites Revisados: já passaram pela IA online (ou decididos): não voltam p/ a IA sem pedido (os feeds de
-- ameaça continuam valendo — acerto novo reabre a análise pelo caminho normal).
ALTER TABLE domains ADD COLUMN IF NOT EXISTS revisado_at timestamptz;
UPDATE domains SET revisado_at = online_at WHERE online_at IS NOT NULL AND revisado_at IS NULL;

-- Candidatos a whitelist já respondidos pela IA online com um modelo só (TRABALHO, reconhecido, sem lista):
-- pergunta de novo (a re-pergunta sempre tem segunda opinião) — a whitelist exige dois modelos de acordo.
UPDATE domains SET online_at = NULL, lista_duvida = true
WHERE online_at IS NOT NULL AND online_resp->>'classificacao' = 'TRABALHO' AND (online_resp->>'reconhecido')::boolean
  AND coalesce(online_resp->>'lista', 'nenhuma') = 'nenhuma' AND NOT (online_resp->'_meta' ? 'antes');
