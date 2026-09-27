-- Triagem por acesso (performance, 2026-09-27): 83% da fila da fase 1 eram domínios com <= 2 consultas de 1
-- computador. Domínio com pouco acesso fica na fila com a prioridade SUSPENSA (aguarda_recorrencia): só as
-- regras valem até o site recorrer (LLM_MIN_QUERIES consultas ou LLM_MIN_CLIENTS computadores); então volta à
-- fila normal. Risco (feed de ameaça, SUSPEITO/MALICIOSO) e análise pedida por pessoa nunca esperam.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS aguarda_recorrencia boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS domains_aguarda_recorrencia ON domains (total_queries) WHERE aguarda_recorrencia;
-- backlog: quem já está na fila com pouco acesso passa a esperar (mantém llm_pending e a classificação atual)
UPDATE domains d SET aguarda_recorrencia = true
WHERE llm_pending AND NOT locked AND kind = 'public' AND NOT reanalise_pedida
  AND classification IS DISTINCT FROM 'SUSPEITO' AND classification IS DISTINCT FROM 'MALICIOSO'
  AND coalesce(ti_signature, '') = ''
  AND total_queries < 3
  AND (SELECT coalesce(sum(clients_count), 0) FROM tenant_domains td WHERE td.domain_id = d.id) < 2;
