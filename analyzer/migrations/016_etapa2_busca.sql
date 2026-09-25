-- Etapa 2 (busca na web): domínios que a IA deixou como DESCONHECIDO são pesquisados
-- no SearXNG local depois que a fila da etapa 1 esvazia. Uma vez por domínio.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS web_search_at timestamptz;
CREATE INDEX IF NOT EXISTS domains_etapa2 ON domains (total_queries DESC)
    WHERE classification = 'DESCONHECIDO' AND classified_by = 'llm' AND web_search_at IS NULL;
