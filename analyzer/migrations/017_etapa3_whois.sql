-- Etapa 3: WHOIS/RDAP (+ CNPJ na Receita) p/ o que continua DESCONHECIDO depois da busca na web.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS whois_at timestamptz;
CREATE INDEX IF NOT EXISTS domains_etapa3 ON domains (total_queries DESC)
    WHERE classification = 'DESCONHECIDO' AND whois_at IS NULL;
