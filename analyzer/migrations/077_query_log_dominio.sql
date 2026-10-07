-- Cópia dos logs por domínio: "o que o Technitium acabou de responder para este domínio" (teste de DNS da etapa 1).
-- Sem o índice a busca varria as últimas horas inteiras (~600 ms por domínio, medido em 07/10).
CREATE INDEX IF NOT EXISTS query_log_domain_ts ON query_log (domain_id, ts DESC);
