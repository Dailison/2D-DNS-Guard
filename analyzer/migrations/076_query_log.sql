-- Cópia dos logs de consulta do Technitium, linha a linha (07/10, pedido do usuário): a vista Detalhado dos Logs lia do
-- Technitium (SQLite), onde cada chamada custa a contagem do período — o dia inteiro levava 28 s e dava timeout — e o
-- filtro por empresa era feito no console. O coletor já trazia todas as consultas e só guardava o resumo por hora
-- (query_agg); agora guarda também cada uma aqui, por 7 dias (LOG_RETENCAO_DIAS), em partições diárias (UTC) criadas
-- pelo coletor (query_log_AAAAMMDD) e apagadas inteiras na retenção.
CREATE TABLE IF NOT EXISTS query_log (
    ts         timestamptz NOT NULL,
    tenant_id  int         NOT NULL,
    client_ip  inet        NOT NULL,
    domain_id  bigint      NOT NULL,
    qname      text        NOT NULL,
    qtype      text,
    rtype      text,          -- tipo de resposta do Technitium (Recursive, Cached, Blocked, Authoritative…)
    rcode      text,
    answer     text
) PARTITION BY RANGE (ts);
-- (índices no pai: cada partição nova já nasce com eles)
CREATE INDEX IF NOT EXISTS query_log_ts ON query_log (ts DESC);
CREATE INDEX IF NOT EXISTS query_log_tenant_ts ON query_log (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS query_log_ip_ts ON query_log (client_ip, ts DESC);
