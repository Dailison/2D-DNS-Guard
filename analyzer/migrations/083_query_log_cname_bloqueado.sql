-- (05/11) Logs DNS agrupados: a cadeia CNAME dos nomes bloqueados (o culpado do bloqueio) era procurada pelo índice de
-- domínio, lendo o dia inteiro de cada domínio bloqueado (~370 mil páginas) para achar poucas linhas. Fora do cache levava
-- 60 s e a tela dava ReadTimeout. Índice só das linhas bloqueadas com resposta CNAME (uma fração mínima do log).
CREATE INDEX IF NOT EXISTS query_log_cname_bloqueado ON query_log (qname, ts DESC)
    WHERE rtype LIKE '%Blocked%' AND answer LIKE 'CNAME%';
