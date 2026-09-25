-- Vista agrupada dos Logs DNS lida do analisador (em vez do Query Logs SQLite do
-- Technitium, que leva 15-30 s por página): índice por hora p/ "todos os clientes".
CREATE INDEX IF NOT EXISTS query_agg_bucket ON query_agg (bucket);
