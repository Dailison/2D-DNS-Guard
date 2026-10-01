-- Listas por empresa/unidade (01/10, pedido do usuário): a lista de bloqueio continua uma só (a IA alimenta p/ todos) e
-- cada empresa ou unidade guarda os PRÓPRIOS ajustes — "liberar aqui" (tira o site das listas só ali) ou "bloquear
-- aqui". O da unidade vence o da empresa. O analisador publica, por escopo, as duas listas já resolvidas
-- (/ajustes/<liberar|bloquear>/<token>.txt) e o Technitium as assina no grupo do escopo.
CREATE TABLE IF NOT EXISTS ajustes_lista (
    scope   text NOT NULL,          -- tenant:<id> | unit:<id>:<unidade>
    domain  text NOT NULL,
    acao    text NOT NULL CHECK (acao IN ('liberar', 'bloquear')),
    por     text,
    em      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, domain)
);
CREATE INDEX IF NOT EXISTS ajustes_lista_domain ON ajustes_lista (domain);

-- quem fez o quê (inclusive desfazer): o ajuste some da tabela, o registro fica
CREATE TABLE IF NOT EXISTS ajustes_lista_log (
    id      bigserial PRIMARY KEY,
    scope   text NOT NULL,
    domain  text NOT NULL,
    acao    text NOT NULL,          -- liberar | bloquear | desfazer
    por     text,
    em      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ajustes_lista_log_scope ON ajustes_lista_log (scope, em DESC);
