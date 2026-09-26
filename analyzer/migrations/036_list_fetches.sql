-- Plano de confiabilidade, fase 4.3: pulso das listas publicadas (última busca do Technitium) e proteção
-- contra publicar lista esvaziada (last_n = tamanho da última versão servida).
CREATE TABLE IF NOT EXISTS list_fetches (
    category  text PRIMARY KEY,
    last_at   timestamptz,
    last_ip   text,
    last_n    int,
    recusada_at timestamptz,
    recusada_n  int
);
