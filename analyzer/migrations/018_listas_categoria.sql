-- Listas de bloqueio por categoria (jogos, apostas, adulto, vpn_proxy, ameaca), publicadas em
-- /listas/<categoria>.txt e ASSINADAS pelas políticas do Technitium (blockListUrls). O
-- bloqueio automático do analisador alimenta estas listas; o console gerencia.
CREATE TABLE IF NOT EXISTS category_lists (
    category  text NOT NULL,
    domain    text NOT NULL,
    added_by  text,
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (category, domain)
);
CREATE INDEX IF NOT EXISTS category_lists_domain ON category_lists (domain);
