-- Serviço / lista de liberação liberado só para um IP (ou faixa), sem liberar para a empresa inteira.
-- O console monta um grupo próprio para o IP no Technitium (política da rede dele + estes serviços).
-- Mesmos dados dos IPs liberados (empresa/filial/departamento/usuário/tipo e quem autorizou); o histórico
-- vai para liberado_log com o serviço em detalhe->>'servico'.
CREATE TABLE IF NOT EXISTS ip_servicos (
    ip             text NOT NULL,              -- normalizado, ex.: 10.100.10.20/32
    slug           text NOT NULL REFERENCES allow_lists(slug) ON DELETE CASCADE ON UPDATE CASCADE,
    tenant_id      int REFERENCES tenants(id) ON DELETE SET NULL,
    filial         text,
    departamento   text,
    usuario        text,
    tipo           text,
    autorizado_por text,                       -- quem da empresa autorizou
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text,
    updated_at     timestamptz,
    updated_by     text,
    PRIMARY KEY (ip, slug)
);
CREATE INDEX IF NOT EXISTS ip_servicos_slug ON ip_servicos (slug);
