-- (06/11/2026) Computadores em varredura (pedido do usuário): acima de VARREDURA_LIMITE_HORA (50) domínios inéditos
-- por hora o computador fica travado para avaliação e os domínios que só ele acessou ficam retidos (nenhuma fase da IA
-- os pega) até um computador comum acessá-los ou uma pessoa liberar o computador. Ver dnsanalyzer/varredura.py.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS varredura boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS domains_varredura ON domains (id) WHERE varredura;

CREATE TABLE IF NOT EXISTS dispositivos_varredura (
    tenant_id    int    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id    bigint NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    ip           inet   NOT NULL,
    estado       text   NOT NULL DEFAULT 'travado' CHECK (estado IN ('travado', 'liberado', 'confirmado')),
    detectado_em timestamptz NOT NULL DEFAULT now(),
    visto_em     timestamptz NOT NULL DEFAULT now(),
    pior_hora    int    NOT NULL DEFAULT 0,
    ultima_hora  int    NOT NULL DEFAULT 0,
    exemplos     jsonb  NOT NULL DEFAULT '[]',
    decidido_por text,
    decidido_em  timestamptz,
    PRIMARY KEY (tenant_id, client_id)
);
CREATE INDEX IF NOT EXISTS dispositivos_varredura_ip ON dispositivos_varredura (tenant_id, ip);
