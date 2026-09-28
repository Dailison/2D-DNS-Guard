-- IPs liberados: quem da empresa autorizou a liberação e histórico (quem do console liberou/editou/revogou)
ALTER TABLE liberado_meta ADD COLUMN IF NOT EXISTS autorizado_por text;
ALTER TABLE liberado_meta ADD COLUMN IF NOT EXISTS updated_at timestamptz;
ALTER TABLE liberado_meta ADD COLUMN IF NOT EXISTS updated_by text;

CREATE TABLE IF NOT EXISTS liberado_log (
    id             bigserial PRIMARY KEY,
    at             timestamptz NOT NULL DEFAULT now(),
    ip             text NOT NULL,
    acao           text NOT NULL CHECK (acao IN ('liberar', 'editar', 'revogar')),
    por            text,                      -- usuário logado no console
    autorizado_por text,                      -- quem da empresa autorizou
    tenant_id      int REFERENCES tenants(id) ON DELETE SET NULL,
    detalhe        jsonb
);
CREATE INDEX IF NOT EXISTS liberado_log_at ON liberado_log (at DESC);
CREATE INDEX IF NOT EXISTS liberado_log_ip ON liberado_log (ip, at DESC);
