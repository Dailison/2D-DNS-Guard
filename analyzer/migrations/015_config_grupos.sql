-- Configuração dos grupos de bloqueio do Technitium que o Advanced Blocking não guarda.
-- especifico = grupo temático (ex.: "Anuncios"): fica de fora do "Bloquear em todas".
CREATE TABLE IF NOT EXISTS group_settings (
    name       text PRIMARY KEY,
    especifico boolean NOT NULL DEFAULT false,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
