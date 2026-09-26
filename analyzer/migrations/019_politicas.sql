-- Política de bloqueio por empresa (e exceção por unidade): quais listas por categoria valem e
-- quais serviços ficam liberados como exceção. O console transforma isso nos grupos do
-- Technitium (um grupo interno por política distinta) — ninguém mais edita grupo à mão.
-- escopo: 'default' (redes fora do cadastro) | 'tenant:<id>' | 'unit:<id>:<unidade>'
CREATE TABLE IF NOT EXISTS policies (
    scope       text PRIMARY KEY,
    lists       text[] NOT NULL DEFAULT '{}',
    services    text[] NOT NULL DEFAULT '{}',
    updated_by  text,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO policies (scope, lists, updated_by)
VALUES ('default', ARRAY['ameaca','vpn_proxy','adulto','apostas','jogos'], 'migração 019')
ON CONFLICT (scope) DO NOTHING;
