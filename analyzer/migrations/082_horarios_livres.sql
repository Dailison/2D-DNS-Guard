-- (26/10, pedido do usuário) Horários livres por empresa/unidade: em certos dias e horas, listas escolhidas deixam de
-- bloquear (ex.: redes sociais no almoço). O console aplica no Technitium a política "vigente agora" (sem as listas
-- liberadas) e vira sozinho no começo/fim de cada horário. dias: 0 = domingo … 6 = sábado. fim < início = passa da
-- meia-noite.
CREATE TABLE IF NOT EXISTS horarios_livres (
    id         serial PRIMARY KEY,
    scope      text NOT NULL,              -- tenant:<id> ou unit:<id>:<unidade> (como em policies)
    dias       smallint[] NOT NULL,
    inicio     time NOT NULL,
    fim        time NOT NULL,
    listas     text[] NOT NULL,
    criado_por text,
    criado_em  timestamptz NOT NULL DEFAULT now(),
    CHECK (inicio <> fim)
);
CREATE INDEX IF NOT EXISTS horarios_livres_scope ON horarios_livres (scope);
