-- Plano de confiabilidade, fase 3.3: exceções imediatas ("manter liberado" vale na hora) que o console
-- põe no `allowed` dos grupos do Technitium. Registradas aqui p/ o console só tirar as SUAS (nunca um
-- `allowed` posto à mão no Technitium).
CREATE TABLE IF NOT EXISTS technitium_allowed_console (
    domain    text NOT NULL,
    grupo     text NOT NULL,
    added_by  text,
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, grupo)
);
