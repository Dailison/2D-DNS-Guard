-- Cota do Gemini persistida (27/09): o contador vivia só na memória e o classificador reiniciou 32 vezes num
-- dia (deploys); cada reinício zerava a conta e os modelos Flash (20/dia) passaram do limite. Cada pedido é
-- gravado por (chave, modelo, dia do Pacífico — a cota do Google zera à meia-noite lá), com a pausa do dia
-- (429 "PerDay") e o limite que o Google informou (quotaValue).
CREATE TABLE IF NOT EXISTS online_cota (
    chave         smallint NOT NULL,          -- 1 = GEMINI_API_KEY, 2..4 = GEMINI_API_KEY_2..4
    modelo        text NOT NULL,
    dia           date NOT NULL,
    n             int NOT NULL DEFAULT 0,     -- pedidos feitos (contam todos, com resposta ou não)
    limite        int,                        -- quotaValue do dia informado pelo Google no 429
    esgotou_at    timestamptz,                -- 429 de cota do DIA: pausado até o dia virar
    atualizado_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chave, modelo, dia)
);
-- hoje (Pacífico) já gasto antes da persistência: aproxima pelos eventos da fase 4 (na chave 1; as outras chaves
-- ficam com o 429 do Google como guarda até o dia virar)
INSERT INTO online_cota (chave, modelo, dia, n)
SELECT 1, m, d, count(*) FROM (
    SELECT (regexp_match(detail, 'fase 4 · ([a-z0-9.-]+)'))[1] AS m, (created_at AT TIME ZONE 'America/Los_Angeles')::date AS d
    FROM ai_events WHERE kind = 'online_done') x
WHERE m IS NOT NULL AND d = (now() AT TIME ZONE 'America/Los_Angeles')::date
GROUP BY m, d
ON CONFLICT DO NOTHING;
