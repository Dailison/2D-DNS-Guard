-- Rodadas em que todos os modelos da IA online responderam sem JSON (ex.: filtro de segurança do Gemini em site
-- adulto). Na 3ª o domínio vai p/ a Decisão Humana em vez de voltar p/ o topo da fila da fase 4 (naticr.com, 27/09).
ALTER TABLE domains ADD COLUMN IF NOT EXISTS online_falhas int NOT NULL DEFAULT 0;
