-- (22/10) Qual analisador fez a análise local (coluna "Analisador" do IA ao vivo): 'vm' ou o IP do reforço
-- (GPU/CPU). Nulo nos eventos antigos e nos que não são da IA local.
ALTER TABLE ai_events ADD COLUMN IF NOT EXISTS maquina text;
