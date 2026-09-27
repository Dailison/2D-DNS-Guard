-- Coluna "Decisão" do IA ao vivo: quem decidiu (fase 1-3 IA local, 4 IA online, 5 equipe de TI, regras, bloqueio
-- automático). domains.lista_fase = fase da resposta de lista atual (1-3 IA local, 4 IA online).
ALTER TABLE ai_events ADD COLUMN IF NOT EXISTS origem text;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_fase smallint;
UPDATE domains SET lista_fase = 4 WHERE lista_fonte LIKE 'online%' AND lista_fase IS NULL;
