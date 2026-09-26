-- Fluxo em 4 fases (pedido do usuário 2026-09-26): 1 IA local; 2 busca na web (+WHOIS) + IA local;
-- 3 IA online (Gemini); 4 manual (Para revisar). Dúvida da etapa "lista" espera a fase 3 antes de
-- ir para Para revisar.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_duvida boolean NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS online_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS online_claimed_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS online_resp jsonb;
CREATE INDEX IF NOT EXISTS domains_lista_duvida ON domains (total_queries DESC) WHERE lista_duvida;
-- Compras passa a contar como categoria de trabalho (compras da empresa)
UPDATE site_categories SET nonwork = false WHERE code = 'compras';
