-- Todo site vai p/ uma fila: lista de bloqueio ou whitelist por categoria (pedido do usuário 2026-09-27: "Bloquear/
-- Liberar não existe mais"). Whitelists novas (ERP/gestão, RH/benefícios, logística, fornecedores, institucional,
-- telecom, jurídico, vendas/CRM, serviços, outros liberados). O que só a IA pôs na whitelist fica na categoria sem
-- publicar no DNS (publicar = false): a whitelist vence qualquer bloqueio em todas as empresas; publica quem tem pessoa,
-- catálogo ou dois modelos online. domains.lista_wl = whitelist escolhida pela IA na resposta de lista em uso.
ALTER TABLE whitelist_domains ADD COLUMN IF NOT EXISTS publicar boolean NOT NULL DEFAULT true;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_wl text;
-- "Sem resposta" pelo log do Technitium: consultas A não bloqueadas e quantas voltaram sem IP (NoError vazio,
-- NXDOMAIN, SERVFAIL, REFUSED) — antes só NXDOMAIN contava (hbgamesnm.com: 21 consultas, NoError sem IP)
ALTER TABLE query_agg ADD COLUMN IF NOT EXISTS ip_q int NOT NULL DEFAULT 0;
ALTER TABLE query_agg ADD COLUMN IF NOT EXISTS sem_ip int NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS query_agg_domain_bucket ON query_agg (domain_id, bucket);

-- liberados pela IA local sem categoria ("Aprovados"): a IA local escolhe a whitelist (fila de listas da fase 1)
UPDATE domains d SET lista_at = NULL
WHERE d.kind = 'public' AND d.lista_fonte = 'local' AND d.lista_ia IS NULL AND d.lista_wl IS NULL
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name)
  AND NOT EXISTS (SELECT 1 FROM whitelist_domains w WHERE w.domain = d.name);

-- liberados pela IA online com certeza: entram na whitelist da categoria que ela deu (reaplica)
UPDATE domains d SET lista_aplicada_at = NULL
WHERE d.kind = 'public' AND d.lista_fonte LIKE 'online%' AND d.lista_ia IS NULL AND d.lista_conf >= 0.8
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name)
  AND NOT EXISTS (SELECT 1 FROM whitelist_domains w WHERE w.domain = d.name);
