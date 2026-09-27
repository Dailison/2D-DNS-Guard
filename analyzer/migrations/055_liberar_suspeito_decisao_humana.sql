-- 27/09: resposta "liberar" (whitelist) com certeza num site classificado SUSPEITO/MALICIOSO entrava na whitelist e
-- o whitelist.aplicar tirava em seguida: o site ficava sem fila nenhuma ("Aprovados", 69 casos). Agora vai p/ a
-- Decisão Humana (listas_ia._suspeito); reaplica os que ficaram assim.
UPDATE domains d SET lista_aplicada_at = NULL
WHERE d.kind = 'public' AND d.classification IN ('SUSPEITO', 'MALICIOSO') AND d.lista_wl IS NOT NULL
  AND d.lista_fonte <> 'falhou' AND NOT d.llm_pending
  AND NOT EXISTS (SELECT 1 FROM whitelist_domains w WHERE w.domain = d.name)
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name)
  AND NOT EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed');
