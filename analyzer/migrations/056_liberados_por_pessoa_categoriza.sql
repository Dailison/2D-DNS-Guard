-- Pedido do usuário 27/09: "Aprovados" liberados por uma pessoa (global, empresa ou ajuste p/ trabalho) com a
-- sugestão de lista antiga do qwen3:8b voltam p/ a fase 1: o gemma4 dá a categoria de whitelist; se recomendar
-- lista de bloqueio com confiança, vai p/ a Decisão Humana (contraria decisão humana, 053). Decididos: reanalise_pedida.
WITH em AS (SELECT domain FROM category_lists UNION SELECT domain FROM allow_list_domains UNION SELECT domain FROM whitelist_domains)
UPDATE domains d SET llm_pending = true, reanalise_pedida = dominio_decidido(d.id), lista_duvida = false, lista_segue = false,
       claimed_at = NULL, llm_attempts = 0
WHERE d.kind = 'public' AND d.classification IS NOT NULL AND NOT d.llm_pending AND NOT d.locked
  AND d.lista_ia IS NOT NULL AND d.lista_fonte = 'local' AND d.lista_modelo IS NULL
  AND NOT EXISTS (SELECT 1 FROM em WHERE em.domain = d.name OR d.name LIKE '%.' || em.domain)
  AND (EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed')
       OR EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id
                  AND (td.review_status = 'allowed' OR td.override_classification = 'TRABALHO')));
