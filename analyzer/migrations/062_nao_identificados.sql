-- Lista "Não identificados" (27/09, pedido do usuário): o que termina as 4 fases como DESCONHECIDO não vai mais p/ a
-- whitelist "Outros liberados" (espelhos de cassino como cs8sp.com, com nome aleatório e sem presença na web, eram
-- liberados). Move p/ a lista nova quem está em Outros liberados com classificação DESCONHECIDO e sem decisão de pessoa.
WITH mover AS (
    DELETE FROM whitelist_domains w USING domains d
    WHERE w.category = 'outros_liberados' AND d.name = w.domain AND d.classification = 'DESCONHECIDO'
      AND NOT d.locked
      AND NOT EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed')
      AND NOT EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id
                      AND (td.review_status = 'allowed' OR td.override_classification = 'TRABALHO'))
    RETURNING w.domain)
INSERT INTO category_lists (category, domain, added_by)
SELECT 'nao_identificado', domain, 'IA (não identificado)' FROM mover
ON CONFLICT DO NOTHING;
