-- Pedido do usuário 27/09: resposta confiável da IA (online com certeza, ou gemma4 com confiança alta e coerente) que
-- contraria uma decisão humana — liberado por pessoa x IA recomenda bloquear; lista posta por pessoa/migração x IA
-- recomenda outro destino — vai p/ a Decisão Humana com o parecer (listas_ia.aplicar). Reaplica os que já existem.
WITH ap AS (SELECT DISTINCT x FROM policies, unnest(lists) x),
d AS (SELECT d.id, d.name, d.lista_ia FROM domains d
      WHERE d.lista_at IS NOT NULL AND d.lista_fonte <> 'falhou'
        AND ((d.lista_fonte LIKE 'online%' AND coalesce(d.lista_conf, 0) >= 0.8)
             OR (d.lista_fonte = 'local' AND d.lista_modelo LIKE 'gemma4%' AND coalesce(d.lista_conf, 0) >= 0.9
                 AND NOT (d.lista_ia = 'ameaca' AND d.classification IS DISTINCT FROM 'MALICIOSO')))
        AND NOT EXISTS (SELECT 1 FROM category_lists r WHERE r.domain = d.name AND r.category = 'para_revisar')
        AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name AND l.category = d.lista_ia)),
alvo AS (
  SELECT id FROM d WHERE d.lista_ia IN (SELECT x FROM ap)
    AND ((SELECT locked FROM domains WHERE id = d.id)
         OR EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed'
                    AND g.reviewed_by NOT LIKE 'IA%' AND g.reviewed_by NOT LIKE 'bloqueio automático%')
         OR EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id
                    AND (td.review_status = 'allowed' OR td.override_classification = 'TRABALHO')))
  UNION
  SELECT d.id FROM d JOIN category_lists l ON l.domain = d.name
  WHERE l.category NOT IN ('para_revisar', 'outros_bloqueios')
    AND coalesce(l.added_by, '') NOT LIKE 'IA%' AND coalesce(l.added_by, '') NOT LIKE 'bloqueio automático%'
    AND NOT (l.category = 'infra_bloqueio' AND l.added_by LIKE 'migração%'))
UPDATE domains SET lista_aplicada_at = NULL WHERE id IN (SELECT id FROM alvo);
