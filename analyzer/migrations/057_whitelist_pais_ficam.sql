-- 27/09: pai de algo bloqueado (amazonaws.com, fastly.net, appspot.com…) com resposta "whitelist" saía da whitelist e
-- ficava sem categoria ("Aprovados"). Agora fica só na lista (sem publicar); reaplica os que ficaram soltos.
WITH em AS (SELECT domain FROM category_lists UNION SELECT domain FROM allow_list_domains UNION SELECT domain FROM whitelist_domains)
UPDATE domains d SET lista_aplicada_at = NULL
WHERE d.kind = 'public' AND NOT d.llm_pending AND d.lista_wl IS NOT NULL AND d.lista_fonte <> 'falhou'
  AND d.classification NOT IN ('SUSPEITO', 'MALICIOSO')
  AND NOT EXISTS (SELECT 1 FROM em WHERE em.domain = d.name OR d.name LIKE '%.' || em.domain);
