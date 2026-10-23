-- (22/10) Nome que não termina num domínio de topo conhecido (UUIDs, "didi", "target_domain", "11_1"…) é nome da rede
-- local que vazou p/ o DNS: o coletor o cadastrava como domínio público (o último rótulo virava o "domínio") e ele ia
-- p/ a IA, as listas e a investigação (ex.: 447d59ce-c346-11f1-9d87-58020527b510 investigado). Agora é interno
-- (features.analyze_name); aqui os já cadastrados (todos sem ponto) saem das filas e das entradas automáticas.
UPDATE domains SET kind = 'internal', llm_pending = false, needs_analysis = false, aguarda_recorrencia = false,
       reanalise_pedida = false, lista_duvida = false, claimed_at = NULL, investigacao_claimed_at = NULL
WHERE name NOT LIKE '%.%' AND kind IN ('public', 'inexistente');
DELETE FROM category_lists WHERE domain NOT LIKE '%.%'
  AND (added_by LIKE 'IA%' OR added_by LIKE 'regras%' OR added_by LIKE 'bloqueio automático%');
DELETE FROM whitelist_domains WHERE domain NOT LIKE '%.%' AND added_by LIKE 'IA%';
DELETE FROM global_reviews g USING domains d WHERE d.id = g.domain_id AND d.name NOT LIKE '%.%'
  AND (g.reviewed_by LIKE 'IA%' OR g.reviewed_by LIKE 'bloqueio automático%' OR g.reviewed_by LIKE 'regra%');
