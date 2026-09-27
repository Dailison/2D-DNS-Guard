-- Pedido do usuário 27/09: o que espera as fases 2, 3 e 4 com resposta da IA local antiga (qwen3:8b) volta p/ a fase 1
-- com o gemma4:26b. WHOIS e busca na web já feitos ficam no cache e entram no dossiê da fase 1; sem confiança alta, segue
-- p/ a fase que falta ou p/ a IA online. Ficam de fora: o que o gemma4 já respondeu (dúvida legítima dele) e o
-- DESCONHECIDO sem nenhum resultado na web (classified_by 'web': nenhuma IA avaliou, não há o que reavaliar).
-- (050 pegou só a dúvida de lista; os que estavam nas fases 2/3 às 02:44 chegaram à fase 4 depois dela.)
UPDATE domains d SET llm_pending = true, lista_duvida = false, reanalise_pedida = dominio_decidido(d.id),
       claimed_at = NULL, llm_attempts = 0
WHERE d.kind = 'public' AND NOT d.llm_pending AND NOT d.locked
  AND coalesce(d.model, '') NOT LIKE 'gemma4%' AND coalesce(d.lista_modelo, '') NOT LIKE 'gemma4%'
  AND d.classified_by IS DISTINCT FROM 'web'
  AND (
    -- fase 4 (fila da IA online: online._FILA)
    (d.lista_duvida AND (d.online_at IS NULL OR d.online_at < d.lista_at))
    OR (d.classification = 'DESCONHECIDO' AND (d.online_at IS NULL OR d.online_at < d.analyzed_at)
        AND ((d.web_search_at IS NOT NULL AND (NOT dominio_decidido(d.id) OR d.reanalise_pedida))
             OR d.name IN (SELECT domain FROM category_lists WHERE category IN ('para_revisar', 'outros_bloqueios'))))
    -- fases 2 e 3 (WHOIS / busca na web ainda por fazer)
    OR (((d.classification = 'DESCONHECIDO' AND d.classified_by = 'llm')
         OR (d.lista_fonte = 'local' AND coalesce(d.lista_conf, 0) < 0.9 AND d.lista_at >= d.analyzed_at AND NOT d.lista_duvida))
        AND (d.whois_at IS NULL OR d.web_search_at IS NULL) AND (NOT dominio_decidido(d.id) OR d.reanalise_pedida)));
