-- Novas listas (pedido do usuário 2026-09-26: "falta alguma lista p/ facilitar o trabalho das IAs?"):
-- adware (Adware / Apps indesejados) e cripto_trading (Cripto / Trading). Reclassifica (etapa "lista" ->
-- IA online) o que pode cair nelas: finanças e os não trabalho de categorias genéricas fora de listas.
UPDATE domains d SET lista_at = NULL, lista_aplicada_at = NULL
WHERE d.kind = 'public' AND d.classification IS NOT NULL AND d.classification <> 'DESCONHECIDO' AND NOT d.llm_pending
  AND (d.category = 'financas'
       OR (d.classification IN ('NAO_TRABALHO', 'SUSPEITO')
           AND d.category IN ('outros', 'comunicacao', 'produtividade', 'servicos_pessoais', 'educacao', 'desconhecido', 'infraestrutura')))
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name AND l.category <> 'para_revisar'
                  AND coalesce(l.added_by, '') NOT LIKE 'IA automática%');
