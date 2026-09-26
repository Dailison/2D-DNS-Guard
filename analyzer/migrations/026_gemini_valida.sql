-- A IA online passa a VALIDAR as sugestões da IA local (pedido do usuário 2026-09-26): tudo o que a
-- IA local sugeriu (inclusive o que já pôs sozinha numa lista) e tudo o que está em Decisões (fase 5)
-- entra na fila da fase 4. Com certeza, a resposta dela põe na lista certa (ou tira de Decisões).
UPDATE domains SET lista_duvida = true
WHERE online_at IS NULL AND lista_fonte = 'local' AND lista_ia IS NOT NULL;
UPDATE domains d SET lista_duvida = true
WHERE online_at IS NULL AND EXISTS (SELECT 1 FROM category_lists l WHERE l.category = 'para_revisar' AND l.domain = d.name);
