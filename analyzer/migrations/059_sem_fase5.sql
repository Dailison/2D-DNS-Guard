-- Pedido do usuário 27/09: sem fase 5 (Decisão Humana) — a IA decide tudo na fase 4 e a TI corrige os erros nas
-- listas. Esvazia "Para revisar" (nenhuma empresa a aplicava: não bloqueava nada); quem estava lá volta p/
-- `listas_ia.aplicar` decidir com a resposta que já tem (ou, sem resposta, `listas.sem_destino`).
UPDATE domains SET lista_aplicada_at = NULL
WHERE name IN (SELECT domain FROM category_lists WHERE category = 'para_revisar') AND NOT llm_pending AND lista_at IS NOT NULL;
DELETE FROM category_lists WHERE category = 'para_revisar';
