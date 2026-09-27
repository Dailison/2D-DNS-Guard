-- Prova de 27/09: com as whitelists como opção, a IA local (8B) liberou com 100% mensageiro (zaloapp.com), rede social
-- (masto.pt) e CDN de apostas. Pedido do usuário: a liberação da IA local também passa pela IA online. As que ela já
-- fez (4.117, entradas "IA local" na whitelist, sem publicar) vão p/ a fila da fase 4; ficam na categoria até lá.
UPDATE domains d SET lista_duvida = true
WHERE d.lista_fonte = 'local' AND d.lista_ia IS NULL
  AND EXISTS (SELECT 1 FROM whitelist_domains w WHERE w.domain = d.name AND w.added_by LIKE 'IA local%');
