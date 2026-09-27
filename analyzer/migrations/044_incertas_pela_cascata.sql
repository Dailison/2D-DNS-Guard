-- Pedido do usuário (2026-09-27): sugestões da IA local SEM confiança alta que foram p/ a fila da IA online sem passar
-- pelas fases 2 (WHOIS) e 3 (busca na web) voltam p/ a cascata (1.309 em 27/09). As com confiança alta seguem na fila
-- da IA online (validação: a IA local erra com "certeza", ex. adguard.com -> publicidade).
UPDATE domains SET lista_duvida = false
WHERE kind = 'public' AND lista_duvida AND lista_fonte = 'local' AND coalesce(lista_conf, 0) < 0.9
  AND (online_at IS NULL OR online_at < lista_at) AND (whois_at IS NULL OR web_search_at IS NULL);
