-- Regras novas da fase 4 (2026-09-26): a IA online não precisa mais bater com "é trabalho?" (a lista diz o
-- que o site é) e 0,8 basta p/ ela. Reaplica tudo o que ela já respondeu; e pergunta de novo o que ela
-- chamou de CDN/estático/API sem lista (domínio técnico de um serviço vai p/ a lista do serviço).
UPDATE domains SET online_at = NULL, lista_duvida = true
WHERE online_at IS NOT NULL AND online_resp->>'lista' = 'nenhuma'
  AND online_resp->>'servico' ~* '(cdn|est[aá]tic|static|imagens|image|api|arquivos|distribui[cç][aã]o de conte[uú]do|assets|m[ií]dia)';
UPDATE domains SET lista_aplicada_at = NULL WHERE online_at IS NOT NULL;
