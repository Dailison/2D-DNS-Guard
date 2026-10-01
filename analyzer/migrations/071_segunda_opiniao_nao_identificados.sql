-- 2ª opinião da IA online também p/ a investigação que terminou SEM identificar o serviço (30/09, pedido do usuário:
-- ssiloc.com — infraestrutura da Akamai — terminava "não identificado" e não ia p/ a IA online). Os já investigados
-- que não aplicaram e não passaram pela IA online depois da investigação entram na fila agora.
UPDATE domains SET online_pedido_at = now()
WHERE investigado_at IS NOT NULL AND investigacao IS NOT NULL
  AND NOT coalesce((investigacao->>'aplicado')::boolean, false)
  AND coalesce(investigacao->>'sem_aplicar', '') NOT LIKE 'lista de ameaça%'
  AND coalesce(investigacao->>'sem_aplicar', '') NOT LIKE 'erro:%'
  AND (online_at IS NULL OR online_at < investigado_at)
  AND (online_pedido_at IS NULL OR online_pedido_at < investigado_at);
