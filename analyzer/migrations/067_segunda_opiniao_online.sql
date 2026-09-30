-- IA online como 2ª opinião da investigação (30/09, pedido do usuário): quando a fase 6 chega a uma hipótese sem
-- certeza suficiente p/ aplicar (confiança 0,6 até o mínimo, ou o revisor discordou), o domínio volta p/ a fila da
-- fase 4 e a IA online decide lendo o dossiê completo da investigação.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS online_pedido_at timestamptz;

-- os que já foram investigados nesse caso entram na fila agora (só os que ninguém decidiu)
UPDATE domains d SET online_pedido_at = now()
 WHERE d.investigacao IS NOT NULL AND NOT (d.investigacao->>'aplicado')::boolean
   AND (d.investigacao->'veredito'->>'recognized')::boolean
   AND d.investigacao->'veredito'->>'classification' <> 'DESCONHECIDO'
   AND (d.investigacao->'veredito'->>'confidence')::numeric >= 0.6
   AND d.investigacao->>'sem_aplicar' NOT LIKE 'lista de ameaça%'
   AND d.classification IN ('DESCONHECIDO', 'SUSPEITO') AND NOT d.locked AND NOT dominio_decidido(d.id);
