-- "Reanalisar" pedido antes da correção (93e962a) levava o site à fase 1 mas o deixava na Decisão Humana (74 em
-- 27/09 ~00:38). Tira da fila quem tem revisão pedida e entrou na Decisão Humana ANTES da nova análise; se a
-- cascata terminar sem certeza de novo, o site volta sozinho.
SELECT set_config('dnsguard.por', 'reanálise pedida', true),
       set_config('dnsguard.motivo', 'nova análise pedida: volta à fase 1 (correção 047)', true);
DELETE FROM category_lists l USING domains d
WHERE l.category = 'para_revisar' AND l.domain = d.name AND d.reanalise_pedida
  AND NOT EXISTS (SELECT 1 FROM list_audit a WHERE a.domain = d.name AND a.category = 'para_revisar' AND a.acao = 'add'
                  AND a.at >= d.analyzed_at);
