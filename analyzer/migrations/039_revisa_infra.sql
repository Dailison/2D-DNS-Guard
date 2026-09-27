-- Revisão da Infraestrutura (pedido do usuário 2026-09-26): as entradas que vieram da migração (antigo
-- grupo "CDN", que não era aplicado a ninguém e passou a bloquear p/ 17 empresas — ex. telemetria da
-- Microsoft via data.trafficmanager.net) passam pela IA online: lista certa com certeza; "nenhuma" com dois
-- modelos de acordo tira; sem certeza, fica.
UPDATE domains d SET online_at = NULL, lista_duvida = true
WHERE EXISTS (SELECT 1 FROM category_lists l WHERE l.category = 'infra_bloqueio' AND l.domain = d.name
              AND l.added_by LIKE 'migração%');
