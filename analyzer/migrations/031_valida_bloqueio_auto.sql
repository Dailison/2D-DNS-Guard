-- Plano de confiabilidade, fase 1.2: o bloqueio automático passa a esperar a confirmação da IA online.
-- O que ele já pôs e a IA online nunca viu entra na fila da fase 4 (continua bloqueado enquanto isso).
UPDATE domains d SET lista_duvida = true
WHERE d.online_at IS NULL AND NOT d.lista_duvida
  AND EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name AND l.added_by LIKE 'bloqueio automático%');
