-- Revisão da Infraestrutura (039): entradas da migração bloqueadas por pessoa no grupo antigo estavam com
-- llm_pending = true. A fase 1 nunca pega domínio decidido e a fila online exige NOT llm_pending: ficavam
-- presas fora da revisão. Libera só essas para a IA online.
UPDATE domains d SET llm_pending = false
WHERE d.llm_pending AND dominio_decidido(d.id)
  AND EXISTS (SELECT 1 FROM category_lists l WHERE l.category = 'infra_bloqueio' AND l.domain = d.name
              AND l.added_by LIKE 'migração%');
