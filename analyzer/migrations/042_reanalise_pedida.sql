-- "Reanalisar" pedido por uma pessoa leva o domínio pela fase 1 (IA local) de novo, mesmo decidido — antes a fase 1
-- pulava todo decidido e o pedido ficava parado (as 98 da Infraestrutura, 2026-09-26). A marca sai na fase 4.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS reanalise_pedida boolean NOT NULL DEFAULT false;

-- os que ficaram parados: pedido de reanálise sem fase 1 (llm_pending) e os que o pedido deixou como
-- DESCONHECIDO só pelas regras (sites adultos já bloqueados; a 041 tinha só tirado a marca)
UPDATE domains SET reanalise_pedida = true, llm_pending = true, claimed_at = NULL
WHERE kind = 'public' AND NOT locked AND dominio_decidido(id)
  AND (llm_pending OR (classification = 'DESCONHECIDO' AND classified_by = 'rules'));
