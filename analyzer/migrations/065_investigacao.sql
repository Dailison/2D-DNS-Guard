-- Fase 6 (29/09, pedido do usuário): investigação profunda dos DESCONHECIDOS/SUSPEITOS com a fila da IA vazia —
-- fontes que as fases 1-4 não usam (registros DNS, certificados públicos, Wayback, páginas do site, buscas pela marca,
-- coocorrência nos logs do Technitium) e raciocínio em duas rodadas, até ~10 min por domínio. Com alta certeza muda a
-- classificação e a lista; sem certeza só guarda o dossiê (sem fase 5: nada vai p/ revisão humana).
ALTER TABLE domains ADD COLUMN IF NOT EXISTS investigado_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS investigacao jsonb;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS investigacao_claimed_at timestamptz;
