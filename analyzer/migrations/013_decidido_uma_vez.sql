-- "Decidido uma vez, não volta": um site com decisão (global ou em qualquer empresa)
-- sai da fila de decisões de todas as empresas sem decisão própria e da fila da IA
-- (exceto SUSPEITO). Pedido do usuário em 2026-09-25.
CREATE INDEX IF NOT EXISTS tenant_domains_decididos ON tenant_domains (domain_id) WHERE review_status IS NOT NULL;

CREATE OR REPLACE FUNCTION dominio_decidido(d bigint) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM global_reviews WHERE domain_id = d)
      OR EXISTS (SELECT 1 FROM tenant_domains WHERE domain_id = d AND review_status IS NOT NULL)
$$;
