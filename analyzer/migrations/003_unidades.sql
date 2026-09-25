-- Cadastro de empresas: cada rede (CIDR) de uma empresa é uma UNIDADE com nome
-- (ex.: Moral Auto Peças -> PBS 10.57.0.0/16, CAN 10.58.0.0/16).
ALTER TABLE tenant_networks ADD COLUMN IF NOT EXISTS unit text NOT NULL DEFAULT '';
