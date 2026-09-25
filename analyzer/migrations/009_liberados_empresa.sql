-- Liberados ligados ao cadastro de Empresas: empresa (tenant) + filial (unit da rede).
-- `empresa` (texto livre) fica só como legado para linhas que não casaram.
ALTER TABLE liberado_meta ADD COLUMN IF NOT EXISTS tenant_id int REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE liberado_meta ADD COLUMN IF NOT EXISTS filial text;

-- 1) pelo IP: rede mais específica do cadastro que contém o IP/faixa liberado
UPDATE liberado_meta m SET tenant_id = n.tenant_id, filial = NULLIF(n.unit, '')
FROM (
    SELECT DISTINCT ON (lm.ip) lm.ip, tn.tenant_id, tn.unit
    FROM liberado_meta lm JOIN tenant_networks tn ON lm.ip::cidr <<= tn.cidr
    ORDER BY lm.ip, masklen(tn.cidr) DESC
) n
WHERE n.ip = m.ip AND m.tenant_id IS NULL;

-- 2) sem rede no cadastro: pelo nome digitado (ignora maiúsculas/acentos comuns)
UPDATE liberado_meta m SET tenant_id = t.id
FROM tenants t
WHERE m.tenant_id IS NULL AND m.empresa IS NOT NULL
  AND upper(translate(t.name, 'ÁÀÂÃÉÊÍÓÔÕÚÇáàâãéêíóôõúç', 'AAAAEEIOOOUCaaaaeeiooouc'))
    = upper(translate(m.empresa, 'ÁÀÂÃÉÊÍÓÔÕÚÇáàâãéêíóôõúç', 'AAAAEEIOOOUCaaaaeeiooouc'));
