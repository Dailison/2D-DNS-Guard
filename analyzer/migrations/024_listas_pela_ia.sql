-- Etapa "lista": a IA diz a qual lista de bloqueio cada site pertence (o que o site É). Com certeza,
-- entra direto na lista; sem certeza, vai para "Para revisar" com a sugestão (etapa 4 / aprovação).
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_ia text;            -- NULL = nenhuma lista
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_conf real;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_motivo text;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_servico text;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_fonte text;         -- local | etapa4:<quem> | falhou
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_aplicada_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_claimed_at timestamptz;
CREATE INDEX IF NOT EXISTS domains_lista_fila ON domains (total_queries DESC)
    WHERE lista_at IS NULL AND classification IS NOT NULL;

-- Nova organização (pedido do usuário 2026-09-26): DoH/DNS sai de Infraestrutura para lista própria.
-- Quem aplicava Infraestrutura passa a aplicar DoH / DNS também (nada deixa de ser bloqueado).
UPDATE category_lists SET category = 'doh_dns', added_by = coalesce(added_by, '') || ' → DoH / DNS'
WHERE category = 'infra_bloqueio' AND domain IN ('adguard-dns.com', 'chrome.cloudflare-dns.com', 'dns.adguard.com',
  'dns.nextdns.io', 'dns.quad9.net', 'dns-tunnel-check.googlezip.net', 'dns.wechat.com',
  'doh-dns-apple-com.v.aaplimg.com', 'mozilla.cloudflare-dns.com', 'opendns.com');
UPDATE policies SET lists = array_append(lists, 'doh_dns'), updated_at = now()
WHERE 'infra_bloqueio' = ANY(lists) AND NOT ('doh_dns' = ANY(lists));
