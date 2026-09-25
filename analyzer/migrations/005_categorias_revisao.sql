-- Categoria do site (vocabulário fixo, 2ª classificação além de trabalho/não trabalho)
CREATE TABLE IF NOT EXISTS site_categories (
    code        text PRIMARY KEY,
    label       text NOT NULL,
    description text NOT NULL DEFAULT '',
    nonwork     boolean NOT NULL DEFAULT false,  -- tipicamente não relacionado ao trabalho
    sort_order  int NOT NULL DEFAULT 0
);
INSERT INTO site_categories (code, label, description, nonwork, sort_order) VALUES
 ('produtividade',   'Produtividade e negócios', 'Office/Microsoft 365, Google Workspace, ERPs, CRMs, SaaS de empresa', false, 1),
 ('comunicacao',     'Comunicação',              'E-mail, mensageiros, videoconferência', false, 2),
 ('financas',        'Bancos e finanças',        'Bancos, pagamentos, contabilidade, meios de pagamento', false, 3),
 ('governo',         'Governo e órgãos públicos','gov.br, judiciário, fiscal, prefeituras', false, 4),
 ('infraestrutura',  'Infraestrutura e sistema', 'CDNs, nuvem, atualizações de sistema, certificados, APIs técnicas', false, 5),
 ('seguranca',       'Segurança',                'Antivírus, EDR, autenticação', false, 6),
 ('desenvolvimento', 'TI e desenvolvimento',     'Ferramentas de TI, desenvolvimento, suporte remoto', false, 7),
 ('educacao',        'Educação e referência',    'Cursos, enciclopédias, documentação', false, 8),
 ('saude',           'Saúde',                    'Saúde, clínicas, planos, sistemas de saúde', false, 9),
 ('noticias',        'Notícias e portais',       'Portais de notícias e entretenimento geral', true, 20),
 ('compras',         'Compras',                  'Lojas online, marketplaces', true, 21),
 ('servicos_pessoais','Serviços pessoais',       'Delivery, transporte, viagens, serviços do dia a dia', true, 22),
 ('redes_sociais',   'Redes sociais',            'Facebook, Instagram, TikTok, Kwai, X...', true, 23),
 ('streaming',       'Vídeo e streaming',        'Streaming de vídeo e música', true, 24),
 ('jogos',           'Jogos',                    'Jogos e plataformas de jogos', true, 25),
 ('apostas',         'Apostas',                  'Apostas e cassinos online', true, 26),
 ('adulto',          'Conteúdo adulto',          'Conteúdo adulto', true, 27),
 ('publicidade',     'Publicidade e rastreamento','Redes de anúncios, analytics, rastreamento', true, 28),
 ('vpn_proxy',       'VPN / Proxy',              'VPNs, proxies, DoH público, contorno de filtro', true, 29),
 ('ameaca',          'Ameaça',                   'Malware, phishing, C2', true, 40),
 ('interno',         'Interno',                  'Nomes internos da rede / AD', false, 41),
 ('outros',          'Outros',                   'Não se encaixa nas demais', false, 50),
 ('desconhecido',    'Desconhecido',             'Serviço não identificado', false, 51)
ON CONFLICT (code) DO NOTHING;

ALTER TABLE domains ADD COLUMN IF NOT EXISTS category text REFERENCES site_categories(code);
CREATE INDEX IF NOT EXISTS domains_category ON domains (category);

-- Fila "Aguardando decisão" por empresa (não trabalho / risco): o operador decide
ALTER TABLE tenant_domains ADD COLUMN IF NOT EXISTS review_status text;      -- NULL=pendente | blocked | allowed
ALTER TABLE tenant_domains ADD COLUMN IF NOT EXISTS reviewed_by text;
ALTER TABLE tenant_domains ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;

-- Webhook: marca quando o alerta foi enviado à TI
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notified_at timestamptz;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notify_error text;

-- visão por empresa passa a expor a categoria e a revisão
DROP VIEW IF EXISTS v_tenant_domains;
CREATE VIEW v_tenant_domains AS
SELECT td.tenant_id,
       d.id AS domain_id,
       d.name,
       d.kind,
       d.topic,
       d.category,
       COALESCE(td.override_classification, d.classification) AS classification,
       CASE WHEN td.override_classification IS NOT NULL
            THEN COALESCE(td.override_work_score, d.work_score)
            ELSE d.work_score END AS work_score,
       d.risk_score,
       d.confidence,
       d.recommended_action,
       d.classified_by,
       (td.override_classification IS NOT NULL) AS overridden,
       td.first_seen,
       td.last_seen,
       td.total_queries,
       td.clients_count,
       d.popularity_rank,
       d.ti_hits,
       d.analyzed_at,
       d.llm_pending,
       td.review_status,
       td.reviewed_by,
       td.reviewed_at
FROM tenant_domains td
JOIN domains d ON d.id = td.domain_id;
