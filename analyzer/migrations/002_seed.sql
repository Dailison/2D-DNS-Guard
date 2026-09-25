-- Categorias (novas categorias: INSERT aqui ou via SQL; o prompt da IA lê desta tabela)
INSERT INTO categories (code, label, description, is_threat, sort_order) VALUES
 ('TRABALHO',     'Trabalho',      'Ferramentas, sistemas e infraestrutura usados para o trabalho (e-mail corporativo, Office/Microsoft 365, ERPs, bancos, governo, atualizações de sistema, CDNs e certificados).', false, 1),
 ('NAO_TRABALHO', 'Não trabalho',  'Uso pessoal/lazer: redes sociais, streaming, jogos, apostas, compras pessoais, publicidade/rastreamento. Não é malicioso por si só.', false, 2),
 ('SUSPEITO',     'Suspeito',      'Indícios técnicos de risco (lista de ameaça de confiança média/baixa, padrão DGA, domínio muito novo, TLD abusado) sem confirmação.', true, 3),
 ('MALICIOSO',    'Malicioso',     'Presente em fonte de ameaça de alta confiança (malware, C2, phishing).', true, 4),
 ('DESCONHECIDO', 'Desconhecido',  'Não há evidências suficientes para classificar.', false, 5)
ON CONFLICT (code) DO NOTHING;

-- Fontes de Threat Intelligence gratuitas (baixadas e comparadas LOCALMENTE;
-- nenhum domínio dos clientes é enviado para fora).
-- weight = pontos de risco de um acerto exato. confidence controla o que a fonte
-- pode concluir: só "high" leva a MALICIOSO; "low" é apenas sinal.
INSERT INTO ti_sources (name, label, kind, url, threat, confidence, weight, refresh_hours, license_note) VALUES
 ('urlhaus',        'URLhaus (abuse.ch) — hosts online com malware', 'hosts',
  'https://urlhaus.abuse.ch/downloads/hostfile/', 'malware', 'high', 90, 1, 'abuse.ch — uso livre (CC0)'),
 ('threatfox',      'ThreatFox (abuse.ch) — IOCs de malware/C2',       'hosts',
  'https://threatfox.abuse.ch/downloads/hostfile/', 'c2', 'high', 85, 3, 'abuse.ch — uso livre (CC0)'),
 ('hagezi_tif',     'HaGeZi Threat Intelligence Feeds',               'adblock',
  'https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt', 'threat', 'medium', 60, 12, 'HaGeZi — GPL-3.0'),
 ('hagezi_badware', 'HaGeZi Badware Hoster',                          'adblock',
  'https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt', 'badware', 'low', 30, 24, 'HaGeZi — GPL-3.0'),
 ('hagezi_dyndns',  'HaGeZi DynDNS',                                  'adblock',
  'https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt', 'dyndns', 'low', 20, 24, 'HaGeZi — GPL-3.0'),
 ('hagezi_bypass',  'HaGeZi Bypass (VPN/Proxy/DoH/TOR)',              'adblock',
  'https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt', 'bypass', 'low', 15, 24, 'HaGeZi — GPL-3.0; sinal de política, não de ameaça'),
 ('hagezi_tlds',    'HaGeZi TLDs mais abusados',                      'tld_adblock',
  'https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt', 'abused_tld', 'low', 15, 72, 'HaGeZi — GPL-3.0'),
 ('phishing_db',    'Phishing.Database (ativos)',                     'plain',
  'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt', 'phishing', 'low', 30, 12, 'MIT; tem falsos positivos em plataformas grandes')
ON CONFLICT (name) DO NOTHING;
