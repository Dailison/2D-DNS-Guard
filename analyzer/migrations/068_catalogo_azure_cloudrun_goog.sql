-- Etapa 1 com menos desconhecidos (30/09, pedido do usuário): Azure (windows.net e subdomínios, Traffic Manager),
-- Google Cloud Run (run.app), AWS Global Accelerator, CDN77 e o TLD .goog da Google passaram a ser do catálogo, como a
-- AWS: sem IA, whitelist Infraestrutura (translate.goog fica fora: são páginas de terceiros traduzidas). Os que já foram
-- vistos e ainda fora da whitelist voltam às regras; a pergunta de lista verifica (listas de ameaça, VirusTotal,
-- URLScan) e só então grava a whitelist sem chamar a IA. Ficam como estão: travados à mão e quem está numa lista de
-- bloqueio (identificados pela IA ou por pessoa — o catálogo não desbloqueia).
UPDATE domains d SET needs_analysis = true
WHERE d.kind = 'public' AND NOT d.locked
  AND (d.name IN ('windows.net', 'trafficmanager.net', 'run.app', 'awsglobalaccelerator.com', 'cdn77.org')
       OR d.name LIKE '%.windows.net' OR d.name LIKE '%.trafficmanager.net' OR d.name LIKE '%.run.app'
       OR d.name LIKE '%.awsglobalaccelerator.com' OR d.name LIKE '%.cdn77.org'
       OR (d.name LIKE '%.goog' AND d.name NOT LIKE '%.translate.goog'))
  AND d.lista_wl IS NULL
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name AND l.category NOT IN ('para_revisar', 'nao_identificado'));

-- Lista Blacklist (30/09, pedido do usuário): infraestrutura de terceiros que não passou na verificação. Vale onde a
-- lista Ameaças já vale (o console publica no Technitium ao sincronizar as políticas).
UPDATE policies SET lists = array_append(lists, 'blacklist'), updated_at = now()
WHERE 'ameaca' = ANY(lists) AND NOT ('blacklist' = ANY(lists));
