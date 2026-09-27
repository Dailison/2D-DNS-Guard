-- Pedido do usuário 27/09: CDN ganha whitelist própria ("CDN e entrega de conteúdo"), separada de "Infraestrutura e
-- sistemas". Move as entradas de CDN da infraestrutura (nome de CDN conhecido, "cdn" no nome ou serviço descrito como CDN).
CREATE TEMP TABLE _cdn AS
SELECT w.domain FROM whitelist_domains w LEFT JOIN domains d ON d.name = w.domain
WHERE w.category = 'infraestrutura'
  AND (w.domain ~ '(^|\.)(cloudfront\.net|akamai(edge|hd|zed)?\.net|akamaitechnologies\.com|edgekey\.net|edgesuite\.net|akadns\.net|fastly\.net|fastly-edge\.com|fastlylb\.net|azureedge\.net|azurefd\.net|b-cdn\.net|cdn77\.org|edgecastcdn\.net|llnwd\.net|kxcdn\.com|jsdelivr\.net|stackpathcdn\.com|gcdn\.co|bunnycdn\.com|cloudflare\.net)$'
       OR w.domain ~ 'cdn'
       OR coalesce(d.lista_servico, d.topic, '') ~* '\mCDN\M|content delivery|entrega de conte');
UPDATE whitelist_domains w SET category = 'cdn' WHERE w.category = 'infraestrutura' AND w.domain IN (SELECT domain FROM _cdn)
  AND NOT EXISTS (SELECT 1 FROM whitelist_domains x WHERE x.category = 'cdn' AND x.domain = w.domain);
DELETE FROM whitelist_domains WHERE category = 'infraestrutura' AND domain IN (SELECT domain FROM _cdn);
UPDATE domains SET lista_wl = 'cdn' WHERE lista_wl = 'infraestrutura' AND name IN (SELECT domain FROM _cdn);
DROP TABLE _cdn;
