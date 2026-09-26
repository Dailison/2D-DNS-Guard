-- Serviços só para LIBERAR (pedido do usuário 2026-09-26): as listas de bloqueio são aplicadas
-- inteiras; serviços viram whitelists prontas. Ficam: YouTube, Spotify, Spotify Video, Deezer,
-- Instagram, Facebook, Pinterest, Discord, Mercado Livre, Amazon, Telegram (+ avulsas do usuário).
DELETE FROM allow_lists WHERE slug IN (
  'tiktok','x','kwai','snapchat','linkedin','whatsapp','netflix','twitch','globoplay','prime-video',
  'disney-plus','max','roblox','steam','epic-games','xbox','playstation','riot-games','free-fire',
  'bet365','betano') AND created_by LIKE 'migração%';
UPDATE policies SET services = ARRAY(SELECT unnest(services) INTERSECT SELECT slug FROM allow_lists),
                    services_blocked = '{}';
UPDATE allow_lists SET category = NULL;

INSERT INTO allow_lists (slug, name, created_by) VALUES
  ('spotify-video', 'Spotify Video', 'migração 022'),
  ('mercado-livre', 'Mercado Livre', 'migração 022'),
  ('amazon', 'Amazon', 'migração 022')
ON CONFLICT (slug) DO NOTHING;
INSERT INTO allow_list_domains (list_slug, domain, added_by)
SELECT s, d, 'migração 022' FROM (VALUES
  ('spotify-video', 'video-ak.cdn.spotify.com'), ('spotify-video', 'video-fa.cdn.spotify.com'), ('spotify-video', 'video-fa.scdn.co'),
  ('mercado-livre', 'mercadolivre.com.br'), ('mercado-livre', 'mercadolivre.com'), ('mercado-livre', 'mercadolibre.com'),
  ('mercado-livre', 'mlstatic.com'), ('mercado-livre', 'mercadopago.com.br'), ('mercado-livre', 'mercadopago.com'),
  ('amazon', 'amazon.com.br'), ('amazon', 'amazon.com'), ('amazon', 'media-amazon.com'),
  ('amazon', 'ssl-images-amazon.com'), ('amazon', 'images-amazon.com'),
  ('deezer', 'deezer.net'), ('youtube', 'youtubei.googleapis.com'), ('spotify', 'spotify.map.fastly.net')
) v(s, d) ON CONFLICT DO NOTHING;
