-- Serviços (estilo AdGuard): as listas de liberação viram SERVIÇOS com categoria opcional.
-- Serviço com categoria = sublista da lista de bloqueio (Instagram em Redes sociais); a
-- empresa pode bloquear só o serviço ou liberá-lo mesmo com a categoria bloqueada.
-- Serviço sem categoria = lista de liberação avulsa ("Sistemas do cliente", "Bancos").
ALTER TABLE allow_lists ADD COLUMN IF NOT EXISTS category text;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS services_blocked text[] NOT NULL DEFAULT '{}';

INSERT INTO allow_lists (slug, name, created_by) VALUES
  ('snapchat', 'Snapchat', 'migração 021'), ('pinterest', 'Pinterest', 'migração 021'),
  ('twitch', 'Twitch', 'migração 021'), ('globoplay', 'Globoplay', 'migração 021'),
  ('prime-video', 'Prime Video', 'migração 021'), ('disney-plus', 'Disney+', 'migração 021'),
  ('max', 'Max (HBO)', 'migração 021'), ('deezer', 'Deezer', 'migração 021'),
  ('roblox', 'Roblox', 'migração 021'), ('steam', 'Steam', 'migração 021'),
  ('epic-games', 'Epic Games', 'migração 021'), ('xbox', 'Xbox', 'migração 021'),
  ('playstation', 'PlayStation', 'migração 021'), ('riot-games', 'Riot Games (LoL/Valorant)', 'migração 021'),
  ('free-fire', 'Free Fire (Garena)', 'migração 021'), ('discord', 'Discord', 'migração 021'),
  ('bet365', 'Bet365', 'migração 021'), ('betano', 'Betano', 'migração 021')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO allow_list_domains (list_slug, domain, added_by)
SELECT s, d, 'migração 021' FROM (VALUES
  ('snapchat', 'snapchat.com'), ('snapchat', 'snap.com'), ('snapchat', 'sc-cdn.net'), ('snapchat', 'snapkit.com'),
  ('pinterest', 'pinterest.com'), ('pinterest', 'pinimg.com'), ('pinterest', 'pinterest.com.br'),
  ('twitch', 'twitch.tv'), ('twitch', 'ttvnw.net'), ('twitch', 'jtvnw.net'), ('twitch', 'twitchcdn.net'),
  ('globoplay', 'globoplay.globo.com'), ('globoplay', 'globoplay.com'),
  ('prime-video', 'primevideo.com'), ('prime-video', 'aiv-cdn.net'), ('prime-video', 'aiv-delivery.net'),
  ('disney-plus', 'disneyplus.com'), ('disney-plus', 'disney-plus.net'), ('disney-plus', 'dssott.com'), ('disney-plus', 'bamgrid.com'),
  ('max', 'max.com'), ('max', 'hbomax.com'), ('max', 'hbo.com'),
  ('deezer', 'deezer.com'), ('deezer', 'dzcdn.net'),
  ('roblox', 'roblox.com'), ('roblox', 'rbxcdn.com'), ('roblox', 'rbx.com'),
  ('steam', 'steampowered.com'), ('steam', 'steamcommunity.com'), ('steam', 'steamstatic.com'), ('steam', 'steamcontent.com'),
  ('epic-games', 'epicgames.com'), ('epic-games', 'unrealengine.com'), ('epic-games', 'epicgames.dev'),
  ('xbox', 'xbox.com'), ('xbox', 'xboxlive.com'), ('xbox', 'xboxservices.com'),
  ('playstation', 'playstation.com'), ('playstation', 'playstation.net'), ('playstation', 'sonyentertainmentnetwork.com'),
  ('riot-games', 'riotgames.com'), ('riot-games', 'leagueoflegends.com'), ('riot-games', 'playvalorant.com'), ('riot-games', 'riotcdn.net'),
  ('free-fire', 'garena.com'), ('free-fire', 'freefiremobile.com'), ('free-fire', 'ff.garena.com'),
  ('discord', 'discord.com'), ('discord', 'discordapp.com'), ('discord', 'discord.gg'), ('discord', 'discordapp.net'), ('discord', 'discord.media'),
  ('bet365', 'bet365.com'), ('bet365', 'bet365.bet.br'),
  ('betano', 'betano.com'), ('betano', 'betano.bet.br')
) v(s, d) ON CONFLICT DO NOTHING;

UPDATE allow_lists SET category = 'redes_sociais' WHERE slug IN ('instagram','facebook','tiktok','x','kwai','snapchat','pinterest','linkedin') AND category IS NULL;
UPDATE allow_lists SET category = 'streaming' WHERE slug IN ('youtube','netflix','spotify','twitch','globoplay','prime-video','disney-plus','max','deezer') AND category IS NULL;
UPDATE allow_lists SET category = 'jogos' WHERE slug IN ('roblox','steam','epic-games','xbox','playstation','riot-games','free-fire') AND category IS NULL;
UPDATE allow_lists SET category = 'mensageiros' WHERE slug IN ('whatsapp','telegram','discord') AND category IS NULL;
UPDATE allow_lists SET category = 'apostas' WHERE slug IN ('bet365','betano') AND category IS NULL;
