-- Listas de LIBERAÇÃO (whitelist) com nome, vinculadas às empresas pela política (policies.services
-- guarda os slugs). Publicadas em /liberacao/<slug>.txt p/ o Technitium (allowListUrls): a
-- liberação vence qualquer lista de bloqueio. Os antigos "pacotes de serviços" viram listas prontas.
CREATE TABLE IF NOT EXISTS allow_lists (
    slug        text PRIMARY KEY,
    name        text NOT NULL,
    description text,
    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS allow_list_domains (
    list_slug  text NOT NULL REFERENCES allow_lists(slug) ON DELETE CASCADE ON UPDATE CASCADE,
    domain     text NOT NULL,
    added_by   text,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (list_slug, domain)
);
CREATE INDEX IF NOT EXISTS allow_list_domains_domain ON allow_list_domains (domain);
INSERT INTO allow_lists (slug, name, created_by) VALUES
  ('instagram', 'Instagram', 'migração 020'),
  ('facebook', 'Facebook', 'migração 020'),
  ('whatsapp', 'WhatsApp', 'migração 020'),
  ('youtube', 'YouTube', 'migração 020'),
  ('linkedin', 'LinkedIn', 'migração 020'),
  ('tiktok', 'TikTok', 'migração 020'),
  ('x', 'X (Twitter)', 'migração 020'),
  ('telegram', 'Telegram', 'migração 020'),
  ('spotify', 'Spotify', 'migração 020'),
  ('netflix', 'Netflix', 'migração 020'),
  ('kwai', 'Kwai', 'migração 020')
ON CONFLICT (slug) DO NOTHING;
INSERT INTO allow_list_domains (list_slug, domain, added_by)
SELECT s, d, 'migração 020' FROM (VALUES
  ('instagram', 'instagram.com'),
  ('instagram', 'cdninstagram.com'),
  ('instagram', 'instagr.am'),
  ('instagram', 'ig.me'),
  ('facebook', 'facebook.com'),
  ('facebook', 'facebook.net'),
  ('facebook', 'fbcdn.net'),
  ('facebook', 'fbsbx.com'),
  ('facebook', 'fb.com'),
  ('facebook', 'fb.me'),
  ('facebook', 'messenger.com'),
  ('facebook', 'm.me'),
  ('facebook', 'facebook.com.br'),
  ('whatsapp', 'whatsapp.com'),
  ('whatsapp', 'whatsapp.net'),
  ('whatsapp', 'wa.me'),
  ('youtube', 'youtube.com'),
  ('youtube', 'youtu.be'),
  ('youtube', 'ytimg.com'),
  ('youtube', 'googlevideo.com'),
  ('youtube', 'youtube-nocookie.com'),
  ('youtube', 'ggpht.com'),
  ('linkedin', 'linkedin.com'),
  ('linkedin', 'licdn.com'),
  ('linkedin', 'lnkd.in'),
  ('tiktok', 'tiktok.com'),
  ('tiktok', 'tiktokcdn.com'),
  ('tiktok', 'tiktokv.com'),
  ('tiktok', 'tiktokcdn-us.com'),
  ('tiktok', 'ttwstatic.com'),
  ('tiktok', 'ibytedtos.com'),
  ('tiktok', 'byteoversea.com'),
  ('tiktok', 'bytedance.com'),
  ('x', 'twitter.com'),
  ('x', 'x.com'),
  ('x', 'twimg.com'),
  ('x', 't.co'),
  ('telegram', 'telegram.org'),
  ('telegram', 'telegram.me'),
  ('telegram', 't.me'),
  ('telegram', 'telesco.pe'),
  ('spotify', 'spotify.com'),
  ('spotify', 'scdn.co'),
  ('spotify', 'spotifycdn.com'),
  ('netflix', 'netflix.com'),
  ('netflix', 'nflxvideo.net'),
  ('netflix', 'nflximg.net'),
  ('netflix', 'nflxext.com'),
  ('netflix', 'nflxso.net'),
  ('kwai', 'kwai.com'),
  ('kwai', 'kwai.net'),
  ('kwai', 'kwaicdn.com'),
  ('kwai', 'kslawin.com'),
  ('kwai', 'yximgs.com'),
  ('kwai', 'kuaishou.com')
) v(s, d) ON CONFLICT DO NOTHING;
