-- Listas curadas de anúncios/rastreadores (AdGuard DNS filter, Peter Lowe, EasyList, EasyPrivacy):
-- domínio listado = publicidade/rastreamento pelas regras, sem gastar IA.
CREATE TABLE IF NOT EXISTS ad_domains (
    name    text PRIMARY KEY,
    sources text[] NOT NULL
);
CREATE TABLE IF NOT EXISTS adlist_state (
    id           int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    refreshed_at timestamptz,
    entries      int,
    detail       jsonb
);

-- nome e seus "pais" (a.b.c.com -> {a.b.c.com, b.c.com, c.com, com}); o sufixo público
-- nunca está em ad_domains, então incluí-lo é inofensivo
CREATE OR REPLACE FUNCTION _parents(n text) RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
  SELECT array_agg(array_to_string(p[i:], '.'))
  FROM (SELECT string_to_array(lower(n), '.') AS p) x, generate_subscripts(x.p, 1) AS i
$$;
