-- Whitelists novas p/ o que não é trabalho (27/09, pedido do usuário): Religião e espiritualidade, Infantil, hobby e
-- arte, Fitness/saúde pessoal/família — separadas de "Outros liberados". Move os que já estavam lá.
UPDATE whitelist_domains SET category = 'religiao' WHERE category = 'outros_liberados' AND domain IN (
    'biblia.pt', 'kjvbiblenow.com', 'idailybible.com', 'aplicativodabiblia.com.br', 'biblebox.com', 'bibliaon.com',
    'bibliaonline.com.br', 'devocionaldiario.com.br', 'flutlabs.com', 'odbm.org', 'universal.org');
UPDATE whitelist_domains SET category = 'infantil_hobby' WHERE category = 'outros_liberados' AND domain IN (
    'amocolorir.com.br', 'tudoparacolorir.com.br', 'ibispaint.com', 'redflamenco.com', 'imagepng.org');
UPDATE whitelist_domains SET category = 'bem_estar' WHERE category = 'outros_liberados' AND domain IN (
    'strava.com', 'runtastic.com', 'gymrats.app', 'babycenter.com', 'appsdevlab.com');
