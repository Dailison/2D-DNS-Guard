-- Backlog da 011 também para sites que tinham UMA empresa no momento da decisão
-- (ex.: platinumai.net, só Locan às 23:37). As decisões são tomadas na visão padrão
-- "Todos os clientes", então vale como decisão do site.
INSERT INTO global_reviews (domain_id, status, reviewed_by, reviewed_at)
SELECT l.domain_id, l.status, l.by, l.at
FROM (
    SELECT td.domain_id, td.review_status AS status, td.reviewed_by AS by,
           min(td.reviewed_at) AS ini, max(td.reviewed_at) AS at, count(*) AS n
    FROM tenant_domains td
    WHERE td.review_status IS NOT NULL
    GROUP BY td.domain_id, td.review_status, td.reviewed_by
    HAVING max(td.reviewed_at) - min(td.reviewed_at) <= interval '15 seconds'
) l
WHERE l.n >= (SELECT count(*) FROM tenant_domains x
              WHERE x.domain_id = l.domain_id AND x.first_seen <= l.ini - interval '10 minutes')
ON CONFLICT (domain_id) DO NOTHING;
