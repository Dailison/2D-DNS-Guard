-- Decisão global por site (tomada na visão "Todos os clientes"): vale também para
-- empresas que acessarem o site DEPOIS. A decisão da empresa, quando existe, prevalece.
-- Na fila, só "allowed" esconde o site de empresa sem decisão própria; "blocked" fica
-- registrado, mas quem esconde é o próprio bloqueio no Technitium (listas da empresa).
CREATE TABLE IF NOT EXISTS global_reviews (
    domain_id   bigint PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    status      text NOT NULL CHECK (status IN ('allowed', 'blocked')),
    reviewed_by text,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);

-- Backlog: decisões em lote já tomadas na visão "Todos" = mesma pessoa, mesmo status,
-- 2+ empresas em até 15 s, cobrindo TODAS as empresas que já tinham acessado o site
-- naquele momento.
INSERT INTO global_reviews (domain_id, status, reviewed_by, reviewed_at)
SELECT l.domain_id, l.status, l.by, l.at
FROM (
    SELECT td.domain_id, td.review_status AS status, td.reviewed_by AS by,
           max(td.reviewed_at) AS at, count(*) AS n
    FROM tenant_domains td
    WHERE td.review_status IS NOT NULL
    GROUP BY td.domain_id, td.review_status, td.reviewed_by
    HAVING count(*) >= 2 AND max(td.reviewed_at) - min(td.reviewed_at) <= interval '15 seconds'
) l
WHERE l.n = (SELECT count(*) FROM tenant_domains x WHERE x.domain_id = l.domain_id AND x.first_seen <= l.at)
ON CONFLICT (domain_id) DO NOTHING;
