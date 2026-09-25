-- Recomendação para ambiente corporativo (todos os clientes são empresas):
-- BLOQUEAR | LIBERAR | REVISAR + justificativa; origem 'ia' ou 'politica' (padrão por categoria).
ALTER TABLE domains ADD COLUMN IF NOT EXISTS corp_action text;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS corp_reason text;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS corp_by text;

DROP VIEW IF EXISTS v_tenant_domains;
CREATE VIEW v_tenant_domains AS
SELECT td.tenant_id,
       d.id AS domain_id,
       d.name,
       d.kind,
       d.topic,
       d.category,
       COALESCE(td.override_classification, d.classification) AS classification,
       CASE WHEN td.override_classification IS NOT NULL
            THEN COALESCE(td.override_work_score, d.work_score)
            ELSE d.work_score END AS work_score,
       d.risk_score,
       d.confidence,
       d.recommended_action,
       -- recomendação corporativa; ajuste manual da empresa prevalece
       CASE td.override_classification
            WHEN 'TRABALHO' THEN 'LIBERAR' WHEN 'MALICIOSO' THEN 'BLOQUEAR'
            WHEN 'NAO_TRABALHO' THEN COALESCE(NULLIF(d.corp_action, 'LIBERAR'), 'REVISAR')
            ELSE d.corp_action END AS corp_action,
       CASE WHEN td.override_classification IS NOT NULL THEN 'ajuste manual: ' || COALESCE(NULLIF(td.override_note, ''), td.override_classification)
            ELSE d.corp_reason END AS corp_reason,
       CASE WHEN td.override_classification IS NOT NULL THEN 'manual' ELSE d.corp_by END AS corp_by,
       d.classified_by,
       (td.override_classification IS NOT NULL) AS overridden,
       td.first_seen,
       td.last_seen,
       td.total_queries,
       td.clients_count,
       d.popularity_rank,
       d.ti_hits,
       d.analyzed_at,
       d.llm_pending,
       td.review_status,
       td.reviewed_by,
       td.reviewed_at
FROM tenant_domains td
JOIN domains d ON d.id = td.domain_id;
