-- (07/10) Incidente do com.br: às 15:24 a regra DNS Inativo pôs "com.br" na lista de bloqueio (o nome com.br não
-- resolve) e todo *.com.br ficou bloqueado até 15:56. No ciclo das 15:29 a trava da whitelist ("está numa lista de
-- bloqueio") apagou 2.308 domínios .com.br postos pela IA/catálogo. Aqui eles voltam, pela auditoria (list_audit):
-- mesma categoria, quem tinha posto e a data original, SEM publicar — o ciclo da whitelist republica os que merecem
-- (catálogo protegido, dois modelos). Fica de fora quem já voltou sozinho ou está (ele ou um pai) numa lista de bloqueio.
-- As travas que impedem a repetição estão no código (dnsativo.testavel, listas.sufixo_publico, whitelist._MAX_POR_PAI).
SELECT set_config('dnsguard.por', 'correção 079', true),
       set_config('dnsguard.motivo', 'volta à whitelist: apagado pela trava no incidente do com.br (07/10)', true);

DELETE FROM category_lists WHERE domain = 'com.br';

INSERT INTO whitelist_domains (category, domain, added_by, added_at, publicar)
SELECT DISTINCT ON (r.domain) substr(r.category, 4), r.domain, coalesce(o.por, 'IA (restaurado 079)'), coalesce(o.at, r.at), false
FROM list_audit r
LEFT JOIN LATERAL (SELECT a.por, a.at FROM list_audit a
                   WHERE a.domain = r.domain AND a.category = r.category AND a.acao = 'add' AND a.id < r.id
                     AND a.por NOT LIKE 'whitelist (trava)%'
                   ORDER BY a.id DESC LIMIT 1) o ON true
WHERE r.acao = 'remove' AND r.por = 'whitelist (trava)' AND r.motivo = 'está numa lista de bloqueio'
  AND r.at >= '2026-10-07 15:24:00-03' AND r.at < '2026-10-07 15:57:00-03'
  AND r.category LIKE 'wl:%' AND r.domain LIKE '%.com.br'
  AND NOT EXISTS (SELECT 1 FROM whitelist_domains w WHERE w.domain = r.domain)
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.category <> 'para_revisar'
                  AND (l.domain = r.domain OR right(r.domain, length(l.domain) + 1) = '.' || l.domain))
ORDER BY r.domain, r.id DESC
ON CONFLICT DO NOTHING;
