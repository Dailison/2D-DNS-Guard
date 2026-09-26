"""Análise comportamental por tenant -> alertas (somente análise; nada é bloqueado).

Alertas:
* malicious_access  — computador consultou domínio MALICIOSO (crítico)
* suspicious_access — domínio SUSPEITO consultado (1 alerta/domínio/dia, com os computadores)
* new_domains_spike — computador acessou muito mais domínios INÉDITOS que os colegas do mesmo cliente
* volume_spike      — consultas na última hora muito acima da média do próprio computador
* dga_burst         — muitos nomes aleatórios com NXDOMAIN (assinatura típica de malware com DGA)
* blocked_work      — site de TRABALHO (classificação, categoria de trabalho ou protegido) bloqueado
* block_spike       — um domínio bloqueado para muitos computadores da empresa na mesma hora
  (os dois só olham bloqueio NOVO — nenhuma hora das 24 anteriores com ≥ 20% das consultas do domínio
  bloqueadas na empresa — e ignoram bloqueio INTENCIONAL: posto numa lista por pessoa/migração ou numa
  lista de uso misto. Bloqueio via CNAME de uma entrada antiga, ex. telemetria da Microsoft por
  data.trafficmanager.net, é conhecido e não alerta; o incidente apple-dns.net, novo, alertaria)

Comparações entre computadores são SEMPRE dentro do mesmo tenant.
Detectores que dependem de histórico só rodam após o período de aquecimento.
"""

from __future__ import annotations

import logging
import statistics
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from . import catalog, corporate, db

log = logging.getLogger(__name__)
WARMUP_DAYS = 7


def _upsert_alert(c, tenant_id, kind, severity, title, dedup, details, client_id=None, domain_id=None) -> bool:
    r = c.execute(
        "INSERT INTO alerts (tenant_id, kind, severity, client_id, domain_id, title, details, dedup_key) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (tenant_id, dedup_key) DO UPDATE SET details=EXCLUDED.details, updated_at=now() "
        "RETURNING (xmax = 0) AS inserted",
        (tenant_id, kind, severity, client_id, domain_id, title, Jsonb(details), dedup)).fetchone()
    return bool(r and r["inserted"])


_AUTO = ("IA automática", "IA com dúvida", "IA sem certeza", "bloqueio automático")
_USO_MISTO = {"mensageiros", "ia_chatbots", "nuvem_remoto", "doh_dns"}   # (DoH: bloquear é o objetivo da lista)


def _intencional(c, nome: str) -> bool:
    """Bloqueio de propósito: o domínio (ou um pai) está numa lista posta por pessoa/migração, ou numa lista
    de uso misto (a empresa escolheu aplicá-la)."""
    p = nome.split(".")
    cands = [".".join(p[i:]) for i in range(len(p) - 1)]
    for r in c.execute("SELECT category, coalesce(added_by, '') AS por FROM category_lists "
                       "WHERE domain = ANY(%s) AND category <> 'para_revisar'", (cands,)):
        if r["category"] in _USO_MISTO or not r["por"].startswith(_AUTO):
            return True
    return False


def _robust_threshold(values: list[float], k: float = 5.0, floor: float = 0) -> float:
    if not values:
        return float("inf")
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values]) or 1.0
    return max(floor, med + k * 1.4826 * mad)


def run(since: datetime | None = None) -> dict:
    now = datetime.now(timezone.utc)
    since = since or (now - timedelta(hours=1))
    day = now.strftime("%Y-%m-%d")
    created = {"malicious_access": 0, "suspicious_access": 0, "new_domains_spike": 0,
               "volume_spike": 0, "dga_burst": 0, "blocked_work": 0, "block_spike": 0}
    hora = since.replace(minute=0, second=0, microsecond=0)
    with db.conn() as c:
        tenants = c.execute("SELECT id, name FROM tenants WHERE active").fetchall()
        for t in tenants:
            tid = t["id"]
            # 1) acesso a MALICIOSO
            for r in c.execute(
                "SELECT cd.client_id, host(cl.ip) AS ip, v.domain_id, v.name, cd.queries, cd.last_seen "
                "FROM client_domains cd JOIN clients cl ON cl.id=cd.client_id "
                "JOIN v_tenant_domains v ON v.tenant_id=cd.tenant_id AND v.domain_id=cd.domain_id "
                "WHERE cd.tenant_id=%s AND cd.last_seen >= %s AND v.classification='MALICIOSO'", (tid, since)):
                if _upsert_alert(c, tid, "malicious_access", "critical",
                                 f"{r['ip']} consultou domínio malicioso {r['name']}",
                                 f"mal:{r['client_id']}:{r['domain_id']}:{day}",
                                 {"ip": r["ip"], "domain": r["name"], "queries": r["queries"],
                                  "last_seen": r["last_seen"].isoformat()}, r["client_id"], r["domain_id"]):
                    created["malicious_access"] += 1

            # 2) acesso a SUSPEITO (agrupado por domínio)
            for r in c.execute(
                "SELECT v.domain_id, v.name, v.risk_score, array_agg(DISTINCT host(cl.ip)) AS ips, "
                " sum(cd.queries) AS q FROM client_domains cd JOIN clients cl ON cl.id=cd.client_id "
                "JOIN v_tenant_domains v ON v.tenant_id=cd.tenant_id AND v.domain_id=cd.domain_id "
                "WHERE cd.tenant_id=%s AND cd.last_seen >= %s AND v.classification='SUSPEITO' "
                "GROUP BY v.domain_id, v.name, v.risk_score", (tid, since)):
                sev = "high" if (r["risk_score"] or 0) >= 75 else "medium"
                if _upsert_alert(c, tid, "suspicious_access", sev,
                                 f"Domínio suspeito {r['name']} consultado por {len(r['ips'])} computador(es)",
                                 f"susp:{r['domain_id']}:{day}",
                                 {"domain": r["name"], "risk": r["risk_score"], "ips": r["ips"][:50],
                                  "queries": int(r["q"])}, None, r["domain_id"]):
                    created["suspicious_access"] += 1

            # 3) DGA: muitos nomes aleatórios com NXDOMAIN por computador (24h)
            for r in c.execute(
                "SELECT q.client_id, host(cl.ip) AS ip, count(DISTINCT q.fqdn_id) AS n, "
                " (array_agg(DISTINCT f.name))[1:10] AS ex FROM query_agg q "
                "JOIN fqdns f ON f.id=q.fqdn_id JOIN clients cl ON cl.id=q.client_id "
                "WHERE q.tenant_id=%s AND q.bucket >= %s AND q.nxdomain > 0 "
                " AND ((f.features->>'sub_dga')::float >= 0.6 OR (f.features->>'sld_dga')::float >= 0.6) "
                "GROUP BY q.client_id, cl.ip HAVING count(DISTINCT q.fqdn_id) >= 10",
                    (tid, now - timedelta(hours=24))):
                if _upsert_alert(c, tid, "dga_burst", "high",
                                 f"{r['ip']}: {r['n']} nomes aleatórios inexistentes (possível malware com DGA)",
                                 f"dga:{r['client_id']}:{day}", {"ip": r["ip"], "count": r["n"], "examples": r["ex"]},
                                 r["client_id"]):
                    created["dga_burst"] += 1

            # 4) bloqueios suspeitos na última hora (site de trabalho / muitos computadores)
            bloq = c.execute(
                "SELECT q.domain_id, v.name, v.classification, v.category, count(DISTINCT q.client_id) AS pcs, "
                " sum(q.blocked) AS b, (array_agg(DISTINCT host(cl.ip)))[1:50] AS ips FROM query_agg q "
                "JOIN clients cl ON cl.id = q.client_id "
                "JOIN v_tenant_domains v ON v.tenant_id = q.tenant_id AND v.domain_id = q.domain_id "
                "WHERE q.tenant_id = %s AND q.bucket >= %s AND q.blocked > 0 "
                "GROUP BY q.domain_id, v.name, v.classification, v.category", (tid, hora)).fetchall()
            if bloq:
                ativos = c.execute("SELECT count(DISTINCT client_id) AS n FROM query_agg WHERE tenant_id = %s AND bucket >= %s",
                                   (tid, hora)).fetchone()["n"]
                # bloqueio que já existia: em alguma hora das 24 anteriores à janela o domínio já teve ≥ 20% das
                # consultas bloqueadas na empresa — conhecido, não é o que o alerta procura
                antigos = {r["domain_id"] for r in c.execute(
                    "SELECT DISTINCT domain_id FROM (SELECT domain_id, bucket FROM query_agg WHERE tenant_id = %s "
                    " AND domain_id = ANY(%s) AND bucket < %s AND bucket >= %s - interval '24 hours' "
                    " GROUP BY domain_id, bucket HAVING sum(blocked) >= 5 AND sum(blocked) >= 0.2 * sum(queries)) x",
                    (tid, [r["domain_id"] for r in bloq], hora, hora))}
                for r in bloq:
                    if r["domain_id"] in antigos or _intencional(c, r["name"]):
                        continue
                    e = catalog.match(r["name"])
                    trabalho = (r["classification"] == "TRABALHO" or r["category"] in corporate.NEVER_BLOCK
                                or bool(e and e.get("protected")))
                    det = {"domain": r["name"], "computadores": r["pcs"], "bloqueios": int(r["b"]), "ips": r["ips"],
                           "classificacao": r["classification"], "categoria": r["category"]}
                    if trabalho and _upsert_alert(c, tid, "blocked_work", "high",
                                                  f"Site de trabalho bloqueado: {r['name']} ({r['pcs']} computador(es))",
                                                  f"blkwork:{r['domain_id']}:{day}", det, None, r["domain_id"]):
                        created["blocked_work"] += 1
                    if r["pcs"] >= max(5, 0.3 * ativos) and _upsert_alert(
                            c, tid, "block_spike", "high",
                            f"Bloqueio em massa: {r['name']} bloqueado para {r['pcs']} de {ativos} computadores",
                            f"blkspike:{r['domain_id']}:{day}", {**det, "ativos": ativos}, None, r["domain_id"]):
                        created["block_spike"] += 1

            # detectores que exigem histórico
            oldest = c.execute("SELECT min(first_seen) AS m FROM tenant_domains WHERE tenant_id=%s",
                               (tid,)).fetchone()["m"]
            if not oldest or oldest > now - timedelta(days=WARMUP_DAYS):
                continue

            # 4) muitos domínios inéditos (para o cliente) por computador, vs colegas (24h)
            rows = c.execute(
                "SELECT cd.client_id, host(cl.ip) AS ip, count(*) AS n FROM client_domains cd "
                "JOIN clients cl ON cl.id=cd.client_id "
                "JOIN tenant_domains td ON td.tenant_id=cd.tenant_id AND td.domain_id=cd.domain_id "
                "WHERE cd.tenant_id=%s AND cd.first_seen >= %s AND td.first_seen >= %s "
                "GROUP BY cd.client_id, cl.ip", (tid, now - timedelta(hours=24), now - timedelta(hours=24))
            ).fetchall()
            active = c.execute("SELECT count(DISTINCT client_id) AS n FROM client_domains "
                               "WHERE tenant_id=%s AND last_seen >= %s", (tid, now - timedelta(hours=24))
                               ).fetchone()["n"]
            vals = [r["n"] for r in rows] + [0] * max(active - len(rows), 0)
            thr = _robust_threshold(vals, 5.0, 20)
            for r in rows:
                if r["n"] >= thr:
                    if _upsert_alert(c, tid, "new_domains_spike", "medium",
                                     f"{r['ip']} acessou {r['n']} domínios inéditos nas últimas 24h "
                                     f"(colegas: mediana {statistics.median(vals):.0f})",
                                     f"newdom:{r['client_id']}:{day}",
                                     {"ip": r["ip"], "count": r["n"], "peer_median": statistics.median(vals),
                                      "threshold": round(thr)}, r["client_id"]):
                        created["new_domains_spike"] += 1

            # 5) pico de volume: última hora vs média horária do próprio computador (7 dias)
            for r in c.execute(
                "WITH h AS (SELECT client_id, sum(queries) FILTER (WHERE bucket >= %s) AS last_h, "
                "  sum(queries) FILTER (WHERE bucket < %s AND bucket >= %s) / 168.0 AS avg_h "
                "  FROM query_agg WHERE tenant_id=%s AND bucket >= %s GROUP BY client_id) "
                "SELECT h.*, host(cl.ip) AS ip FROM h JOIN clients cl ON cl.id=h.client_id "
                "WHERE last_h >= 500 AND last_h >= 5 * GREATEST(avg_h, 1)",
                    (now - timedelta(hours=1), now - timedelta(hours=1), now - timedelta(days=7, hours=1), tid,
                     now - timedelta(days=7, hours=1))):
                if _upsert_alert(c, tid, "volume_spike", "medium",
                                 f"{r['ip']}: {int(r['last_h'])} consultas na última hora "
                                 f"(média {r['avg_h']:.0f}/h)",
                                 f"vol:{r['client_id']}:{now:%Y-%m-%d-%H}",
                                 {"ip": r["ip"], "last_hour": int(r["last_h"]), "avg_hour": round(float(r["avg_h"]), 1)},
                                 r["client_id"]):
                    created["volume_spike"] += 1
        # avisa a TI (webhook) sobre os alertas de risco ainda não enviados
        from . import webhook
        created["webhook"] = webhook.notify_pending(c)
    return created
