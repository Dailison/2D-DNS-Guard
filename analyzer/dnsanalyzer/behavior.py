"""Análise comportamental por tenant -> alertas (somente análise; nada é bloqueado).

Alertas:
* malicious_access  — computador consultou domínio MALICIOSO (crítico)
* suspicious_access — domínio SUSPEITO consultado (1 alerta/domínio/dia, com os computadores)
* new_domains_spike — computador acessou muito mais domínios INÉDITOS que os colegas do mesmo cliente
* volume_spike      — consultas na última hora muito acima da média do próprio computador
* dga_burst         — muitos nomes aleatórios com NXDOMAIN (assinatura típica de malware com DGA)

Comparações entre computadores são SEMPRE dentro do mesmo tenant.
Detectores que dependem de histórico só rodam após o período de aquecimento.
"""

from __future__ import annotations

import logging
import statistics
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from . import db

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
               "volume_spike": 0, "dga_burst": 0}
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
