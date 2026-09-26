"""API interna (consumida pelo console dns-guard.2dtecnologia.com).

Autenticação: header `Authorization: Bearer <API_TOKEN>`. Rotas de dados são
escopadas por empresa (/tenants/{tid}/...). tid=0 = visão "Todos os clientes"
(consolidada para a 2D): toda linha nela identifica a empresa de origem.
"""

from __future__ import annotations

import hmac
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from . import __version__, db
from .config import settings
from .features import analyze_name
from .llm import OllamaClient

app = FastAPI(title="2D DNS Analyzer", version=__version__, docs_url=None, redoc_url=None)


def auth(authorization: str = Header(default="")) -> None:
    token = settings().api_token
    if not token:
        raise HTTPException(503, "API_TOKEN não configurado")
    got = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(got, token):
        raise HTTPException(401, "token inválido")


def _since(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 365)))


def _tenant(c, tid: int) -> dict:
    t = c.execute("SELECT id, slug, name, active, auto_created FROM tenants WHERE id=%s", (tid,)).fetchone()
    if not t:
        raise HTTPException(404, "tenant não encontrado")
    return t


def _domain_name(name: str) -> str:
    info = analyze_name(name, settings().internal_suffixes)
    return info.registrable


# ------------------------------------------------------------------ saúde
@app.get("/health")
def health():
    out = {"version": __version__, "db": False}
    try:
        with db.conn() as c:
            c.execute("SELECT 1")
            out["db"] = True
            out["ingest_cursor"] = (c.execute("SELECT value FROM ingest_state WHERE key='ingest_cursor'")
                                    .fetchone() or {}).get("value")
            out["queue"] = dict(c.execute(
                "SELECT count(*) FILTER (WHERE needs_analysis) AS regras, "
                "count(*) FILTER (WHERE llm_pending AND NOT dominio_decidido(id)) AS ia, count(*) AS dominios FROM domains").fetchone())
    except Exception as e:  # noqa: BLE001
        out["db_error"] = str(e)[:200]
    ok, msg = OllamaClient().available()
    out["llm"] = {"ok": ok, "detail": msg, "model": settings().ollama_model, "enabled": settings().llm_enabled}
    out["webhook"] = {"enabled": bool(settings().webhook_urls), "kinds": settings().webhook_kinds,
                      "push": bool(settings().push_api_url and settings().push_api_token)}
    return out


@app.get("/stats", dependencies=[Depends(auth)])
def stats():
    with db.conn() as c:
        q = dict(c.execute(
            "SELECT count(*) FILTER (WHERE needs_analysis) AS fila_regras, count(*) FILTER (WHERE llm_pending AND NOT dominio_decidido(id)) AS fila_ia, "
            "count(*) FILTER (WHERE classified_by='llm') AS classificados_ia, count(*) AS dominios FROM domains").fetchone())
        q["ia_24h"] = c.execute("SELECT count(*) AS n FROM classification_history WHERE source='llm' "
                                "AND created_at >= now() - interval '24 hours'").fetchone()["n"]
        runs = c.execute("SELECT DISTINCT ON (kind) kind, started_at, finished_at, ok, stats, error "
                         "FROM analysis_runs ORDER BY kind, started_at DESC").fetchall()
        return {"queue": q, "last_runs": runs,
                "cursor": (c.execute("SELECT value, updated_at FROM ingest_state WHERE key='ingest_cursor'")
                           .fetchone())}


# ------------------------------------------------------------------ tenants
class NetworkIn(BaseModel):
    cidr: str
    unit: str = ""
    description: str = ""


class TenantIn(BaseModel):
    name: str
    networks: list[NetworkIn] = []


class TenantPatch(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None


class NetworkPatch(BaseModel):
    unit: Optional[str] = None
    tenant_id: Optional[int] = None
    description: Optional[str] = None


class ImportRow(BaseModel):
    empresa: str
    unidade: str = ""
    cidr: str


class ImportIn(BaseModel):
    rows: list[ImportRow]
    replace: bool = False


class MergeIn(BaseModel):
    into: int


class ResolveIn(BaseModel):
    ips: list[str]


def _cidr(s: str) -> str:
    try:
        return str(ipaddress.ip_network(s.strip(), strict=False))
    except ValueError:
        raise HTTPException(400, f"CIDR inválido: {s}")


def _after_network_change(c) -> dict:
    """Realoca dados conforme o cadastro e limpa empresas automáticas vazias."""
    from . import registry
    moved = registry.reassign_clients(c)
    moved["tenants_removed"] = registry.cleanup_empty_tenants(c, only_auto=True)
    return moved


@app.get("/tenants", dependencies=[Depends(auth)])
def tenants():
    with db.conn() as c:
        rows = c.execute(
            "SELECT t.*, COALESCE(json_agg(json_build_object('id', n.id, 'cidr', n.cidr::text, 'unit', n.unit, "
            " 'description', n.description) ORDER BY n.cidr) FILTER (WHERE n.id IS NOT NULL), '[]') AS networks, "
            " (SELECT count(*) FROM clients cl WHERE cl.tenant_id=t.id) AS clients, "
            " (SELECT max(last_seen) FROM clients cl WHERE cl.tenant_id=t.id) AS last_seen "
            "FROM tenants t LEFT JOIN tenant_networks n ON n.tenant_id=t.id GROUP BY t.id "
            "ORDER BY t.auto_created, t.name").fetchall()
        return rows


@app.post("/tenants", dependencies=[Depends(auth)])
def tenant_create(body: TenantIn):
    from . import registry
    from .tenants import slugify
    with db.conn() as c:
        registry.lock(c)
        if c.execute("SELECT 1 FROM tenants WHERE slug=%s", (slugify(body.name),)).fetchone():
            raise HTTPException(409, "já existe uma empresa com esse nome")
        t = c.execute("INSERT INTO tenants (slug, name) VALUES (%s, %s) RETURNING *",
                      (slugify(body.name), body.name.strip())).fetchone()
        for n in body.networks:
            c.execute("INSERT INTO tenant_networks (tenant_id, cidr, unit, description) VALUES (%s, %s, %s, %s) "
                      "ON CONFLICT (cidr) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, unit=EXCLUDED.unit",
                      (t["id"], _cidr(n.cidr), n.unit.strip(), n.description))
        res = _after_network_change(c)
        return {**t, "realocacao": res}


@app.post("/tenants/import", dependencies=[Depends(auth)])
def tenant_import(body: ImportIn):
    from . import registry
    with db.conn() as c:
        try:
            return registry.import_rows(c, [r.model_dump() for r in body.rows], body.replace)
        except ValueError as e:
            raise HTTPException(400, str(e))


@app.post("/tenants/{tid}/merge", dependencies=[Depends(auth)])
def tenant_merge(tid: int, body: MergeIn):
    from . import registry
    with db.conn() as c:
        _tenant(c, tid)
        _tenant(c, body.into)
        try:
            return registry.merge_tenant(c, tid, body.into)
        except ValueError as e:
            raise HTTPException(400, str(e))


@app.delete("/tenants/{tid}", dependencies=[Depends(auth)])
def tenant_delete(tid: int):
    with db.conn() as c:
        _tenant(c, tid)
        busy = c.execute("SELECT (SELECT count(*) FROM tenant_networks WHERE tenant_id=%s) AS n, "
                         "(SELECT count(*) FROM clients WHERE tenant_id=%s) AS c", (tid, tid)).fetchone()
        if busy["n"] or busy["c"]:
            raise HTTPException(409, "empresa tem redes ou dados: remova as redes ou use mesclar")
        c.execute("DELETE FROM tenants WHERE id=%s", (tid,))
        return {"deleted": tid}


@app.patch("/networks/{nid}", dependencies=[Depends(auth)])
def network_update(nid: int, body: NetworkPatch):
    from . import registry
    with db.conn() as c:
        registry.lock(c)
        n = c.execute("SELECT * FROM tenant_networks WHERE id=%s", (nid,)).fetchone()
        if not n:
            raise HTTPException(404, "rede não encontrada")
        if body.unit is not None:
            c.execute("UPDATE tenant_networks SET unit=%s WHERE id=%s", (body.unit.strip(), nid))
        if body.description is not None:
            c.execute("UPDATE tenant_networks SET description=%s WHERE id=%s", (body.description, nid))
        res = {}
        if body.tenant_id is not None and body.tenant_id != n["tenant_id"]:
            _tenant(c, body.tenant_id)
            c.execute("UPDATE tenant_networks SET tenant_id=%s WHERE id=%s", (body.tenant_id, nid))
            res = _after_network_change(c)
        return {"ok": True, "realocacao": res}


@app.post("/resolve", dependencies=[Depends(auth)])
def resolve(body: ResolveIn):
    """IP -> empresa/unidade pelo cadastro (usado pelas telas de Logs e Bloqueios)."""
    from . import registry
    with db.conn() as c:
        return registry.resolve_ips(c, body.ips[:5000])


@app.patch("/tenants/{tid}", dependencies=[Depends(auth)])
def tenant_update(tid: int, body: TenantPatch):
    with db.conn() as c:
        _tenant(c, tid)
        if body.name is not None and body.name.strip():
            c.execute("UPDATE tenants SET name=%s, auto_created=false WHERE id=%s", (body.name.strip(), tid))
        if body.active is not None:
            c.execute("UPDATE tenants SET active=%s WHERE id=%s", (body.active, tid))
        return _tenant(c, tid)


@app.post("/tenants/{tid}/networks", dependencies=[Depends(auth)])
def network_add(tid: int, body: NetworkIn):
    from . import registry
    net = _cidr(body.cidr)
    with db.conn() as c:
        registry.lock(c)
        _tenant(c, tid)
        r = c.execute("INSERT INTO tenant_networks (tenant_id, cidr, unit, description) VALUES (%s,%s,%s,%s) "
                      "ON CONFLICT (cidr) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, unit=EXCLUDED.unit, "
                      "description=EXCLUDED.description RETURNING id, cidr::text AS cidr",
                      (tid, net, body.unit.strip(), body.description)).fetchone()
        return {**r, "realocacao": _after_network_change(c)}


@app.delete("/tenants/{tid}/networks/{nid}", dependencies=[Depends(auth)])
def network_del(tid: int, nid: int):
    from . import registry
    with db.conn() as c:
        registry.lock(c)
        n = c.execute("DELETE FROM tenant_networks WHERE id=%s AND tenant_id=%s RETURNING id", (nid, tid)).fetchone()
        if not n:
            raise HTTPException(404, "rede não encontrada")
        return {"deleted": nid, "realocacao": _after_network_change(c)}


# ------------------------------------------------------------------ painel do tenant
CLASSES = ["TRABALHO", "NAO_TRABALHO", "SUSPEITO", "MALICIOSO", "DESCONHECIDO"]


ALL = 0   # tid=0 = todos os clientes (visão geral da 2D; cada linha diz de qual empresa é)


def _scope(c, tid: int) -> dict:
    if tid == ALL:
        return {"id": ALL, "slug": "todos", "name": "Todos os clientes", "active": True, "auto_created": False}
    return _tenant(c, tid)


def _vt(tid: int) -> str:
    """Visão de domínios do escopo (subquery). Um cliente: v_tenant_domains (com override).
    Todos: agregado por domínio (classificação base, soma de consultas, nº de empresas)."""
    if tid != ALL:
        return "(SELECT v.*, 1 AS tenants FROM v_tenant_domains v WHERE v.tenant_id = %(t)s)"
    return ("(SELECT 0 AS tenant_id, d.id AS domain_id, d.name, d.kind, d.topic, d.category, d.classification, "
            " d.work_score, NULL::text AS review_status, NULL::text AS reviewed_by, NULL::timestamptz AS reviewed_at, "
            " d.risk_score, d.confidence, d.recommended_action, d.corp_action, d.corp_reason, d.corp_by, "
            " d.classified_by, false AS overridden, "
            " min(td.first_seen) AS first_seen, max(td.last_seen) AS last_seen, sum(td.total_queries) AS total_queries, "
            " sum(td.clients_count)::int AS clients_count, d.popularity_rank, d.ti_hits, d.analyzed_at, d.llm_pending, "
            " count(*) AS tenants FROM tenant_domains td JOIN domains d ON d.id = td.domain_id GROUP BY d.id)")


# filtro de tenant p/ tabelas com tenant_id (alias x): vale p/ um cliente ou todos
def _tf(alias: str) -> str:
    return f"(%(t)s = 0 OR {alias}.tenant_id = %(t)s)"


@app.get("/tenants/{tid}/summary", dependencies=[Depends(auth)])
def summary(tid: int, days: int = 7):
    p = {"t": tid, "s": _since(days), "s1": _since(1)}
    vt = _vt(tid)
    with db.conn() as c:
        t = _scope(c, tid)
        counts = {r["classification"] or "PENDENTE": r["n"] for r in c.execute(
            f"SELECT classification, count(*) AS n FROM {vt} v WHERE last_seen >= %(s)s GROUP BY classification", p)}
        pending_ai = c.execute(f"SELECT count(*) AS n FROM {vt} v WHERE last_seen >= %(s)s AND llm_pending",
                               p).fetchone()["n"]
        per_domain = (
            "SELECT v.name, v.classification, v.topic, v.category, v.risk_score, v.work_score, v.overridden, "
            " v.corp_action, v.corp_reason, v.corp_by, "
            " sum(q.queries) AS queries, count(DISTINCT q.client_id) AS clients, count(DISTINCT q.tenant_id) AS tenants, "
            " max(q.last_seen) AS last_seen "
            f"FROM query_agg q JOIN {vt} v ON v.domain_id=q.domain_id AND (%(t)s = 0 OR v.tenant_id=q.tenant_id) "
            f"WHERE {_tf('q')} AND q.bucket >= %(s)s AND {{cond}} "
            "GROUP BY v.name, v.classification, v.topic, v.category, v.risk_score, v.work_score, v.overridden, "
            " v.corp_action, v.corp_reason, v.corp_by "
            "ORDER BY {order} LIMIT 15")
        top_nonwork = c.execute(per_domain.format(cond="v.classification='NAO_TRABALHO'", order="queries DESC"),
                                p).fetchall()
        top_risk = c.execute(per_domain.format(cond="v.classification IN ('SUSPEITO','MALICIOSO')",
                                               order="v.risk_score DESC, queries DESC"), p).fetchall()
        top_all = c.execute(per_domain.format(cond="true", order="queries DESC"), p).fetchall()
        new_domains = c.execute(
            f"SELECT name, classification, topic, risk_score, first_seen, total_queries, clients_count, tenants "
            f"FROM {vt} v WHERE first_seen >= %(s1)s AND kind='public' ORDER BY first_seen DESC LIMIT 15", p).fetchall()
        alerts = c.execute(
            "SELECT a.id, a.tenant_id, t.name AS tenant_name, a.kind, a.severity, a.title, a.status, a.created_at, "
            f"a.updated_at FROM alerts a JOIN tenants t ON t.id=a.tenant_id WHERE {_tf('a')} "
            "ORDER BY (a.status='open') DESC, a.created_at DESC LIMIT 15", p).fetchall()
        clients = _clients(c, tid, p["s"], 10)
        out = {"tenant": t, "days": days, "counts": {k: counts.get(k, 0) for k in CLASSES},
               "total_domains": sum(counts.values()), "pending_ai": pending_ai,
               "top_nonwork": top_nonwork, "top_risk": top_risk, "top_domains": top_all,
               "new_domains": new_domains, "alerts": alerts, "anomalous_clients": clients}
        if tid == ALL:
            # resumo por empresa (visão geral)
            out["by_tenant"] = c.execute(
                "SELECT t.id, t.name, t.auto_created, count(DISTINCT q.client_id) AS clients, sum(q.queries) AS queries, "
                " count(DISTINCT q.domain_id) AS domains, "
                " sum(q.queries) FILTER (WHERE d.classification='NAO_TRABALHO') AS nonwork_q, "
                " count(DISTINCT q.domain_id) FILTER (WHERE d.classification IN ('SUSPEITO','MALICIOSO')) AS risky, "
                " (SELECT count(*) FROM alerts a WHERE a.tenant_id=t.id AND a.status='open') AS open_alerts "
                "FROM query_agg q JOIN tenants t ON t.id=q.tenant_id JOIN domains d ON d.id=q.domain_id "
                "WHERE q.bucket >= %(s)s GROUP BY t.id ORDER BY queries DESC", p).fetchall()
        return out


def _clients(c, tid: int, since: datetime, limit: int, ip: str | None = None) -> list[dict]:
    rows = c.execute(
        f"""
        WITH q AS (
          SELECT q.client_id, sum(q.queries) AS queries, count(DISTINCT q.domain_id) AS domains,
                 sum(q.queries) FILTER (WHERE v.classification='NAO_TRABALHO') AS nonwork_q,
                 count(DISTINCT q.domain_id) FILTER (WHERE v.classification='SUSPEITO') AS susp,
                 count(DISTINCT q.domain_id) FILTER (WHERE v.classification='MALICIOSO') AS mal,
                 max(q.last_seen) AS last_seen
          FROM query_agg q JOIN v_tenant_domains v ON v.tenant_id=q.tenant_id AND v.domain_id=q.domain_id
          WHERE {_tf('q')} AND q.bucket >= %(s)s GROUP BY q.client_id),
        nd AS (SELECT cd.client_id, count(*) AS n FROM client_domains cd
               JOIN tenant_domains td ON td.tenant_id=cd.tenant_id AND td.domain_id=cd.domain_id
               WHERE {_tf('cd')} AND cd.first_seen >= now() - interval '24 hours'
                 AND td.first_seen >= now() - interval '24 hours' GROUP BY cd.client_id),
        al AS (SELECT a.client_id, count(*) AS n FROM alerts a WHERE {_tf('a')} AND a.status='open'
               AND a.client_id IS NOT NULL GROUP BY a.client_id)
        SELECT host(cl.ip) AS ip, cl.label, cl.tenant_id, t.name AS tenant_name, q.*,
               COALESCE(nd.n,0) AS new_domains_24h, COALESCE(al.n,0) AS open_alerts
        FROM q JOIN clients cl ON cl.id=q.client_id JOIN tenants t ON t.id=cl.tenant_id
        LEFT JOIN nd ON nd.client_id=q.client_id LEFT JOIN al ON al.client_id=q.client_id
        WHERE (%(ip)s::inet IS NULL OR cl.ip = %(ip)s::inet)
        """, {"t": tid, "s": since, "ip": ip}).fetchall()
    out = []
    for r in rows:
        share = float(r["nonwork_q"] or 0) / float(r["queries"] or 1)
        score = min(100, round(30 * share + 8 * (r["susp"] or 0) + 25 * (r["mal"] or 0)
                               + 10 * r["open_alerts"] + r["new_domains_24h"] / 5))
        out.append({**r, "nonwork_share": round(share, 3), "anomaly_score": score})
    out.sort(key=lambda x: (x["anomaly_score"], x["queries"]), reverse=True)
    return out[:limit]


@app.get("/tenants/{tid}/domains", dependencies=[Depends(auth)])
def domains(tid: int, classification: Optional[str] = None, q: Optional[str] = None,
            sort: str = "queries", days: int = 7, limit: int = Query(100, le=1000), offset: int = 0,
            category: Optional[str] = None, corp: Optional[str] = None):
    since = _since(days)
    order = {"queries": "total_queries DESC", "last_seen": "last_seen DESC", "risk": "risk_score DESC NULLS LAST",
             "first_seen": "first_seen DESC", "work": "work_score ASC NULLS LAST"}.get(sort, "total_queries DESC")
    with db.conn() as c:
        _scope(c, tid)
        p = {"t": tid, "s": since, "lim": limit, "off": offset}
        where = ["last_seen >= %(s)s"]
        if classification:
            where.append("classification = %(cls)s")
            p["cls"] = classification.upper()
        if q:
            where.append("name ILIKE %(q)s")
            p["q"] = f"%{q.strip().lower()}%"
        if category:
            where.append("category = %(cat)s")
            p["cat"] = category
        if corp:
            where.append("corp_action = %(corp)s")
            p["corp"] = corp.upper()
        base = f"FROM {_vt(tid)} v WHERE {' AND '.join(where)}"
        rows = c.execute(
            "SELECT name, kind, classification, topic, category, risk_score, work_score, confidence, overridden, "
            "classified_by, llm_pending, first_seen, last_seen, total_queries, clients_count, popularity_rank, tenants, "
            "review_status, corp_action, corp_reason, corp_by "
            f"{base} ORDER BY {order} LIMIT %(lim)s OFFSET %(off)s", p).fetchall()
        total = c.execute(f"SELECT count(*) AS n {base}", p).fetchone()["n"]
        return {"total": total, "items": rows}


@app.get("/tenants/{tid}/domains/{name}", dependencies=[Depends(auth)])
def domain_detail(tid: int, name: str):
    reg = _domain_name(name)
    with db.conn() as c:
        _scope(c, tid)
        d = c.execute("SELECT * FROM domains WHERE name=%s", (reg,)).fetchone()
        if not d:
            raise HTTPException(404, "domínio nunca observado")
        p = {"t": tid, "d": d["id"]}
        td = c.execute(f"SELECT * FROM {_vt(tid)} v WHERE v.domain_id=%(d)s", p).fetchone()
        ov = None if tid == ALL else c.execute(
            "SELECT override_classification, override_work_score, override_note, override_by, override_at "
            "FROM tenant_domains WHERE tenant_id=%(t)s AND domain_id=%(d)s", p).fetchone()
        clients = c.execute(
            "SELECT host(cl.ip) AS ip, cl.label, cd.tenant_id, t.name AS tenant_name, cd.queries, cd.blocked, "
            "cd.nxdomain, cd.first_seen, cd.last_seen FROM client_domains cd JOIN clients cl ON cl.id=cd.client_id "
            f"JOIN tenants t ON t.id=cd.tenant_id WHERE {_tf('cd')} AND cd.domain_id=%(d)s "
            "ORDER BY cd.queries DESC LIMIT 200", p).fetchall()
        fqdns = c.execute(
            "SELECT f.name, sum(q.queries) AS queries, max(q.last_seen) AS last_seen FROM query_agg q "
            f"JOIN fqdns f ON f.id=q.fqdn_id WHERE {_tf('q')} AND q.domain_id=%(d)s "
            "GROUP BY f.name ORDER BY queries DESC LIMIT 50", p).fetchall()
        timeline = c.execute(
            "SELECT date_trunc('day', bucket) AS day, sum(queries) AS queries FROM query_agg q "
            f"WHERE {_tf('q')} AND domain_id=%(d)s AND bucket >= now() - interval '30 days' "
            "GROUP BY 1 ORDER BY 1", p).fetchall()
        history = c.execute(
            "SELECT h.classification, h.risk_score, h.work_score, h.confidence, h.topic, h.source, h.model, h.note, "
            "h.created_at, t.name AS tenant_name FROM classification_history h LEFT JOIN tenants t ON t.id=h.tenant_id "
            "WHERE h.domain_id=%(d)s AND (h.tenant_id IS NULL OR %(t)s = 0 OR h.tenant_id=%(t)s) "
            "ORDER BY h.created_at DESC LIMIT 30", p).fetchall()
        glob = c.execute("SELECT status, reviewed_by, reviewed_at FROM global_reviews WHERE domain_id=%(d)s",
                         p).fetchone()
        out = {"domain": d, "tenant_view": td, "override": ov, "clients": clients, "fqdns": fqdns,
               "timeline": timeline, "history": history, "global_review": glob}
        if tid == ALL:
            out["by_tenant"] = c.execute(
                "SELECT t.id, t.name, td.total_queries, td.clients_count, td.first_seen, td.last_seen, "
                "td.override_classification FROM tenant_domains td JOIN tenants t ON t.id=td.tenant_id "
                "WHERE td.domain_id=%(d)s ORDER BY td.total_queries DESC", p).fetchall()
        return out


@app.get("/site-categories", dependencies=[Depends(auth)])
def site_categories_list():
    with db.conn() as c:
        return c.execute("SELECT code, label, description, nonwork FROM site_categories ORDER BY sort_order").fetchall()


@app.get("/tenants/{tid}/review", dependencies=[Depends(auth)])
def review_queue(tid: int, days: int = 30, limit: int = Query(200, le=1000)):
    """Fila "Aguardando decisão": não trabalho, risco e não reconhecidos pela IA, ainda não decididos
    (por empresa). DESCONHECIDO só entra depois que a IA analisou — antes disso é só "na fila da IA".
    Já bloqueado para a empresa (todas as consultas da última hora em que apareceu foram bloqueadas)
    também sai: vale qualquer forma de bloqueio no Technitium (entrada, lista por URL, regex, pai)."""
    with db.conn() as c:
        _scope(c, tid)
        return c.execute(
            "WITH cand AS ("
            " SELECT v.* FROM v_tenant_domains v "
            f" WHERE {_tf('v')} AND v.last_seen >= %(s)s AND v.review_status IS NULL AND v.kind='public' "
            "  AND NOT dominio_decidido(v.domain_id) "   # decidido uma vez (global ou outra empresa) não volta
            "  AND (v.classification IN ('NAO_TRABALHO','SUSPEITO','MALICIOSO') OR (v.classification='DESCONHECIDO' "
            "       AND v.classified_by IN ('llm','web') AND NOT v.llm_pending))), "
            "ult AS ("   # última hora (bucket) em que a empresa consultou o site
            " SELECT DISTINCT ON (q.tenant_id, q.domain_id) q.tenant_id, q.domain_id, "
            "  sum(q.queries) AS queries, sum(q.blocked) AS blocked "
            " FROM query_agg q JOIN cand USING (tenant_id, domain_id) "
            " WHERE q.bucket >= %(s)s - interval '1 hour' "
            " GROUP BY q.tenant_id, q.domain_id, q.bucket ORDER BY q.tenant_id, q.domain_id, q.bucket DESC) "
            "SELECT v.tenant_id, t.name AS tenant_name, v.name, v.classification, v.category, v.topic, v.risk_score, "
            " v.corp_action, v.corp_reason, v.corp_by, "
            " v.work_score, v.total_queries, v.clients_count, v.first_seen, v.last_seen "
            "FROM cand v JOIN tenants t ON t.id=v.tenant_id "
            "LEFT JOIN ult u ON u.tenant_id=v.tenant_id AND u.domain_id=v.domain_id "
            "WHERE u.blocked IS NULL OR u.blocked < u.queries "
            "ORDER BY (v.classification='MALICIOSO') DESC, (v.classification='SUSPEITO') DESC, "
            " COALESCE(v.corp_action='BLOQUEAR', false) DESC, COALESCE(v.corp_action='REVISAR', false) DESC, "
            " v.total_queries DESC LIMIT %(lim)s", {"t": tid, "s": _since(days), "lim": limit}).fetchall()


class ReviewIn(BaseModel):
    status: Optional[str] = None     # blocked | allowed | None (volta p/ pendente)
    by: str = ""


@app.post("/tenants/{tid}/review/{name}", dependencies=[Depends(auth)])
def review_decide(tid: int, name: str, body: ReviewIn):
    if body.status not in (None, "blocked", "allowed"):
        raise HTTPException(400, "status inválido")
    reg = _domain_name(name)
    with db.conn() as c:
        _tenant(c, tid)
        r = c.execute(
            "UPDATE tenant_domains td SET review_status=%s, reviewed_by=%s, "
            "reviewed_at=CASE WHEN %s::text IS NULL THEN NULL ELSE now() END "
            "FROM domains d WHERE d.id=td.domain_id AND d.name=%s AND td.tenant_id=%s RETURNING td.domain_id",
            (body.status, body.by or None, body.status, reg, tid)).fetchone()
        if not r:
            raise HTTPException(404, "domínio não observado nesta empresa")
        return {"ok": True, "domain": reg, "status": body.status}


@app.post("/domains/{name}/review", dependencies=[Depends(auth)])
def review_global(name: str, body: ReviewIn):
    """Decisão global do site (visão "Todos os clientes"); status None remove."""
    if body.status not in (None, "blocked", "allowed"):
        raise HTTPException(400, "status inválido")
    reg = _domain_name(name)
    with db.conn() as c:
        d = c.execute("SELECT id FROM domains WHERE name=%s", (reg,)).fetchone()
        if not d:
            raise HTTPException(404, "domínio nunca observado")
        if body.status is None:
            c.execute("DELETE FROM global_reviews WHERE domain_id=%s", (d["id"],))
        else:
            c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s,%s,%s) "
                      "ON CONFLICT (domain_id) DO UPDATE SET status=EXCLUDED.status, "
                      "reviewed_by=EXCLUDED.reviewed_by, reviewed_at=now()", (d["id"], body.status, body.by or None))
        return {"ok": True, "domain": reg, "status": body.status}


class OverrideIn(BaseModel):
    classification: Optional[str] = None     # None = remover override
    work_score: Optional[int] = None
    note: str = ""
    by: str = ""


@app.put("/tenants/{tid}/domains/{name}/override", dependencies=[Depends(auth)])
def domain_override(tid: int, name: str, body: OverrideIn):
    reg = _domain_name(name)
    with db.conn() as c:
        _tenant(c, tid)
        d = c.execute("SELECT id FROM domains WHERE name=%s", (reg,)).fetchone()
        if not d:
            raise HTTPException(404, "domínio nunca observado")
        cls = body.classification.upper() if body.classification else None
        if cls and not c.execute("SELECT 1 FROM categories WHERE code=%s", (cls,)).fetchone():
            raise HTTPException(400, "categoria inválida")
        c.execute(
            "UPDATE tenant_domains SET override_classification=%s, override_work_score=%s, override_note=%s, "
            "override_by=%s, override_at=CASE WHEN %s::text IS NULL THEN NULL ELSE now() END "
            "WHERE tenant_id=%s AND domain_id=%s",
            (cls, body.work_score if cls else None, body.note if cls else None, body.by if cls else None, cls,
             tid, d["id"]))
        c.execute(
            "INSERT INTO classification_history (domain_id, tenant_id, classification, work_score, source, note) "
            "VALUES (%s,%s,%s,%s,'manual',%s)",
            (d["id"], tid, cls, body.work_score, (f"override por {body.by}: {body.note}" if cls
                                                  else f"override removido por {body.by}")[:500]))
        return {"ok": True, "domain": reg, "override": cls}


class FalsePositiveIn(BaseModel):
    source: Optional[str] = None   # nome da fonte; None = todas
    note: str = ""
    by: str = ""


@app.post("/domains/{name}/false-positive", dependencies=[Depends(auth)])
def false_positive(name: str, body: FalsePositiveIn):
    reg = _domain_name(name)
    with db.conn() as c:
        sid = None
        if body.source:
            s = c.execute("SELECT id FROM ti_sources WHERE name=%s", (body.source,)).fetchone()
            if not s:
                raise HTTPException(400, "fonte inexistente")
            sid = s["id"]
        c.execute("INSERT INTO ti_suppressions (domain, source_id, note, created_by) VALUES (%s,%s,%s,%s) "
                  "ON CONFLICT DO NOTHING", (reg, sid, body.note, body.by))
        c.execute("UPDATE domains SET needs_analysis=true, evidence_hash='' WHERE name=%s", (reg,))
        return {"ok": True, "domain": reg, "source": body.source or "todas"}


@app.post("/domains/{name}/reanalyze", dependencies=[Depends(auth)])
def reanalyze(name: str):
    reg = _domain_name(name)
    with db.conn() as c:
        r = c.execute("UPDATE domains SET needs_analysis=true, evidence_hash='', classified_by=NULL, "
                      "llm_attempts=0 WHERE name=%s AND NOT locked RETURNING id", (reg,)).fetchone()
        if not r:
            raise HTTPException(404, "domínio não encontrado (ou travado)")
        return {"ok": True, "domain": reg}


# ------------------------------------------------------------------ computadores e alertas
@app.get("/tenants/{tid}/clients", dependencies=[Depends(auth)])
def clients(tid: int, days: int = 7, limit: int = Query(200, le=1000)):
    with db.conn() as c:
        _scope(c, tid)
        return _clients(c, tid, _since(days), limit)


@app.get("/tenants/{tid}/clients/{ip}", dependencies=[Depends(auth)])
def client_detail(tid: int, ip: str, days: int = 7):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "IP inválido")
    since = _since(days)
    with db.conn() as c:
        if tid == ALL:   # visão geral: o computador pertence a uma empresa — usa a dela
            r = c.execute("SELECT tenant_id FROM clients WHERE ip=%s::inet ORDER BY last_seen DESC LIMIT 1",
                          (ip,)).fetchone()
            if not r:
                raise HTTPException(404, "computador nunca observado")
            tid = r["tenant_id"]
        _tenant(c, tid)
        info = _clients(c, tid, since, 1, ip)
        if not info:
            raise HTTPException(404, "computador sem consultas no período")
        doms = c.execute(
            "SELECT v.name, v.classification, v.topic, v.risk_score, v.work_score, sum(q.queries) AS queries, "
            " max(q.last_seen) AS last_seen FROM query_agg q JOIN clients cl ON cl.id=q.client_id "
            "JOIN v_tenant_domains v ON v.tenant_id=q.tenant_id AND v.domain_id=q.domain_id "
            "WHERE q.tenant_id=%s AND cl.ip=%s::inet AND q.bucket >= %s "
            "GROUP BY v.name, v.classification, v.topic, v.risk_score, v.work_score ORDER BY queries DESC LIMIT 300",
            (tid, ip, since)).fetchall()
        alerts = c.execute("SELECT a.* FROM alerts a JOIN clients cl ON cl.id=a.client_id "
                           "WHERE a.tenant_id=%s AND cl.ip=%s::inet ORDER BY a.created_at DESC LIMIT 50",
                           (tid, ip)).fetchall()
        return {"client": info[0], "domains": doms, "alerts": alerts}


@app.get("/tenants/{tid}/alerts", dependencies=[Depends(auth)])
def alerts(tid: int, status: Optional[str] = "open", limit: int = Query(100, le=500)):
    with db.conn() as c:
        _scope(c, tid)
        p = {"t": tid, "lim": limit, "st": status}
        where = [_tf("a")]
        if status and status != "all":
            where.append("a.status=%(st)s")
        return c.execute(
            "SELECT a.*, host(cl.ip) AS ip, d.name AS domain, t.name AS tenant_name FROM alerts a "
            "JOIN tenants t ON t.id=a.tenant_id "
            "LEFT JOIN clients cl ON cl.id=a.client_id LEFT JOIN domains d ON d.id=a.domain_id "
            f"WHERE {' AND '.join(where)} ORDER BY a.created_at DESC LIMIT %(lim)s", p).fetchall()


class AlertStatusIn(BaseModel):
    status: str
    by: str = ""


@app.post("/tenants/{tid}/alerts/{aid}/status", dependencies=[Depends(auth)])
def alert_status(tid: int, aid: int, body: AlertStatusIn):
    if body.status not in ("open", "ack", "closed"):
        raise HTTPException(400, "status inválido")
    with db.conn() as c:
        r = c.execute("UPDATE alerts SET status=%s, ack_by=%s, updated_at=now() WHERE id=%s AND tenant_id=%s "
                      "RETURNING id", (body.status, body.by, aid, tid)).fetchone()
        if not r:
            raise HTTPException(404, "alerta não encontrado")
        return {"ok": True}


# ------------------------------------------------------------------ fontes / histórico
@app.get("/sources", dependencies=[Depends(auth)])
def sources():
    with db.conn() as c:
        return c.execute("SELECT id, name, label, kind, threat, confidence, weight, enabled, refresh_hours, "
                         "license_note, last_fetch, last_status, entries FROM ti_sources ORDER BY id").fetchall()


class SourcePatch(BaseModel):
    enabled: Optional[bool] = None
    weight: Optional[int] = None


@app.patch("/sources/{sid}", dependencies=[Depends(auth)])
def source_update(sid: int, body: SourcePatch):
    from . import ti
    with db.conn() as c:
        if not c.execute("SELECT 1 FROM ti_sources WHERE id=%s", (sid,)).fetchone():
            raise HTTPException(404, "fonte não encontrada")
        if body.enabled is not None:
            c.execute("UPDATE ti_sources SET enabled=%s WHERE id=%s", (body.enabled, sid))
        if body.weight is not None:
            c.execute("UPDATE ti_sources SET weight=%s WHERE id=%s", (max(0, min(100, body.weight)), sid))
        # peso mudou: domínios com algum acerto precisam recalcular o risco
        c.execute("UPDATE domains SET needs_analysis=true WHERE ti_signature <> ''")
    ti.mark_changed_domains()   # depois do commit: enxerga a fonte já ligada/desligada
    with db.conn() as c:
        return c.execute("SELECT * FROM ti_sources WHERE id=%s", (sid,)).fetchone()


@app.get("/ai/events", dependencies=[Depends(auth)])
def ai_events(after_id: int = 0, limit: int = Query(60, le=300)):
    """Feed "IA ao vivo": eventos novos (id > after_id), o que está em análise agora e o ritmo."""
    with db.conn() as c:
        events = c.execute(
            "SELECT id, kind, name, classification, risk, work, seconds, detail, created_at FROM ai_events "
            "WHERE id > %s ORDER BY id DESC LIMIT %s", (after_id, limit)).fetchall()
        cur = c.execute(
            "SELECT name, claimed_at, total_queries, extract(epoch from now() - claimed_at)::int AS elapsed "
            "FROM domains WHERE claimed_at IS NOT NULL AND claimed_at > now() - interval '30 minutes' "
            "ORDER BY claimed_at DESC LIMIT 1").fetchone()
        queue = c.execute("SELECT count(*) FILTER (WHERE llm_pending AND NOT dominio_decidido(id)) AS ia, "
                          "count(*) FILTER (WHERE needs_analysis) AS regras, "
                          "count(*) FILTER (WHERE classification='DESCONHECIDO' AND classified_by='llm' "
                          " AND web_search_at IS NULL AND NOT llm_pending AND kind='public' "
                          " AND NOT dominio_decidido(id)) AS busca FROM domains").fetchone()
        hour = c.execute("SELECT count(*) AS done, round(avg(seconds)::numeric, 1) AS avg_seconds FROM ai_events "
                         "WHERE kind='llm_done' AND created_at > now() - interval '1 hour'").fetchone()
    ok, msg = OllamaClient().available()
    eta = None
    if hour["done"] and queue["ia"]:   # pelo ritmo real (várias análises simultâneas / reforço com GPU)
        eta = int(queue["ia"] * 3600 / hour["done"])
    return {"events": events, "current": cur, "queue": queue, "last_hour": hour, "eta_seconds": eta,
            "llm": {"ok": ok, "detail": msg, "model": settings().ollama_model}}


@app.get("/runs", dependencies=[Depends(auth)])
def runs(kind: Optional[str] = None, limit: int = Query(50, le=500)):
    with db.conn() as c:
        if kind:
            return c.execute("SELECT * FROM analysis_runs WHERE kind=%s ORDER BY started_at DESC LIMIT %s",
                             (kind, limit)).fetchall()
        return c.execute("SELECT * FROM analysis_runs ORDER BY started_at DESC LIMIT %s", (limit,)).fetchall()


@app.get("/domains/{name}", dependencies=[Depends(auth)])
def domain_global(name: str):
    """Inteligência global do domínio (sem dados de tenant)."""
    reg = _domain_name(name)
    with db.conn() as c:
        d = c.execute("SELECT id, name, kind, tld, features, popularity_rank, registered_at, ti_hits, classification, "
                      "risk_score, work_score, confidence, topic, reasons, evidence, recommended_action, "
                      "classified_by, model, analyzed_at, llm_pending FROM domains WHERE name=%s", (reg,)).fetchone()
        if not d:
            raise HTTPException(404, "domínio nunca observado")
        return d


# ------------------------------------------------------------------ console web (dns-guard)
# Operadores e metadados de liberados do console (dns-guard.2dtecnologia.com). A senha
# chega já em hash (werkzeug): quem valida o login é o console.
OP_COLS = "id, email, nome, senha_hash, is_super, ativo, created_at, last_login"


class OperatorIn(BaseModel):
    email: Optional[str] = None
    nome: Optional[str] = None
    senha_hash: Optional[str] = None
    is_super: Optional[bool] = None
    ativo: Optional[bool] = None
    last_login: Optional[bool] = None    # true = marca o login agora


@app.get("/console/operators", dependencies=[Depends(auth)])
def operators_list(email: Optional[str] = None):
    with db.conn() as c:
        if email:
            return c.execute(f"SELECT {OP_COLS} FROM console_operators WHERE email=%s",
                             (email.strip().lower(),)).fetchall()
        return c.execute(f"SELECT {OP_COLS} FROM console_operators ORDER BY ativo DESC, nome").fetchall()


@app.get("/console/operators/{oid}", dependencies=[Depends(auth)])
def operator_get(oid: int):
    with db.conn() as c:
        r = c.execute(f"SELECT {OP_COLS} FROM console_operators WHERE id=%s", (oid,)).fetchone()
        if not r:
            raise HTTPException(404, "operador não encontrado")
        return r


@app.post("/console/operators", dependencies=[Depends(auth)])
def operator_create(body: OperatorIn):
    email = (body.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "e-mail inválido")
    with db.conn() as c:
        r = c.execute(
            f"INSERT INTO console_operators (email, nome, senha_hash, is_super, ativo) VALUES (%s,%s,%s,%s,%s) "
            f"ON CONFLICT (email) DO NOTHING RETURNING {OP_COLS}",
            (email, (body.nome or email)[:150], body.senha_hash, bool(body.is_super),
             True if body.ativo is None else body.ativo)).fetchone()
        if not r:
            raise HTTPException(409, "já existe operador com esse e-mail")
        return r


@app.patch("/console/operators/{oid}", dependencies=[Depends(auth)])
def operator_update(oid: int, body: OperatorIn):
    sets, vals = [], []
    for k in ("nome", "senha_hash", "is_super", "ativo"):
        v = getattr(body, k)
        if v is not None:
            sets.append(f"{k}=%s")
            vals.append(v)
    if body.last_login:
        sets.append("last_login=now()")
    if not sets:
        raise HTTPException(400, "nada para alterar")
    with db.conn() as c:
        r = c.execute(f"UPDATE console_operators SET {', '.join(sets)} WHERE id=%s RETURNING {OP_COLS}",
                      (*vals, oid)).fetchone()
        if not r:
            raise HTTPException(404, "operador não encontrado")
        return r


class LiberadoMetaIn(BaseModel):
    ip: str
    tenant_id: Optional[int] = None
    filial: Optional[str] = None
    empresa: Optional[str] = None
    departamento: Optional[str] = None
    usuario: Optional[str] = None
    tipo: Optional[str] = None
    by: str = ""


@app.get("/console/liberados-meta", dependencies=[Depends(auth)])
def liberados_meta_list():
    with db.conn() as c:
        return c.execute("SELECT m.ip, m.tenant_id, t.name AS tenant_name, m.filial, m.empresa, m.departamento, "
                         "m.usuario, m.tipo, m.created_at, m.created_by "
                         "FROM liberado_meta m LEFT JOIN tenants t ON t.id=m.tenant_id ORDER BY m.ip").fetchall()


@app.put("/console/liberados-meta", dependencies=[Depends(auth)])
def liberados_meta_upsert(body: LiberadoMetaIn):
    def s(v, n):
        return ((v or "").strip()[:n]) or None
    with db.conn() as c:
        if body.tenant_id is not None:
            _tenant(c, body.tenant_id)
        # empresa escolhida no cadastro -> o texto livre (legado) deixa de valer
        c.execute(
            "INSERT INTO liberado_meta (ip, tenant_id, filial, empresa, departamento, usuario, tipo, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (ip) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, "
            "filial=EXCLUDED.filial, empresa=EXCLUDED.empresa, departamento=EXCLUDED.departamento, "
            "usuario=EXCLUDED.usuario, tipo=EXCLUDED.tipo",
            (body.ip, body.tenant_id, s(body.filial, 150) if body.tenant_id else None,
             None if body.tenant_id else s(body.empresa, 150), s(body.departamento, 255), s(body.usuario, 255),
             s(body.tipo, 20), body.by or None))
        return {"ok": True, "ip": body.ip}


@app.delete("/console/liberados-meta", dependencies=[Depends(auth)])
def liberados_meta_delete(ip: str):
    with db.conn() as c:
        n = c.execute("DELETE FROM liberado_meta WHERE ip=%s", (ip,)).rowcount
        return {"ok": True, "removed": n}


# ------------------------------------------------------------------ logs agrupados (console)
# classificação efetiva (ajuste manual da empresa > IA) e "pior" quando a linha junta empresas
_CLS_EFETIVA = "COALESCE(td.override_classification, d.classification)"
_CLS_ORDEM = ("TRABALHO", "DESCONHECIDO", "NAO_TRABALHO", "SUSPEITO", "MALICIOSO")   # pior por último
_CLS_RANK = "CASE " + _CLS_EFETIVA + " " + " ".join(
    f"WHEN '{c}' THEN {i + 1}" for i, c in enumerate(_CLS_ORDEM)) + " ELSE 0 END"
_CLS_DO_RANK = "CASE max(" + _CLS_RANK + ") " + " ".join(
    f"WHEN {i + 1} THEN '{c}'" for i, c in enumerate(_CLS_ORDEM)) + " END"
_CLS_COLS = (f"{_CLS_DO_RANK} AS classificacao, bool_or(td.override_classification IS NOT NULL) AS ajustada, "
             "min(d.category) AS categoria, max(d.risk_score) AS risco, min(d.topic) AS assunto")


@app.get("/logs/grouped", dependencies=[Depends(auth)])
def logs_grouped(start: datetime, end: datetime, tid: int = 0, ip: Optional[str] = None,
                 cidr: list[str] = Query(default=[]), ip_like: Optional[str] = None,
                 dominio: Optional[str] = None, blocked: bool = False,
                 cls: list[str] = Query(default=[]), categoria: Optional[str] = None,
                 por_cliente: bool = False, limit: int = Query(1000, le=5000)):
    """Logs DNS agrupados por nome consultado (a partir de query_agg, por hora), com os
    mesmos filtros da tela Logs DNS. Atraso = o da coleta (~5-7 min).
    Cada linha traz a classificação efetiva (ajuste da empresa > IA; juntando empresas, a pior).
    cls = classificações (PENDENTE = ainda sem classificação); por_cliente = uma linha por
    nome × computador × empresa (quem acessou)."""
    where = ["q.bucket >= date_trunc('hour', %(s)s::timestamptz)", "q.bucket < %(e)s",
             "q.last_seen >= %(s)s", "q.first_seen <= %(e)s"]
    p: dict = {"s": start, "e": end, "lim": limit + 1}
    if tid:
        where.append("q.tenant_id = %(t)s"); p["t"] = tid
    if ip:
        where.append("cl.ip = %(ip)s::inet"); p["ip"] = ip.strip()
    if cidr:
        try:
            p["cidrs"] = [str(ipaddress.ip_network(c, strict=False)) for c in cidr]
        except ValueError:
            raise HTTPException(400, "CIDR inválido")
        where.append("cl.ip <<= ANY(%(cidrs)s::cidr[])")
    if ip_like:
        where.append("host(cl.ip) LIKE %(ipl)s"); p["ipl"] = f"%{ip_like.strip()}%"
    if dominio:
        where.append("f.name LIKE %(dom)s"); p["dom"] = f"%{dominio.strip().lower()}%"
    if blocked:
        where.append("q.blocked > 0")
    cls = [x.strip().upper() for x in cls if x and x.strip()]
    if cls:
        p["cls"] = [x for x in cls if x != "PENDENTE"]
        cond = [f"{_CLS_EFETIVA} = ANY(%(cls)s)"] if p["cls"] else []
        if "PENDENTE" in cls:
            cond.append(f"{_CLS_EFETIVA} IS NULL")
        where.append("(" + " OR ".join(cond) + ")")
    if categoria:
        where.append("d.category = %(cat)s"); p["cat"] = categoria
    base = ("FROM query_agg q JOIN fqdns f ON f.id=q.fqdn_id JOIN clients cl ON cl.id=q.client_id "
            "JOIN tenants t ON t.id=q.tenant_id JOIN domains d ON d.id=q.domain_id "
            "LEFT JOIN tenant_domains td ON td.tenant_id=q.tenant_id AND td.domain_id=q.domain_id ")
    if por_cliente:
        # nome do computador: rótulo do cliente ou, se não houver, o usuário/descrição dos Liberados
        sql = ("SELECT g.dominio, host(g.ip) AS ip, COALESCE(g.label, lm.usuario) AS computador, "
               " g.tenant_id, g.empresa, g.n, g.bloqueadas, g.ultima, g.classificacao, g.ajustada, "
               " g.categoria, g.risco, g.assunto FROM ("
               "SELECT f.name AS dominio, cl.ip, min(cl.label) AS label, t.id AS tenant_id, t.name AS empresa, "
               " sum(q.queries) AS n, sum(q.blocked) AS bloqueadas, max(q.last_seen) AS ultima, " + _CLS_COLS + " "
               + base + f"WHERE {' AND '.join(where)} GROUP BY f.name, cl.ip, t.id, t.name "
               "ORDER BY max(q.last_seen) DESC LIMIT %(lim)s) g "
               "LEFT JOIN LATERAL (SELECT m.usuario FROM liberado_meta m "
               " WHERE m.ip IN (host(g.ip), host(g.ip) || '/32') ORDER BY m.ip LIMIT 1) lm ON true "
               "ORDER BY g.ultima DESC")
    else:
        sql = ("SELECT f.name AS dominio, sum(q.queries) AS n, sum(q.blocked) AS bloqueadas, "
               " count(DISTINCT q.client_id) AS nclientes, max(q.last_seen) AS ultima, "
               " array_agg(DISTINCT t.name ORDER BY t.name) AS empresas, " + _CLS_COLS + " "
               + base + f"WHERE {' AND '.join(where)} GROUP BY f.name ORDER BY max(q.last_seen) DESC LIMIT %(lim)s")
    with db.conn() as c:
        rows = c.execute(sql, p).fetchall()
        cursor = (c.execute("SELECT value FROM ingest_state WHERE key='ingest_cursor'").fetchone() or {}).get("value")
    return {"rows": rows[:limit], "cap": len(rows) > limit, "coletado_ate": cursor}


class ClassificarIn(BaseModel):
    nomes: list[str]


@app.post("/logs/classificar", dependencies=[Depends(auth)])
def logs_classificar(body: ClassificarIn):
    """Classificação de cada nome consultado (vista Detalhado, que vem do Technitium em tempo
    real). Nome ainda não coletado herda a do domínio pai já conhecido. `ajustes` = correções
    por empresa ({tenant_id: classificação}); quem mostra aplica a da empresa do IP."""
    nomes = list(dict.fromkeys(n.strip().lower().rstrip(".") for n in body.nomes if n and n.strip()))[:5000]
    cands: dict[str, list[str]] = {}
    for n in nomes:
        parts = n.split(".")
        lista = [_domain_name(n)] + [".".join(parts[i:]) for i in range(len(parts) - 1)]
        cands[n] = [x for x in dict.fromkeys(lista) if x and "." in x]
    todos = sorted({x for v in cands.values() for x in v})
    if not todos:
        return {}
    with db.conn() as c:
        doms = {r["name"]: r for r in c.execute(
            "SELECT d.id, d.name, d.classification, d.category, d.risk_score, d.topic, "
            " COALESCE((SELECT jsonb_object_agg(td.tenant_id::text, td.override_classification) "
            "           FROM tenant_domains td WHERE td.domain_id=d.id "
            "           AND td.override_classification IS NOT NULL), '{}'::jsonb) AS ajustes "
            "FROM domains d WHERE d.name = ANY(%s)", (todos,)).fetchall()}
    out = {}
    for n, lista in cands.items():
        d = next((doms[x] for x in lista if x in doms), None)
        out[n] = None if d is None else {
            "dominio": d["name"], "classificacao": d["classification"], "categoria": d["category"],
            "risco": d["risk_score"], "assunto": d["topic"], "ajustes": d["ajustes"]}
    return out


@app.get("/charts", dependencies=[Depends(auth)])
def charts(start: datetime, end: datetime, tid: int = 0, cls: list[str] = Query(default=[]),
           categoria: Optional[str] = None, resposta: Optional[str] = None, top: int = Query(15, le=50)):
    """Tela Gráficos: consultas liberadas × bloqueadas no tempo e por classificação da IA,
    categoria do site, empresa e site (top), com os mesmos filtros. resposta = liberado |
    bloqueado (só aquela parte das consultas). Série por hora até 2 dias; acima, por dia."""
    if end <= start:
        raise HTTPException(400, "período inválido")
    gran = "hour" if end - start <= timedelta(days=2) else "day"
    p: dict = {"s": start, "e": end, "top": top}
    wq = ["q.bucket >= date_trunc('hour', %(s)s::timestamptz)", "q.bucket < %(e)s"]
    if tid:
        wq.append("q.tenant_id = %(t)s"); p["t"] = tid
    wf = []
    cls = [x.strip().upper() for x in cls if x and x.strip()]
    if cls:
        p["cls"] = [x for x in cls if x != "PENDENTE"]
        cond = ["cls = ANY(%(cls)s)"] if p["cls"] else []
        if "PENDENTE" in cls:
            cond.append("cls IS NULL")
        wf.append("(" + " OR ".join(cond) + ")")
    if categoria:
        wf.append("cat = %(cat)s"); p["cat"] = categoria
    lib, blk = "(n - blk)", "blk"
    if resposta == "liberado":
        blk = "0"
    elif resposta == "bloqueado":
        lib = "0"
    elif resposta:
        raise HTTPException(400, "resposta inválida (liberado | bloqueado)")
    medida = f"sum({lib}) AS liberadas, sum({blk}) AS bloqueadas"
    ordem = f"sum({lib}) + sum({blk}) DESC"
    with db.conn() as c:
        # 1 passada em query_agg (por período × empresa × domínio); o resto sai dessa tabela
        c.execute(
            f"CREATE TEMP TABLE ch ON COMMIT DROP AS SELECT * FROM ("
            f" SELECT b.t, b.tenant_id, b.domain_id, b.n, b.blk, {_CLS_EFETIVA} AS cls, d.category AS cat, "
            "  d.name AS dom FROM ("
            f"  SELECT date_trunc('{gran}', q.bucket) AS t, q.tenant_id, q.domain_id, sum(q.queries) AS n, "
            "   sum(q.blocked) AS blk FROM query_agg q "
            f"  WHERE {' AND '.join(wq)} GROUP BY 1, 2, 3) b "
            " JOIN domains d ON d.id=b.domain_id "
            " LEFT JOIN tenant_domains td ON td.tenant_id=b.tenant_id AND td.domain_id=b.domain_id) x"
            + (f" WHERE {' AND '.join(wf)}" if wf else ""), p)
        serie = c.execute(f"SELECT t, {medida} FROM ch GROUP BY t ORDER BY t").fetchall()
        por_cls = c.execute(f"SELECT COALESCE(cls, 'PENDENTE') AS chave, {medida} FROM ch GROUP BY 1 "
                            f"ORDER BY {ordem}").fetchall()
        por_cat = c.execute(f"SELECT cat AS chave, {medida} FROM ch GROUP BY 1 ORDER BY {ordem}").fetchall()
        por_emp = c.execute(f"SELECT t.id, t.name AS chave, {medida} FROM ch JOIN tenants t ON t.id=ch.tenant_id "
                            f"GROUP BY t.id, t.name ORDER BY {ordem}").fetchall()
        top_dom = c.execute(
            f"SELECT dom AS chave, {medida}, (array_agg(cls ORDER BY n DESC))[1] AS classificacao, "
            f" min(cat) AS categoria FROM ch GROUP BY dom HAVING sum({lib}) + sum({blk}) > 0 "
            f"ORDER BY {ordem} LIMIT %(top)s", p).fetchall()
        tot = c.execute(
            f"SELECT COALESCE(sum({lib}), 0) AS liberadas, COALESCE(sum({blk}), 0) AS bloqueadas, "
            f" count(DISTINCT domain_id) FILTER (WHERE {lib} + {blk} > 0) AS sites, "
            f" COALESCE(sum({lib} + {blk}) FILTER (WHERE cls IN ('MALICIOSO', 'SUSPEITO')), 0) AS ameacas FROM ch"
        ).fetchone()
        cursor = (c.execute("SELECT value FROM ingest_state WHERE key='ingest_cursor'").fetchone() or {}).get("value")
    def limpa(rows):   # com o filtro de resposta, tira o que zerou
        return [r for r in rows if (r["liberadas"] or 0) + (r["bloqueadas"] or 0) > 0]
    return {"granularidade": gran, "serie": serie, "por_classificacao": limpa(por_cls),
            "por_categoria": limpa(por_cat), "por_empresa": limpa(por_emp), "top_dominios": top_dom,
            "totais": tot, "coletado_ate": cursor}


# ------------------------------------------------------------------ configuração dos grupos (console)
class GroupSettingIn(BaseModel):
    name: str
    especifico: bool = False
    rename_to: Optional[str] = None
    by: str = ""


@app.get("/console/group-settings", dependencies=[Depends(auth)])
def group_settings_list():
    with db.conn() as c:
        return c.execute("SELECT name, especifico, updated_by, updated_at FROM group_settings ORDER BY name").fetchall()


@app.put("/console/group-settings", dependencies=[Depends(auth)])
def group_settings_set(body: GroupSettingIn):
    """Grava a config do grupo; com rename_to só renomeia (grupo renomeado no Technitium)."""
    with db.conn() as c:
        if body.rename_to:
            c.execute("UPDATE group_settings SET name=%s, updated_by=%s, updated_at=now() WHERE name=%s",
                      (body.rename_to, body.by or None, body.name))
        else:
            c.execute("INSERT INTO group_settings (name, especifico, updated_by) VALUES (%s,%s,%s) "
                      "ON CONFLICT (name) DO UPDATE SET especifico=EXCLUDED.especifico, "
                      "updated_by=EXCLUDED.updated_by, updated_at=now()", (body.name, body.especifico, body.by or None))
        return {"ok": True}


@app.delete("/console/group-settings", dependencies=[Depends(auth)])
def group_settings_delete(name: str):
    with db.conn() as c:
        c.execute("DELETE FROM group_settings WHERE name=%s", (name,))
        return {"ok": True}
