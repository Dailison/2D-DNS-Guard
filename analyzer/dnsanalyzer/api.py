"""API interna (consumida pelo console dns-guard.2dtecnologia.com).

Autenticação: header `Authorization: Bearer <API_TOKEN>`. Rotas de dados são
escopadas por empresa (/tenants/{tid}/...). tid=0 = visão "Todos os clientes"
(consolidada para a 2D): toda linha nela identifica a empresa de origem.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from . import __version__, db, listas
from .config import settings
from .features import analyze_name
from .llm import OllamaClient

log = logging.getLogger(__name__)
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
                "count(*) FILTER (WHERE llm_pending AND NOT aguarda_recorrencia AND NOT dominio_decidido(id)) AS ia, "
                "count(*) FILTER (WHERE aguarda_recorrencia) AS aguarda, count(*) AS dominios FROM domains").fetchone())
    except Exception as e:  # noqa: BLE001
        out["db_error"] = str(e)[:200]
    try:   # pulso das listas publicadas (o 2D-Monitoramento lê /health)
        with db.conn() as c:
            f = {r["category"]: r for r in c.execute("SELECT category, last_at, last_n, recusada_at, recusada_n FROM list_fetches")}
            aplicadas = sorted({x for r in c.execute("SELECT lists FROM policies") for x in (r["lists"] or [])})
        out["listas"] = {k: {"last_at": v["last_at"], "last_n": v["last_n"], "recusada_at": v["recusada_at"],
                             "recusada_n": v["recusada_n"]} for k, v in f.items()}
        lim = datetime.now(timezone.utc) - timedelta(hours=2)
        out["listas_atrasadas"] = [k for k in aplicadas if not (f.get(k) or {}).get("last_at") or f[k]["last_at"] < lim]
        out["listas_recusadas"] = [k for k, v in f.items() if v["recusada_at"]]
    except Exception as e:  # noqa: BLE001
        out["listas_error"] = str(e)[:200]
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
            "count(*) FILTER (WHERE aguarda_recorrencia) AS aguarda, "
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
            " v.work_score, v.total_queries, v.clients_count, v.first_seen, v.last_seen, "
            " (SELECT dd.lista_ia FROM domains dd WHERE dd.id = v.domain_id) AS lista_ia "
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
        if body.status:   # decidido por pessoa: Site Revisado (não volta p/ a IA sem pedido)
            c.execute("UPDATE domains SET revisado_at = coalesce(revisado_at, now()) WHERE id = %s", (r["domain_id"],))
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
            c.execute("UPDATE domains SET revisado_at = coalesce(revisado_at, now()) WHERE id = %s", (d["id"],))
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
def reanalyze(name: str, by: str = ""):
    reg = _domain_name(name)
    with db.conn() as c:
        if not _reanalisar(c, [reg], by):
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
        from . import eventos
        # regras/feeds (saiu da whitelist por feed ou trava, sem resposta no DNS, lista recusada) não são decisão da IA:
        # ficam só no histórico do domínio e na página da lista (pedido do usuário 27/09)
        so_ia = "origem IS DISTINCT FROM 'regras'"
        if after_id:
            events = c.execute(
                "SELECT id, kind, name, classification, risk, work, seconds, detail, origem, created_at FROM ai_events "
                "WHERE id > %s AND " + so_ia + " ORDER BY id DESC LIMIT %s", (after_id, max(limit, 300))).fetchall()
        else:   # carga inicial: as últimas de CADA coluna (classificação e decisão)
            events = c.execute(
                "(SELECT id, kind, name, classification, risk, work, seconds, detail, origem, created_at FROM ai_events "
                " WHERE kind <> ALL(%(d)s) AND " + so_ia + " ORDER BY id DESC LIMIT %(n)s) UNION ALL "
                "(SELECT id, kind, name, classification, risk, work, seconds, detail, origem, created_at FROM ai_events "
                " WHERE kind = ANY(%(d)s) AND " + so_ia + " ORDER BY id DESC LIMIT %(n)s) ORDER BY id DESC",
                {"d": list(eventos.DECISAO), "n": limit}).fetchall()
        # o que está em análise agora e em que fase (1-3 = claimed_at; lista = fase 1; 4 = IA online). São vários ao
        # mesmo tempo (workers da VM + reforço com GPU; a IA online roda em paralelo). Reservas "de espera" não contam:
        # a IA local adia com claimed_at no futuro (WHOIS) ou recuado (busca ocupada) p/ tentar depois, e a online reserva 10 min após resposta inválida
        # (online_falhas > 0)
        # entrada: novo (nunca passou pela IA / pela IA online), reavaliacao (já tinha resposta) ou pedida (alguém pediu);
        # desde_s: há quanto tempo foi visto pela 1ª vez (novo) ou analisado pela última vez (reavaliação)
        # (pelo histórico da IA, não por domains.model: as regras zeram o model ao regravar)
        local = ("CASE WHEN reanalise_pedida THEN 'pedida' WHEN u.ult IS NOT NULL THEN 'reavaliacao' ELSE 'novo' END AS entrada, "
                 "extract(epoch from now() - COALESCE(u.ult, first_seen))::int AS desde_s")
        ult = (" LEFT JOIN LATERAL (SELECT max(created_at) AS ult FROM classification_history h "
               "  WHERE h.domain_id = domains.id AND h.source = 'llm') u ON true ")
        em_analise = c.execute(
            "SELECT name, total_queries, fase, entrada, desde_s, extract(epoch from now() - t)::int AS elapsed FROM ("
            " SELECT name, total_queries, claimed_at AS t, CASE WHEN llm_pending THEN '1' "
            "   WHEN whois_at IS NULL THEN '2' WHEN web_search_at IS NULL THEN '3' ELSE '1' END AS fase, " + local +
            " FROM domains" + ult + "WHERE claimed_at BETWEEN now() - interval '5 minutes' AND now() "
            " UNION ALL SELECT name, total_queries, online_claimed_at, '4', "
            "   CASE WHEN reanalise_pedida THEN 'pedida' WHEN online_resp IS NOT NULL THEN 'reavaliacao' ELSE 'novo' END, "
            "   extract(epoch from now() - CASE WHEN online_resp IS NOT NULL THEN COALESCE(online_at, first_seen) ELSE first_seen END)::int FROM domains "
            "   WHERE online_claimed_at > now() - interval '10 minutes' AND online_falhas = 0 "
            " UNION ALL SELECT name, total_queries, lista_claimed_at, '1', " + local + " FROM domains" + ult +
            "   WHERE lista_claimed_at > now() - interval '10 minutes') x ORDER BY t DESC LIMIT 30").fetchall()
        vistos: set = set()   # o mesmo domínio pode estar reservado na IA local e na fila de lista: aparece uma vez
        em_analise = [r for r in em_analise if (r["name"], r["fase"] == "4") not in vistos
                      and not vistos.add((r["name"], r["fase"] == "4"))]
        cur = em_analise[0] if em_analise else None   # o mais recente (console antigo)
        from .listas_ia import incerta_sql
        _incerta = incerta_sql()   # sugestão de lista sem confiança alta: também passa pelas fases 2 e 3
        # fase 1 inteira: o pouco acesso (aguarda_recorrencia) também roda, no fim da fila
        queue = c.execute("SELECT count(*) FILTER (WHERE llm_pending AND (NOT dominio_decidido(id) OR reanalise_pedida)) AS ia, "
                          "count(*) FILTER (WHERE llm_pending AND aguarda_recorrencia AND (NOT dominio_decidido(id) OR reanalise_pedida)) AS aguarda, "
                          "count(*) FILTER (WHERE needs_analysis) AS regras, "
                          "count(*) FILTER (WHERE ((classification='DESCONHECIDO' AND classified_by='llm') OR " + _incerta + ") "
                          " AND web_search_at IS NULL AND NOT llm_pending AND kind='public' "
                          " AND (NOT dominio_decidido(id) OR reanalise_pedida)) AS busca, "   # (a busca espera o WHOIS)
                          "count(*) FILTER (WHERE ((classification='DESCONHECIDO' AND classified_by IN ('llm','web')) OR " + _incerta + ") "
                          " AND whois_at IS NULL AND NOT llm_pending AND kind='public' "
                          " AND (NOT dominio_decidido(id) OR reanalise_pedida)) AS whois FROM domains").fetchone()
        from . import listas_ia, online
        queue = {**queue, "lista": listas_ia.status(c)["fila"], "online": online.status(c)["fila"],
                 "online_on": online.habilitado(),
                 "revisar": c.execute(listas.FASE5_SQL).fetchone()["n"]}
        hour = c.execute("SELECT count(*) AS done, round(avg(seconds)::numeric, 1) AS avg_seconds FROM ai_events "
                         "WHERE kind='llm_done' AND created_at > now() - interval '1 hour'").fetchone()
    ok, msg = OllamaClient().available()
    eta = None
    if hour["done"] and queue["ia"]:   # pelo ritmo real (várias análises simultâneas / reforço com GPU)
        eta = int(queue["ia"] * 3600 / hour["done"])
    return {"events": events, "current": cur, "em_analise": em_analise, "queue": queue, "last_hour": hour, "eta_seconds": eta,
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
    autorizado_por: Optional[str] = None   # quem da empresa autorizou (vazio na edição = mantém)
    acao: Optional[str] = None             # liberar | editar (histórico); sem = pelo que já existia
    by: str = ""


@app.get("/console/liberados-meta", dependencies=[Depends(auth)])
def liberados_meta_list():
    with db.conn() as c:
        return c.execute("SELECT m.ip, m.tenant_id, t.name AS tenant_name, m.filial, m.empresa, m.departamento, "
                         "m.usuario, m.tipo, m.autorizado_por, m.created_at, m.created_by, m.updated_at, m.updated_by "
                         "FROM liberado_meta m LEFT JOIN tenants t ON t.id=m.tenant_id ORDER BY m.ip").fetchall()


@app.get("/console/liberados-log", dependencies=[Depends(auth)])
def liberados_log(ip: Optional[str] = None, limit: int = Query(50, le=500)):
    """Histórico dos IPs liberados: quem do console liberou/editou/revogou e quem da empresa autorizou."""
    with db.conn() as c:
        return c.execute("SELECT l.at, l.ip, l.acao, l.por, l.autorizado_por, l.tenant_id, t.name AS tenant_name, l.detalhe "
                         "FROM liberado_log l LEFT JOIN tenants t ON t.id = l.tenant_id "
                         "WHERE %(ip)s::text IS NULL OR l.ip = %(ip)s ORDER BY l.at DESC, l.id DESC LIMIT %(n)s",
                         {"ip": ip, "n": limit}).fetchall()


@app.put("/console/liberados-meta", dependencies=[Depends(auth)])
def liberados_meta_upsert(body: LiberadoMetaIn):
    def s(v, n):
        return ((v or "").strip()[:n]) or None
    with db.conn() as c:
        if body.tenant_id is not None:
            _tenant(c, body.tenant_id)
        # empresa escolhida no cadastro -> o texto livre (legado) deixa de valer
        existia = c.execute("SELECT 1 FROM liberado_meta WHERE ip=%s", (body.ip,)).fetchone() is not None
        r = c.execute(
            "INSERT INTO liberado_meta (ip, tenant_id, filial, empresa, departamento, usuario, tipo, autorizado_por, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (ip) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, "
            "filial=EXCLUDED.filial, empresa=EXCLUDED.empresa, departamento=EXCLUDED.departamento, "
            "usuario=EXCLUDED.usuario, tipo=EXCLUDED.tipo, "
            "autorizado_por=COALESCE(EXCLUDED.autorizado_por, liberado_meta.autorizado_por), "
            "updated_at=now(), updated_by=EXCLUDED.created_by "
            "RETURNING tenant_id, filial, departamento, usuario, tipo, autorizado_por",
            (body.ip, body.tenant_id, s(body.filial, 150) if body.tenant_id else None,
             None if body.tenant_id else s(body.empresa, 150), s(body.departamento, 255), s(body.usuario, 255),
             s(body.tipo, 20), s(body.autorizado_por, 255), body.by or None)).fetchone()
        acao = body.acao if body.acao in ("liberar", "editar") else ("editar" if existia else "liberar")
        c.execute("INSERT INTO liberado_log (ip, acao, por, autorizado_por, tenant_id, detalhe) VALUES (%s,%s,%s,%s,%s,%s)",
                  (body.ip, acao, body.by or None, r["autorizado_por"], r["tenant_id"],
                   Jsonb({k: r[k] for k in ("filial", "departamento", "usuario", "tipo") if r[k]})))
        return {"ok": True, "ip": body.ip}


@app.delete("/console/liberados-meta", dependencies=[Depends(auth)])
def liberados_meta_delete(ip: str, by: str = ""):
    with db.conn() as c:
        r = c.execute("DELETE FROM liberado_meta WHERE ip=%s RETURNING tenant_id, autorizado_por, filial, departamento, "
                      "usuario, tipo", (ip,)).fetchone()
        c.execute("INSERT INTO liberado_log (ip, acao, por, autorizado_por, tenant_id, detalhe) VALUES (%s,'revogar',%s,%s,%s,%s)",
                  (ip, by or None, (r or {}).get("autorizado_por"), (r or {}).get("tenant_id"),
                   Jsonb({k: r[k] for k in ("filial", "departamento", "usuario", "tipo") if r and r[k]})))
        return {"ok": True, "removed": 1 if r else 0}


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
                 por_cliente: bool = False, sem_locais: bool = False, excluir: list[str] = Query(default=[]),
                 limit: int = Query(1000, le=5000)):
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
    if sem_locais:   # nomes locais (zonas locais do Technitium, INTERNAL_SUFFIXES, sem ponto, reversos) fora
        where.append("d.kind NOT IN ('internal', 'reverse')")
        suf = [x.strip().lower().strip(".") for x in excluir if x and x.strip()]
        if suf:
            where.append("NOT (f.name = ANY(%(suf)s) OR f.name LIKE ANY(%(sufl)s))")
            p["suf"], p["sufl"] = suf, ["%." + x for x in suf]
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
           categoria: Optional[str] = None, resposta: Optional[str] = None, top: int = Query(15, le=50),
           unidade: Optional[str] = None):
    """Tela Gráficos: consultas liberadas × bloqueadas no tempo e por classificação da IA,
    categoria do site, empresa e site (top), com os mesmos filtros. resposta = liberado |
    bloqueado (só aquela parte das consultas). Série por hora até 2 dias; acima, por dia.
    unidade (com tid) = só os computadores da filial: IP na rede mais específica da empresa marcada com ela."""
    if end <= start:
        raise HTTPException(400, "período inválido")
    gran = "hour" if end - start <= timedelta(days=2) else "day"
    p: dict = {"s": start, "e": end, "top": top}
    wq = ["q.bucket >= date_trunc('hour', %(s)s::timestamptz)", "q.bucket < %(e)s"]
    if tid:
        wq.append("q.tenant_id = %(t)s"); p["t"] = tid
        if unidade:
            wq.append("q.client_id IN (SELECT cl.id FROM clients cl WHERE cl.tenant_id = %(t)s AND ("
                      " SELECT tn.unit FROM tenant_networks tn WHERE tn.tenant_id = cl.tenant_id AND cl.ip <<= tn.cidr "
                      " ORDER BY masklen(tn.cidr) DESC LIMIT 1) = %(u)s)")
            p["u"] = unidade
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


# ------------------------------------------------------------------ listas por categoria + bloqueio automático
@app.get("/listas/{categoria}.txt", response_class=PlainTextResponse)
def lista_txt(categoria: str, request: Request):
    """Lista publicada p/ o Technitium assinar (blockListUrls): 1 domínio por linha. Sem token
    (o Technitium não manda cabeçalho); só os IPs de LISTS_ALLOWED_IPS."""
    if request.client is None or request.client.host not in settings().lists_allowed_ips:
        raise HTTPException(403, "IP sem acesso às listas")
    if categoria not in listas.CATEGORIAS:
        raise HTTPException(404, "categoria sem lista")
    force = request.query_params.get("force") == "1"
    with db.conn() as c:
        doms = listas.dominios(c, categoria)
        ult = c.execute("SELECT last_n FROM list_fetches WHERE category = %s", (categoria,)).fetchone()
        n0 = (ult or {}).get("last_n") or 0
        recusar = not force and n0 >= 50 and len(doms) < 0.8 * n0
    if recusar:
        with db.conn() as c:
            # lista encolheu demais de uma vez: recusa (o Technitium segue com a última versão baixada) até
            # alguém aceitar em Domínios bloqueados (POST /listas/{cat}/aceitar) — protege contra esvaziar
            c.execute("INSERT INTO list_fetches (category, recusada_at, recusada_n) VALUES (%s, now(), %s) "
                      "ON CONFLICT (category) DO UPDATE SET recusada_at = now(), recusada_n = EXCLUDED.recusada_n",
                      (categoria, len(doms)))
            log.error("lista %s encolheu de %d para %d: publicação recusada", categoria, n0, len(doms))
            from . import eventos
            eventos.registrar("lista_recusada", None, origem="regras", detail=f"{categoria}|lista encolheu de {n0} para {len(doms)} domínios; "
                              "publicação recusada até alguém aceitar (o DNS segue com a versão anterior)")
        raise HTTPException(503, f"lista {categoria} encolheu de {n0} para {len(doms)}; publicação recusada")
    with db.conn() as c:
        c.execute("INSERT INTO list_fetches (category, last_at, last_ip, last_n) VALUES (%s, now(), %s, %s) "
                  "ON CONFLICT (category) DO UPDATE SET last_at = now(), last_ip = EXCLUDED.last_ip, last_n = EXCLUDED.last_n, "
                  "recusada_at = NULL, recusada_n = NULL", (categoria, request.client.host, len(doms)))
    return f"# 2D DNS Guard - lista {categoria} ({len(doms)} domínios)\n" + "".join(d + "\n" for d in doms)


@app.post("/listas/{categoria}/aceitar", dependencies=[Depends(auth)])
def lista_aceitar(categoria: str, by: str = ""):
    """Aceita a lista menor (limpeza de propósito): a próxima busca do Technitium já recebe a versão nova."""
    with db.conn() as c:
        n = len(listas.dominios(c, categoria))
        c.execute("UPDATE list_fetches SET last_n = %s, recusada_at = NULL, recusada_n = NULL WHERE category = %s", (n, categoria))
    from . import eventos
    eventos.registrar("decisao", None, detail=f"{categoria}|{by or 'manual'}: aceitou publicar a lista {categoria} com {n} domínios",
                      origem="f5:ti")
    return {"ok": True, "dominios": n}


@app.get("/listas", dependencies=[Depends(auth)])
def listas_resumo():
    with db.conn() as c:
        n = {k: len(listas.dominios(c, k)) for k in listas.CATEGORIAS}
        n24 = c.execute("SELECT count(*) AS n FROM category_lists WHERE added_by LIKE %s "
                        "AND added_at > now() - interval '24 hours'", (listas.AUTO_BY + "%",)).fetchone()["n"]
        pulso = {r["category"]: r for r in c.execute("SELECT * FROM list_fetches")}
    return {"categorias": [{"categoria": k, "total": n.get(k, 0), "tipo": "manual" if k in listas.CATEGORIAS_MANUAIS
                            else "ia", "pulso": pulso.get(k)} for k in listas.CATEGORIAS],
            "auto": listas.categorias_auto(), "auto_24h": n24}


@app.get("/listas-dominios", dependencies=[Depends(auth)])
def listas_dominios(cats: list[str] = Query(default=[])):
    """{categoria: [domínios]} de várias listas numa chamada (índice de bloqueio do console)."""
    with db.conn() as c:
        return {k: listas.dominios(c, k) for k in cats if k in listas.CATEGORIAS}


@app.get("/listas-busca", dependencies=[Depends(auth)])
def listas_busca(q: str, limit: int = Query(100, le=500)):
    """Procura o domínio (ou parte dele) em TODAS as listas de bloqueio (página Domínios bloqueados):
    [{domain, listas, classification, total_queries, pai}], exatos primeiro. Subdomínio também acha a entrada do
    domínio-pai que o bloqueia (pai = true; 28/09: cdn.qrofertas.com, bloqueado por qrofertas.com em Compras)."""
    termo = q.strip().lower().rstrip(".")
    if len(termo) < 3:
        return []
    padrao = "%" + termo.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    with db.conn() as c:
        return c.execute(
            "SELECT l.domain, array_agg(l.category ORDER BY l.category) AS listas, d.classification, "
            "       coalesce(d.total_queries, 0) AS total_queries, right(%(t)s, length(l.domain) + 1) = '.' || l.domain AS pai "
            "FROM category_lists l LEFT JOIN domains d ON d.name = l.domain "
            "WHERE (l.domain LIKE %(p)s OR right(%(t)s, length(l.domain) + 1) = '.' || l.domain) AND l.category <> 'para_revisar' "
            "GROUP BY l.domain, d.classification, d.total_queries "
            "ORDER BY (l.domain = %(t)s OR right(%(t)s, length(l.domain) + 1) = '.' || l.domain) DESC, (l.domain LIKE %(fim)s) DESC, "
            "         coalesce(d.total_queries, 0) DESC, l.domain LIMIT %(n)s",
            {"p": padrao, "t": termo, "fim": "%." + termo, "n": limit}).fetchall()


@app.get("/listas/{categoria}", dependencies=[Depends(auth)])
def lista_itens(categoria: str, q: Optional[str] = None, limit: int = Query(500, le=20000)):
    if categoria not in listas.CATEGORIAS:
        raise HTTPException(404, "categoria sem lista")
    with db.conn() as c:
        rows = [r for r in listas.itens(c, categoria) if not q or q.lower() in r["domain"]]
    rows.sort(key=lambda r: r["added_at"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return rows[:limit]


@app.get("/listas/{categoria}/sugestoes", dependencies=[Depends(auth)])
def lista_sugestoes(categoria: str, limit: int = Query(500, le=5000)):
    """Sugestões da IA p/ uma lista curada (redes sociais, streaming...): revisão manual."""
    with db.conn() as c:
        return listas.sugestoes(c, categoria, limit)


@app.get("/listas/{categoria}/detalhes", dependencies=[Depends(auth)])
def lista_detalhes(categoria: str, q: Optional[str] = None, cls: Optional[str] = None, cat_ia: Optional[str] = None,
                   revisao: Optional[str] = None, sug: Optional[str] = None, rec: Optional[str] = None, tid: Optional[int] = None,
                   fase5: bool = False,
                   ordem: str = "recentes", offset: int = Query(0, ge=0),
                   limit: int = Query(100, le=1000)):
    """Itens da lista com a classificação da IA, a revisão manual (quem/quando) e facetas p/ filtrar."""
    if categoria not in listas.CATEGORIAS:
        raise HTTPException(404, "categoria sem lista")
    with db.conn() as c:
        return listas.detalhes(c, categoria, tid=tid, fase5=fase5, q=q, cls=cls, cat_ia=cat_ia, revisao=revisao, sug=sug, rec=rec, ordem=ordem,
                               offset=offset, limit=limit)


@app.get("/sem-lista", dependencies=[Depends(auth)])
def sem_lista(q: Optional[str] = None, cls: Optional[str] = None, cat_ia: Optional[str] = None,
              revisao: Optional[str] = None, sug: Optional[str] = None, rec: Optional[str] = None, ordem: str = "consultas", offset: int = Query(0, ge=0),
              limit: int = Query(100, le=1000)):
    """Domínios analisados fora de qualquer lista (não vão p/ o Technitium)."""
    with db.conn() as c:
        return listas.sem_lista(c, q=q, cls=cls, cat_ia=cat_ia, revisao=revisao, sug=sug, rec=rec, ordem=ordem,
                                offset=offset, limit=limit)


class MoverIn(BaseModel):
    domains: list[str]
    de: str
    para: list[str]
    by: str = ""


@app.post("/listas-mover", dependencies=[Depends(auth)])
def listas_mover(body: MoverIn):
    """Tira os domínios da lista `de` e põe nas listas `para` (para=[] só tira)."""
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    ruins = [x for x in [body.de, *body.para] if x not in listas.CATEGORIAS]
    if ruins:
        raise HTTPException(422, f"lista inexistente: {', '.join(ruins)}")
    with db.conn() as c:
        listas.contexto(c, body.by or "manual", (f"pôs em {', '.join(body.para)}" if body.para else "manter liberado")
                        + f" (saiu de {body.de})")
        if body.para:
            _tira_da_whitelist(c, doms, body.by)
        for cat in body.para:
            c.execute("INSERT INTO category_lists (category, domain, added_by) SELECT %s, d, %s FROM unnest(%s::text[]) d "
                      "ON CONFLICT DO NOTHING", (cat, body.by or None, doms))
        n = 0 if body.de in body.para else c.execute(
            "DELETE FROM category_lists WHERE category=%s AND domain = ANY(%s)", (body.de, doms)).rowcount
    for d in doms:
        _decisao(d, ",".join(body.para) or body.de,
                 (f"pôs em {', '.join(body.para)}" if body.para else "manteve liberado") + f" (saiu de {body.de})", body.by)
    return {"ok": True, "movidos": len(doms), "removidos": n}


def _decisao(dominio: str, cat: str, texto: str, by: str = "") -> None:
    """Decisão manual na coluna "Decisão" do IA ao vivo."""
    from . import eventos
    try:
        with db.conn() as c:
            cls = (c.execute("SELECT classification FROM domains WHERE name = %s", (dominio,)).fetchone() or {}).get("classification")
    except Exception:  # noqa: BLE001 — o evento não pode derrubar a decisão
        cls = None
    eventos.lista("decisao", dominio, cat, (f"{by}: " if by else "manual: ") + texto, origem="f5:ti", classificacao=cls)


class AprovarIn(BaseModel):
    domains: list[str]
    de: str
    by: str = ""


@app.post("/listas-aprovar", dependencies=[Depends(auth)])
def listas_aprovar(body: AprovarIn):
    """Aprova a sugestão da IA: cada domínio sai da lista `de` e vai p/ a lista sugerida — de bloqueio ou whitelist
    (sugestão antiga "nenhuma" = só sai). Sem sugestão ainda: fica onde está."""
    from . import whitelist
    if body.de not in listas.CATEGORIAS:
        raise HTTPException(422, "lista inexistente")
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    out = {"movidos": {}, "tirados": [], "liberados": {}, "sem_sugestao": []}
    with db.conn() as c:
        listas.contexto(c, body.by or "manual", f"aprovou a sugestão da IA (saiu de {body.de})")
        sug = {r["name"]: r for r in c.execute("SELECT name, lista_ia, lista_wl, lista_at, lista_fonte FROM domains WHERE name = ANY(%s)",
                                                 (doms,))}
        for d in doms:
            r = sug.get(d)
            if not r or not r["lista_at"] or r["lista_fonte"] == "falhou":
                out["sem_sugestao"].append(d)
                continue
            alvo = r["lista_ia"]
            if alvo and alvo in listas.CATEGORIAS and alvo != body.de:
                _tira_da_whitelist(c, [d], body.by)
                c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                          (alvo, d, body.by or None))
                out["movidos"].setdefault(alvo, []).append(d)
            elif alvo == body.de:
                continue
            elif r["lista_wl"] in whitelist.CATEGORIAS:   # sugestão = liberar numa whitelist
                _para_whitelist(c, [d], r["lista_wl"], body.by, f"aprovou a sugestão da IA: whitelist {whitelist.CATEGORIAS[r['lista_wl']]}")
                out["liberados"].setdefault(r["lista_wl"], []).append(d)
                continue
            else:
                out["tirados"].append(d)
            c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (body.de, d))
    for alvo, ds in out["movidos"].items():
        for d in ds:
            _decisao(d, alvo, f"aprovou a sugestão da IA: {alvo} (saiu de {body.de})", body.by)
    for d in out["tirados"]:
        _decisao(d, body.de, f"aprovou a sugestão da IA: nenhuma lista (saiu de {body.de})", body.by)
    for wl, ds in out["liberados"].items():
        for d in ds:
            _decisao(d, f"wl:{wl}", f"aprovou a sugestão da IA: whitelist {whitelist.CATEGORIAS[wl]} (saiu de {body.de})", body.by)
    return {"ok": True, **out}


@app.get("/listas-ia/status", dependencies=[Depends(auth)])
def listas_ia_status():
    from . import listas_ia
    with db.conn() as c:
        return listas_ia.status(c)


# ------------------------------------------------------------------ exceções imediatas do console (allowed)
class NomesInConsole(BaseModel):
    domains: list[str]


class ExcecoesIn(BaseModel):
    excecoes: dict[str, list[str]]   # {domínio: [grupos]}
    por: str = ""


@app.post("/console/excecoes", dependencies=[Depends(auth)])
def excecoes_grava(body: ExcecoesIn):
    with db.conn() as c:
        for d, grupos in body.excecoes.items():
            for g in grupos:
                c.execute("INSERT INTO technitium_allowed_console (domain, grupo, added_by) VALUES (%s, %s, %s) "
                          "ON CONFLICT DO NOTHING", (d, g, body.por or None))
    return {"ok": True}


@app.get("/console/excecoes", dependencies=[Depends(auth)])
def excecoes_lista(domains: list[str] = Query(default=[])):
    """{domínio: [grupos]} das exceções que o console pôs (vazio = todas)."""
    with db.conn() as c:
        rows = c.execute("SELECT domain, grupo FROM technitium_allowed_console" + (" WHERE domain = ANY(%s)" if domains else "")
                         + " ORDER BY domain, grupo", (domains,) if domains else None).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        out.setdefault(r["domain"], []).append(r["grupo"])
    return out


@app.post("/console/excecoes/remover", dependencies=[Depends(auth)])
def excecoes_remove(body: NomesInConsole):
    with db.conn() as c:
        n = c.execute("DELETE FROM technitium_allowed_console WHERE domain = ANY(%s)", (body.domains,)).rowcount
    return {"ok": True, "removidos": n}


# ------------------------------------------------------------------ prévia de impacto (política / pôr na lista)
def _uso_por_dominio(c, tid: int, dias: int) -> list[dict]:
    return c.execute(
        "SELECT d.name, sum(q.queries) AS consultas FROM query_agg q JOIN domains d ON d.id = q.domain_id "
        "WHERE q.bucket >= now() - make_interval(days => %s) AND (%s = 0 OR q.tenant_id = %s) GROUP BY d.name",
        (dias, tid, tid)).fetchall()


@app.get("/policies/impacto", dependencies=[Depends(auth)])
def politica_impacto(tid: Optional[int] = None, lists: str = "", days: int = Query(7, ge=1, le=31)):
    """Se a empresa (tid; 0 = todas) passar a aplicar estas listas: por lista, computadores, consultas e os 20
    domínios mais consultados nos últimos `days` dias que cairiam nela (domínio ou pai na lista)."""
    if tid is None:
        raise HTTPException(422, "informe tid (0 = todas as empresas)")
    cats = [x for x in lists.split(",") if x in listas.CATEGORIAS]
    out = {}
    with db.conn() as c:
        uso = _uso_por_dominio(c, tid, days)
        for cat in cats:
            conj = set(listas.dominios(c, cat))
            nomes = [u["name"] for u in uso if listas._em_lista(u["name"], conj)]
            if not nomes:
                out[cat] = {"computadores": 0, "consultas": 0, "top": []}
                continue
            r = c.execute("SELECT count(DISTINCT q.client_id) AS pcs, coalesce(sum(q.queries), 0) AS n FROM query_agg q "
                          "JOIN domains d ON d.id = q.domain_id WHERE q.bucket >= now() - make_interval(days => %s) "
                          "AND (%s = 0 OR q.tenant_id = %s) AND d.name = ANY(%s)", (days, tid, tid, nomes)).fetchone()
            top = sorted((u for u in uso if u["name"] in set(nomes)), key=lambda u: -u["consultas"])[:20]
            out[cat] = {"computadores": r["pcs"], "consultas": int(r["n"]),
                        "top": [{"domain": u["name"], "consultas": int(u["consultas"])} for u in top]}
    return out


class ImpactoDominiosIn(BaseModel):
    domains: list[str]
    days: int = 7


@app.post("/domains/impacto", dependencies=[Depends(auth)])
def dominios_impacto(body: ImpactoDominiosIn):
    """Antes de pôr domínios numa lista: quantas empresas e computadores os consultaram (com subdomínios)."""
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    if not doms:
        return {"empresas": [], "computadores": 0, "consultas": 0}
    with db.conn() as c:
        r = c.execute(
            "SELECT count(DISTINCT q.client_id) AS pcs, coalesce(sum(q.queries), 0) AS n, "
            " array_agg(DISTINCT t.name) FILTER (WHERE t.name IS NOT NULL) AS empresas "
            "FROM query_agg q JOIN domains d ON d.id = q.domain_id JOIN tenants t ON t.id = q.tenant_id "
            "WHERE q.bucket >= now() - make_interval(days => %s) "
            " AND EXISTS (SELECT 1 FROM unnest(%s::text[]) x WHERE d.name = x OR d.name LIKE '%%.' || x)",
            (max(1, min(body.days, 31)), doms)).fetchone()
    return {"empresas": sorted(r["empresas"] or []), "computadores": r["pcs"], "consultas": int(r["n"])}


# ------------------------------------------------------------------ backups do config do Technitium (console)
class TechBackupIn(BaseModel):
    config: dict
    por: str = ""
    motivo: str = ""


@app.post("/console/technitium-backups", dependencies=[Depends(auth)])
def tech_backup_grava(body: TechBackupIn):
    """O console grava aqui o config que leu, antes de gravar no Technitium (mantém os 100 mais recentes)."""
    with db.conn() as c:
        r = c.execute("INSERT INTO technitium_config_backups (taken_by, motivo, config) VALUES (%s, %s, %s) RETURNING id",
                      (body.por[:120] or None, body.motivo[:300] or None, Jsonb(body.config))).fetchone()
        c.execute("DELETE FROM technitium_config_backups WHERE id NOT IN "
                  "(SELECT id FROM technitium_config_backups ORDER BY id DESC LIMIT 100)")
    return {"ok": True, "id": r["id"]}


@app.get("/console/technitium-backups", dependencies=[Depends(auth)])
def tech_backup_lista(limit: int = Query(30, le=100)):
    with db.conn() as c:
        return c.execute("SELECT id, taken_at, taken_by, motivo FROM technitium_config_backups ORDER BY id DESC LIMIT %s",
                         (limit,)).fetchall()


@app.get("/console/technitium-backups/{bid}", dependencies=[Depends(auth)])
def tech_backup_um(bid: int):
    with db.conn() as c:
        r = c.execute("SELECT id, taken_at, taken_by, motivo, config FROM technitium_config_backups WHERE id = %s",
                      (bid,)).fetchone()
    if not r:
        raise HTTPException(404, "backup não encontrado")
    return r


# ------------------------------------------------------------------ fase 3 (IA online)
@app.get("/online/status", dependencies=[Depends(auth)])
def online_status():
    from . import online
    with db.conn() as c:
        return online.status(c)


@app.get("/online/pendentes", dependencies=[Depends(auth)])
def online_pendentes(limit: int = Query(50, le=500)):
    """Fila da fase 3 (dúvidas da etapa "lista" + desconhecidos após a busca), com o contexto de cada um —
    p/ outra IA online responder por /online/decisao (além do Gemini automático)."""
    from . import listas_ia, online
    with db.conn() as c:
        rows = c.execute(
            "SELECT d.name, d.topic, d.classification, d.category, d.corp_reason, d.reasons, d.evidence, d.lista_ia, "
            " d.lista_conf, d.lista_motivo, d.total_queries FROM domains d WHERE " + online._FILA +
            " ORDER BY d.lista_duvida DESC, d.total_queries DESC LIMIT %s", (limit,)).fetchall()
    return [{"domain": r["name"], "contexto": listas_ia._contexto(r), "sugestao_local": r["lista_ia"] or listas_ia.NENHUMA,
             "confianca_local": r["lista_conf"], "motivo_local": r["lista_motivo"], "total_queries": r["total_queries"]}
            for r in rows]


class OnlineIn(BaseModel):
    domain: str
    lista: str
    confianca: float = Field(ge=0, le=1)
    classificacao: Optional[str] = None
    categoria: Optional[str] = None
    reconhecido: bool = False
    motivo: str = ""
    servico: str = ""
    fonte: str = "claude"


@app.post("/online/decisao", dependencies=[Depends(auth)])
def online_decisao(body: OnlineIn):
    """Resposta de uma IA online p/ um domínio (mesmo efeito da resposta do Gemini): vira a sugestão de
    lista e, para desconhecido reconhecido com certeza, a classificação. O próximo ciclo aplica."""
    from . import listas_ia, online
    if body.lista not in listas_ia.LISTAS_IA and body.lista != listas_ia.NENHUMA:
        raise HTTPException(422, "lista inválida")
    with db.conn() as c:
        d = c.execute("SELECT id, name, classification FROM domains WHERE name = %s",
                      (body.domain.strip().lower().rstrip("."),)).fetchone()
        if not d:
            raise HTTPException(404, "domínio não encontrado")
        cats = [r["code"] for r in c.execute("SELECT code FROM site_categories")]
        online.gravar(c, d, {"lista": body.lista, "confianca": body.confianca, "classificacao": body.classificacao,
                             "categoria": body.categoria, "reconhecido": body.reconhecido, "motivo": body.motivo,
                             "servico": body.servico}, {"model": body.fonte}, cats, fonte="online:" + (body.fonte or "online")[:30])
    return {"ok": True}


class NomesIn(BaseModel):
    domains: list[str]
    by: str = ""
    de: str = ""   # lista de onde o pedido veio (bloqueio ou "wl:<categoria>"): o domínio sai dela


def _reanalisar(c, nomes: list[str], by: str = "", de: str = "") -> list[str]:
    """Nova análise pedida por uma pessoa: volta à fase 1 (mesmo decidido: reanalise_pedida) e sai da fase em que
    estava — Decisão Humana (para_revisar) e fila da IA online. Se de novo nenhuma fase tiver certeza, volta à
    Decisão Humana sozinho. Travados à mão ficam de fora."""
    from . import eventos
    enviados = [r["name"] for r in c.execute(
        "UPDATE domains SET needs_analysis=true, evidence_hash='', classified_by=NULL, llm_attempts=0, revisado_at=NULL, "
        "reanalise_pedida=true, lista_duvida=false, online_claimed_at=NULL WHERE name = ANY(%s) AND NOT locked RETURNING name",
        (nomes,))]
    if enviados:
        listas.contexto(c, by or "manual", "nova análise pedida: volta à fase 1")
        sairam = [r["domain"] for r in c.execute("DELETE FROM category_lists WHERE category = 'para_revisar' AND domain = ANY(%s) "
                                                 "RETURNING domain", (enviados,))]
        from . import whitelist
        if de in listas.CATEGORIAS and de != "para_revisar":   # pedido numa lista de bloqueio: sai dela
            c.execute("DELETE FROM category_lists WHERE category = %s AND domain = ANY(%s)", (de, enviados))
        elif de.startswith("wl:") and de[3:] in whitelist.CATEGORIAS:   # numa whitelist: sai dela
            c.execute("DELETE FROM whitelist_domains WHERE category = %s AND domain = ANY(%s)", (de[3:], enviados))
        for n in enviados[:50]:
            eventos.lista("decisao", n, de or ("para_revisar" if n in sairam else None),
                          f"{by or 'manual'}: pediu nova análise (volta à fase 1)", origem="f5:ti")
    return enviados


@app.post("/domains-reanalyze", dependencies=[Depends(auth)])
def reanalyze_lote(body: NomesIn):
    """Nova análise em lote (regras agora; IA, WHOIS e busca na fila) — ver _reanalisar."""
    nomes = sorted({_domain_name(x) for x in body.domains if x and x.strip()})
    with db.conn() as c:
        n = len(_reanalisar(c, nomes, body.by, body.de))
    return {"ok": True, "enviados": n, "ignorados": len(nomes) - n}


@app.get("/auditoria", dependencies=[Depends(auth)])
def auditoria(domain: Optional[str] = None, category: Optional[str] = None, limit: int = Query(100, le=1000)):
    """Histórico permanente das listas (list_audit): o que entrou/saiu, quando, quem e por quê. Com domain,
    inclui os domínios pais (o bloqueio pode vir de um pai)."""
    cond, par = [], []
    if domain:
        p = domain.strip().lower().rstrip(".").split(".")
        cond.append("domain = ANY(%s)")
        par.append([".".join(p[i:]) for i in range(len(p) - 1)] or [domain])
    if category:
        cond.append("category = %s")
        par.append(category)
    with db.conn() as c:
        return c.execute("SELECT id, at, domain, category, acao, por, motivo FROM list_audit"
                         + (" WHERE " + " AND ".join(cond) if cond else "") + " ORDER BY id DESC LIMIT %s",
                         (*par, limit)).fetchall()


# ------------------------------------------------------------------ whitelists por categoria
@app.get("/whitelist/{categoria}.txt", response_class=PlainTextResponse)
def whitelist_txt(categoria: str, request: Request):
    """Whitelist publicada p/ o Technitium (allowListUrls de todos os grupos). Sem token; só LISTS_ALLOWED_IPS."""
    from . import whitelist
    if request.client is None or request.client.host not in settings().lists_allowed_ips:
        raise HTTPException(403, "IP sem acesso às listas")
    if categoria not in whitelist.CATEGORIAS:
        raise HTTPException(404, "categoria sem whitelist")
    with db.conn() as c:
        doms = whitelist.dominios(c, categoria)
        c.execute("INSERT INTO list_fetches (category, last_at, last_ip, last_n) VALUES (%s, now(), %s, %s) "
                  "ON CONFLICT (category) DO UPDATE SET last_at = now(), last_ip = EXCLUDED.last_ip, last_n = EXCLUDED.last_n",
                  ("wl:" + categoria, request.client.host, len(doms)))
    return f"# 2D DNS Guard - whitelist {categoria} ({len(doms)} domínios)\n" + "".join(d + "\n" for d in doms)


@app.get("/whitelist", dependencies=[Depends(auth)])
def whitelist_resumo():
    from . import whitelist
    with db.conn() as c:
        n = {r["category"]: r for r in c.execute("SELECT category, count(*) AS n, count(*) FILTER (WHERE publicar) AS pub "
                                                  "FROM whitelist_domains GROUP BY 1")}
        revisados = c.execute("SELECT count(*) AS n FROM domains WHERE revisado_at IS NOT NULL").fetchone()["n"]
    return {"categorias": [{"categoria": k, "rotulo": v, "total": (n.get(k) or {}).get("n", 0),
                            "publicados": (n.get(k) or {}).get("pub", 0)} for k, v in whitelist.CATEGORIAS.items()],
            "revisados": revisados}


@app.get("/whitelist-dominios", dependencies=[Depends(auth)])
def whitelist_dominios():
    """Domínios das whitelists publicados no DNS (o console considera no índice de bloqueio: vencem as listas)."""
    with db.conn() as c:
        return [r["domain"] for r in c.execute("SELECT DISTINCT domain FROM whitelist_domains WHERE publicar")]


@app.get("/whitelist/{categoria}/detalhes", dependencies=[Depends(auth)])
def whitelist_detalhes(categoria: str, q: Optional[str] = None, cls: Optional[str] = None, cat_ia: Optional[str] = None,
                       revisao: Optional[str] = None, sug: Optional[str] = None, rec: Optional[str] = None,
                       ordem: str = "consultas", offset: int = Query(0, ge=0), limit: int = Query(100, le=1000)):
    from . import whitelist
    if categoria not in whitelist.CATEGORIAS:
        raise HTTPException(404, "categoria sem whitelist")
    with db.conn() as c:
        return listas.detalhes_whitelist(c, categoria, q=q, cls=cls, cat_ia=cat_ia, revisao=revisao, sug=sug, rec=rec,
                                         ordem=ordem, offset=offset, limit=limit)


class WhitelistIn(BaseModel):
    domains: list[str]
    by: str = ""


def _para_whitelist(c, doms: list[str], categoria: str, by: str = "", texto: str = "") -> None:
    """Liberação por pessoa numa whitelist: sai das listas de bloqueio e de outra whitelist, vale no DNS (publicar) e
    conta como decisão humana "liberado" (a IA não põe de volta numa lista de bloqueio)."""
    from . import whitelist
    listas.contexto(c, by or "manual", texto or f"liberou na whitelist {whitelist.CATEGORIAS[categoria]}")
    c.execute("DELETE FROM category_lists WHERE domain = ANY(%s)", (doms,))
    c.execute("DELETE FROM whitelist_domains WHERE domain = ANY(%s) AND category <> %s", (doms, categoria))
    c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) SELECT %s, d, %s, true FROM unnest(%s::text[]) d "
              "ON CONFLICT (category, domain) DO UPDATE SET publicar = true, added_by = EXCLUDED.added_by",
              (categoria, by or "manual", doms))
    c.execute("UPDATE domains SET revisado_at = coalesce(revisado_at, now()), lista_duvida = false WHERE name = ANY(%s)", (doms,))
    c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) SELECT id, 'allowed', %s FROM domains WHERE name = ANY(%s) "
              "ON CONFLICT (domain_id) DO UPDATE SET status = 'allowed', reviewed_by = EXCLUDED.reviewed_by, reviewed_at = now()",
              (by or "manual", doms))


@app.post("/whitelist/{categoria}", dependencies=[Depends(auth)])
def whitelist_add(categoria: str, body: WhitelistIn):
    """Liberação manual numa whitelist (ver _para_whitelist)."""
    from . import whitelist
    if categoria not in whitelist.CATEGORIAS:
        raise HTTPException(404, "categoria sem whitelist")
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    with db.conn() as c:
        _para_whitelist(c, doms, categoria, body.by)
    for d in doms:
        _decisao(d, f"wl:{categoria}", f"liberou na whitelist {whitelist.CATEGORIAS[categoria]}", body.by)
    return {"ok": True, "dominios": len(doms)}


@app.post("/whitelist-remover", dependencies=[Depends(auth)])
def whitelist_remover(body: WhitelistIn):
    with db.conn() as c:
        listas.contexto(c, body.by or "manual", "tirou da whitelist")
        n = c.execute("DELETE FROM whitelist_domains WHERE domain = ANY(%s)", (body.domains,)).rowcount
    for d in body.domains[:200]:
        _decisao(d, "wl", "tirou da whitelist", body.by)
    return {"ok": True, "removidos": n}


def _tira_da_whitelist(c, doms: list[str], by: str = "") -> None:
    """Pessoa pôs numa lista de bloqueio: sai da whitelist (senão a whitelist venceria o bloqueio) e a decisão global
    "liberado" de antes vira "bloqueado" por ela (ex.: aprovou o parecer da IA que contrariava a decisão humana)."""
    c.execute("DELETE FROM whitelist_domains WHERE domain = ANY(%s)", (doms,))
    c.execute("UPDATE global_reviews g SET status = 'blocked', reviewed_by = %s, reviewed_at = now() FROM domains d "
              "WHERE g.domain_id = d.id AND d.name = ANY(%s) AND g.status = 'allowed'", (by or "manual", doms))


_FONTE = {"llm": "Fase 1 · IA local", "web": "Fase 3 · busca na web + IA local", "online": "Fase 4 · IA online",
          "catalog": "Catálogo", "rules": "Regras", "internal": "Interno", "manual": "Manual"}


@app.get("/domains/{name}/historico", dependencies=[Depends(auth)])
def dominio_historico(name: str):
    """Tudo o que aconteceu com o domínio até o estado atual, em ordem: classificações de cada fase, resposta
    da IA online, entradas/saídas das listas e da whitelist, decisões de pessoas e eventos recentes."""
    reg = name.strip().lower().rstrip(".")
    p = reg.split(".")
    cands = [".".join(p[i:]) for i in range(len(p) - 1)] or [reg]
    with db.conn() as c:
        d = c.execute("SELECT id, name, classification, category, topic, confidence, corp_action, corp_reason, classified_by, "
                      "first_seen, analyzed_at, whois_at, web_search_at, online_at, revisado_at, lista_ia, lista_conf, lista_fonte, "
                      "lista_motivo, online_resp, ti_signature, total_queries FROM domains WHERE name = %s", (reg,)).fetchone()
        if not d:
            raise HTTPException(404, "domínio nunca observado")
        tl = []
        for h in c.execute("SELECT created_at, source, classification, topic, confidence, model, note FROM classification_history "
                           "WHERE domain_id = %s ORDER BY created_at", (d["id"],)):
            tl.append({"at": h["created_at"], "tipo": "classificacao", "titulo": _FONTE.get(h["source"], h["source"] or "?"),
                       "texto": " · ".join(x for x in (h["classification"], h["topic"],
                                                       f"{h['confidence'] * 100:.0f}%" if h["confidence"] else "", h["model"] or "") if x),
                       "nota": h["note"]})
        for a in c.execute("SELECT at, domain, category, acao, por, motivo FROM list_audit WHERE domain = ANY(%s) ORDER BY at", (cands,)):
            lista = a["category"]
            tl.append({"at": a["at"], "tipo": "lista", "titulo": ("entrou em " if a["acao"] == "add" else "saiu de ") + lista,
                       "texto": " · ".join(x for x in (a["por"], a["motivo"]) if x) + (f" (domínio pai {a['domain']})" if a["domain"] != reg else ""),
                       "lista": lista, "acao": a["acao"]})
        g = c.execute("SELECT status, reviewed_by, reviewed_at FROM global_reviews WHERE domain_id = %s", (d["id"],)).fetchone()
        if g:
            tl.append({"at": g["reviewed_at"], "tipo": "decisao", "titulo": "decisão global: " + {"blocked": "bloquear", "allowed": "manter liberado"}[g["status"]],
                       "texto": g["reviewed_by"] or ""})
        for t in c.execute("SELECT t.name, td.review_status, td.reviewed_by, td.reviewed_at, td.override_classification, td.override_by, "
                           "td.override_at FROM tenant_domains td JOIN tenants t ON t.id = td.tenant_id WHERE td.domain_id = %s "
                           "AND (td.review_status IS NOT NULL OR td.override_classification IS NOT NULL)", (d["id"],)):
            if t["review_status"]:
                tl.append({"at": t["reviewed_at"], "tipo": "decisao", "titulo": f"decisão de {t['name']}: " +
                           {"blocked": "bloquear", "allowed": "manter liberado"}[t["review_status"]], "texto": t["reviewed_by"] or ""})
            if t["override_classification"]:
                tl.append({"at": t["override_at"], "tipo": "decisao", "titulo": f"{t['name']} ajustou para {t['override_classification']}",
                           "texto": t["override_by"] or ""})
        for e in c.execute("SELECT created_at, kind, classification, detail, origem FROM ai_events WHERE name = %s "
                           "AND kind NOT IN ('llm_done', 'rules_final') ORDER BY id", (reg,)):
            det = e["detail"] or ""
            titulo = _EVENTO_TITULO.get(e["kind"], e["kind"]) + (f" · por {ORIGEM[e['origem']]}" if e["origem"] in ORIGEM else "")
            if e["kind"] == "lista_local":
                titulo = f"Fase {det.split('|', 1)[0]} · IA local: lista"
            elif e["kind"] in ("whois_done", "search_done") and e["classification"]:
                titulo += f" → {e['classification']}"
            tl.append({"at": e["created_at"], "tipo": "evento", "titulo": titulo, "texto": det.split("|", 1)[-1]})
        listas_atuais = [r["category"] for r in c.execute("SELECT category FROM category_lists WHERE domain = ANY(%s)", (cands,))]
        wl = [r["category"] for r in c.execute("SELECT category FROM whitelist_domains WHERE domain = ANY(%s)", (cands,))]
    o = d["online_resp"] or {}
    if d["online_at"] and o:
        antes = (o.get("_meta") or {}).get("antes") or {}
        tl.append({"at": d["online_at"], "tipo": "classificacao", "titulo": "Fase 4 · IA online",
                   "texto": " · ".join(x for x in (o.get("classificacao"), f"lista {o.get('lista')}", f"{float(o.get('confianca') or 0) * 100:.0f}%",
                                                   o.get("servico"), (o.get("_meta") or {}).get("model")) if x),
                   "nota": (o.get("motivo") or "") + (f" · 1ª opinião ({antes.get('modelo')}): {antes.get('lista')} "
                                                       f"{float(antes.get('confianca') or 0) * 100:.0f}%" if antes else "")})
    tl.sort(key=lambda x: x["at"] or datetime.min.replace(tzinfo=timezone.utc))
    estado = ("bloqueado (" + ", ".join(listas_atuais) + ")" if [x for x in listas_atuais if x != "para_revisar"]
              else "na Decisão Humana (fase 5)" if "para_revisar" in listas_atuais
              else "whitelist (" + ", ".join(wl) + ")" if wl else "aprovado (fora de listas)" if d["revisado_at"] else "em análise")
    return {"domain": reg, "estado": estado, "classificacao": d["classification"], "categoria": d["category"], "servico": d["topic"],
            "recomendacao": d["corp_action"], "motivo": d["corp_reason"], "fonte": _FONTE.get(d["classified_by"], d["classified_by"]),
            "listas": listas_atuais, "whitelist": wl, "feeds": d["ti_signature"] or None, "consultas": d["total_queries"],
            "fases": {"visto": d["first_seen"], "fase1": d["analyzed_at"], "fase2_whois": d["whois_at"], "fase3_busca": d["web_search_at"],
                      "fase4_online": d["online_at"], "revisado": d["revisado_at"]},
            "linha_do_tempo": tl}


ORIGEM = {"f1:local": "Fase 1 · IA local", "f2:local": "Fase 2 · IA local", "f3:local": "Fase 3 · IA local",
          "local": "IA local", "f4:online": "Fase 4 · IA online", "f5:ti": "Fase 5 · Decisão Humana",
          "auto": "bloqueio automático", "regras": "regras (feeds/travas)", "catalogo": "catálogo"}
_EVENTO_TITULO = {"aprovado": "liberado (Aprovados)", "whois_start": "Fase 2 · consultando WHOIS", "whois_done": "Fase 2 · WHOIS + IA local",
                  "whois_error": "Fase 2 · WHOIS indisponível", "search_start": "Fase 3 · buscando na web",
                  "search_done": "Fase 3 · busca na web + IA local", "search_error": "Fase 3 · busca indisponível",
                  "llm_start": "Fase 1 · IA local analisando", "llm_error": "Fase 1 · falha da IA local",
                  "online_done": "Fase 4 · IA online", "lista_add": "entrou numa lista", "lista_rem": "saiu de uma lista",
                  "fase5": "foi para a Decisão Humana (fase 5)", "decisao": "decisão manual", "auto_block": "bloqueio automático",
                  "rules_alert": "alerta das regras"}


@app.get("/domains/{name}/irmaos", dependencies=[Depends(auth)])
def dominio_irmaos(name: str, limit: int = Query(50, le=200)):
    """Domínios já vistos nos logs que compartilham o CERTIFICADO (SAN) ou o TITULAR do WHOIS (mesmo CNPJ) com
    este e que NÃO estão nas mesmas listas — p/ bloquear a família inteira de uma vez. Ficam de fora os que
    nunca devem ir junto: protegidos no catálogo, na whitelist ou populares (Tranco ≤ 10.000) — certificado
    compartilhado (ex.: o do youtu.be é o do Google) traria google.ca, android.com, google-analytics.com."""
    from . import catalog
    reg = name.strip().lower().rstrip(".")
    with db.conn() as c:
        if not c.execute("SELECT 1 FROM domains WHERE name = %s", (reg,)).fetchone():
            raise HTTPException(404, "domínio nunca observado")
        motivos: dict[str, str] = {}
        web = c.execute("SELECT value FROM lookup_cache WHERE kind = 'web' AND key = %s", (reg,)).fetchone()
        cert = ((web or {}).get("value") or {}).get("cert")   # null quando o site não tem HTTPS
        for x in (cert or {}).get("san_domains") or []:
            motivos.setdefault(str(x).lower(), "mesmo certificado (está no certificado deste)")
        for r in c.execute("SELECT key FROM lookup_cache WHERE kind = 'web' AND value->'cert'->'san_domains' ? %s", (reg,)):
            motivos.setdefault(r["key"], "mesmo certificado (este está no certificado dele)")
        w = c.execute("SELECT value->'titular' AS t FROM lookup_cache WHERE kind = 'whois' AND key = %s", (reg,)).fetchone()
        t = (w or {}).get("t")
        if isinstance(t, dict) and t.get("tipo") == "cnpj" and t.get("doc"):
            for r in c.execute("SELECT key FROM lookup_cache WHERE kind = 'whois' AND value->'titular'->>'doc' = %s", (t["doc"],)):
                motivos[r["key"]] = f"mesmo titular no WHOIS ({t.get('nome') or 'CNPJ'} · {t['doc']})"
        motivos.pop(reg, None)
        if not motivos:
            return []
        minhas = {r["category"] for r in c.execute("SELECT category FROM category_lists WHERE domain = %s", (reg,))}
        rows = c.execute("SELECT name, total_queries, classification, category, popularity_rank FROM domains WHERE name = ANY(%s)",
                         (list(motivos),)).fetchall()
        na_wl = {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains WHERE domain = ANY(%s)", (list(motivos),))}
        rows = [r for r in rows if r["name"] not in na_wl and not (r["popularity_rank"] and r["popularity_rank"] <= 10000)
                and not (catalog.match(r["name"]) or {}).get("protected")]
        listas_de = {}
        for r in c.execute("SELECT domain, category FROM category_lists WHERE domain = ANY(%s)", ([r["name"] for r in rows],)):
            listas_de.setdefault(r["domain"], []).append(r["category"])
    out = [{"domain": r["name"], "motivo": motivos[r["name"]], "listas_atuais": sorted(listas_de.get(r["name"], [])),
            "total_queries": r["total_queries"], "classificacao": r["classification"], "categoria": r["category"]}
           for r in rows if not (minhas and minhas <= set(listas_de.get(r["name"], [])))]
    return sorted(out, key=lambda x: -(x["total_queries"] or 0))[:limit]


@app.get("/ai/precisao", dependencies=[Depends(auth)])
def ai_precisao(days: int = Query(7, ge=1, le=90)):
    """Quanto do que a IA pôs sozinha nas listas uma PESSOA desfez depois (auditoria permanente), por fonte,
    e o que as pessoas fizeram com as sugestões em Decisões."""
    humano = ("NOT (r.por LIKE 'IA%%' OR r.por LIKE 'bloqueio automático%%' OR r.por LIKE 'whitelist%%' "
              "OR r.por LIKE 'expiração%%' OR r.por LIKE 'inexistente%%' OR r.por = '?')")
    with db.conn() as c:
        fontes = c.execute(
            "SELECT CASE WHEN a.category LIKE 'wl:%%' THEN 'whitelist' WHEN a.por LIKE 'bloqueio automático%%' THEN 'bloqueio automático' "
            "            WHEN a.motivo LIKE 'IA online%%' THEN 'IA online' WHEN a.motivo LIKE 'IA local%%' THEN 'IA local' ELSE 'outra' END AS fonte, "
            " count(*) AS aplicadas, count(*) FILTER (WHERE EXISTS (SELECT 1 FROM list_audit r WHERE r.domain = a.domain "
            "   AND r.category = a.category AND r.acao = 'remove' AND r.at > a.at AND " + humano + ")) AS corrigidas "
            "FROM list_audit a WHERE a.acao = 'add' AND a.at > now() - make_interval(days => %s) "
            " AND (a.por LIKE 'IA automática%%' OR a.por LIKE 'bloqueio automático%%' OR a.por LIKE 'IA whitelist%%' "
            "      OR a.por LIKE 'catálogo%%') GROUP BY 1 ORDER BY 2 DESC", (days,)).fetchall()
        dec = c.execute(
            "SELECT count(*) FILTER (WHERE motivo LIKE 'aprovou a sugestão%%') AS aprovou_sugestao, "
            " count(*) FILTER (WHERE motivo LIKE 'pôs em %%') AS outra_lista, "
            " count(*) FILTER (WHERE motivo LIKE 'manter liberado%%') AS manteve_liberado "
            "FROM list_audit WHERE category = 'para_revisar' AND acao = 'remove' AND at > now() - make_interval(days => %s) "
            " AND NOT (por LIKE 'IA%%' OR por LIKE 'inexistente%%' OR por = '?')", (days,)).fetchone()
    return {"dias": days, "fontes": [{**f, "pct_corrigidas": round(100 * f["corrigidas"] / f["aplicadas"], 1) if f["aplicadas"] else 0}
                                     for f in fontes], "decisoes": dec}


@app.get("/listas-dominio/{name}", dependencies=[Depends(auth)])
def listas_do_dominio(name: str):
    """Em que listas o domínio está (ele mesmo ou um domínio pai)."""
    n = name.strip().lower().rstrip(".")
    parts = n.split(".")
    cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    with db.conn() as c:
        rows = c.execute("SELECT category, domain, added_by, added_at FROM category_lists WHERE domain = ANY(%s)",
                         (cands,)).fetchall()
        vistos = {(r["category"], r["domain"]) for r in rows}
        for cat in listas.CATEGORIAS_DINAMICAS:
            rows += [{"category": cat, **r} for r in c.execute(
                listas.DINAMICA_SQL + " AND d.name = ANY(%(cands)s)", {"cat": cat, "cands": cands}).fetchall()
                     if (cat, r["domain"]) not in vistos]
        return rows


class ListaIn(BaseModel):
    domain: str
    by: str = ""


@app.post("/listas/{categoria}", dependencies=[Depends(auth)])
def lista_add(categoria: str, body: ListaIn):
    if categoria not in listas.CATEGORIAS:
        raise HTTPException(404, "categoria sem lista")
    d = body.domain.strip().lower().rstrip(".")
    if not d or "." not in d:
        raise HTTPException(400, "domínio inválido")
    with db.conn() as c:
        listas.contexto(c, body.by or "manual", f"pôs em {categoria}")
        _tira_da_whitelist(c, [d], body.by)
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                  (categoria, d, body.by or None))
    _decisao(d, categoria, f"pôs em {categoria}", body.by)
    return {"ok": True}


class ListasLoteIn(BaseModel):
    cats: list[str] = []
    domains: list[str]
    by: str = ""


def _dom_ok(d: str) -> str:
    d = (d or "").strip().lower().rstrip(".")
    return d if d and "." in d and " " not in d else ""


@app.post("/listas-lote", dependencies=[Depends(auth)])
def listas_lote(body: ListasLoteIn):
    """Põe vários domínios em várias listas de uma vez (Decisões, Domínios, migração)."""
    ruins = [c for c in body.cats if c not in listas.CATEGORIAS]
    if ruins or not body.cats:
        raise HTTPException(400, f"lista inválida: {', '.join(ruins) or '(nenhuma)'}")
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    with db.conn() as c, c.cursor() as cur:
        listas.contexto(c, body.by or "manual", f"pôs em {', '.join(body.cats)}")
        _tira_da_whitelist(c, doms, body.by)
        cur.executemany("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                        [(cat, d, body.by or None) for cat in body.cats for d in doms])
    if len(doms) <= 200:   # (migrações em massa não enchem o feed)
        for d in doms:
            _decisao(d, ",".join(body.cats), f"pôs em {', '.join(body.cats)}", body.by)
    return {"ok": True, "dominios": len(doms)}


@app.post("/listas-remover", dependencies=[Depends(auth)])
def listas_remover(body: ListasLoteIn):
    """Tira domínios das listas indicadas (cats vazio = de todas)."""
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    with db.conn() as c:
        listas.contexto(c, body.by or "manual", "tirou " + (f"de {', '.join(body.cats)}" if body.cats else "de todas as listas"))
        if body.cats:
            n = c.execute("DELETE FROM category_lists WHERE domain = ANY(%s) AND category = ANY(%s)", (doms, body.cats)).rowcount
        else:
            n = c.execute("DELETE FROM category_lists WHERE domain = ANY(%s)", (doms,)).rowcount
    if n:
        for d in doms[:200]:
            _decisao(d, ",".join(body.cats), "tirou " + (f"de {', '.join(body.cats)}" if body.cats else "de todas as listas"), body.by)
    return {"ok": True, "removidos": n}


@app.delete("/listas/{categoria}/{domain}", dependencies=[Depends(auth)])
def lista_rem(categoria: str, domain: str, by: str = ""):
    with db.conn() as c:
        listas.contexto(c, by or "manual", f"tirou de {categoria} (manter liberado)")
        n = c.execute("DELETE FROM category_lists WHERE category=%s AND domain=%s",
                      (categoria, domain.strip().lower().rstrip("."))).rowcount
    if n:
        _decisao(domain.strip().lower().rstrip("."), categoria, f"tirou de {categoria}")
    return {"ok": True, "removidos": n}


# ------------------------------------------------------------------ listas de LIBERAÇÃO (whitelist)
@app.get("/servico/{slug}.txt", response_class=PlainTextResponse)
@app.get("/liberacao/{slug}.txt", response_class=PlainTextResponse)
def liberacao_txt(slug: str, request: Request):
    """Lista de liberação p/ o Technitium (allowListUrls). Sem token; só LISTS_ALLOWED_IPS."""
    if request.client is None or request.client.host not in settings().lists_allowed_ips:
        raise HTTPException(403, "IP sem acesso às listas")
    with db.conn() as c:
        if not c.execute("SELECT 1 FROM allow_lists WHERE slug=%s", (slug,)).fetchone():
            raise HTTPException(404, "lista de liberação inexistente")
        doms = [r["domain"] for r in c.execute(
            "SELECT domain FROM allow_list_domains WHERE list_slug=%s ORDER BY domain", (slug,)).fetchall()]
    return f"# 2D DNS Guard - liberação {slug} ({len(doms)} domínios)\n" + "".join(d + "\n" for d in doms)


@app.get("/liberacao", dependencies=[Depends(auth)])
def liberacao_listas():
    with db.conn() as c:
        return c.execute("SELECT l.slug, l.name, l.category, l.description, l.created_by, l.created_at, "
                         " (SELECT count(*) FROM allow_list_domains d WHERE d.list_slug = l.slug) AS total "
                         "FROM allow_lists l ORDER BY lower(l.name)").fetchall()


class AllowListIn(BaseModel):
    name: str
    category: Optional[str] = None     # serviço de uma lista de bloqueio; vazio = liberação avulsa
    description: str = ""
    by: str = ""


@app.post("/liberacao", dependencies=[Depends(auth)])
def liberacao_criar(body: AllowListIn):
    import re
    import unicodedata
    nome = body.name.strip()
    if not nome:
        raise HTTPException(400, "nome obrigatório")
    slug = re.sub(r"[^a-z0-9]+", "-", unicodedata.normalize("NFKD", nome).encode("ascii", "ignore").decode().lower()).strip("-")[:40]
    if not slug:
        raise HTTPException(400, "nome inválido")
    cat = body.category or None
    if cat and cat not in listas.CATEGORIAS:
        raise HTTPException(400, "categoria inválida")
    with db.conn() as c:
        r = c.execute("INSERT INTO allow_lists (slug, name, category, description, created_by) VALUES (%s, %s, %s, %s, %s) "
                      "ON CONFLICT (slug) DO NOTHING RETURNING slug", (slug, nome, cat, body.description or None, body.by or None)).fetchone()
    if not r:
        raise HTTPException(409, f"já existe uma lista '{slug}'")
    return {"ok": True, "slug": slug}


@app.delete("/liberacao/{slug}", dependencies=[Depends(auth)])
def liberacao_apagar(slug: str):
    """Apaga a lista e tira ela das políticas que a usavam."""
    with db.conn() as c:
        c.execute("UPDATE policies SET services = array_remove(services, %s), "
                  "services_blocked = array_remove(services_blocked, %s), updated_at = now() "
                  "WHERE %s = ANY(services) OR %s = ANY(services_blocked)", (slug, slug, slug, slug))
        n = c.execute("DELETE FROM allow_lists WHERE slug=%s", (slug,)).rowcount
    return {"ok": True, "removidas": n}


@app.put("/liberacao/{slug}", dependencies=[Depends(auth)])
def liberacao_editar(slug: str, body: AllowListIn):
    """Renomeia / muda a categoria do serviço (vazio = liberação avulsa)."""
    cat = body.category or None
    if cat and cat not in listas.CATEGORIAS:
        raise HTTPException(400, "categoria inválida")
    with db.conn() as c:
        n = c.execute("UPDATE allow_lists SET name=%s, category=%s WHERE slug=%s", (body.name.strip() or slug, cat, slug)).rowcount
    if not n:
        raise HTTPException(404, "serviço inexistente")
    return {"ok": True}


@app.get("/liberacao/{slug}", dependencies=[Depends(auth)])
def liberacao_itens(slug: str, q: Optional[str] = None, limit: int = Query(2000, le=20000)):
    with db.conn() as c:
        return c.execute("SELECT domain, added_by, added_at FROM allow_list_domains WHERE list_slug=%s "
                         "AND (%s::text IS NULL OR domain LIKE %s) ORDER BY domain LIMIT %s",
                         (slug, q, f"%{(q or '').lower()}%", limit)).fetchall()


@app.post("/liberacao/{slug}/dominios", dependencies=[Depends(auth)])
def liberacao_add(slug: str, body: ListasLoteIn):
    doms = sorted({x for x in map(_dom_ok, body.domains) if x})
    with db.conn() as c:
        if not c.execute("SELECT 1 FROM allow_lists WHERE slug=%s", (slug,)).fetchone():
            raise HTTPException(404, "lista de liberação inexistente")
        with c.cursor() as cur:
            cur.executemany("INSERT INTO allow_list_domains (list_slug, domain, added_by) VALUES (%s, %s, %s) "
                            "ON CONFLICT DO NOTHING", [(slug, d, body.by or None) for d in doms])
    return {"ok": True, "dominios": len(doms)}


@app.delete("/liberacao/{slug}/dominios/{domain}", dependencies=[Depends(auth)])
def liberacao_rem(slug: str, domain: str):
    with db.conn() as c:
        n = c.execute("DELETE FROM allow_list_domains WHERE list_slug=%s AND domain=%s",
                      (slug, domain.strip().lower().rstrip("."))).rowcount
    return {"ok": True, "removidos": n}


@app.get("/liberacao-dominio/{name}", dependencies=[Depends(auth)])
def liberacao_do_dominio(name: str):
    """Em que listas de liberação o domínio está (ele mesmo ou um domínio pai)."""
    n = name.strip().lower().rstrip(".")
    parts = n.split(".")
    cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    with db.conn() as c:
        return c.execute("SELECT d.list_slug AS slug, l.name, d.domain FROM allow_list_domains d "
                         "JOIN allow_lists l ON l.slug = d.list_slug WHERE d.domain = ANY(%s)", (cands,)).fetchall()


# ------------------------------------------------------------------ políticas (empresa -> listas)
def _scope_ok(scope: str) -> bool:
    import re
    return scope == "default" or bool(re.fullmatch(r"tenant:\d+|unit:\d+:.{1,120}", scope))


@app.get("/policies", dependencies=[Depends(auth)])
def policies_list():
    with db.conn() as c:
        return c.execute("SELECT scope, lists, services, services_blocked, updated_by, updated_at FROM policies ORDER BY scope").fetchall()


class PolicyIn(BaseModel):
    lists: list[str] = []
    services: list[str] = []            # serviços / listas de liberação LIBERADOS
    services_blocked: list[str] = []    # serviços BLOQUEADOS (sem bloquear a categoria inteira)
    by: str = ""


@app.put("/policies/{scope}", dependencies=[Depends(auth)])
def policy_set(scope: str, body: PolicyIn):
    """Grava a política do escopo (empresa, unidade ou default). Lista desconhecida = 400."""
    if not _scope_ok(scope):
        raise HTTPException(400, "escopo inválido")
    ruins = [x for x in body.lists if x not in listas.CATEGORIAS]
    if ruins:
        raise HTTPException(400, f"lista desconhecida: {', '.join(ruins)}")
    with db.conn() as c:
        existem = {r["slug"] for r in c.execute("SELECT slug FROM allow_lists").fetchall()}
        ruins = [x for x in body.services + body.services_blocked if x not in existem]
        if ruins:
            raise HTTPException(400, f"serviço/lista de liberação desconhecido: {', '.join(ruins)}")
        lib = sorted(set(body.services))
        blq = sorted(set(body.services_blocked) - set(lib))   # liberar vence bloquear
        c.execute("INSERT INTO policies (scope, lists, services, services_blocked, updated_by) VALUES (%s, %s, %s, %s, %s) "
                  "ON CONFLICT (scope) DO UPDATE SET lists=EXCLUDED.lists, services=EXCLUDED.services, "
                  "services_blocked=EXCLUDED.services_blocked, updated_by=EXCLUDED.updated_by, updated_at=now()",
                  (scope, sorted(set(body.lists)), lib, blq, body.by or None))
    return {"ok": True}


@app.delete("/policies/{scope}", dependencies=[Depends(auth)])
def policy_delete(scope: str):
    """Tira a exceção de uma unidade (volta a valer a da empresa). O default não se apaga."""
    if scope == "default" or not _scope_ok(scope):
        raise HTTPException(400, "escopo inválido")
    with db.conn() as c:
        c.execute("DELETE FROM policies WHERE scope=%s", (scope,))
    return {"ok": True}


@app.get("/auto-block/candidates", dependencies=[Depends(auth)])
def auto_block_candidates(limit: int = Query(300, le=2000)):
    """O que o bloqueio automático vai colocar nas listas no próximo ciclo."""
    with db.conn() as c:
        return listas.candidatos(c, limite=limit)
