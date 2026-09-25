"""Coleta incremental dos logs do Technitium e agregação por tenant/cliente/FQDN/hora.

Janelas fechadas [início, fim) com fim = agora - INGEST_LAG (o Technitium grava
os logs em lote; o atraso evita perder entradas). O cursor só avança na mesma
transação em que os agregados são gravados -> sem perdas nem duplicação.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from . import db
from .config import settings
from .features import analyze_name, domain_features, name_features
from .technitium import TechnitiumClient, parse_ts
from .tenants import TenantResolver, auto_network_for, slugify

log = logging.getLogger(__name__)
CURSOR_KEY = "ingest_cursor"
BLOCKED_TYPES = {"Blocked", "UpstreamBlocked", "CacheBlocked"}


@dataclass
class Agg:
    queries: int = 0
    blocked: int = 0
    nxdomain: int = 0
    first: datetime | None = None
    last: datetime | None = None

    def add(self, ts: datetime, blocked: bool, nx: bool) -> None:
        self.queries += 1
        self.blocked += int(blocked)
        self.nxdomain += int(nx)
        self.first = ts if self.first is None or ts < self.first else self.first
        self.last = ts if self.last is None or ts > self.last else self.last


def hour_bucket(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def aggregate(entries, start: datetime, end: datetime, excluded=()) -> dict[tuple, Agg]:
    """Agrega entradas cruas por (ip, fqdn, hora), só com start <= ts < end.

    Função pura (testável sem banco)."""
    out: dict[tuple, Agg] = {}
    for e in entries:
        ts = parse_ts(e.get("timestamp", ""))
        if ts is None or ts < start or ts >= end:
            continue
        ip = (e.get("clientIpAddress") or "").strip()
        qname = (e.get("qname") or "").strip().rstrip(".").lower()
        if not ip or not qname:
            continue
        if excluded:
            try:
                a = ipaddress.ip_address(ip)
                if any(a in n for n in excluded):
                    continue
            except ValueError:
                continue
        key = (ip, qname, hour_bucket(ts))
        ag = out.get(key)
        if ag is None:
            ag = out[key] = Agg()
        ag.add(ts, e.get("responseType") in BLOCKED_TYPES, e.get("rcode") == "NxDomain")
    return out


def ensure_partitions(c, start: datetime, end: datetime) -> None:
    """Cria partições mensais de query_agg cobrindo [start, end]."""
    m = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while m <= end:
        nxt = (m + timedelta(days=32)).replace(day=1)
        name = f"query_agg_{m:%Y%m}"
        c.execute(
            f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF query_agg "
            f"FOR VALUES FROM ('{m:%Y-%m-%d}') TO ('{nxt:%Y-%m-%d}')"
        )
        m = nxt


def load_resolver(c) -> TenantResolver:
    rows = c.execute(
        "SELECT n.tenant_id, n.cidr::text AS cidr FROM tenant_networks n "
        "JOIN tenants t ON t.id=n.tenant_id WHERE t.active"
    ).fetchall()
    return TenantResolver([(r["tenant_id"], r["cidr"]) for r in rows], settings().mesh_cidr)


def _auto_tenant(c, ip: str) -> int | None:
    net = auto_network_for(ip, settings().mesh_cidr)
    if net is None:
        return None
    name = f"Rede {net}"
    row = c.execute(
        "INSERT INTO tenants (slug, name, auto_created) VALUES (%s, %s, true) "
        "ON CONFLICT (slug) DO UPDATE SET name=tenants.name RETURNING id",
        (slugify(name), name),
    ).fetchone()
    c.execute(
        "INSERT INTO tenant_networks (tenant_id, cidr, description) VALUES (%s, %s, %s) "
        "ON CONFLICT (cidr) DO NOTHING",
        (row["id"], str(net), "criada automaticamente — renomeie/reatribua no admin"),
    )
    log.warning("IP %s sem tenant: criado tenant automático '%s'", ip, name)
    return row["id"]


def store(c, aggs: dict[tuple, Agg]) -> dict:
    """Grava agregados (mesma transação do cursor)."""
    cfg = settings()
    if not aggs:
        return {"rows": 0}
    # serializa com mudanças no cadastro de empresas (realocação de dados)
    from .registry import lock
    lock(c)
    resolver = load_resolver(c)

    # 1) tenant de cada IP (auto-cria para redes desconhecidas)
    ip_tenant: dict[str, int] = {}
    for ip in {k[0] for k in aggs}:
        tid = resolver.resolve(ip)
        if tid is None:
            tid = _auto_tenant(c, ip)
            resolver = load_resolver(c)
        if tid is not None:
            ip_tenant[ip] = tid

    # 2) nomes -> domínios/FQDNs
    infos = {fq: analyze_name(fq, cfg.internal_suffixes) for fq in {k[1] for k in aggs}}
    now = datetime.now(timezone.utc)
    dom_rows = {}
    for fq, info in infos.items():
        dom_rows.setdefault(info.registrable, info)
    with c.cursor() as cur:
        cur.executemany(
            "INSERT INTO domains (name, kind, tld, features, needs_analysis) VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (name) DO NOTHING",
            [(reg, i.kind, i.tld, Jsonb(domain_features(reg) if i.kind == "public" else {}),
              True) for reg, i in dom_rows.items()],
        )
    dom_id = {r["name"]: r["id"] for r in c.execute(
        "SELECT id, name FROM domains WHERE name = ANY(%s)", (list(dom_rows),)).fetchall()}

    with c.cursor() as cur:
        cur.executemany(
            "INSERT INTO fqdns (name, domain_id, candidates, features) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (name) DO NOTHING",
            [(fq, dom_id[i.registrable], i.candidates,
              Jsonb(name_features(i) if i.kind == "public" else {})) for fq, i in infos.items()],
        )
    fq_id = {r["name"]: r["id"] for r in c.execute(
        "SELECT id, name FROM fqdns WHERE name = ANY(%s)", (list(infos),)).fetchall()}

    # 3) clientes
    firsts: dict[tuple, datetime] = {}
    lasts: dict[tuple, datetime] = {}
    for (ip, _fq, _b), ag in aggs.items():
        if ip not in ip_tenant:
            continue
        k = (ip_tenant[ip], ip)
        firsts[k] = min(firsts.get(k, ag.first), ag.first)
        lasts[k] = max(lasts.get(k, ag.last), ag.last)
    with c.cursor() as cur:
        cur.executemany(
            "INSERT INTO clients (tenant_id, ip, first_seen, last_seen) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (tenant_id, ip) DO UPDATE SET "
            "last_seen=GREATEST(clients.last_seen, EXCLUDED.last_seen)",
            [(t, ip, firsts[(t, ip)], lasts[(t, ip)]) for (t, ip) in firsts],
        )
    cli_id = {(r["tenant_id"], r["ip"]): r["id"] for r in c.execute(
        "SELECT id, tenant_id, host(ip) AS ip FROM clients WHERE (tenant_id, ip) IN "
        "(SELECT * FROM unnest(%s::int[], %s::inet[]))",
        ([t for t, _ in firsts], [ip for _, ip in firsts]),
    ).fetchall()}

    # 4) query_agg (por hora), client_domains e tenant_domains
    buckets = [k[2] for k in aggs]
    ensure_partitions(c, min(buckets), max(buckets))
    qa, cd, td = [], {}, {}
    for (ip, fq, bucket), ag in aggs.items():
        tid = ip_tenant.get(ip)
        if tid is None:
            continue
        cid = cli_id[(tid, ip)]
        did = dom_id[infos[fq].registrable]
        qa.append((tid, cid, did, fq_id[fq], bucket, ag.queries, ag.blocked, ag.nxdomain, ag.first, ag.last))
        k = (tid, cid, did)
        x = cd.get(k)
        cd[k] = [min(x[0], ag.first), max(x[1], ag.last), x[2] + ag.queries, x[3] + ag.blocked,
                 x[4] + ag.nxdomain] if x else [ag.first, ag.last, ag.queries, ag.blocked, ag.nxdomain]
        k2 = (tid, did)
        y = td.get(k2)
        td[k2] = [min(y[0], ag.first), max(y[1], ag.last), y[2] + ag.queries] if y else [ag.first, ag.last, ag.queries]

    with c.cursor() as cur:
        cur.executemany(
            "INSERT INTO query_agg (tenant_id, client_id, domain_id, fqdn_id, bucket, queries, blocked, "
            "nxdomain, first_seen, last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (tenant_id, client_id, fqdn_id, bucket) DO UPDATE SET "
            "queries=query_agg.queries+EXCLUDED.queries, blocked=query_agg.blocked+EXCLUDED.blocked, "
            "nxdomain=query_agg.nxdomain+EXCLUDED.nxdomain, "
            "first_seen=LEAST(query_agg.first_seen, EXCLUDED.first_seen), "
            "last_seen=GREATEST(query_agg.last_seen, EXCLUDED.last_seen)",
            qa,
        )
        cur.executemany(
            "INSERT INTO client_domains (tenant_id, client_id, domain_id, first_seen, last_seen, queries, "
            "blocked, nxdomain) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (tenant_id, client_id, domain_id) DO UPDATE SET "
            "first_seen=LEAST(client_domains.first_seen, EXCLUDED.first_seen), "
            "last_seen=GREATEST(client_domains.last_seen, EXCLUDED.last_seen), "
            "queries=client_domains.queries+EXCLUDED.queries, "
            "blocked=client_domains.blocked+EXCLUDED.blocked, "
            "nxdomain=client_domains.nxdomain+EXCLUDED.nxdomain",
            [(t, cl, d, *v) for (t, cl, d), v in cd.items()],
        )
        cur.executemany(
            "INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, total_queries) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (tenant_id, domain_id) DO UPDATE SET "
            "first_seen=LEAST(tenant_domains.first_seen, EXCLUDED.first_seen), "
            "last_seen=GREATEST(tenant_domains.last_seen, EXCLUDED.last_seen), "
            "total_queries=tenant_domains.total_queries+EXCLUDED.total_queries",
            [(t, d, *v) for (t, d), v in td.items()],
        )
    # contagem de clientes só dos pares tocados
    c.execute(
        "UPDATE tenant_domains td SET clients_count = s.n FROM ("
        " SELECT cd.tenant_id, cd.domain_id, count(*) AS n FROM client_domains cd"
        " JOIN unnest(%s::int[], %s::bigint[]) AS t(tenant_id, domain_id)"
        "   ON t.tenant_id=cd.tenant_id AND t.domain_id=cd.domain_id"
        " GROUP BY cd.tenant_id, cd.domain_id) s "
        "WHERE td.tenant_id=s.tenant_id AND td.domain_id=s.domain_id",
        ([t for t, _ in td], [d for _, d in td]),
    )
    # estatística global do domínio (volume/última ocorrência; usado p/ prioridade)
    dom_tot: dict[int, list] = {}
    for (t, d), v in td.items():
        z = dom_tot.get(d)
        dom_tot[d] = [max(z[0], v[1]), z[1] + v[2]] if z else [v[1], v[2]]
    with c.cursor() as cur:
        cur.executemany(
            "UPDATE domains SET last_seen=GREATEST(last_seen, %s), total_queries=total_queries+%s WHERE id=%s",
            [(v[0], v[1], d) for d, v in dom_tot.items()],
        )
    return {"rows": len(qa), "clients": len(firsts), "domains": len(dom_rows), "fqdns": len(infos),
            "tenants": len(set(ip_tenant.values())), "at": now.isoformat()}


def collect_once(client: TechnitiumClient | None = None) -> dict:
    """Processa UMA janela. Retorna estatísticas (window_end=None se nada a fazer)."""
    cfg = settings()
    client = client or TechnitiumClient()
    cur_s = db.get_state(CURSOR_KEY)
    now = datetime.now(timezone.utc)
    start = parse_ts(cur_s) if cur_s else (now - timedelta(hours=cfg.ingest_backfill_hours)).replace(
        second=0, microsecond=0)
    limit = (now - timedelta(seconds=cfg.ingest_lag)).replace(microsecond=0)
    end = min(start + timedelta(minutes=cfg.ingest_max_window_minutes), limit)
    if end <= start:
        return {"window_end": None}

    entries = list(client.iter_logs(start, end, cfg.ingest_page_size))
    aggs = aggregate(entries, start, end, cfg.exclude_clients)
    with db.conn() as c:
        stats = store(c, aggs)
        c.execute(
            "INSERT INTO ingest_state (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()",
            (CURSOR_KEY, end.isoformat()),
        )
    stats.update({"entries": len(entries), "window_start": start.isoformat(), "window_end": end.isoformat(),
                  "caught_up": end >= limit})
    return stats


def purge_old(c, retention_days: int) -> list[str]:
    """Remove partições mensais inteiramente fora da retenção."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    dropped = []
    rows = c.execute(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid "
        "JOIN pg_class p ON p.oid=i.inhparent WHERE p.relname='query_agg'"
    ).fetchall()
    for r in rows:
        name = r["relname"]
        try:
            m = datetime.strptime(name.rsplit("_", 1)[1], "%Y%m").replace(tzinfo=timezone.utc)
        except (ValueError, IndexError):
            continue
        nxt = (m + timedelta(days=32)).replace(day=1)
        if nxt <= cutoff:
            c.execute(f"DROP TABLE IF EXISTS {name}")
            dropped.append(name)
    return dropped
