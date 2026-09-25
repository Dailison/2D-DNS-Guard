"""Cadastro de empresas (tenants) -> unidades (redes/CIDR) e realocação de dados.

Quando um CIDR muda de empresa (importação, edição, mescla), os dados já
coletados dos IPs daquela rede são MOVIDOS para a empresa certa — o histórico
acompanha o cadastro. Tudo sob um advisory lock compartilhado com o coletor,
para a coleta nunca gravar no meio de uma realocação.
"""

from __future__ import annotations

import ipaddress
import logging

from .config import settings
from .tenants import TenantResolver, slugify

log = logging.getLogger(__name__)
LOCK_KEY = 424242


def lock(c) -> None:
    c.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))


def _resolver(c) -> TenantResolver:
    rows = c.execute("SELECT n.tenant_id, n.cidr::text AS cidr FROM tenant_networks n "
                     "JOIN tenants t ON t.id=n.tenant_id WHERE t.active").fetchall()
    return TenantResolver([(r["tenant_id"], r["cidr"]) for r in rows], settings().mesh_cidr)


def normalize_cidr(s: str) -> str:
    return str(ipaddress.ip_network(s.strip(), strict=False))


def _salvar_decisoes(c, where: str, params: tuple) -> None:
    """Antes de apagar linhas empresa×domínio (CIDR mudou, mescla), a decisão vira decisão
    do site — senão o site voltava para a fila na empresa nova."""
    c.execute(
        "INSERT INTO global_reviews (domain_id, status, reviewed_by, reviewed_at) "
        "SELECT DISTINCT ON (td.domain_id) td.domain_id, td.review_status, td.reviewed_by, td.reviewed_at "
        f"FROM tenant_domains td WHERE td.review_status IS NOT NULL AND {where} "
        "ORDER BY td.domain_id, td.reviewed_at DESC ON CONFLICT (domain_id) DO NOTHING", params)


def recompute_tenant_domains(c, tenant_ids: set[int]) -> None:
    """Recalcula tenant_domains a partir de client_domains (preserva overrides)."""
    if not tenant_ids:
        return
    ids = list(tenant_ids)
    c.execute(
        "INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, total_queries, clients_count) "
        "SELECT tenant_id, domain_id, min(first_seen), max(last_seen), sum(queries), count(*) "
        "FROM client_domains WHERE tenant_id = ANY(%s) GROUP BY tenant_id, domain_id "
        "ON CONFLICT (tenant_id, domain_id) DO UPDATE SET first_seen=EXCLUDED.first_seen, "
        "last_seen=EXCLUDED.last_seen, total_queries=EXCLUDED.total_queries, clients_count=EXCLUDED.clients_count",
        (ids,))
    _salvar_decisoes(c, "td.tenant_id = ANY(%s) AND td.override_classification IS NULL AND NOT EXISTS "
                     "(SELECT 1 FROM client_domains cd WHERE cd.tenant_id=td.tenant_id AND cd.domain_id=td.domain_id)", (ids,))
    c.execute(
        "DELETE FROM tenant_domains td WHERE td.tenant_id = ANY(%s) AND td.override_classification IS NULL "
        "AND NOT EXISTS (SELECT 1 FROM client_domains cd WHERE cd.tenant_id=td.tenant_id AND cd.domain_id=td.domain_id)",
        (ids,))


def _move_client(c, cl: dict, target: int) -> None:
    other = c.execute("SELECT id FROM clients WHERE tenant_id=%s AND ip=%s::inet",
                      (target, cl["ip"])).fetchone()
    if other is None:
        # caso comum: o computador ainda não existe na empresa de destino
        c.execute("UPDATE clients SET tenant_id=%s WHERE id=%s", (target, cl["id"]))
        c.execute("UPDATE query_agg SET tenant_id=%s WHERE client_id=%s", (target, cl["id"]))
        c.execute("UPDATE client_domains SET tenant_id=%s WHERE client_id=%s", (target, cl["id"]))
        c.execute("UPDATE alerts SET tenant_id=%s WHERE client_id=%s", (target, cl["id"]))
        return
    # já existe no destino: funde os agregados e remove o registro antigo
    oid = other["id"]
    c.execute(
        "INSERT INTO query_agg (tenant_id, client_id, domain_id, fqdn_id, bucket, queries, blocked, nxdomain, "
        " first_seen, last_seen) SELECT %s, %s, domain_id, fqdn_id, bucket, queries, blocked, nxdomain, first_seen, "
        " last_seen FROM query_agg WHERE client_id=%s "
        "ON CONFLICT (tenant_id, client_id, fqdn_id, bucket) DO UPDATE SET "
        " queries=query_agg.queries+EXCLUDED.queries, blocked=query_agg.blocked+EXCLUDED.blocked, "
        " nxdomain=query_agg.nxdomain+EXCLUDED.nxdomain, first_seen=LEAST(query_agg.first_seen, EXCLUDED.first_seen), "
        " last_seen=GREATEST(query_agg.last_seen, EXCLUDED.last_seen)", (target, oid, cl["id"]))
    c.execute("DELETE FROM query_agg WHERE client_id=%s", (cl["id"],))
    c.execute(
        "INSERT INTO client_domains (tenant_id, client_id, domain_id, first_seen, last_seen, queries, blocked, nxdomain) "
        "SELECT %s, %s, domain_id, first_seen, last_seen, queries, blocked, nxdomain FROM client_domains "
        "WHERE client_id=%s ON CONFLICT (tenant_id, client_id, domain_id) DO UPDATE SET "
        " first_seen=LEAST(client_domains.first_seen, EXCLUDED.first_seen), "
        " last_seen=GREATEST(client_domains.last_seen, EXCLUDED.last_seen), "
        " queries=client_domains.queries+EXCLUDED.queries, blocked=client_domains.blocked+EXCLUDED.blocked, "
        " nxdomain=client_domains.nxdomain+EXCLUDED.nxdomain", (target, oid, cl["id"]))
    c.execute("DELETE FROM client_domains WHERE client_id=%s", (cl["id"],))
    c.execute("DELETE FROM alerts WHERE client_id=%s", (cl["id"],))   # serão regerados se ainda valerem
    c.execute("UPDATE clients SET first_seen=LEAST(first_seen, %s), last_seen=GREATEST(last_seen, %s) WHERE id=%s",
              (cl["first_seen"], cl["last_seen"], oid))
    c.execute("DELETE FROM clients WHERE id=%s", (cl["id"],))


def reassign_clients(c) -> dict:
    """Move cada computador (e seus dados) para a empresa que o cadastro indica hoje."""
    from .collector import _auto_tenant
    resolver = _resolver(c)
    affected: set[int] = set()
    moved = 0
    for cl in c.execute("SELECT id, tenant_id, host(ip) AS ip, first_seen, last_seen FROM clients").fetchall():
        target = resolver.resolve(cl["ip"])
        if target is None:
            target = _auto_tenant(c, cl["ip"])
            resolver = _resolver(c)
        if target is None or target == cl["tenant_id"]:
            continue
        _move_client(c, cl, target)
        affected.update({cl["tenant_id"], target})
        moved += 1
    recompute_tenant_domains(c, affected)
    return {"moved_clients": moved, "tenants_affected": len(affected)}


def cleanup_empty_tenants(c, only_auto: bool = True) -> list[str]:
    """Remove empresas sem redes e sem computadores (por padrão, só as automáticas)."""
    rows = c.execute(
        "DELETE FROM tenants t WHERE (%s = false OR t.auto_created) "
        "AND NOT EXISTS (SELECT 1 FROM tenant_networks n WHERE n.tenant_id=t.id) "
        "AND NOT EXISTS (SELECT 1 FROM clients cl WHERE cl.tenant_id=t.id) RETURNING name", (only_auto,)).fetchall()
    return [r["name"] for r in rows]


def get_or_create_tenant(c, name: str) -> int:
    name = name.strip()
    row = c.execute(
        "INSERT INTO tenants (slug, name, auto_created) VALUES (%s, %s, false) "
        "ON CONFLICT (slug) DO UPDATE SET name=EXCLUDED.name, auto_created=false RETURNING id",
        (slugify(name), name)).fetchone()
    return row["id"]


def import_rows(c, rows: list[dict], replace: bool = False) -> dict:
    """Importa o cadastro: rows = [{"empresa", "unidade", "cidr"}].

    Cada CIDR passa a pertencer à empresa indicada (move se era de outra).
    replace=True: redes de empresas NÃO automáticas que não estão na lista são
    removidas (os IPs delas vão para empresas automáticas "Rede ...")."""
    lock(c)
    seen: set[str] = set()
    created, updated = 0, 0
    for r in rows:
        empresa = (r.get("empresa") or "").strip()
        cidr = normalize_cidr(r["cidr"])
        if not empresa:
            raise ValueError(f"linha sem empresa: {r}")
        if cidr in seen:
            raise ValueError(f"CIDR repetido na importação: {cidr}")
        seen.add(cidr)
        tid = get_or_create_tenant(c, empresa)
        prev = c.execute("SELECT id FROM tenant_networks WHERE cidr=%s", (cidr,)).fetchone()
        c.execute(
            "INSERT INTO tenant_networks (tenant_id, cidr, unit) VALUES (%s, %s, %s) "
            "ON CONFLICT (cidr) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, unit=EXCLUDED.unit",
            (tid, cidr, (r.get("unidade") or "").strip()))
        if prev:
            updated += 1
        else:
            created += 1
    removed = []
    if replace:
        removed = [r["cidr"] for r in c.execute(
            "DELETE FROM tenant_networks n USING tenants t WHERE t.id=n.tenant_id AND NOT t.auto_created "
            "AND NOT (n.cidr::text = ANY(%s)) RETURNING n.cidr::text AS cidr", (list(seen),)).fetchall()]
    moved = reassign_clients(c)
    gone = cleanup_empty_tenants(c, only_auto=not replace)
    gone += cleanup_empty_tenants(c, only_auto=True)
    return {"networks_created": created, "networks_updated": updated, "networks_removed": removed,
            **moved, "tenants_removed": sorted(set(gone))}


def merge_tenant(c, source: int, into: int) -> dict:
    """Mescla a empresa `source` em `into` (redes + dados) e remove a origem."""
    if source == into:
        raise ValueError("origem e destino iguais")
    lock(c)
    c.execute("UPDATE tenant_networks SET tenant_id=%s WHERE tenant_id=%s", (into, source))
    c.execute("UPDATE tenants SET auto_created=true WHERE id=%s", (source,))   # vira descartável
    moved = reassign_clients(c)
    # sobras sem rede (ex.: overrides) saem junto com a empresa de origem
    _salvar_decisoes(c, "td.tenant_id = %s", (source,))
    c.execute("DELETE FROM tenant_domains WHERE tenant_id=%s", (source,))
    c.execute("UPDATE alerts SET tenant_id=%s WHERE tenant_id=%s AND client_id IS NULL "
              "AND NOT EXISTS (SELECT 1 FROM alerts a2 WHERE a2.tenant_id=%s AND a2.dedup_key=alerts.dedup_key)",
              (into, source, into))
    gone = cleanup_empty_tenants(c, only_auto=True)
    return {**moved, "tenants_removed": gone}


def resolve_ips(c, ips: list[str]) -> dict[str, dict]:
    """IP -> {tenant_id, empresa, unidade, cidr} pelo cadastro atual."""
    resolver = _resolver(c)
    tenants = {r["id"]: r["name"] for r in c.execute("SELECT id, name FROM tenants")}
    units = {r["cidr"]: r["unit"] for r in c.execute("SELECT cidr::text AS cidr, unit FROM tenant_networks")}
    out = {}
    for ip in dict.fromkeys(ips):
        tid, net = resolver.resolve_net(ip)
        if tid is None:
            continue
        out[ip] = {"tenant_id": tid, "empresa": tenants.get(tid, "?"),
                   "unidade": units.get(str(net), "") if net else "", "cidr": str(net) if net else None}
    return out
