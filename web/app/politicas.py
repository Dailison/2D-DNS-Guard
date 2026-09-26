"""Políticas de bloqueio por empresa: quais LISTAS por categoria valem para cada empresa (e,
quando precisa, para uma unidade), e quais serviços ficam liberados como exceção.

Fonte da verdade: tabela `policies` do analisador. Depois de cada mudança o console sincroniza
o Technitium (um grupo interno "Empresa: …" por política; ver technitium.sincronizar_politicas).
"""

from __future__ import annotations

from flask import current_app

from app import analyzer_client as api
from app import technitium as dnslib


def lista() -> list[dict]:
    return api.get("/policies")


def por_escopo() -> dict[str, dict]:
    return {p["scope"]: p for p in lista()}


def sincronizar() -> dict:
    """Aplica todas as políticas no Technitium (empresas cadastradas; as detectadas nos logs e as
    redes fora do cadastro ficam no default)."""
    from app import empresas as emp
    empresas = [e for e in emp.lista() if not e.get("auto_created")]
    r = dnslib.sincronizar_politicas(empresas, lista())
    current_app.logger.info("políticas -> Technitium: criados %s, apagados %s, %d rede(s)",
                            r["criados"], r["apagados"], r["redes"])
    return r


def resumo_empresas(empresas: list[dict], pol: dict[str, dict]) -> dict[int, dict]:
    """{tenant_id: {"lists", "services", "unidades": {unidade: {"lists","services"}}}} p/ as telas."""
    out = {}
    for e in empresas:
        p = pol.get(f"tenant:{e['id']}") or {}
        un = {}
        for n in e.get("networks") or []:
            u = n.get("unit") or ""
            pu = pol.get(f"unit:{e['id']}:{u}") if u else None
            if pu:
                un[u] = {"lists": pu.get("lists") or [], "services": pu.get("services") or []}
        out[e["id"]] = {"lists": p.get("lists") or [], "services": p.get("services") or [],
                        "definida": bool(p), "unidades": un}
    return out
