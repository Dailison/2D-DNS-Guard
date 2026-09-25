"""Cadastro de empresas (fonte: analisador de DNS) — resolução IP/CIDR -> "Empresa · Unidade".

Usado por Logs DNS e Bloqueios para identificar a empresa mesmo quando várias
compartilham o mesmo grupo de bloqueio do Technitium. Se o analisador estiver
fora do ar, as telas seguem funcionando (só sem os nomes).
"""

from __future__ import annotations

import ipaddress

from flask import current_app, g

from app import analyzer_client as api
from app.analyzer_client import AnalyzerError


def habilitado() -> bool:
    return bool(current_app.config.get("ANALYZER_ENABLED"))


def lista() -> list[dict]:
    """Empresas cadastradas (cache por requisição)."""
    if not habilitado():
        return []
    if "_empresas" not in g:
        try:
            g._empresas = api.get("/tenants")
        except AnalyzerError:
            g._empresas = []
    return g._empresas


def rotulo(info: dict | None) -> str:
    if not info:
        return ""
    return info["empresa"] + (f" · {info['unidade']}" if info.get("unidade") else "")


def resolver(ips) -> dict[str, dict]:
    """IP (ou endereço de rede) -> {empresa, unidade, cidr, tenant_id}."""
    ips = [str(x) for x in dict.fromkeys(ips) if x]
    if not ips or not habilitado():
        return {}
    try:
        return api.post("/resolve", {"ips": ips})
    except AnalyzerError:
        return {}


def rotulos_de_redes(cidrs) -> dict[str, str]:
    """CIDR -> rótulo da empresa dona (pelo endereço de rede)."""
    base = {}
    for c in cidrs:
        try:
            base[c] = str(ipaddress.ip_network(c, strict=False).network_address)
        except ValueError:
            continue
    info = resolver(base.values())
    return {c: rotulo(info.get(a)) for c, a in base.items() if info.get(a)}


def redes_da_empresa(tid: int) -> list:
    """Redes da empresa + IPs dos roteadores dos sites na malha (10.100.100.N p/ 10.N.0.0/16)."""
    emp = next((e for e in lista() if e["id"] == tid), None)
    if not emp:
        return []
    out = []
    for n in emp.get("networks", []):
        try:
            net = ipaddress.ip_network(n["cidr"], strict=False)
        except ValueError:
            continue
        out.append(net)
        if net.version == 4 and net.prefixlen == 16 and str(net).startswith("10."):
            octet = int(str(net.network_address).split(".")[1])
            if octet != 100:
                out.append(ipaddress.ip_network(f"10.100.100.{octet}/32"))
    return out
