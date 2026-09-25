"""Resolução IP -> empresa (tenant) e unidade (rede), por maior prefixo.

Regras (em ordem):
1. Rede cadastrada mais específica que contém o IP (tenant_networks).
2. IP da malha WireGuard (MESH_CIDR, ex.: 10.100.100.N) = roteador do site N
   (quando o site faz NAT, as consultas chegam com esse IP): vai para a empresa
   dona de 10.N.0.0/16. Se o site não estiver cadastrado, NÃO cai na rede ampla
   (10.100.0.0/16 = 2D): vira a rede automática do site (10.N.0.0/16).
3. Sem correspondência: cria (uma vez) a empresa "Rede 10.X.0.0/16" (ou /24 para
   outras faixas) — dados de redes desconhecidas nunca caem noutra empresa.
   O operador renomeia ou mescla no cadastro de Empresas.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
import unicodedata

log = logging.getLogger(__name__)


class TenantResolver:
    def __init__(self, networks: list[tuple[int, str]], mesh_cidr=None):
        self._lock = threading.Lock()
        self.mesh_cidr = mesh_cidr
        self._nets: list[tuple[ipaddress._BaseNetwork, int]] = []
        self.load(networks)

    def load(self, networks: list[tuple[int, str]]) -> None:
        nets = []
        for tenant_id, cidr in networks:
            try:
                nets.append((ipaddress.ip_network(str(cidr), strict=False), tenant_id))
            except ValueError:
                log.warning("rede inválida ignorada: %s", cidr)
        nets.sort(key=lambda x: x[0].prefixlen, reverse=True)  # mais específica primeiro
        with self._lock:
            self._nets = nets

    def is_mesh(self, addr) -> bool:
        return self.mesh_cidr is not None and addr.version == self.mesh_cidr.version and addr in self.mesh_cidr

    def resolve_net(self, ip: str):
        """(tenant_id, rede_casada) ou (None, None)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None, None
        with self._lock:
            nets = self._nets
        for net, tid in nets:
            if addr.version == net.version and addr in net:
                if self.is_mesh(addr) and net.prefixlen < 24:
                    # IP de malha só casou com rede ampla (ex.: 10.100/16): é o roteador de um site
                    return self._mesh_site(addr, nets)
                return tid, net
        if self.is_mesh(addr):
            return self._mesh_site(addr, nets)
        return None, None

    def resolve(self, ip: str) -> int | None:
        return self.resolve_net(ip)[0]

    @staticmethod
    def site_net(addr) -> ipaddress.IPv4Network | None:
        """10.100.100.N -> 10.N.0.0/16."""
        if addr.version != 4:
            return None
        octet = int(str(addr).split(".")[-1])
        if not 0 < octet < 255:
            return None
        return ipaddress.ip_network(f"10.{octet}.0.0/16")

    @classmethod
    def _mesh_site(cls, addr, nets):
        site = cls.site_net(addr)
        if site is None:
            return None, None
        for net, tid in nets:
            if net == site:
                return tid, net
        for net, tid in nets:  # ex.: só 10.N.20.0/24 cadastrada
            if net.version == 4 and net.prefixlen >= 16 and net.subnet_of(site):
                return tid, net
        return None, None


def auto_network_for(ip: str, mesh_cidr=None) -> ipaddress._BaseNetwork | None:
    """Rede sugerida para a empresa automática de um IP não mapeado."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if mesh_cidr is not None and addr.version == mesh_cidr.version and addr in mesh_cidr:
        return TenantResolver.site_net(addr)
    if addr.version == 4:
        if addr in ipaddress.ip_network("10.0.0.0/8"):
            return ipaddress.ip_network(f"{addr}/16", strict=False)
        return ipaddress.ip_network(f"{addr}/24", strict=False)
    return ipaddress.ip_network(f"{addr}/64", strict=False)


def slugify(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()  # Madá -> Mada
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "tenant"
