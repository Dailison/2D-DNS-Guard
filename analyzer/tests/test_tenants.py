import ipaddress

from dnsanalyzer.tenants import TenantResolver, auto_network_for, slugify

NETS = [
    (1, "10.100.0.0/16"),      # 2D
    (2, "10.70.0.0/16"),       # G&D
    (2, "10.100.100.70/32"),   # roteador da G&D na malha (explícito)
    (3, "10.34.0.0/16"),       # Economize Ice Beer (sem /32 cadastrado)
    (4, "10.28.20.0/24"),      # só uma sub-rede cadastrada
]
MESH = ipaddress.ip_network("10.100.100.0/24")


def test_longest_prefix():
    r = TenantResolver(NETS, MESH)
    assert r.resolve("10.70.20.9") == 2
    assert r.resolve("10.100.10.25") == 1
    assert r.resolve("10.100.100.70") == 2       # /32 explícito vence o /16


def test_resolve_net_returns_matched_network():
    r = TenantResolver(NETS, MESH)
    tid, net = r.resolve_net("10.28.20.5")
    assert tid == 4 and str(net) == "10.28.20.0/24"


def test_mesh_convention():
    r = TenantResolver(NETS, MESH)
    # 10.100.100.34 = roteador do site 10.34 -> Economize Ice Beer (não a 2D)
    assert r.resolve("10.100.100.34") == 3
    # site só com sub-rede cadastrada
    assert r.resolve("10.100.100.28") == 4
    # site NÃO cadastrado na malha: não cai na 2D (10.100/16) — fica sem dono
    assert r.resolve("10.100.100.99") is None


def test_auto_network_for_mesh_is_site_network():
    assert str(auto_network_for("10.100.100.38", MESH)) == "10.38.0.0/16"
    assert str(auto_network_for("10.57.3.4", MESH)) == "10.57.0.0/16"
    assert str(auto_network_for("192.168.11.20")) == "192.168.11.0/24"


def test_unmapped():
    r = TenantResolver(NETS, MESH)
    assert r.resolve("10.57.1.1") is None
    assert r.resolve("not-an-ip") is None


def test_slugify():
    assert slugify("G&D") == "g-d"
    assert slugify("Madá") == "mada"
    assert slugify("Moral Auto Peças") == "moral-auto-pecas"
    assert slugify("Rede 10.57.0.0/16") == "rede-10-57-0-0-16"
