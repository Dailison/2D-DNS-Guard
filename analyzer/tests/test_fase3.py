"""Plano de confiabilidade, fase 3: prévia de impacto, exceções do console e alertas de bloqueio
suspeito. PostgreSQL real (pgserver) com consultas sintéticas em query_agg."""

from datetime import datetime, timedelta, timezone

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-f3"
H = {"Authorization": f"Bearer {TOKEN}"}
AGORA = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    import os

    from dnsanalyzer import config, db
    from dnsanalyzer.collector import ensure_partitions
    from dnsanalyzer.migrate import migrate

    srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
    uri = srv.get_uri()
    antes = {k: os.environ.get(k) for k in ("DATABASE_URL", "API_TOKEN", "DNSANALYZER_ENV")}
    os.environ.update(DATABASE_URL=uri, API_TOKEN=TOKEN, DNSANALYZER_ENV="/nao-existe")
    config._settings = None
    db.close()
    migrate(uri)
    with db.conn() as c:
        ensure_partitions(c, AGORA - timedelta(days=2), AGORA)
        _dados(c)
    from fastapi.testclient import TestClient

    from dnsanalyzer.api import app
    yield TestClient(app)
    db.close()
    for k, v in antes.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    config._settings = None
    srv.cleanup()


def _dados(c):
    """Empresa A (10 PCs): roblox (jogos, 6 PCs bloqueados = pico, posto pela IA), erp.com.br (TRABALHO,
    bloqueado em 2 PCs via lista da IA), youtube (streaming posto por pessoa: intencional, 8 PCs)."""
    t = {s: c.execute("INSERT INTO tenants (slug, name) VALUES (%s, %s) RETURNING id", (s, f"Empresa {s.upper()}")).fetchone()["id"]
         for s in ("a", "b")}
    pcs = [c.execute("INSERT INTO clients (tenant_id, ip, first_seen, last_seen) VALUES (%s, %s, %s, %s) RETURNING id",
                     (t["a"], f"10.1.0.{i}", AGORA, AGORA)).fetchone()["id"] for i in range(10)]
    pb = c.execute("INSERT INTO clients (tenant_id, ip, first_seen, last_seen) VALUES (%s, '10.2.0.1', %s, %s) RETURNING id",
                   (t["b"], AGORA, AGORA)).fetchone()["id"]
    dom = {}
    for n, cls, cat in (("roblox.com", "NAO_TRABALHO", "jogos"), ("erp.com.br", "TRABALHO", "produtividade"),
                        ("youtube.com", "NAO_TRABALHO", "streaming"), ("loja.com", "NAO_TRABALHO", "compras")):
        dom[n] = c.execute("INSERT INTO domains (name, classification, category) VALUES (%s, %s, %s) RETURNING id",
                           (n, cls, cat)).fetchone()["id"]
        c.execute("INSERT INTO fqdns (name, domain_id) VALUES (%s, %s)", ("www." + n, dom[n]))
    fq = {r["name"]: r["id"] for r in c.execute("SELECT id, name FROM fqdns")}

    def q(tid, cl, n, queries, blocked, bucket=AGORA):
        c.execute("INSERT INTO query_agg (tenant_id, client_id, domain_id, fqdn_id, bucket, queries, blocked, nxdomain, "
                  "first_seen, last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,0,%s,%s)",
                  (tid, cl, dom[n], fq["www." + n], bucket, queries, blocked, bucket, bucket))
        c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen) VALUES (%s,%s,%s,%s) "
                  "ON CONFLICT DO NOTHING", (tid, dom[n], bucket, bucket))
    for cl in pcs[:6]:
        q(t["a"], cl, "roblox.com", 10, 10)
    for cl in pcs[:2]:
        q(t["a"], cl, "erp.com.br", 5, 5)
    for cl in pcs[:8]:
        q(t["a"], cl, "youtube.com", 20, 20)
    for cl in pcs:
        q(t["a"], cl, "loja.com", 3, 0, AGORA - timedelta(days=1))
    q(t["b"], pb, "loja.com", 7, 0)
    c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'roblox.com', 'IA automática (jogos)'), "
              "('outros_bloqueios', 'erp.com.br', 'bloqueio automático (x)'), ('streaming', 'youtube.com', 'op@2d'), "
              "('compras', 'loja.com', 'op@2d')")


def test_previa_de_impacto(api):
    tid = next(t["id"] for t in api.get("/tenants", headers=H).json() if t["name"] == "Empresa A")
    j = api.get("/policies/impacto", headers=H, params={"tid": tid, "lists": "compras,jogos,xx"}).json()
    assert set(j) == {"compras", "jogos"}
    assert j["compras"]["computadores"] == 10 and j["compras"]["consultas"] == 30 and j["compras"]["top"][0]["domain"] == "loja.com"
    assert j["jogos"] == {"computadores": 6, "consultas": 60, "top": [{"domain": "roblox.com", "consultas": 60}]}
    todas = api.get("/policies/impacto", headers=H, params={"tid": 0, "lists": "compras"}).json()
    assert todas["compras"]["computadores"] == 11 and todas["compras"]["consultas"] == 37
    assert api.get("/policies/impacto", headers=H, params={"lists": "compras"}).status_code == 422
    d = api.post("/domains/impacto", headers=H, json={"domains": ["loja.com", "nada.com"]}).json()
    assert d == {"empresas": ["Empresa A", "Empresa B"], "computadores": 11, "consultas": 37}


def test_excecoes_do_console(api):
    assert api.post("/console/excecoes", headers=H, json={"excecoes": {"a.com": ["Empresa: X", "default"], "b.com": ["Empresa: Y"]},
                                                          "por": "op"}).json()["ok"]
    j = api.get("/console/excecoes", headers=H, params={"domains": ["a.com"]}).json()
    assert list(j) == ["a.com"] and sorted(j["a.com"]) == ["Empresa: X", "default"]
    assert api.post("/console/excecoes/remover", headers=H, json={"domains": ["a.com"]}).json()["removidos"] == 2
    assert api.get("/console/excecoes", headers=H).json() == {"b.com": ["Empresa: Y"]}


def test_alertas_de_bloqueio(api):
    from dnsanalyzer import behavior, db
    r = behavior.run(AGORA - timedelta(minutes=30))
    with db.conn() as c:
        al = {(a["kind"], a["dominio"]): a for a in c.execute(
            "SELECT a.kind, a.title, a.details, d.name AS dominio FROM alerts a LEFT JOIN domains d ON d.id = a.domain_id")}
    assert ("blocked_work", "erp.com.br") in al and "Site de trabalho bloqueado: erp.com.br (2 computador(es))" == al[("blocked_work", "erp.com.br")]["title"]
    assert ("block_spike", "roblox.com") in al and al[("block_spike", "roblox.com")]["details"]["ativos"] == 8
    assert ("block_spike", "youtube.com") not in al, "posto por pessoa: bloqueio intencional"
    assert ("blocked_work", "roblox.com") not in al and ("block_spike", "erp.com.br") not in al
    assert r["blocked_work"] == 1 and r["block_spike"] == 1
    assert behavior.run(AGORA - timedelta(minutes=30))["block_spike"] == 0, "dedup por dia"


def test_texto_do_aviso(api):
    from dnsanalyzer import webhook
    a = {"id": 1, "severity": "high", "kind": "blocked_work", "tenant_name": "Empresa A", "tenant_id": 1, "title": "Site de trabalho bloqueado: erp.com.br (2 computador(es))",
         "domain": "erp.com.br", "details": {"computadores": 2, "ips": ["10.1.0.1"]}, "created_at": AGORA}
    assert "Se for engano" in webhook._payload(a)["text"]
