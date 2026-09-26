"""Logs DNS com a classificação da IA (/logs/grouped e /logs/classificar), num PostgreSQL
real (pgserver) com as migrações do analisador. Sem pgserver instalado, os testes são pulados."""

from datetime import datetime, timedelta, timezone

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-logs"
H = {"Authorization": f"Bearer {TOKEN}"}
AGORA = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)


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
        ensure_partitions(c, AGORA, AGORA)
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
    """2 empresas; 'ruim.com' é MALICIOSO pela IA; 'loja.com' é NAO_TRABALHO mas a empresa A
    ajustou para TRABALHO; 'novo.com' ainda sem classificação."""
    t = {}
    for slug in ("a", "b"):
        t[slug] = c.execute("INSERT INTO tenants (slug, name) VALUES (%s, %s) RETURNING id",
                            (slug, f"Empresa {slug.upper()}")).fetchone()["id"]
    cl = {}
    for slug, ip, label in (("a", "10.1.0.5", None), ("a", "10.1.0.6", "PC-FIN"), ("b", "10.2.0.9", None)):
        cl[ip] = c.execute("INSERT INTO clients (tenant_id, ip, label, first_seen, last_seen) "
                           "VALUES (%s, %s, %s, %s, %s) RETURNING id", (t[slug], ip, label, AGORA, AGORA)).fetchone()["id"]
    c.execute("INSERT INTO liberado_meta (ip, usuario) VALUES ('10.1.0.5/32', 'Notebook Joana')")
    d = {}
    for name, cls, cat, risco in (("ruim.com", "MALICIOSO", "ameaca", 95), ("loja.com", "NAO_TRABALHO", "compras", 10),
                                  ("novo.com", None, None, None)):
        d[name] = c.execute("INSERT INTO domains (name, tld, classification, category, risk_score, topic) "
                            "VALUES (%s, 'com', %s, %s, %s, %s) RETURNING id",
                            (name, cls, cat, risco, f"assunto {name}")).fetchone()["id"]
    f = {}
    for fq, dom in (("x.ruim.com", "ruim.com"), ("www.loja.com", "loja.com"), ("novo.com", "novo.com")):
        f[fq] = c.execute("INSERT INTO fqdns (name, domain_id) VALUES (%s, %s) RETURNING id", (fq, d[dom])).fetchone()["id"]
    linhas = [("a", "10.1.0.5", "x.ruim.com", 3, 3), ("b", "10.2.0.9", "x.ruim.com", 2, 0),
              ("a", "10.1.0.6", "www.loja.com", 5, 0), ("b", "10.2.0.9", "www.loja.com", 4, 0),
              ("a", "10.1.0.5", "novo.com", 1, 0)]
    for slug, ip, fq, n, blk in linhas:
        dom = next(k for k in d if fq.endswith(k))
        c.execute("INSERT INTO query_agg (tenant_id, client_id, domain_id, fqdn_id, bucket, queries, blocked, "
                  "nxdomain, first_seen, last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,0,%s,%s)",
                  (t[slug], cl[ip], d[dom], f[fq], AGORA, n, blk, AGORA, AGORA + timedelta(minutes=5)))
        c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, total_queries, clients_count) "
                  "VALUES (%s,%s,%s,%s,%s,1) ON CONFLICT DO NOTHING", (t[slug], d[dom], AGORA, AGORA, n))
    c.execute("UPDATE tenant_domains SET override_classification='TRABALHO' WHERE tenant_id=%s AND domain_id=%s",
              (t["a"], d["loja.com"]))


def _grouped(api, **kw):
    p = {"start": (AGORA - timedelta(hours=1)).isoformat(), "end": (AGORA + timedelta(hours=2)).isoformat(), **kw}
    r = api.get("/logs/grouped", params=p, headers=H)
    assert r.status_code == 200, r.text
    return r.json()["rows"]


def test_grouped_traz_classificacao_efetiva_e_a_pior_entre_empresas(api):
    rows = {r["dominio"]: r for r in _grouped(api)}
    assert rows["x.ruim.com"]["classificacao"] == "MALICIOSO"
    assert rows["x.ruim.com"]["categoria"] == "ameaca" and rows["x.ruim.com"]["risco"] == 95
    # A ajustou p/ TRABALHO, B segue NAO_TRABALHO: juntando as duas, vale a pior
    assert rows["www.loja.com"]["classificacao"] == "NAO_TRABALHO"
    assert rows["www.loja.com"]["ajustada"] is True
    assert rows["novo.com"]["classificacao"] is None
    assert rows["www.loja.com"]["n"] == 9


def test_grouped_por_empresa_respeita_o_ajuste(api):
    tid = api.get("/tenants", headers=H).json()
    a = next(t["id"] for t in tid if t["name"] == "Empresa A")
    rows = {r["dominio"]: r for r in _grouped(api, tid=a)}
    assert rows["www.loja.com"]["classificacao"] == "TRABALHO"


def test_filtros_cls_pendente_e_categoria(api):
    assert [r["dominio"] for r in _grouped(api, cls=["MALICIOSO", "SUSPEITO"])] == ["x.ruim.com"]
    assert [r["dominio"] for r in _grouped(api, cls=["PENDENTE"])] == ["novo.com"]
    assert {r["dominio"] for r in _grouped(api, cls=["PENDENTE", "MALICIOSO"])} == {"novo.com", "x.ruim.com"}
    assert [r["dominio"] for r in _grouped(api, categoria="compras")] == ["www.loja.com"]
    # o filtro vale por empresa: só a linha da B (sem ajuste) é NAO_TRABALHO
    rows = _grouped(api, cls=["NAO_TRABALHO"], por_cliente="true")
    assert [(r["dominio"], r["empresa"]) for r in rows] == [("www.loja.com", "Empresa B")]


def test_por_cliente_quem_acessou_o_malicioso(api):
    rows = _grouped(api, cls=["MALICIOSO"], por_cliente="true")
    got = sorted((r["ip"], r["computador"], r["empresa"], r["n"], r["bloqueadas"]) for r in rows)
    assert got == [("10.1.0.5", "Notebook Joana", "Empresa A", 3, 3), ("10.2.0.9", None, "Empresa B", 2, 0)]
    pc = _grouped(api, dominio="loja", por_cliente="true")
    assert {r["computador"] for r in pc} == {"PC-FIN", None}


def test_classificar_herda_do_pai_e_traz_ajustes(api):
    r = api.post("/logs/classificar", json={"nomes": ["a.b.ruim.com", "www.loja.com.", "nunca-visto.org", "novo.com"]},
                 headers=H)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["a.b.ruim.com"]["classificacao"] == "MALICIOSO" and j["a.b.ruim.com"]["dominio"] == "ruim.com"
    assert j["www.loja.com"]["classificacao"] == "NAO_TRABALHO"
    assert list(j["www.loja.com"]["ajustes"].values()) == ["TRABALHO"]
    assert j["nunca-visto.org"] is None
    assert j["novo.com"]["classificacao"] is None


def test_classificar_exige_token(api):
    assert api.post("/logs/classificar", json={"nomes": ["x.com"]}).status_code == 401
