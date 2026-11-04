"""(04/11) Coleta de mais de um Technitium (principal + Technitium Cloud): cada um com o seu cursor. PostgreSQL real."""

from datetime import datetime, timedelta, timezone

import pytest

pgserver = pytest.importorskip("pgserver")

PRINCIPAL = "http://principal:5380"
REPLICA = "http://replica:5380"


class FakeClient:
    def __init__(self, entradas):
        self.entradas = entradas
        self.pedidos = []

    def iter_logs(self, start, end, page_size=5000):
        self.pedidos.append((start, end))
        yield from self.entradas


@pytest.fixture(scope="module")
def banco(tmp_path_factory):
    import os

    from dnsanalyzer import config, db
    from dnsanalyzer.migrate import migrate

    srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
    uri = srv.get_uri()
    chaves = ("DATABASE_URL", "DNSANALYZER_ENV", "TECHNITIUM_URL", "TECHNITIUM_TOKEN", "TECHNITIUM_REPLICAS",
              "TECHNITIUM_REPLICA_TOKEN", "INGEST_BACKFILL_HOURS")
    antes = {k: os.environ.get(k) for k in chaves}
    os.environ.update(DATABASE_URL=uri, DNSANALYZER_ENV="/nao-existe", TECHNITIUM_URL=PRINCIPAL,
                      TECHNITIUM_TOKEN="tok-p", TECHNITIUM_REPLICAS=REPLICA, INGEST_BACKFILL_HOURS="1")
    os.environ.pop("TECHNITIUM_REPLICA_TOKEN", None)
    config._settings = None
    db.close()
    migrate(uri)
    with db.conn() as c:
        for slug, cidr in (("emp-p", "10.11.0.0/16"), ("emp-r", "10.70.0.0/16")):
            tid = c.execute("INSERT INTO tenants (slug, name) VALUES (%s, %s) RETURNING id", (slug, slug)).fetchone()["id"]
            c.execute("INSERT INTO tenant_networks (tenant_id, cidr) VALUES (%s, %s)", (tid, cidr))
    yield db
    db.close()
    for k, v in antes.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    config._settings = None
    srv.cleanup()


def _e(ts, ip, q):
    return {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "clientIpAddress": ip, "qname": q,
            "qtype": "A", "responseType": "Recursive", "rcode": "NoError", "answer": "1.2.3.4"}


def test_fontes_principal_primeiro_com_a_chave_antiga(banco):
    from dnsanalyzer.collector import CURSOR_KEY, fontes
    assert fontes() == [(PRINCIPAL, "tok-p", CURSOR_KEY), (REPLICA, "tok-p", f"{CURSOR_KEY}@{REPLICA}")]


def test_cada_technitium_tem_seu_cursor_e_as_consultas_somam(banco):
    from dnsanalyzer import collector

    t = datetime.now(timezone.utc) - timedelta(minutes=30)
    p = FakeClient([_e(t, "10.11.20.5", "www.exemplo.com.br")])
    r = FakeClient([_e(t, "10.70.20.9", "www.exemplo.com.br"), _e(t + timedelta(seconds=1), "10.70.20.9", "outro.com")])

    sp = collector.collect_once(p, collector.CURSOR_KEY)
    sr = collector.collect_once(r, f"{collector.CURSOR_KEY}@{REPLICA}")
    assert sp["entries"] == 1 and sr["entries"] == 2

    with banco.conn() as c:
        cur = collector.cursores(c)
        assert cur[PRINCIPAL] == sp["window_end"] and cur[REPLICA] == sr["window_end"]
        por_emp = {x["slug"]: x["n"] for x in c.execute(
            "SELECT t.slug, sum(q.queries) AS n FROM query_agg q JOIN tenants t ON t.id = q.tenant_id GROUP BY t.slug")}
        assert por_emp == {"emp-p": 1, "emp-r": 2}
        assert c.execute("SELECT count(*) AS n FROM query_log").fetchone()["n"] == 3
        # o mesmo domínio visto nos dois servidores soma no total dele
        assert c.execute("SELECT total_queries FROM domains WHERE name = 'exemplo.com.br'").fetchone()["total_queries"] == 2


def test_coletado_ate_e_o_technitium_mais_atrasado(banco):
    from dnsanalyzer import collector
    atrasado = "2026-11-04T10:00:00+00:00"
    with banco.conn() as c:
        c.execute("UPDATE ingest_state SET value = %s WHERE key = %s", (atrasado, f"{collector.CURSOR_KEY}@{REPLICA}"))
        assert collector.coletado_ate(c) == atrasado
        # réplica que ainda não coletou nada não segura as telas
        c.execute("DELETE FROM ingest_state WHERE key = %s", (f"{collector.CURSOR_KEY}@{REPLICA}",))
        assert collector.coletado_ate(c) == collector.cursores(c)[PRINCIPAL]
