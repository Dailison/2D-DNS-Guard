"""Computadores em varredura (06/11/2026, pedido do usuário): acima de 50 domínios inéditos por hora o computador
fica travado para avaliação, sai um alerta e os domínios que só ele acessou não entram em nenhuma fila da IA."""
import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-varredura"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    import os

    from dnsanalyzer import config, db
    from dnsanalyzer.migrate import migrate

    srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
    uri = srv.get_uri()
    antes = {k: os.environ.get(k) for k in ("DATABASE_URL", "API_TOKEN", "DNSANALYZER_ENV")}
    os.environ.update(DATABASE_URL=uri, API_TOKEN=TOKEN, DNSANALYZER_ENV="/nao-existe")
    config._settings = None
    db.close()
    migrate(uri)
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


def _cenario(c):
    from dnsanalyzer import collector
    from datetime import datetime, timedelta, timezone
    agora = datetime.now(timezone.utc)
    collector.ensure_log_partitions(c, agora - timedelta(days=1), agora + timedelta(days=1))
    tid = c.execute("INSERT INTO tenants (slug, name) VALUES ('cotrel', 'Cotrel') RETURNING id").fetchone()["id"]
    robo = c.execute("INSERT INTO clients (tenant_id, ip, first_seen, last_seen) VALUES (%s, '192.168.21.165', now(), now()) "
                     "RETURNING id", (tid,)).fetchone()["id"]
    comum = c.execute("INSERT INTO clients (tenant_id, ip, first_seen, last_seen) VALUES (%s, '192.168.21.10', now(), now()) "
                      "RETURNING id", (tid,)).fetchone()["id"]
    ids = []
    for i in range(60):   # 60 domínios inéditos em minutos: acima do limite (50)
        did = c.execute("INSERT INTO domains (name, kind, needs_analysis, llm_pending, first_seen) "
                        "VALUES (%s, 'public', true, true, now() - interval '20 minutes') RETURNING id", (f"site{i}.example",)).fetchone()["id"]
        ids.append(did)
        c.execute("INSERT INTO query_log (ts, tenant_id, client_ip, domain_id, qname) VALUES "
                  "(now() - interval '20 minutes', %s, '192.168.21.165', %s, %s)", (tid, did, f"site{i}.example"))
        c.execute("INSERT INTO client_domains (tenant_id, client_id, domain_id, first_seen, last_seen, queries) "
                  "VALUES (%s, %s, %s, now(), now(), 1)", (tid, robo, did))
        c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, total_queries, clients_count) "
                  "VALUES (%s, %s, now(), now(), 1, 1)", (tid, did))
    # um dos domínios também é de um computador comum: esse não pode ficar retido
    c.execute("INSERT INTO query_log (ts, tenant_id, client_ip, domain_id, qname) VALUES "
              "(now() - interval '5 minutes', %s, '192.168.21.10', %s, 'site0.example')", (tid, ids[0]))
    c.execute("INSERT INTO client_domains (tenant_id, client_id, domain_id, first_seen, last_seen, queries) "
              "VALUES (%s, %s, %s, now(), now(), 1)", (tid, comum, ids[0]))
    c.execute("UPDATE tenant_domains SET clients_count = 2 WHERE tenant_id = %s AND domain_id = %s", (tid, ids[0]))
    return tid, robo, ids


def test_trava_alerta_retem_e_libera(env):
    from dnsanalyzer import db, varredura
    from dnsanalyzer.investigacao import _FILA_FASE1
    with db.conn() as c:
        tid, robo, ids = _cenario(c)
    res = varredura.ciclo()
    assert res["travados"] == 1 and res["retidos"] == 59
    with db.conn() as c:
        v = c.execute("SELECT estado, pior_hora FROM dispositivos_varredura WHERE client_id = %s", (robo,)).fetchone()
        assert v["estado"] == "travado" and v["pior_hora"] == 60
        assert c.execute("SELECT severity FROM alerts WHERE dedup_key = %s", (f"varredura:{robo}",)).fetchone()["severity"] == "high"
        retidos = {r["name"] for r in c.execute("SELECT name FROM domains WHERE varredura").fetchall()}
        assert "site0.example" not in retidos and "site1.example" in retidos and len(retidos) == 59
        # a fila da fase 1 só enxerga o domínio que um computador comum também acessou
        fila = c.execute(_FILA_FASE1.replace("SELECT 1", "SELECT name").replace("LIMIT 1", "")).fetchall()
        assert {r["name"] for r in fila} == {"site0.example"}

    lista = env.get("/varredura", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert lista["limite_hora"] == 50 and lista["travados"] == 1
    assert lista["itens"][0]["ip"] == "192.168.21.165" and lista["itens"][0]["retidos"] == 59

    # falso positivo: liberar devolve os domínios à fila e não trava de novo
    r = env.post(f"/varredura/{tid}/{robo}", json={"acao": "liberar", "by": "teste"},
                 headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert r["estado"] == "liberado" and r["soltos"] == 59
    assert varredura.ciclo()["travados"] == 0
    with db.conn() as c:
        assert not c.execute("SELECT 1 FROM domains WHERE varredura").fetchone()
        assert c.execute("SELECT status FROM alerts WHERE dedup_key = %s", (f"varredura:{robo}",)).fetchone()["status"] == "closed"


def test_acao_invalida(env):
    r = env.post("/varredura/1/999999", json={"acao": "apagar"}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 400
