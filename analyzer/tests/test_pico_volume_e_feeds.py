"""(05/11) Pico de volume com computador sem histórico (antes: TypeError em 'behavior falhou') e fontes de TI
que pedem chave (abuse.ch). PostgreSQL real."""

from datetime import datetime, timedelta, timezone

import pytest

pgserver = pytest.importorskip("pgserver")

AGORA = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


@pytest.fixture(scope="module")
def banco(tmp_path_factory):
    import os

    from dnsanalyzer import config, db
    from dnsanalyzer.collector import ensure_partitions
    from dnsanalyzer.migrate import migrate

    srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
    uri = srv.get_uri()
    antes = {k: os.environ.get(k) for k in ("DATABASE_URL", "DNSANALYZER_ENV", "ABUSECH_AUTH_KEY")}
    os.environ.update(DATABASE_URL=uri, DNSANALYZER_ENV="/nao-existe")
    os.environ.pop("ABUSECH_AUTH_KEY", None)
    config._settings = None
    db.close()
    migrate(uri)
    with db.conn() as c:
        ensure_partitions(c, AGORA - timedelta(days=8), AGORA)
        _dados(c)
    yield db
    db.close()
    for k, v in antes.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    config._settings = None
    srv.cleanup()


def _dados(c):
    tid = c.execute("INSERT INTO tenants (slug, name) VALUES ('v', 'Empresa V') RETURNING id").fetchone()["id"]
    did = c.execute("INSERT INTO domains (name) VALUES ('site.com') RETURNING id").fetchone()["id"]
    fid = c.execute("INSERT INTO fqdns (name, domain_id) VALUES ('www.site.com', %s) RETURNING id", (did,)).fetchone()["id"]
    # empresa já passou do aquecimento (7 dias)
    c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen) VALUES (%s, %s, %s, %s)",
              (tid, did, AGORA - timedelta(days=10), AGORA))

    def pc(ip):
        return c.execute("INSERT INTO clients (tenant_id, ip, first_seen, last_seen) VALUES (%s, %s, %s, %s) RETURNING id",
                         (tid, ip, AGORA, AGORA)).fetchone()["id"]

    def q(cl, bucket, n):
        c.execute("INSERT INTO query_agg (tenant_id, client_id, domain_id, fqdn_id, bucket, queries, blocked, nxdomain, "
                  "first_seen, last_seen) VALUES (%s,%s,%s,%s,%s,%s,0,0,%s,%s)", (tid, cl, did, fid, bucket, n, bucket, bucket))

    novo, veterano, recente = pc("10.9.0.1"), pc("10.9.0.2"), pc("10.9.0.3")
    q(novo, AGORA, 900)                                   # só a última hora: sem média (era o TypeError)
    for h in range(2, 72):                                # 3 dias a 10/h, depois 1000 na última hora
        q(veterano, AGORA - timedelta(hours=h), 10)
    q(veterano, AGORA, 1000)
    for h in range(2, 12):                                # visto há 12 h: pouco histórico, sem comparação
        q(recente, AGORA - timedelta(hours=h), 5)
    q(recente, AGORA, 800)


def test_pico_de_volume_so_com_historico(banco):
    from dnsanalyzer import behavior
    r = behavior.run(AGORA - timedelta(minutes=30))
    assert r["volume_spike"] == 1
    with banco.conn() as c:
        al = c.execute("SELECT title, details FROM alerts WHERE kind = 'volume_spike'").fetchall()
    assert len(al) == 1 and al[0]["details"]["ip"] == "10.9.0.2"
    # média pelas horas desde a 1ª consulta (≈ 71 h), não por 168 h fixas
    assert 9 <= al[0]["details"]["avg_hour"] <= 11, al[0]


def test_fonte_com_chave_e_pulada_sem_erro(banco, monkeypatch):
    from dnsanalyzer import ti
    with banco.conn() as c:
        tf = c.execute("SELECT url FROM ti_sources WHERE name = 'threatfox'").fetchone()["url"]
        uh = c.execute("SELECT url FROM ti_sources WHERE name = 'urlhaus'").fetchone()["url"]
    assert "{ABUSECH_AUTH_KEY}" in tf and "abuse.ch/downloads" not in uh
    baixados = []
    monkeypatch.setattr(ti, "refresh_source", lambda s: baixados.append(s["name"]) or 1)
    monkeypatch.setattr(ti, "mark_changed_domains", lambda: 0)
    res = ti.refresh_due(force=True, only="threatfox")
    assert res["errors"] == {} and baixados == ["threatfox"]   # refresh_source trocado: chega até ele

    monkeypatch.undo()
    res = ti.refresh_due(force=True, only="threatfox")
    assert res == {"refreshed": {}, "errors": {}, "marked_for_reanalysis": 0}
    with banco.conn() as c:
        st = c.execute("SELECT last_status FROM ti_sources WHERE name = 'threatfox'").fetchone()["last_status"]
    assert st.startswith("aguardando chave") and "ABUSECH_AUTH_KEY" in st


def test_chave_entra_na_url_e_nao_aparece_no_erro(banco, monkeypatch):
    from dnsanalyzer import config, ti
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "segredo123")
    config._settings = None
    try:
        assert ti.resolve_url("https://x/exports/{ABUSECH_AUTH_KEY}/hostfile.txt") == "https://x/exports/segredo123/hostfile.txt"
        assert ti.resolve_url("https://sem-marca/lista.txt") == "https://sem-marca/lista.txt"

        def falha(url):
            raise RuntimeError(f"Client error '401' for url '{url}'")
        monkeypatch.setattr(ti, "_download", falha)
        res = ti.refresh_due(force=True, only="threatfox")
        assert "segredo123" not in res["errors"]["threatfox"] and "***" in res["errors"]["threatfox"]
        with banco.conn() as c:
            assert "segredo123" not in c.execute("SELECT last_status FROM ti_sources WHERE name='threatfox'").fetchone()["last_status"]
    finally:
        monkeypatch.delenv("ABUSECH_AUTH_KEY")
        config._settings = None
