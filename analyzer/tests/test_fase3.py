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
    # telemetria.com: TRABALHO, bloqueada há dias (via CNAME de entrada antiga) -> bloqueio conhecido, sem alerta
    dom["telemetria.com"] = c.execute("INSERT INTO domains (name, classification, category) VALUES "
                                      "('telemetria.com', 'TRABALHO', 'produtividade') RETURNING id").fetchone()["id"]
    c.execute("INSERT INTO fqdns (name, domain_id) VALUES ('www.telemetria.com', %s)", (dom["telemetria.com"],))
    fq["www.telemetria.com"] = c.execute("SELECT id FROM fqdns WHERE name='www.telemetria.com'").fetchone()["id"]
    for cl in pcs[:7]:
        q(t["a"], cl, "telemetria.com", 10, 10)
        q(t["a"], cl, "telemetria.com", 10, 4, AGORA - timedelta(hours=3))
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
    assert not any(d == "telemetria.com" for _, d in al), "já vinha sendo bloqueado: conhecido, sem alerta"
    assert r["blocked_work"] == 1 and r["block_spike"] == 1
    assert behavior.run(AGORA - timedelta(minutes=30))["block_spike"] == 0, "dedup por dia"


def test_texto_do_aviso(api):
    from dnsanalyzer import webhook
    a = {"id": 1, "severity": "high", "kind": "blocked_work", "tenant_name": "Empresa A", "tenant_id": 1, "title": "Site de trabalho bloqueado: erp.com.br (2 computador(es))",
         "domain": "erp.com.br", "details": {"computadores": 2, "ips": ["10.1.0.1"]}, "created_at": AGORA}
    assert "Se for engano" in webhook._payload(a)["text"]


# ---------------------------------------------------------------- fase 4
def test_ameaca_expira_fora_dos_feeds(api):
    from dnsanalyzer import db, listas
    with db.conn() as c:
        ids = {}
        for n, sig, dias in (("velha-ameaca.com", "", 8), ("ainda-no-feed.com", "urlhaus", None), ("recente.com", "", 2),
                             ("pessoa-pos.com", "", 30)):
            ids[n] = c.execute("INSERT INTO domains (name, classification, ti_signature, ti_cleared_at) VALUES "
                               "(%s, 'MALICIOSO', %s, now() - make_interval(days => %s)) RETURNING id",
                               (n, sig, dias or 0)).fetchone()["id"]
            por = "op@2d" if n == "pessoa-pos.com" else "bloqueio automático (ameaca)"
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('ameaca', %s, %s)", (n, por))
            c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', %s)", (ids[n], por))
        feitos = listas.expirar_ameacas(c, dias=7)
        restam = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category='ameaca'")}
        rev = c.execute("SELECT 1 FROM global_reviews WHERE domain_id=%s", (ids["velha-ameaca.com"],)).fetchone()
        na = c.execute("SELECT needs_analysis FROM domains WHERE id=%s", (ids["velha-ameaca.com"],)).fetchone()["needs_analysis"]
    assert [r["domain"] for r in feitos] == ["velha-ameaca.com"] and not rev and na
    assert {"ainda-no-feed.com", "recente.com", "pessoa-pos.com"} <= restam


def test_auditoria_por_gatilho(api):
    from dnsanalyzer import db, listas
    with db.conn() as c:
        listas.contexto(c, "op@2d", "teste de auditoria")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'audit.exemplo.com', 'op@2d')")
        c.execute("DELETE FROM category_lists WHERE domain = 'audit.exemplo.com'")
    with db.conn() as c:   # sem contexto: usa o added_by
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('streaming', 'audit.exemplo.com', 'IA automática (streaming)')")
    h = api.get("/auditoria", headers=H, params={"domain": "sub.audit.exemplo.com"}).json()
    assert [(x["category"], x["acao"], x["por"]) for x in h] == [("streaming", "add", "IA automática (streaming)"),
                                                                 ("jogos", "remove", "op@2d"), ("jogos", "add", "op@2d")]
    assert h[1]["motivo"] == "teste de auditoria"
    r = api.post("/listas-mover", headers=H, json={"domains": ["audit.exemplo.com"], "de": "streaming", "para": [], "by": "ana@2d"})
    assert r.status_code == 200
    ult = api.get("/auditoria", headers=H, params={"category": "streaming", "limit": 1}).json()[0]
    assert (ult["acao"], ult["por"]) == ("remove", "ana@2d") and "manter liberado" in ult["motivo"]


def test_lista_publicada_nao_esvazia(api):
    from dnsanalyzer import config, db
    if "testclient" not in config.settings().lists_allowed_ips:
        config.settings().lists_allowed_ips.append("testclient")
    with db.conn() as c:
        c.execute("INSERT INTO category_lists (category, domain, added_by) SELECT 'pirataria', 'p' || i || '.com', 'op' "
                  "FROM generate_series(1, 60) i")
    r = api.get("/listas/pirataria.txt")
    assert r.status_code == 200 and r.text.count("\n") == 61
    with db.conn() as c:
        c.execute("DELETE FROM category_lists WHERE category='pirataria' AND domain IN (SELECT 'p' || i || '.com' FROM generate_series(1, 20) i)")
    assert api.get("/listas/pirataria.txt").status_code == 503, "encolheu 33%: recusada"
    h = api.get("/health").json()
    assert "pirataria" in h["listas_recusadas"] and h["listas"]["pirataria"]["last_n"] == 60
    assert api.get("/listas/pirataria.txt", params={"force": "1"}).status_code == 200
    with db.conn() as c:   # 40 -> 100 publicado; depois limpeza de propósito p/ 60: recusa até aceitar
        c.execute("INSERT INTO category_lists (category, domain, added_by) SELECT 'pirataria', 'q' || i || '.com', 'op' "
                  "FROM generate_series(1, 60) i")
    assert api.get("/listas/pirataria.txt").status_code == 200
    with db.conn() as c:
        c.execute("DELETE FROM category_lists WHERE category='pirataria' AND domain LIKE 'q%' AND length(domain) <= 7")
    assert api.get("/listas/pirataria.txt").status_code == 503
    assert api.post("/listas/pirataria/aceitar", headers=H, params={"by": "op"}).json()["dominios"] == 40
    assert api.get("/listas/pirataria.txt").status_code == 200 and "pirataria" not in api.get("/health").json()["listas_recusadas"]


# ---------------------------------------------------------------- whitelists e Sites Revisados
def test_whitelist_automatica_e_travas(api):
    import json as _j

    from psycopg.types.json import Jsonb

    from dnsanalyzer import classifier, db, whitelist
    trab = {"classificacao": "TRABALHO", "reconhecido": True, "categoria": "financas", "servico": "Banco",
            "_meta": {"antes": {"lista": "nenhuma", "classificacao": "TRABALHO", "confianca": 0.95}}}
    with db.conn() as c:
        def dom(n, cls="TRABALHO", fonte="online:gemini", resp=trab, ev=None, por="llm", conf=0.9, lista=None):
            return c.execute("INSERT INTO domains (name, classification, category, lista_fonte, lista_conf, lista_ia, online_resp, "
                             "evidence, classified_by, analyzed_at) VALUES (%s, %s, 'financas', %s, %s, %s, %s, %s, %s, now()) RETURNING id",
                             (n, cls, fonte, conf, lista, Jsonb(resp), _j.dumps(ev or []), por)).fetchone()["id"]
        dom("banco-wl.com.br")
        dom("microsoft.com", por="catalog", fonte=None, resp={})
        dom("site.pages.dev", ev=[{"kind": "platform", "text": "x"}])
        dom("cdnpai.net")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'jogo.cdnpai.net', 'op')")
        dom("duvida-wl.com", conf=0.5)
        dom("loja-wl.com", resp={"classificacao": "NAO_TRABALHO", "reconhecido": True})
        dom("um-modelo-so.com", resp={"classificacao": "TRABALHO", "reconhecido": True, "categoria": "produtividade"})
        dom("google-analytics-teste.com", resp={**trab, "servico": "Plataforma de analytics e rastreamento"})
        dom("imgcdn-trab.com", resp=trab)
        out = whitelist.aplicar(c)
        wl = {r["domain"]: r["category"] for r in c.execute("SELECT domain, category FROM whitelist_domains")}
    assert wl.get("banco-wl.com.br") == "financas" and wl.get("microsoft.com") == "essenciais"
    assert not {"site.pages.dev", "cdnpai.net", "duvida-wl.com", "loja-wl.com", "um-modelo-so.com",
                "google-analytics-teste.com", "imgcdn-trab.com"} & set(wl), wl
    # apareceu em feed de ameaça -> sai; conflito com lista de bloqueio -> sai (automática)
    with db.conn() as c:
        c.execute("UPDATE domains SET ti_signature = 'urlhaus' WHERE name = 'banco-wl.com.br'")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('compras', 'microsoft.com', 'op')")
        whitelist.aplicar(c)
        wl = {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains")}
        rev = c.execute("SELECT count(*) AS n FROM list_audit WHERE category LIKE 'wl:%%' AND acao = 'remove'").fetchone()["n"]
    assert "banco-wl.com.br" not in wl and "microsoft.com" not in wl and rev >= 2
    # Sites Revisados ficam fora da reanálise periódica
    with db.conn() as c:
        c.execute("UPDATE domains SET revisado_at = now(), analyzed_at = now() - interval '90 days', needs_analysis = false "
                  "WHERE name = 'loja-wl.com'")
        c.execute("UPDATE domains SET revisado_at = NULL, analyzed_at = now() - interval '90 days', needs_analysis = false "
                  "WHERE name = 'duvida-wl.com'")
    classifier.reanalyze_stale(30)
    with db.conn() as c:
        na = {r["name"]: r["needs_analysis"] for r in c.execute("SELECT name, needs_analysis FROM domains WHERE name IN ('loja-wl.com', 'duvida-wl.com')")}
    assert na == {"loja-wl.com": False, "duvida-wl.com": True}


def test_whitelist_api(api):
    from dnsanalyzer import config, db
    if "testclient" not in config.settings().lists_allowed_ips:
        config.settings().lists_allowed_ips.append("testclient")
    with db.conn() as c:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('compras', 'erp-manual.com.br', 'IA automática (compras)')")
    r = api.post("/whitelist/produtividade", headers=H, json={"domains": ["erp-manual.com.br"], "by": "op@2d"}).json()
    assert r["dominios"] == 1
    assert "erp-manual.com.br" in api.get("/whitelist/produtividade.txt").text
    assert api.get("/auditoria", headers=H, params={"domain": "erp-manual.com.br", "limit": 5}).json()[0]["category"] == "wl:produtividade"
    with db.conn() as c:
        assert not c.execute("SELECT 1 FROM category_lists WHERE domain='erp-manual.com.br'").fetchone(), "saiu da lista de bloqueio"
    j = api.get("/whitelist", headers=H).json()
    assert next(x for x in j["categorias"] if x["categoria"] == "produtividade")["total"] >= 1
    d = api.get("/whitelist/produtividade/detalhes", headers=H).json()
    assert any(x["domain"] == "erp-manual.com.br" for x in d["items"])
    assert "erp-manual.com.br" in api.get("/whitelist-dominios", headers=H).json()
    # pôr numa lista de bloqueio tira da whitelist
    api.post("/listas-lote", headers=H, json={"cats": ["jogos"], "domains": ["erp-manual.com.br"], "by": "op"})
    assert "erp-manual.com.br" not in api.get("/whitelist-dominios", headers=H).json()


def test_historico_do_dominio(api):
    from psycopg.types.json import Jsonb

    from dnsanalyzer import db, listas
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, classification, category, topic, classified_by, analyzed_at, online_at, revisado_at, "
                      "online_resp) VALUES ('hist.com.br', 'TRABALHO', 'produtividade', 'ERP', 'online', now(), now(), now(), %s) RETURNING id",
                      (Jsonb({"classificacao": "TRABALHO", "lista": "nenhuma", "confianca": 0.95, "servico": "ERP", "motivo": "sistema",
                              "_meta": {"model": "gemma", "antes": {"modelo": "lite", "lista": "nenhuma", "confianca": 0.9}}}),)).fetchone()["id"]
        c.execute("INSERT INTO classification_history (domain_id, classification, topic, source) VALUES (%s, 'DESCONHECIDO', 'x', 'llm')", (i,))
        listas.contexto(c, "op@2d", "teste")
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by) VALUES ('produtividade', 'hist.com.br', 'op@2d')")
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'allowed', 'ana@2d')", (i,))
    h = api.get("/domains/hist.com.br/historico", headers=H).json()
    assert h["estado"] == "whitelist (produtividade)" and h["whitelist"] == ["produtividade"]
    titulos = [x["titulo"] for x in h["linha_do_tempo"]]
    assert "Fase 1 · IA local" in titulos and "Fase 4 · IA online" in titulos and "entrou em wl:produtividade" in titulos
    assert "decisão global: manter liberado" in titulos
    f4 = next(x for x in h["linha_do_tempo"] if x["titulo"] == "Fase 4 · IA online")
    assert "1ª opinião (lite)" in f4["nota"]
    assert api.get("/domains/nunca-visto.com/historico", headers=H).status_code == 404
