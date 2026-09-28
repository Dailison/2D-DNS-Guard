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


def _charts(api, **kw):
    p = {"start": (AGORA - timedelta(hours=1)).isoformat(), "end": (AGORA + timedelta(hours=2)).isoformat(), **kw}
    r = api.get("/charts", params=p, headers=H)
    assert r.status_code == 200, r.text
    return r.json()


def test_charts_totais_e_quebras(api):
    j = _charts(api)
    assert j["granularidade"] == "hour"
    assert j["totais"] == {"liberadas": 12, "bloqueadas": 3, "sites": 3, "ameacas": 5}
    assert sum(r["liberadas"] + r["bloqueadas"] for r in j["serie"]) == 15
    cls = {r["chave"]: (r["liberadas"], r["bloqueadas"]) for r in j["por_classificacao"]}
    # loja.com: A ajustou p/ TRABALHO (5), B segue NAO_TRABALHO (4) — por empresa, não a pior
    assert cls == {"MALICIOSO": (2, 3), "TRABALHO": (5, 0), "NAO_TRABALHO": (4, 0), "PENDENTE": (1, 0)}
    emp = {r["chave"]: r["liberadas"] + r["bloqueadas"] for r in j["por_empresa"]}
    assert emp == {"Empresa A": 9, "Empresa B": 6}
    assert [r["chave"] for r in j["top_dominios"]][0] == "loja.com"


def test_charts_filtros(api):
    j = _charts(api, resposta="bloqueado")
    assert j["totais"]["liberadas"] == 0 and j["totais"]["bloqueadas"] == 3
    assert [r["chave"] for r in j["top_dominios"]] == ["ruim.com"]
    assert [r["chave"] for r in j["por_empresa"]] == ["Empresa A"]   # B não teve bloqueio: some
    j = _charts(api, cls=["MALICIOSO", "SUSPEITO"])
    assert j["totais"]["liberadas"] + j["totais"]["bloqueadas"] == 5
    j = _charts(api, categoria="compras", resposta="liberado")
    assert j["totais"] == {"liberadas": 9, "bloqueadas": 0, "sites": 1, "ameacas": 0}
    assert api.get("/charts", params={"start": AGORA.isoformat(), "end": AGORA.isoformat()}, headers=H).status_code == 400
    assert api.get("/charts", params={"start": (AGORA - timedelta(hours=1)).isoformat(), "end": AGORA.isoformat(),
                                      "resposta": "x"}, headers=H).status_code == 400


def test_fases_2_e_3_nao_esperam_a_fila_da_fase_1(api):
    from dnsanalyzer import classifier, db
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, web_search_at, total_queries) "
                  "VALUES ('desconhecido-etapa3.com', 'com', 'DESCONHECIDO', 'llm', now(), 50)")
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, whois_at, total_queries) "
                  "VALUES ('desconhecido-busca.com', 'com', 'DESCONHECIDO', 'llm', now(), 40)")
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, llm_pending, total_queries) "
                  "VALUES ('na-fila-da-ia.com', 'com', 'DESCONHECIDO', 'rules', true, 900)")
    with db.conn() as c:   # a fase 1 ainda tem fila: as fases 2 e 3 andam mesmo assim, cada uma com o seu
        d = classifier._claim_etapa3(c)
        assert d and d["name"] == "desconhecido-etapa3.com"
        assert classifier._claim_etapa2(c)["name"] == "desconhecido-busca.com"
        c.execute("UPDATE domains SET whois_at=now(), claimed_at=NULL WHERE id=%s", (d["id"],))
        assert classifier._claim_etapa3(c) is None          # já consultado: não volta


def test_etapa3_em_paralelo_e_br_primeiro(api):
    from dnsanalyzer import classifier, db
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, total_queries) VALUES "
                  "('sem-busca-ainda.com', 'com', 'DESCONHECIDO', 'llm', 900), "
                  "('empresa-exemplo.com.br', 'br', 'DESCONHECIDO', 'llm', 10)")
    with db.conn() as c:
        a = classifier._claim_etapa3(c)       # não espera a busca na web (web_search_at NULL)
        b = classifier._claim_etapa3(c)
        assert [a["name"], b["name"]] == ["empresa-exemplo.com.br", "sem-busca-ainda.com"]


def test_etapa3_sem_br_com_registro_br_em_pausa(api, monkeypatch):
    from dnsanalyzer import classifier, db, whois
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, total_queries) VALUES "
                  "('limitado.com.br', 'br', 'DESCONHECIDO', 'llm', 900), "
                  "('segue-sem-br.com', 'com', 'DESCONHECIDO', 'llm', 10)")
    monkeypatch.setattr(whois, "br_pausado", lambda: True)
    with db.conn() as c:
        assert classifier._claim_etapa3(c)["name"] == "segue-sem-br.com"
        assert classifier._claim_etapa3(c) is None


def test_bloqueio_automatico_e_listas(api):
    from dnsanalyzer import db, listas
    from dnsanalyzer.config import settings
    with db.conn() as c:
        ids = {}
        for nome, cat, corp, cls in (("cassino-x.com", "apostas", "BLOQUEAR", "NAO_TRABALHO"),
                                     ("jogo-y.com", "jogos", "BLOQUEAR", "NAO_TRABALHO"),
                                     ("jogo-liberado.com", "jogos", "BLOQUEAR", "NAO_TRABALHO"),
                                     ("jogo-revisar.com", "jogos", "REVISAR", "NAO_TRABALHO"),
                                     ("noticia-z.com", "noticias", "BLOQUEAR", "NAO_TRABALHO")):
            ids[nome] = c.execute("INSERT INTO domains (name, tld, category, corp_action, classification, classified_by) "
                                  "VALUES (%s, 'com', %s, %s, %s, 'llm') RETURNING id", (nome, cat, corp, cls)).fetchone()["id"]
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'allowed', 'op')",
                  (ids["jogo-liberado.com"],))
    with db.conn() as c:
        feitos = {r["name"] for r in listas.bloquear_auto(c)}
    assert feitos == {"cassino-x.com", "jogo-y.com"}      # decidido, REVISAR e outra categoria ficam de fora
    with db.conn() as c:
        assert listas.bloquear_auto(c) == []                # já decidido (bloqueio automático) não repete
        g = c.execute("SELECT reviewed_by FROM global_reviews WHERE domain_id=%s", (ids["jogo-y.com"],)).fetchone()
        assert g["reviewed_by"] == "bloqueio automático (jogos)"
    assert api.get("/listas/jogos.txt").status_code == 403  # IP fora de LISTS_ALLOWED_IPS
    settings().lists_allowed_ips.append("testclient")
    txt = api.get("/listas/jogos.txt").text
    assert "jogo-y.com\n" in txt and "cassino" not in txt and txt.startswith("#")
    assert api.get("/listas/xxx.txt").status_code == 404
    r = api.get("/listas", headers=H).json()
    assert {x["categoria"]: x["total"] for x in r["categorias"]}["apostas"] >= 1 and r["auto_24h"] == 2
    assert "cassino-x.com" in api.get("/listas-dominios", params={"cats": ["apostas"]}, headers=H).json()["apostas"]
    assert api.post("/listas/adulto", json={"domain": "Site-Adulto.com.", "by": "op"}, headers=H).status_code == 200
    assert [x["category"] for x in api.get("/listas-dominio/www.site-adulto.com", headers=H).json()] == ["adulto"]
    assert api.delete("/listas/adulto/site-adulto.com", headers=H).json()["removidos"] == 1


def test_listas_curadas_so_manual_com_sugestoes(api):
    from dnsanalyzer import db
    from dnsanalyzer.config import settings
    with db.conn() as c:
        t = c.execute("SELECT id FROM tenants WHERE slug='a'").fetchone()["id"]
        ids = {}
        for nome, cls in (("rede-social-1.com", "NAO_TRABALHO"), ("rede-liberada.com", "NAO_TRABALHO"),
                          ("rede-ajustada.com", "NAO_TRABALHO"), ("rede-trabalho.com", "TRABALHO")):
            ids[nome] = c.execute("INSERT INTO domains (name, tld, category, classification, classified_by, total_queries) "
                                  "VALUES (%s, 'com', 'redes_sociais', %s, 'catalog', 5) RETURNING id", (nome, cls)).fetchone()["id"]
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'allowed', 'op')",
                  (ids["rede-liberada.com"],))
        c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, override_classification) "
                  "VALUES (%s, %s, now(), now(), 'TRABALHO')", (t, ids["rede-ajustada.com"]))
    if "testclient" not in settings().lists_allowed_ips:
        settings().lists_allowed_ips.append("testclient")
    assert "rede-social-1.com" not in api.get("/listas/redes_sociais.txt").text      # IA só sugere
    sug = [x["domain"] for x in api.get("/listas/redes_sociais/sugestoes", headers=H).json()]
    assert sug == ["rede-social-1.com"]                                              # liberado/ajustado/trabalho fora
    api.post("/listas/redes_sociais", json={"domain": "rede-social-1.com", "by": "op"}, headers=H)
    assert "rede-social-1.com\n" in api.get("/listas/redes_sociais.txt").text
    assert api.get("/listas/redes_sociais/sugestoes", headers=H).json() == []
    j = api.get("/listas-dominios", params={"cats": ["redes_sociais", "jogos", "xx"]}, headers=H).json()
    assert set(j) == {"redes_sociais", "jogos"} and "rede-social-1.com" in j["redes_sociais"]
    assert "rede-liberada.com" not in j["redes_sociais"]
    m = api.get("/listas-dominio/cdn.rede-social-1.com", headers=H).json()
    assert [(x["category"], x["domain"]) for x in m] == [("redes_sociais", "rede-social-1.com")]
    r = {x["categoria"]: x for x in api.get("/listas", headers=H).json()["categorias"]}
    assert r["redes_sociais"]["tipo"] == "ia" and r["pirataria"]["tipo"] == "ia" and r["outros_bloqueios"]["tipo"] == "manual"


def test_politicas(api):
    pol = {p["scope"]: p for p in api.get("/policies", headers=H).json()}
    assert pol["default"]["lists"] == ["ameaca", "vpn_proxy", "adulto", "apostas", "jogos"]
    assert api.put("/policies/tenant:7", json={"lists": ["jogos", "redes_sociais", "jogos"], "services": ["instagram"], "by": "op"},
                   headers=H).status_code == 200
    assert api.put("/policies/unit:7:Matriz", json={"lists": ["outros_bloqueios"]}, headers=H).status_code == 200
    assert api.put("/policies/tenant:7", json={"lists": ["xx"]}, headers=H).status_code == 400
    assert api.put("/policies/hack", json={"lists": []}, headers=H).status_code == 400
    pol = {p["scope"]: p for p in api.get("/policies", headers=H).json()}
    assert pol["tenant:7"]["lists"] == ["jogos", "redes_sociais"] and pol["tenant:7"]["services"] == ["instagram"]
    assert api.delete("/policies/unit:7:Matriz", headers=H).status_code == 200
    assert api.delete("/policies/default", headers=H).status_code == 400
    assert "unit:7:Matriz" not in {p["scope"] for p in api.get("/policies", headers=H).json()}


def test_listas_em_lote(api):
    r = api.post("/listas-lote", json={"cats": ["streaming", "outros_bloqueios"], "domains": ["A.com.", "b.com", "lixo", ""], "by": "op"}, headers=H)
    assert r.status_code == 200 and r.json()["dominios"] == 2
    assert api.post("/listas-lote", json={"cats": ["xx"], "domains": ["a.com"]}, headers=H).status_code == 400
    assert [x["category"] for x in api.get("/listas-dominio/a.com", headers=H).json()] in (["streaming", "outros_bloqueios"], ["outros_bloqueios", "streaming"])
    assert api.post("/listas-remover", json={"cats": ["streaming"], "domains": ["a.com"]}, headers=H).json()["removidos"] == 1
    assert api.post("/listas-remover", json={"domains": ["a.com", "b.com"]}, headers=H).json()["removidos"] == 3


def test_listas_de_liberacao(api):
    from dnsanalyzer.config import settings
    ls = {x["slug"]: x for x in api.get("/liberacao", headers=H).json()}
    assert ls["instagram"]["total"] >= 4 and ls["facebook"]["name"] == "Facebook"      # pacotes viraram listas
    r = api.post("/liberacao", json={"name": "Sistemas do Cliente Ágil", "by": "op"}, headers=H)
    assert r.status_code == 200 and r.json()["slug"] == "sistemas-do-cliente-agil"
    assert api.post("/liberacao", json={"name": "Sistemas do cliente agil"}, headers=H).status_code == 409
    slug = "sistemas-do-cliente-agil"
    api.post(f"/liberacao/{slug}/dominios", json={"domains": ["ERP.Cliente.com.br.", "lixo"], "by": "op"}, headers=H)
    if "testclient" not in settings().lists_allowed_ips:
        settings().lists_allowed_ips.append("testclient")
    assert "erp.cliente.com.br\n" in api.get(f"/liberacao/{slug}.txt").text
    assert api.get("/liberacao/nao-existe.txt").status_code == 404
    assert [x["slug"] for x in api.get("/liberacao-dominio/api.erp.cliente.com.br", headers=H).json()] == [slug]
    assert api.put("/policies/tenant:8", json={"lists": ["jogos"], "services": [slug, "instagram"]}, headers=H).status_code == 200
    assert api.put("/policies/tenant:8", json={"lists": [], "services": ["nao-existe"]}, headers=H).status_code == 400
    assert api.delete(f"/liberacao/{slug}/dominios/erp.cliente.com.br", headers=H).json()["removidos"] == 1
    assert api.delete(f"/liberacao/{slug}", headers=H).json()["removidas"] == 1
    p = {x["scope"]: x for x in api.get("/policies", headers=H).json()}["tenant:8"]
    assert p["services"] == ["instagram"]                       # apagar a lista tira da política


def test_servicos_so_para_liberar(api):
    ls = {x["slug"]: x for x in api.get("/liberacao", headers=H).json()}
    assert {"youtube", "spotify", "spotify-video", "deezer", "instagram", "facebook", "pinterest", "discord",
            "mercado-livre", "amazon", "telegram"} <= set(ls)
    assert not {"tiktok", "roblox", "bet365", "whatsapp", "netflix"} & set(ls)
    assert all(x["category"] is None for x in ls.values())
    assert "mlstatic.com" in [d["domain"] for d in api.get("/liberacao/mercado-livre", headers=H).json()]


def test_logs_sem_nomes_locais(api):
    from dnsanalyzer import db
    with db.conn() as c:
        t = c.execute("SELECT id FROM tenants WHERE slug='a'").fetchone()["id"]
        cl = c.execute("SELECT id FROM clients WHERE tenant_id=%s LIMIT 1", (t,)).fetchone()["id"]
        for n, kind in (("srv.2d.local", "internal"), ("pc.empresa.corp", "public")):
            i = c.execute("INSERT INTO domains (name, kind) VALUES (%s, %s) RETURNING id", (n, kind)).fetchone()["id"]
            f = c.execute("INSERT INTO fqdns (name, domain_id) VALUES (%s, %s) RETURNING id", (n, i)).fetchone()["id"]
            c.execute("INSERT INTO query_agg (tenant_id, client_id, domain_id, fqdn_id, bucket, queries, blocked, nxdomain, first_seen, last_seen) "
                      "VALUES (%s,%s,%s,%s,%s,3,0,0,%s,%s)", (t, cl, i, f, AGORA, AGORA, AGORA))
    todos = {r["dominio"] for r in _grouped(api)}
    assert {"srv.2d.local", "pc.empresa.corp"} <= todos
    sem = {r["dominio"] for r in _grouped(api, sem_locais="true", excluir=["empresa.corp"])}
    assert "srv.2d.local" not in sem and "pc.empresa.corp" not in sem and "x.ruim.com" in sem


def test_dominio_novo_passa_na_frente_do_backlog_de_reanalise(api):
    """27/09: domínios novos (1-4 consultas) esperavam ~15 h atrás de ~7.000 reenfileirados com muitas consultas."""
    from dnsanalyzer import classifier, db
    with db.conn() as c:
        c.execute("UPDATE domains SET claimed_at = now() WHERE llm_pending")   # (o que outros testes deixaram na fila)
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, model, llm_pending, total_queries) VALUES "
                  "('backlog-velho.com', 'com', 'NAO_TRABALHO', 'llm', 'qwen3:8b', true, 900), "
                  "('novo-hoje.com.br', 'br', NULL, NULL, NULL, true, 2), "
                  "('suspeito-velho.net', 'net', 'SUSPEITO', 'llm', 'qwen3:8b', true, 5)")
        # reanálise já passou pelas regras (model zerado): o histórico de IA é o que a separa de um domínio novo
        c.execute("INSERT INTO domains (name, tld, classification, classified_by, llm_pending, total_queries, reanalise_pedida) "
                  "VALUES ('reanalise-regras.com', 'com', 'DESCONHECIDO', 'rules', true, 800, true)")
        c.execute("INSERT INTO classification_history (domain_id, classification, source) SELECT id, c, 'llm' FROM domains, "
                  "(VALUES ('NAO_TRABALHO')) v(c) WHERE name IN ('reanalise-regras.com', 'backlog-velho.com', 'suspeito-velho.net')")
        # novo de pouco acesso (aberto uma vez): fica atrás dos novos acessados, mas antes de qualquer reanálise
        c.execute("INSERT INTO domains (name, tld, llm_pending, aguarda_recorrencia, total_queries) VALUES "
                  "('novo-raro.com', 'com', true, true, 1)")
    with db.conn() as c:
        ordem = [classifier._claim_llm(c)["name"] for _ in range(5)]
    assert ordem == ["novo-hoje.com.br", "novo-raro.com", "suspeito-velho.net", "backlog-velho.com", "reanalise-regras.com"], ordem


def test_cada_reforco_com_o_seu_modelo_e_rodizio(monkeypatch):
    """27/09: 2º reforço (RTX 5070 Ti) com gemma4:26b IQ3_S: OLLAMA_EXTRA_URLS aceita "url=modelo"; as fases 2/3 alternam."""
    from dnsanalyzer import classifier, config, llm
    monkeypatch.setenv("OLLAMA_EXTRA_URLS", "http://pc1:11434, http://pc2:11434/=gemma4:26b-iq3s")
    monkeypatch.setenv("OLLAMA_EXTRA_MODEL", "gemma4:26b")
    monkeypatch.setattr(config, "_settings", None)
    try:
        cfg = config.settings()
        assert cfg.ollama_extra_urls == ["http://pc1:11434", "http://pc2:11434"]
        assert llm.OllamaClient("http://pc1:11434").model == "gemma4:26b"
        assert llm.OllamaClient("http://pc2:11434").model == "gemma4:26b-iq3s"
        monkeypatch.setattr(llm.OllamaClient, "available", lambda self: (True, "ok"))
        r = classifier._Reforco(llm.OllamaClient())
        assert [r.cliente().url for _ in range(3)] == ["http://pc1:11434", "http://pc2:11434", "http://pc1:11434"]
    finally:
        config._settings = None


def test_etapas_so_na_gpu_rapida_e_workers_por_reforco(monkeypatch):
    """27/09: fases 2/3 presas no PC lento (rodízio) -> OLLAMA_ETAPAS_URLS escolhe a GPU delas; LLM_EXTRA_WORKERS_URL
    dá menos análises simultâneas à mais lenta. Fora do ar, vale outro reforço e depois a VM."""
    from dnsanalyzer import classifier, config, llm
    monkeypatch.setenv("OLLAMA_EXTRA_URLS", "http://pc1:11434=gemma4:26b-iq3s,http://pc2:11434=gemma4:26b-iq3s")
    monkeypatch.setenv("OLLAMA_ETAPAS_URLS", "http://pc2:11434")
    monkeypatch.setenv("LLM_EXTRA_WORKERS_URL", "http://pc1:11434=2")
    monkeypatch.setenv("LLM_EXTRA_WORKERS", "4")
    monkeypatch.setattr(config, "_settings", None)
    try:
        cfg = config.settings()
        assert classifier._workers_reforco(cfg, "http://pc1:11434") == 2 and classifier._workers_reforco(cfg, "http://pc2:11434") == 4
        no_ar = {"http://pc1:11434": True, "http://pc2:11434": True}
        monkeypatch.setattr(llm.OllamaClient, "available", lambda self: (no_ar.get(self.url, True), "ok"))
        r = classifier._Reforco(llm.OllamaClient())
        assert [r.cliente().url for _ in range(3)] == ["http://pc2:11434"] * 3
        no_ar["http://pc2:11434"] = False
        r = classifier._Reforco(llm.OllamaClient())
        assert r.cliente().url == "http://pc1:11434", "a preferida fora: outro reforço"
    finally:
        config._settings = None


def test_reservas_orfas_voltam_a_fila_ao_iniciar(api):
    """27/09: reinício no meio de uma análise deixava o domínio "em análise" por 30 min (reserva órfã)."""
    from dnsanalyzer import classifier, db
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, tld, llm_pending, claimed_at) VALUES "
                  "('orfa-fase1.com', 'com', true, now() - interval '3 minutes')")
        c.execute("INSERT INTO domains (name, tld, lista_claimed_at, online_claimed_at) VALUES "
                  "('orfa-lista.com', 'com', now() - interval '1 minute', now() + interval '3 hours')")
    n, m = classifier.liberar_reservas_orfas()
    with db.conn() as c:
        r = {x["name"]: x for x in c.execute("SELECT name, claimed_at, lista_claimed_at, online_claimed_at FROM domains "
                                             "WHERE name IN ('orfa-fase1.com', 'orfa-lista.com')")}
    assert n >= 1 and m >= 1 and r["orfa-fase1.com"]["claimed_at"] is None and r["orfa-lista.com"]["lista_claimed_at"] is None
    assert r["orfa-lista.com"]["online_claimed_at"] is not None, "reserva da IA online (rodada externa) fica"
