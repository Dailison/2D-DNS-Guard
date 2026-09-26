"""Etapa "lista": a IA diz a qual lista cada site pertence; certeza -> direto na lista, dúvida -> Para
revisar; aprovação da sugestão; etapa 4. PostgreSQL real (pgserver); a IA é simulada."""

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-lia"
H = {"Authorization": f"Bearer {TOKEN}"}


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
    with db.conn() as c:
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


# nome -> (classificação, lista da IA, confiança)
IA = {"chatgpt.com": ("TRABALHO", "ia_chatbots", 1.0), "roblox.com": ("NAO_TRABALHO", "jogos", 0.95),
      "talvez-jogo.com": ("NAO_TRABALHO", "jogos", 0.6), "erp.com.br": ("TRABALHO", "nenhuma", 1.0),
      "loja-trab.com": ("TRABALHO", "jogos", 1.0), "whatsapp.com": ("TRABALHO", "mensageiros", 1.0),
      "tiktok.com": ("NAO_TRABALHO", "redes_sociais", 1.0), "sobra.com": ("NAO_TRABALHO", "pirataria", 0.95),
      "duvida-sobra.com": ("NAO_TRABALHO", "streaming", 0.5), "ja-listado.com": ("NAO_TRABALHO", "compras", 1.0),
      "cognito.aws.com": ("TRABALHO", "nuvem_remoto", 1.0), "de-outros.com": ("NAO_TRABALHO", "jogos", 1.0)}


def _dados(c):
    t = c.execute("INSERT INTO tenants (slug, name) VALUES ('a', 'A') RETURNING id").fetchone()["id"]
    ids = {}
    for n, (cls, _, _) in IA.items():
        ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries) "
                           "VALUES (%s, %s, %s, now(), 10) RETURNING id",
                           (n, cls, "infraestrutura" if n.startswith("cognito") else "outros")).fetchone()["id"]
    c.execute("INSERT INTO domains (name, classification, analyzed_at) VALUES ('nao-sei.com', 'DESCONHECIDO', now())")
    # whatsapp: alguém decidiu "manter liberado" e a empresa A aplica Mensageiros -> não entra sozinho
    c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, review_status, reviewed_by, reviewed_at) "
              "VALUES (%s, %s, now(), now(), 'allowed', 'ana', now())", (t, ids["whatsapp.com"]))
    c.execute("INSERT INTO policies (scope, lists, services) VALUES ('tenant:%s', '{mensageiros,jogos}', '{}')" % t)
    c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', 'sobra.com', 'migração dos grupos antigos'),"
              "('para_revisar', 'duvida-sobra.com', 'migração dos grupos antigos'), ('infra_bloqueio', 'ja-listado.com', 'op'), ('outros_bloqueios', 'de-outros.com', 'migração')")


def test_fila_classifica_e_aplica(env, monkeypatch):
    from dnsanalyzer import db, listas_ia

    vistos = []

    def falso(client, d):
        vistos.append(d["name"])
        _, lista, conf = IA[d["name"]]
        return listas_ia.ListaResult(servico="x", lista=lista, confianca=conf, motivo="m"), {"seconds": 0.1}
    monkeypatch.setattr(listas_ia, "perguntar", falso)
    while listas_ia.fase(object()) == "done":
        pass
    assert sorted(vistos) == sorted(IA), "desconhecido fica de fora"
    with db.conn() as c:
        ap = listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]): r["added_by"] for r in c.execute("SELECT * FROM category_lists")}
        g = {r["name"]: r["reviewed_by"] for r in c.execute(
            "SELECT d.name, g.reviewed_by FROM global_reviews g JOIN domains d ON d.id = g.domain_id")}
        st = listas_ia.status(c)
    assert ("ia_chatbots", "chatgpt.com") in em and em[("jogos", "roblox.com")] == "IA automática (jogos)"
    assert ("redes_sociais", "tiktok.com") in em
    assert em[("para_revisar", "talvez-jogo.com")] == "IA com dúvida (jogos)", "confiança baixa"
    assert ("para_revisar", "loja-trab.com") in em, "jogos + TRABALHO = incoerente"
    assert ("para_revisar", "whatsapp.com") in em and ("mensageiros", "whatsapp.com") not in em, "decisão humana"
    assert ("pirataria", "sobra.com") in em and ("para_revisar", "sobra.com") not in em, "sobra da migração movida"
    assert em[("para_revisar", "duvida-sobra.com")] == "migração dos grupos antigos"
    assert ("compras", "ja-listado.com") not in em, "já numa lista manual (Infraestrutura): fica onde está"
    assert ("jogos", "de-outros.com") in em and ("outros_bloqueios", "de-outros.com") not in em, "Outros = como Para revisar"
    assert ("para_revisar", "cognito.aws.com") in em and ("nuvem_remoto", "cognito.aws.com") not in em, "infra: revisão"
    assert not any(d == "erp.com.br" for _, d in em)
    assert g.get("roblox.com") == "IA automática (jogos)", "jogos é aplicada: decidido"
    assert "chatgpt.com" not in g, "ninguém aplica IA/Chatbots: não vira decisão"
    assert st["fila"] == 0 and st["com_lista"] == 11
    with db.conn() as c:
        assert listas_ia.aplicar(c) == {"direto": [], "revisar": [], "resolvidos": [], "online": []}, "não reaplica"


def test_detalhes_mostram_sugestao_e_aprovar(env):
    j = env.get("/listas/para_revisar/detalhes", headers=H).json()
    it = {r["domain"]: r for r in j["items"]}
    assert it["talvez-jogo.com"]["lista_ia"] == "jogos" and it["talvez-jogo.com"]["lista_conf"] == pytest.approx(0.6)
    assert j["facetas"]["sugestao"]["jogos"] == 2
    j = env.get("/listas/para_revisar/detalhes", headers=H, params={"sug": "streaming"}).json()
    assert [r["domain"] for r in j["items"]] == ["duvida-sobra.com"]
    r = env.post("/listas-aprovar", headers=H, json={"domains": ["talvez-jogo.com", "duvida-sobra.com", "x.com"],
                                                    "de": "para_revisar", "by": "op"}).json()
    assert r["movidos"] == {"jogos": ["talvez-jogo.com"], "streaming": ["duvida-sobra.com"]} and r["sem_sugestao"] == ["x.com"]
    nomes = {x["domain"] for x in env.get("/listas/para_revisar/detalhes", headers=H).json()["items"]}
    assert "talvez-jogo.com" not in nomes and "whatsapp.com" in nomes
    r = env.post("/listas-aprovar", headers=H, json={"domains": ["ja-listado.com"], "de": "infra_bloqueio"}).json()
    assert r["movidos"] == {"compras": ["ja-listado.com"]}


def test_online_decisao_manual(env):
    from dnsanalyzer import db, listas_ia
    p = env.get("/online/pendentes", headers=H).json()
    assert p == [], "sem GEMINI_API_KEY a dúvida vai direto p/ Para revisar (nada na fila da fase 3)"
    assert env.post("/online/decisao", headers=H, json={"domain": "loja-trab.com", "lista": "nenhuma", "confianca": 1.0,
                                                         "motivo": "loja de peças", "fonte": "claude"}).json()["ok"]
    assert env.post("/online/decisao", headers=H, json={"domain": "x.com", "lista": "jogos", "confianca": 1}).status_code == 404
    assert env.post("/online/decisao", headers=H, json={"domain": "loja-trab.com", "lista": "zz", "confianca": 1}).status_code == 422
    with db.conn() as c:
        ap = listas_ia.aplicar(c)
    assert ap["resolvidos"] == ["loja-trab.com"]
    nomes = {x["domain"] for x in env.get("/listas/para_revisar/detalhes", headers=H).json()["items"]}
    assert "loja-trab.com" not in nomes


def test_fase3_gemini(env, monkeypatch):
    """Com a chave: dúvida local -> fila da fase 3 (não vai p/ Para revisar); resposta do Gemini com
    certeza -> lista; sem certeza -> Para revisar; desconhecido reconhecido -> classificação 'online'."""
    from dnsanalyzer import config, db, listas_ia, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        for n, cls in (("duv1.com", "NAO_TRABALHO"), ("duv2.com", "NAO_TRABALHO")):
            i = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries) "
                          "VALUES (%s, %s, 'outros', now(), 50) RETURNING id", (n, cls)).fetchone()["id"]
            listas_ia.salvar(c, i, "jogos", 0.6, "talvez", "x", "local")
        c.execute("INSERT INTO domains (name, classification, category, analyzed_at, web_search_at, total_queries, classified_by) "
                  "VALUES ('misterio.com.br', 'DESCONHECIDO', 'desconhecido', now(), now(), 99, 'web'), "
                  "('ninguem-sabe.com', 'DESCONHECIDO', 'desconhecido', now(), now(), 1, 'web')")
        ap = listas_ia.aplicar(c)
    assert sorted(n for n, _ in ap["online"]) == ["duv1.com", "duv2.com"] and not ap["revisar"]
    fila = [x["domain"] for x in env.get("/online/pendentes", headers=H).json()]
    assert sorted(fila[:2]) == ["duv1.com", "duv2.com"] and "misterio.com.br" in fila, fila
    resp = {"duv1.com": {"lista": "jogos", "confianca": 1.0, "classificacao": "NAO_TRABALHO", "reconhecido": True},
            "duv2.com": {"lista": "jogos", "confianca": 0.5, "classificacao": "NAO_TRABALHO", "reconhecido": False},
            "misterio.com.br": {"lista": "compras", "confianca": 0.95, "classificacao": "TRABALHO", "categoria": "compras",
                                "reconhecido": True, "servico": "Loja de ferramentas", "motivo": "atacado"},
            "ninguem-sabe.com": {"lista": "nenhuma", "confianca": 0.3, "classificacao": "DESCONHECIDO", "reconhecido": False}}
    buscou = []
    monkeypatch.setattr(online._Cota, "esperar", lambda self: True)
    modelos = []

    def falso(d, cats, buscar, modelo):
        buscou.append((d["name"], buscar)); modelos.append((d["name"], modelo))
        o = dict(resp[d["name"]])
        if modelo == "gemini-3.8-flash" and d["name"] == "duv2.com":   # o reforço também fica em dúvida
            o["confianca"] = 0.6
        return o, {"model": modelo}
    monkeypatch.setattr(online, "perguntar", falso)
    while online.fase(["compras", "outros", "desconhecido"]) == "done":
        pass
    assert not any(b for _, b in buscou), "sem nível de busca configurado"
    assert ("duv1.com", "gemini-3.5-flash-lite") in modelos and ("duv1.com", "gemini-3.8-flash") not in modelos, "certo no principal"
    assert ("duv2.com", "gemini-3.8-flash") in modelos, "sem certeza no principal: reforço"
    assert not any(m.startswith("gemini-2") for _, m in modelos), "busca no Google desligada por padrão (sem cota nesta conta)"
    with db.conn() as c:
        listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists")}
        m = c.execute("SELECT classification, classified_by, topic FROM domains WHERE name='misterio.com.br'").fetchone()
    assert ("jogos", "duv1.com") in em and ("para_revisar", "duv2.com") in em
    assert ("compras", "misterio.com.br") in em, "Compras conta como trabalho"
    assert m == {"classification": "TRABALHO", "classified_by": "online", "topic": "Loja de ferramentas"}
    assert ("para_revisar", "ninguem-sabe.com") in em, "nem a IA online sabe: fase 5 (Decisões)"
    assert env.get("/online/pendentes", headers=H).json() == []
