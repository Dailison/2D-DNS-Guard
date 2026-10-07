"""Etapa "lista": a IA diz a qual lista cada site pertence; certeza -> direto na lista, dúvida -> Para
revisar; aprovação da sugestão; etapa 4. PostgreSQL real (pgserver); a IA é simulada."""

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-lia"
H = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def _sem_exigir_busca(monkeypatch):
    """Os testes da IA online são do fluxo por níveis (sem a exigência de busca na web de 30/09); quem testa a
    exigência liga de novo."""
    from dnsanalyzer import config
    monkeypatch.setattr(config.settings(), "online_exige_busca", False, raising=False)


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
        wl = {r["domain"]: r["added_by"] for r in c.execute("SELECT domain, added_by FROM whitelist_domains")}
    assert ("ia_chatbots", "chatgpt.com") in em and em[("jogos", "roblox.com")] == "IA automática (jogos)"
    assert ("redes_sociais", "tiktok.com") in em
    assert not any(cat == "para_revisar" for cat, _ in em), "sem fase 5: nada vai p/ Para revisar (e quem estava sai)"
    assert em[("jogos", "talvez-jogo.com")] == "IA automática (jogos)", "sem certeza, mas é a última resposta: vale"
    assert ("jogos", "loja-trab.com") not in em and wl.get("loja-trab.com"), "jogos + TRABALHO = incoerente: trava -> whitelist"
    assert ("mensageiros", "whatsapp.com") not in em and wl.get("whatsapp.com") == "decisão humana (liberado)", "decisão humana vale"
    assert ("pirataria", "sobra.com") in em, "sobra da migração movida"
    assert ("streaming", "duvida-sobra.com") in em, "sobra da migração sem certeza: vale a IA"
    assert ("compras", "ja-listado.com") not in em, "já numa lista manual (Infraestrutura): fica onde está"
    assert ("jogos", "de-outros.com") in em and ("outros_bloqueios", "de-outros.com") not in em, "Outros = como Para revisar"
    assert ("nuvem_remoto", "cognito.aws.com") not in em and wl.get("cognito.aws.com"), "infra de sistemas: trava -> whitelist"
    assert not any(d == "erp.com.br" for _, d in em)
    assert g.get("roblox.com") == "IA automática (jogos)", "jogos é aplicada: decidido"
    assert "chatgpt.com" not in g, "ninguém aplica IA/Chatbots: não vira decisão"
    assert st["fila"] == 0 and st["com_lista"] == 11
    with db.conn() as c:
        assert listas_ia.aplicar(c) == {"direto": [], "travados": [], "resolvidos": [], "online": [], "local": {}}, "não reaplica"


def test_detalhes_mostram_sugestao_e_aprovar(env):
    """(sem fase 5, Para revisar fica vazia) a sugestão da IA aparece nas listas manuais e "Aprovar" move p/ a sugerida."""
    j = env.get("/listas/infra_bloqueio/detalhes", headers=H).json()
    it = {r["domain"]: r for r in j["items"]}
    assert it["ja-listado.com"]["lista_ia"] == "compras" and it["ja-listado.com"]["lista_conf"] == pytest.approx(1.0)
    assert j["facetas"]["sugestao"]["compras"] == 1
    assert env.get("/listas/para_revisar/detalhes", headers=H).json()["items"] == []
    r = env.post("/listas-aprovar", headers=H, json={"domains": ["ja-listado.com", "x.com"], "de": "infra_bloqueio", "by": "op"}).json()
    assert r["movidos"] == {"compras": ["ja-listado.com"]} and r["sem_sugestao"] == ["x.com"]


def test_online_decisao_manual(env):
    from dnsanalyzer import db, listas_ia
    p = env.get("/online/pendentes", headers=H).json()
    assert p == [], "sem GEMINI_API_KEY a resposta da IA local é a última (nada na fila da fase 4)"
    assert env.post("/online/decisao", headers=H, json={"domain": "loja-trab.com", "lista": "nenhuma", "confianca": 1.0,
                                                         "motivo": "loja de peças", "fonte": "claude"}).json()["ok"]
    assert env.post("/online/decisao", headers=H, json={"domain": "x.com", "lista": "jogos", "confianca": 1}).status_code == 404
    assert env.post("/online/decisao", headers=H, json={"domain": "loja-trab.com", "lista": "zz", "confianca": 1}).status_code == 422
    with db.conn() as c:
        listas_ia.aplicar(c)
        wl = c.execute("SELECT 1 FROM whitelist_domains WHERE domain = 'loja-trab.com'").fetchone()
        bl = c.execute("SELECT 1 FROM category_lists WHERE domain = 'loja-trab.com'").fetchone()
    assert wl and not bl, "liberado: whitelist, fora das listas de bloqueio"


def test_fase3_gemini(env, monkeypatch):
    """Com a chave: dúvida local -> fila da fase 4; a resposta do Gemini é a última (sem fase 5): com ou sem certeza ->
    lista; nem a IA online identifica -> whitelist; desconhecido reconhecido -> classificação 'online'."""
    from dnsanalyzer import config, db, listas_ia, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        for n, cls in (("duv1.com", "NAO_TRABALHO"), ("duv2.com", "NAO_TRABALHO")):
            # (já passaram pelas fases 2 e 3 sem confiança alta: vão p/ a fase 4)
            i = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                          "VALUES (%s, %s, 'outros', now(), 50, now(), now()) RETURNING id", (n, cls)).fetchone()["id"]
            listas_ia.salvar(c, i, "jogos", 0.6, "talvez", "x", "local")
        c.execute("INSERT INTO domains (name, classification, category, analyzed_at, web_search_at, total_queries, classified_by) "
                  "VALUES ('misterio.com.br', 'DESCONHECIDO', 'desconhecido', now(), now(), 99, 'web'), "
                  "('ninguem-sabe.com', 'DESCONHECIDO', 'desconhecido', now(), now(), 1, 'web')")
        ap = listas_ia.aplicar(c)
    assert sorted(n for n, _ in ap["online"]) == ["duv1.com", "duv2.com"] and not ap["travados"]
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
        if modelo == "gemma-4-31b-it" and d["name"] == "duv2.com":   # o reforço também fica em dúvida
            o["confianca"] = 0.6
        return o, {"model": modelo}
    monkeypatch.setattr(online, "perguntar", falso)
    while online.fase(["compras", "outros", "desconhecido"]) == "done":
        pass
    assert not any(b for _, b in buscou), "sem nível de busca configurado"
    assert ("duv1.com", "gemini-3.5-flash-lite") in modelos and ("duv1.com", "gemini-3.8-flash") not in modelos, "certo no principal"
    assert ("duv2.com", "gemma-4-31b-it") in modelos, "sem certeza no principal: segunda opinião (Gemma)"
    assert not any(m.startswith("gemini-2") for _, m in modelos), "busca no Google desligada por padrão (sem cota nesta conta)"
    with db.conn() as c:
        listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists")}
        m = c.execute("SELECT classification, classified_by, topic FROM domains WHERE name='misterio.com.br'").fetchone()
        wl = {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains")}
    assert ("jogos", "duv1.com") in em and ("jogos", "duv2.com") in em, "sem certeza depois da segunda opinião: vale a IA"
    assert ("compras", "misterio.com.br") in em, "Compras conta como trabalho"
    assert m == {"classification": "TRABALHO", "classified_by": "online", "topic": "Loja de ferramentas"}
    assert ("nao_identificado", "ninguem-sabe.com") in em and "ninguem-sabe.com" not in wl, \
        "nem a IA online sabe: Não identificados (27/09; antes ia p/ a whitelist)"
    assert env.get("/online/pendentes", headers=H).json() == []


def test_gemini_valida_sugestoes(env, monkeypatch):
    from dnsanalyzer import config, db, listas_ia, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n, cls in (("v-certo.com", "NAO_TRABALHO"), ("v-errado.com", "NAO_TRABALHO"), ("playrix.com", "TRABALHO"),
                       ("v-sobra.com", "TRABALHO"), ("v-talvez.com", "NAO_TRABALHO")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, "
                               "web_search_at) VALUES (%s, %s, 'outros', now(), 5, now(), now()) RETURNING id", (n, cls)).fetchone()["id"]
        # v-errado: a IA local já tinha posto sozinha em Compras (antes da validação)
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('compras', 'v-errado.com', 'IA automática (compras)'), "
                  "('para_revisar', 'v-sobra.com', 'migração dos grupos antigos'), ('streaming', 'v-talvez.com', 'IA automática (streaming)')")
        listas_ia.salvar(c, ids["v-certo.com"], "jogos", 1.0, "", "", "local")
        listas_ia.salvar(c, ids["playrix.com"], "jogos", 1.0, "", "", "local")
        ids["slatic.net"] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, "
                                      "web_search_at) VALUES ('slatic.net', 'TRABALHO', 'infraestrutura', now(), 9, now(), now()) "
                                      "RETURNING id").fetchone()["id"]
        listas_ia.salvar(c, ids["slatic.net"], "compras", 0.9, "CDN da Lazada", "", "local")
        ap = listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists")}
    assert ("jogos", "v-certo.com") not in em and ("v-certo.com", "jogos") in ap["online"], "lista com confiança alta: a IA online valida"
    assert ("para_revisar", "playrix.com") not in em and ("playrix.com", "jogos") in ap["online"], "incoerência local: IA online"
    resp = {"v-certo.com": {"lista": "jogos", "confianca": 1.0, "classificacao": "NAO_TRABALHO"},
            "v-errado.com": {"lista": "jogos", "confianca": 0.95, "classificacao": "NAO_TRABALHO"},
            "playrix.com": {"lista": "jogos", "confianca": 1.0, "classificacao": "NAO_TRABALHO", "reconhecido": True},
            "v-sobra.com": {"lista": "nenhuma", "confianca": 1.0, "classificacao": "TRABALHO", "reconhecido": True},
            "v-talvez.com": {"lista": "compras", "confianca": 0.5, "classificacao": "NAO_TRABALHO"},
            "cookiefirst.com": {"lista": "publicidade", "confianca": 0.8, "classificacao": "TRABALHO", "categoria": "publicidade",
                                "reconhecido": True}}
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, lista_duvida) "
                  "VALUES ('cookiefirst.com', 'TRABALHO', 'produtividade', now(), 34, true)")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', 'cookiefirst.com', 'IA com dúvida (publicidade)')")
        for n in ("v-errado.com", "v-sobra.com", "v-talvez.com"):
            c.execute("UPDATE domains SET lista_duvida = true WHERE name = %s", (n,))
    vistos = []
    monkeypatch.setattr(online._Cota, "esperar", lambda self: True)

    def falso(d, cats, buscar, modelo):
        vistos.append((d["name"], d.get("lista_ia"), modelo))
        if d["name"] == "slatic.net":   # o flash-lite discorda da IA local; o Gemma (maior) reconhece a Lazada
            return ({"lista": "nenhuma", "confianca": 0.9, "classificacao": "TRABALHO", "reconhecido": True} if "lite" in modelo
                    else {"lista": "compras", "confianca": 1.0, "classificacao": "TRABALHO", "categoria": "compras",
                          "reconhecido": True}), {"model": modelo}
        return dict(resp[d["name"]]), {"model": modelo}
    monkeypatch.setattr(online, "perguntar", falso)
    while online.fase(["outros"]) == "done":
        pass
    assert {vistos[0][0], vistos[1][0]} == {"v-sobra.com", "cookiefirst.com"}, "o que está em Decisões vai primeiro"
    assert ("v-certo.com", "jogos", "gemini-3.5-flash-lite") in vistos, "a IA online recebe a sugestão da IA local"
    assert ("v-certo.com", "jogos", "gemma-4-31b-it") not in vistos, "concordou com certeza: sem segunda opinião"
    assert ("slatic.net", "compras", "gemma-4-31b-it") in vistos, "discordou da IA local: segunda opinião"
    with db.conn() as c:
        ap = listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists")}
    assert ("jogos", "v-certo.com") in em, "validada -> lista"
    assert ("jogos", "v-errado.com") in em and ("compras", "v-errado.com") not in em, "corrige o que a IA local pôs"
    assert ("jogos", "playrix.com") in em, "coerência pela classificação da IA online"
    assert ("compras", "slatic.net") in em, "vale a resposta do modelo maior"
    assert ("para_revisar", "v-sobra.com") not in em, "nenhuma com certeza: sai de Decisões (na hora, sem esperar o ciclo)"
    assert ("compras", "v-talvez.com") in em and ("streaming", "v-talvez.com") not in em, "sem certeza: vale a última resposta"
    assert ("publicidade", "cookiefirst.com") in em and ("para_revisar", "cookiefirst.com") not in em, \
        "IA online: TRABALHO + publicidade 0,8 = lista (a lista diz o que o site é)"


def test_eventos_da_coluna_decisao(env, monkeypatch):
    from dnsanalyzer import db, llm
    monkeypatch.setattr(llm.OllamaClient, "available", lambda self: (True, "ok"))
    with db.conn() as c:
        kinds = {r["kind"] for r in c.execute("SELECT kind FROM ai_events")}
        ev = {(r["kind"], r["name"]): r["detail"] for r in c.execute("SELECT kind, name, detail FROM ai_events")}
    assert {"lista_add", "decisao"} <= kinds and "fase5" not in kinds, kinds
    assert ev[("lista_add", "roblox.com")].startswith("jogos|IA local")
    assert ev[("lista_add", "talvez-jogo.com")].startswith("jogos|IA local") and "sem certeza" in ev[("lista_add", "talvez-jogo.com")]
    assert any(k == "decisao" and d.startswith("compras|op: aprovou a sugestão") for (k, _), d in ev.items())
    with db.conn() as c:   # muita classificação depois: a carga inicial ainda traz a coluna "Decisão"
        for i in range(80):
            c.execute("INSERT INTO ai_events (kind, name) VALUES ('llm_done', %s)", (f"x{i}.com",))
    j = env.get("/ai/events", headers=H, params={"limit": 30}).json()
    ks = [e["kind"] for e in j["events"]]
    assert ks.count("llm_done") == 30 and any(k in ("lista_add", "fase5", "decisao") for k in ks)


def test_sem_fase5_e_contexto_completo(env):
    import json as _j

    from dnsanalyzer import db, online
    j = env.get("/listas/para_revisar/detalhes", headers=H, params={"fase5": True, "limit": 500}).json()
    assert not j["items"], "sem fase 5: Para revisar fica vazia"
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, classification, category, topic, confidence, corp_action, corp_reason, "
                      "classified_by, reasons, evidence, whois_at, web_search_at, analyzed_at) VALUES ('ctx.com.br', 'DESCONHECIDO', "
                      "'desconhecido', 'não reconhecido', 0.4, 'REVISAR', 'sem informação', 'web', %s, %s, now(), now(), now()) RETURNING id",
                      (_j.dumps([{"by": "ia", "text": "não reconheço"}]),
                       _j.dumps([{"id": "E0", "kind": "identity", "text": "nome"},
                                 {"id": "E3", "kind": "whois", "text": "WHOIS/RDAP: titular PESSOA JURÍDICA 'Ctx Ltda' (CNPJ 1)"},
                                 {"id": "E4", "kind": "websearch", "text": "busca: Ctx Ltda — distribuidora de parafusos " + "x" * 1200}]))).fetchone()["id"]
        c.execute("INSERT INTO classification_history (domain_id, classification, topic, source) VALUES (%s, 'DESCONHECIDO', 'x', 'llm')", (i,))
    t = online.contexto_completo({"id": i, "name": "ctx.com.br"})
    assert "fase 3 (busca na web + IA local)" in t and "2 (WHOIS)" in t and "3 (busca na web)" in t
    assert "WHOIS/RDAP (fase 2): WHOIS/RDAP: titular PESSOA JURÍDICA 'Ctx Ltda'" in t and "distribuidora de parafusos" in t
    assert "Histórico de classificações" in t and "fase 1 (IA local): DESCONHECIDO" in t and "nome" not in t.split("Evidências")[1][:40]


def test_whois_que_falha_sempre_nao_trava(env, monkeypatch):
    from dnsanalyzer import classifier, db, whois

    def cai(*a, **k):
        raise whois.WhoisIndisponivel("rdap.org: ConnectError")
    monkeypatch.setattr(classifier, "build_dossier", cai)
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, classification, classified_by, analyzed_at) VALUES "
                      "('miguhara.co.kr', 'DESCONHECIDO', 'llm', now()) RETURNING id").fetchone()["id"]
    res = []
    for _ in range(3):
        with db.conn() as c:
            d = c.execute("SELECT * FROM domains WHERE id = %s", (i,)).fetchone()
        res.append(classifier._refine(None, [], d, etapa3=True))
        with db.conn() as c:
            r = c.execute("SELECT whois_tries, whois_at, claimed_at > now() + interval '4 minutes' AS adiado "
                          "FROM domains WHERE id = %s", (i,)).fetchone()
        if len(res) < 3:
            assert r["adiado"] and r["whois_at"] is None, "adiado ~10 min (o worker pega outro)"
    assert res == ["deferred", "deferred", "done"] and r["whois_tries"] == 3 and r["whois_at"] is not None, "3ª falha: segue sem WHOIS"


def test_repergunta_tem_segunda_opiniao(env, monkeypatch):
    from psycopg.types.json import Jsonb

    from dnsanalyzer import config, db, listas_ia, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, lista_duvida, online_resp) "
                  "VALUES ('telesco.pe', 'TRABALHO', 'comunicacao', now(), 999, true, %s)",
                  (Jsonb({"lista": "nenhuma", "confianca": 0.95}),))
    vistos = []
    monkeypatch.setattr(online._Cota, "esperar", lambda self: True)

    def falso(d, cats, buscar, modelo):
        vistos.append((d["name"], modelo))
        lista = "nenhuma" if "lite" in modelo else "mensageiros"
        return {"lista": lista, "confianca": 0.95, "classificacao": "TRABALHO", "reconhecido": True}, {"model": modelo}
    monkeypatch.setattr(online, "perguntar", falso)
    assert online.fase(["comunicacao"]) == "done"
    assert [m for n, m in vistos if n == "telesco.pe"] == ["gemini-3.5-flash-lite", "gemma-4-31b-it"]
    with db.conn() as c:
        listas_ia.aplicar(c)
        assert c.execute("SELECT 1 FROM category_lists WHERE category='mensageiros' AND domain='telesco.pe'").fetchone()


def test_fase1_travas_nos_caminhos_automaticos(env, monkeypatch):
    """Plano de confiabilidade, fase 1: protegido/trabalho/popular não entram sozinhos (sem fase 5: vão p/ a whitelist,
    só na lista); bloqueio automático espera a IA online; "nenhuma" sem certeza -> whitelist; DoH popular entra."""
    from dnsanalyzer import config, db, listas, listas_ia
    cfg = config.settings()

    def novo(c, nome, cls, cat, rank=None, corp=None):
        return c.execute("INSERT INTO domains (name, classification, category, popularity_rank, corp_action, analyzed_at, "
                         "total_queries) VALUES (%s, %s, %s, %s, %s, now(), 5) RETURNING id", (nome, cls, cat, rank, corp)).fetchone()["id"]

    def em(c, nome):
        return {r["category"]: r["added_by"] for r in c.execute("SELECT category, added_by FROM category_lists WHERE domain=%s", (nome,))}

    def wl(c, nome):
        return c.execute("SELECT category FROM whitelist_domains WHERE domain = %s AND NOT publicar", (nome,)).fetchone()

    # 1) protegido do catálogo com resposta online "streaming" 0,95 -> Decisões
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    with db.conn() as c:
        i = novo(c, "microsoft.com", "NAO_TRABALHO", "streaming")
        listas_ia.salvar(c, i, "streaming", 0.95, "", "", "online:gemini")
        listas_ia.aplicar(c)
        m, w = em(c, "microsoft.com"), wl(c, "microsoft.com")
    assert not m and w, (m, w)
    # 2) categoria de trabalho (financas), IA local "compras" 0,95, IA online DESLIGADA -> Decisões
    monkeypatch.setattr(cfg, "gemini_api_key", "")
    with db.conn() as c:
        i = novo(c, "banco-x.com.br", "NAO_TRABALHO", "financas")
        listas_ia.salvar(c, i, "compras", 0.95, "", "", "local")
        listas_ia.aplicar(c)
        m, w = em(c, "banco-x.com.br"), wl(c, "banco-x.com.br")
    assert not m and w, (m, w)
    # 3) bloqueio automático com a IA online ligada: fonte local não bloqueia (fila da fase 4); online 0,9 bloqueia
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    with db.conn() as c:
        a = novo(c, "jogo-local.com", "NAO_TRABALHO", "jogos", corp="BLOQUEAR")
        b = novo(c, "jogo-online.com", "NAO_TRABALHO", "jogos", corp="BLOQUEAR")
        listas_ia.salvar(c, a, "jogos", 1.0, "", "", "local")
        listas_ia.salvar(c, b, "jogos", 0.9, "", "", "online:gemini")
        c.execute("UPDATE domains SET lista_aplicada_at = lista_at WHERE id = ANY(%s)", ([a, b],))   # só o bloqueio automático
        listas.bloquear_auto(c)
        duv = c.execute("SELECT lista_duvida FROM domains WHERE id=%s", (a,)).fetchone()["lista_duvida"]
        ma, mb = em(c, "jogo-local.com"), em(c, "jogo-online.com")
    assert "jogos" not in ma and duv, ma
    assert mb.get("jogos", "").startswith("bloqueio automático"), mb
    # 4) "nenhuma" 0,5 da IA online em não trabalho fora de lista -> Decisões
    with db.conn() as c:
        i = novo(c, "talvez-nada.com", "NAO_TRABALHO", "outros")
        listas_ia.salvar(c, i, "nenhuma", 0.5, "", "", "online:gemini")
        c.execute("UPDATE domains SET online_at = now() WHERE id = %s", (i,))
        listas_ia.aplicar(c)
        m, w = em(c, "talvez-nada.com"), wl(c, "talvez-nada.com")
    assert not m and w, (m, w)
    # 5) DoH/DNS: só com dois modelos online de acordo (≥ 0,95); um só (ou 0,85) -> Decisões
    from psycopg.types.json import Jsonb
    with db.conn() as c:
        i = novo(c, "dns.google", "TRABALHO", "infraestrutura", rank=50)
        listas_ia.salvar(c, i, "doh_dns", 1.0, "", "", "online:gemini")
        c.execute("UPDATE domains SET online_resp = %s WHERE id = %s",
                  (Jsonb({"_meta": {"antes": {"lista": "doh_dns", "confianca": 1.0}}}), i))
        j2 = novo(c, "impervadns.net", "TRABALHO", "infraestrutura", rank=506)
        listas_ia.salvar(c, j2, "doh_dns", 1.0, "", "", "online:gemini")   # um modelo só
        j3 = novo(c, "bibledns.com", "TRABALHO", "infraestrutura", rank=24340)
        listas_ia.salvar(c, j3, "doh_dns", 0.85, "", "", "online:gemini")
        c.execute("UPDATE domains SET online_resp = %s WHERE id = %s",
                  (Jsonb({"_meta": {"antes": {"lista": "doh_dns", "confianca": 0.85}}}), j3))
        listas_ia.aplicar(c)
        m, m2, m3 = em(c, "dns.google"), em(c, "impervadns.net"), em(c, "bibledns.com")
        w2, w3 = wl(c, "impervadns.net"), wl(c, "bibledns.com")
    assert "doh_dns" in m and "para_revisar" not in m, m
    assert not m2 and w2, "DoH com um modelo só: não bloqueia (whitelist, só na lista)"
    assert not m3 and w3, m3
    # 5b) uso misto (Mensageiros) popular e "comunicação" entra (só a trava do catálogo vale)
    with db.conn() as c:
        i = novo(c, "viber.com", "TRABALHO", "comunicacao", rank=900)
        listas_ia.salvar(c, i, "mensageiros", 0.95, "", "", "online:gemini")
        listas_ia.aplicar(c)
        m = em(c, "viber.com")
    assert "mensageiros" in m and "para_revisar" not in m, m
    # 6) CMP de cookies: a IA local diz "produtividade", a online diz "publicidade" -> sem trava, entra
    with db.conn() as c:
        i = novo(c, "cookie-cmp.com", "TRABALHO", "produtividade")
        listas_ia.salvar(c, i, "publicidade", 0.9, "", "", "online:gemini")
        c.execute("UPDATE domains SET online_resp = '{\"categoria\": \"publicidade\", \"classificacao\": \"TRABALHO\"}' WHERE id = %s", (i,))
        listas_ia.aplicar(c)
        m = em(c, "cookie-cmp.com")
    assert "publicidade" in m and "para_revisar" not in m, m
    rev = {r["domain"] for r in env.get("/listas/para_revisar/detalhes", headers=H, params={"limit": 1000}).json()["items"]}
    assert not {"banco-x.com.br", "microsoft.com", "talvez-nada.com", "impervadns.net"} & rev, "sem fase 5"


def test_doh_pede_segunda_opiniao(env, monkeypatch):
    from dnsanalyzer import config, db, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, lista_duvida) "
                  "VALUES ('doh.exemplo.net', 'TRABALHO', 'infraestrutura', now(), 5000, true)")
    vistos = []
    monkeypatch.setattr(online._Cota, "esperar", lambda self: True)

    def falso(d, cats, buscar, modelo):
        vistos.append((d["name"], modelo))
        return {"lista": "doh_dns", "confianca": 1.0, "classificacao": "TRABALHO", "reconhecido": True}, {"model": modelo}
    monkeypatch.setattr(online, "perguntar", falso)
    online.fase(["infraestrutura"])
    assert [m for n, m in vistos if n == "doh.exemplo.net"] == ["gemini-3.5-flash-lite", "gemma-4-31b-it"]
    with db.conn() as c:
        antes = c.execute("SELECT online_resp->'_meta'->'antes' AS a FROM domains WHERE name='doh.exemplo.net'").fetchone()["a"]
    assert antes["lista"] == "doh_dns" and antes["confianca"] == 1.0


def test_malicioso_da_ia_online_com_certeza_entra_em_ameacas(env):
    from dnsanalyzer import db, listas_ia, online
    with db.conn() as c:
        ids = {}
        for n in ("fdacebook-teste.info", "talvez-golpe.info"):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at) VALUES "
                               "(%s, 'DESCONHECIDO', 'desconhecido', now()) RETURNING id", (n,)).fetchone()["id"]
        online.gravar(c, {"id": ids["fdacebook-teste.info"], "name": "fdacebook-teste.info", "classification": "DESCONHECIDO"},
                      {"lista": "ameaca", "confianca": 0.95, "classificacao": "MALICIOSO", "reconhecido": True}, {"model": "g"}, [])
        online.gravar(c, {"id": ids["talvez-golpe.info"], "name": "talvez-golpe.info", "classification": "DESCONHECIDO"},
                      {"lista": "ameaca", "confianca": 0.6, "classificacao": "MALICIOSO", "reconhecido": True}, {"model": "g"}, [])
        listas_ia.aplicar(c)
        em = {r["domain"]: r["category"] for r in c.execute(
            "SELECT domain, category FROM category_lists WHERE domain IN ('fdacebook-teste.info', 'talvez-golpe.info')")}
    assert em == {"fdacebook-teste.info": "ameaca", "talvez-golpe.info": "ameaca"}, "sem fase 5: a última resposta vale"


def test_candidato_a_whitelist_pede_segunda_opiniao(env, monkeypatch):
    from dnsanalyzer import config, db, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, lista_duvida) "
                  "VALUES ('erp-wl.com.br', 'TRABALHO', 'produtividade', now(), 7000, true)")
    vistos = []
    monkeypatch.setattr(online._Cota, "esperar", lambda self: True)
    monkeypatch.setattr(online, "perguntar", lambda d, cats, b, m: (vistos.append((d["name"], m)) or
                        {"lista": "nenhuma", "confianca": 0.95, "classificacao": "TRABALHO", "reconhecido": True}, {"model": m}))
    online.fase(["produtividade"])
    assert [m for n, m in vistos if n == "erp-wl.com.br"] == ["gemini-3.5-flash-lite", "gemma-4-31b-it"]
    with db.conn() as c:
        a = c.execute("SELECT online_resp->'_meta'->'antes' AS a FROM domains WHERE name='erp-wl.com.br'").fetchone()["a"]
    assert a["classificacao"] == "TRABALHO" and a["lista"] == "nenhuma"


def test_revisao_da_infraestrutura(env):
    from psycopg.types.json import Jsonb

    from dnsanalyzer import db, listas_ia
    dois = {"_meta": {"antes": {"lista": "nenhuma", "confianca": 0.95}}}
    maior = {"_meta": {"nivel_reforco": True}}
    suspeito = {"classificacao": "SUSPEITO", "_meta": {"nivel_reforco": True}}
    with db.conn() as c:
        casos = (("888win-infra.win", "apostas", 0.95, {}, "migração dos grupos antigos"),
                 ("telemetria-infra.net", "nenhuma", 0.95, {}, "migração dos grupos antigos"),       # modelo pequeno: Decisões
                 ("trafficmanager-infra.net", "nenhuma", 0.95, dois, "migração dos grupos antigos"),  # 2 modelos: sai
                 ("omnichat-infra.net", "nenhuma", 0.9, maior, "migração dos grupos antigos"),        # modelo maior: sai
                 ("suspeito-infra.net", "nenhuma", 0.9, suspeito, "migração dos grupos antigos"),     # suspeito: Decisões
                 ("duvida-infra.net", "nenhuma", 0.5, maior, "migração dos grupos antigos"),          # sem certeza: Decisões
                 ("pessoa-infra.net", "nenhuma", 1.0, dois, "op@2d"))                                # posto por pessoa
        for n, lista, conf, resp, por in casos:
            i = c.execute("INSERT INTO domains (name, classification, category, analyzed_at) VALUES (%s, 'TRABALHO', 'infraestrutura', now()) "
                          "RETURNING id", (n,)).fetchone()["id"]
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('infra_bloqueio', %s, %s)", (n, por))
            listas_ia.salvar(c, i, lista, conf, "", "", "online:gemini")
            extra = {"classificacao": "NAO_TRABALHO", "categoria": "apostas"} if lista == "apostas" else {"classificacao": "TRABALHO"}
            c.execute("UPDATE domains SET online_resp = %s WHERE id = %s", (Jsonb({**extra, **resp}), i))
        listas_ia.aplicar(c)
        em = {}
        for r in c.execute("SELECT domain, category FROM category_lists WHERE domain LIKE '%%-infra.%%'"):
            em.setdefault(r["domain"], set()).add(r["category"])
    assert em.get("888win-infra.win") == {"apostas"}, em
    assert em.get("telemetria-infra.net") == {"infra_bloqueio"}, "modelo pequeno só: fica na Infraestrutura"
    assert "trafficmanager-infra.net" not in em, "dois modelos: sai"
    assert "omnichat-infra.net" not in em, "resposta do modelo maior: sai"
    assert em.get("suspeito-infra.net") == {"infra_bloqueio"}, "suspeito: não libera"
    assert em.get("duvida-infra.net") == {"infra_bloqueio"}, "sem certeza: fica onde está (bloqueado)"
    assert em.get("pessoa-infra.net") == {"infra_bloqueio"}, "posto por pessoa: vale a pessoa"


def test_nenhuma_da_ia_local_na_infraestrutura_vai_p_validacao(env, monkeypatch):
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, whois_at, web_search_at) VALUES "
                      "('local-nenhuma-infra.net', 'TRABALHO', 'comunicacao', now(), now(), now()) RETURNING id").fetchone()["id"]
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('infra_bloqueio', 'local-nenhuma-infra.net', "
                  "'migração dos grupos antigos')")
        listas_ia.salvar(c, i, "nenhuma", 0.95, "", "", listas_ia.FONTE_LOCAL)
        listas_ia.aplicar(c)
        assert c.execute("SELECT lista_duvida FROM domains WHERE id = %s", (i,)).fetchone()["lista_duvida"], \
            "a IA online valida antes de tirar da Infraestrutura"


def test_reanalisar_leva_decidido_pela_fase_1(env):
    from dnsanalyzer import classifier, db, online
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, classification, classified_by, total_queries, analyzed_at) VALUES "
                      "('decidido-rean.net', 'TRABALHO', 'llm', 10, now()) RETURNING id").fetchone()["id"]
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', 'op@2d')", (i,))
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', 'decidido-rean.net', 'IA com dúvida (jogos)')")
        c.execute("UPDATE domains SET lista_duvida = true WHERE id = %s", (i,))
    r = env.post("/domains-reanalyze", json={"domains": ["decidido-rean.net"], "by": "tec@2d"}, headers=H)
    assert r.status_code == 200 and r.json()["enviados"] == 1, r.text
    with db.conn() as c:   # sai da fase em que estava (Decisão Humana e fila da IA online) e volta à fase 1
        assert not c.execute("SELECT 1 FROM category_lists WHERE category = 'para_revisar' AND domain = 'decidido-rean.net'").fetchone()
        assert not c.execute("SELECT lista_duvida FROM domains WHERE id = %s", (i,)).fetchone()["lista_duvida"]
        ev = c.execute("SELECT origem, detail FROM ai_events WHERE kind = 'decisao' AND name = 'decidido-rean.net'").fetchone()
        au = c.execute("SELECT por, motivo FROM list_audit WHERE domain = 'decidido-rean.net' AND acao = 'remove'").fetchone()
    assert ev and ev["origem"] == "f5:ti" and "tec@2d: pediu nova análise" in ev["detail"], ev
    # pedida numa lista de bloqueio (ou whitelist): sai dela
    with db.conn() as c:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'decidido-rean.net', 'op@2d')")
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by) VALUES ('educacao', 'decidido-rean.net', 'op@2d')")
    assert env.post("/domains-reanalyze", json={"domains": ["decidido-rean.net"], "by": "tec@2d", "de": "jogos"}, headers=H).json()["enviados"] == 1
    assert env.post("/domains-reanalyze", json={"domains": ["decidido-rean.net"], "by": "tec@2d", "de": "wl:educacao"}, headers=H).json()["enviados"] == 1
    with db.conn() as c:
        assert not c.execute("SELECT 1 FROM category_lists WHERE category = 'jogos' AND domain = 'decidido-rean.net'").fetchone()
        assert not c.execute("SELECT 1 FROM whitelist_domains WHERE domain = 'decidido-rean.net'").fetchone()
    assert au and au["por"] == "tec@2d" and "nova análise" in au["motivo"], au
    with db.conn() as c:
        c.execute("UPDATE domains SET needs_analysis = false, llm_pending = true WHERE id = %s", (i,))   # (fase A)
        assert c.execute("SELECT reanalise_pedida FROM domains WHERE id = %s", (i,)).fetchone()["reanalise_pedida"]
        c.execute("UPDATE domains SET lista_duvida = true, lista_at = now() WHERE id = %s", (i,))
        pegos = set()
        for _ in range(500):   # a fase 4 espera a fase 1
            x = online._reservar(c)
            if x is None:
                break
            pegos.add(x["name"])
        assert "decidido-rean.net" not in pegos
        vistos = set()
        for _ in range(500):
            x = classifier._claim_llm(c)
            if x is None:
                break
            vistos.add(x["name"])
        assert "decidido-rean.net" in vistos, "revisão pedida: a fase 1 pega mesmo decidido"


def test_revisao_da_infraestrutura_vem_antes_na_fila(env):
    from dnsanalyzer import db, online
    with db.conn() as c:
        for n, q, cat, por in (("grande-fila.com", 10**9, "para_revisar", "IA com dúvida (jogos)"),
                               ("infra-fila.net", 1, "infra_bloqueio", "migração dos grupos antigos")):
            c.execute("INSERT INTO domains (name, classification, total_queries, lista_duvida, analyzed_at) "
                      "VALUES (%s, 'TRABALHO', %s, true, now())", (n, q))
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s)", (cat, n, por))
        primeiro = None
        for _ in range(500):
            r = online._reservar(c)
            if r is None:
                break
            if r["name"] in ("grande-fila.com", "infra-fila.net"):
                primeiro = r
                break
    assert primeiro and primeiro["name"] == "infra-fila.net" and primeiro["em_infra"], primeiro


def test_decidido_com_llm_pending_nao_fica_preso_e_nao_vai_p_decisoes(env):
    from dnsanalyzer import db, online
    with db.conn() as c:
        ids = {}
        for n, cat in (("preso-adulto.cc", "adulto"), ("preso-infra.cc", "infra_bloqueio")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, total_queries, lista_duvida, llm_pending, analyzed_at) "
                               "VALUES (%s, 'DESCONHECIDO', 10, true, true, now()) RETURNING id", (n,)).fetchone()["id"]
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, 'migração dos grupos antigos')", (cat, n))
            c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', 'op@2d')", (ids[n],))
        pegos = set()
        for _ in range(500):
            r = online._reservar(c)
            if r is None:
                break
            pegos.add(r["name"])
            if {"preso-adulto.cc", "preso-infra.cc"} <= pegos:
                break
        assert {"preso-adulto.cc", "preso-infra.cc"} <= pegos, "decidido com llm_pending entra na fila online"
        for n in ids:   # a IA online também não reconhece
            online.gravar(c, {"id": ids[n], "name": n, "classification": "DESCONHECIDO"},
                          {"lista": "nenhuma", "confianca": 0.4, "classificacao": "DESCONHECIDO", "reconhecido": False}, {"model": "g"}, [])
        rev = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category = 'para_revisar' AND domain LIKE 'preso-%%'")}
    assert not rev, "sem fase 5: ninguém vai p/ Para revisar (Adulto e Infraestrutura, postos pela migração, ficam)"


def test_cascata_por_confianca(env, monkeypatch):
    """Sem confiança alta: fase 2 (WHOIS) -> 3 (busca) -> 4 (IA online). Lista com confiança alta: a IA online valida
    (prova de 27/09: a IA local não acertou 100% no bloqueio). "Nenhuma lista" com confiança alta p/ site fora de
    listas: a IA local decide (Aprovados)."""
    from types import SimpleNamespace

    from dnsanalyzer import config, db, listas_ia
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    monkeypatch.setattr(cfg, "web_search_url", "http://searx")
    with db.conn() as c:
        ids = {}
        for n in ("cascata-a.com", "cascata-b.com", "cascata-c.com", "cascata-e.com"):   # (lista_duvida de rodada anterior)
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, lista_duvida) "
                               "VALUES (%s, 'NAO_TRABALHO', 'outros', now() - interval '1 minute', 5, true) RETURNING id", (n,)).fetchone()["id"]
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', 'cascata-c.com', 'IA com dúvida (jogos)')")
        c.execute("UPDATE domains SET whois_at = now(), web_search_at = now() WHERE name IN ('cascata-b.com', 'cascata-c.com', 'cascata-e.com')")
        listas_ia.salvar(c, ids["cascata-a.com"], "jogos", 0.6, "talvez", "", "local")
        listas_ia.salvar(c, ids["cascata-b.com"], "jogos", 0.95, "jogo online", "", "local")
        listas_ia.salvar(c, ids["cascata-c.com"], "nenhuma", 0.95, "loja", "", "local")
        listas_ia.salvar(c, ids["cascata-e.com"], "nenhuma", 0.95, "portal de RH", "", "local", 2)
        ap = listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists WHERE domain LIKE 'cascata-%%'")}
        a = c.execute("SELECT lista_duvida, (" + listas_ia.incerta_sql() + ") AS incerta FROM domains WHERE id = %s",
                      (ids["cascata-a.com"],)).fetchone()
        b = c.execute("SELECT lista_duvida, revisado_at FROM domains WHERE id = %s", (ids["cascata-b.com"],)).fetchone()
        cc = c.execute("SELECT lista_duvida FROM domains WHERE id = %s", (ids["cascata-c.com"],)).fetchone()
        e = c.execute("SELECT lista_duvida, revisado_at FROM domains WHERE id = %s", (ids["cascata-e.com"],)).fetchone()
    assert not a["lista_duvida"] and a["incerta"] and not any(n == "cascata-a.com" for n, _ in ap["online"]), "sem confiança: fase 2 antes"
    assert ("jogos", "cascata-b.com") not in em and b["lista_duvida"], "lista com confiança alta: a IA online valida"
    assert ("para_revisar", "cascata-c.com") in em and cc["lista_duvida"], "tirar de Decisões: a IA online valida"
    assert e["lista_duvida"] and not e["revisado_at"], "liberar com confiança alta: a IA online valida (a local não decide sozinha)"
    with db.conn() as c:   # a IA online confirma a liberação: vai p/ a whitelist; a coluna "Decisão" mostra quem decidiu
        listas_ia.salvar(c, ids["cascata-e.com"], "wl:rh_beneficios", 0.9, "portal de RH", "RH X", "online:gemini", 4)
        listas_ia.aplicar(c)
        org = c.execute("SELECT origem FROM ai_events WHERE kind = 'aprovado' AND name = 'cascata-e.com'").fetchone()
        wle = c.execute("SELECT category, added_by FROM whitelist_domains WHERE domain = 'cascata-e.com'").fetchone()
    assert org and org["origem"] == "f4:online" and wle["category"] == "rh_beneficios" and wle["added_by"] == "IA online", (org, wle)
    ev = env.get("/ai/events", headers=H).json()
    assert any(x.get("name") == "cascata-e.com" and x.get("origem") == "f4:online" for x in ev.get("events", ev) if isinstance(x, dict)), \
        "a API entrega a origem"
    with db.conn() as c:   # fases 2 e 3 sem dados úteis: agora vai p/ a fase 4
        c.execute("UPDATE domains SET whois_at = now(), web_search_at = now(), lista_aplicada_at = NULL WHERE id = %s",
                  (ids["cascata-a.com"],))
        ap = listas_ia.aplicar(c)
        a = c.execute("SELECT lista_duvida FROM domains WHERE id = %s", (ids["cascata-a.com"],)).fetchone()
    assert a["lista_duvida"] and ("cascata-a.com", "jogos") in ap["online"], "depois da fase 3 sem confiança: IA online"
    # o log mostra o que a IA local respondeu e o próximo passo
    monkeypatch.setattr(listas_ia, "perguntar", lambda client, d: (
        SimpleNamespace(lista="jogos", confianca=0.6, motivo="parece jogo", servico="Portal X"), {"seconds": 1.0}))
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at) "
                      "VALUES ('cascata-d.com', 'NAO_TRABALHO', 'outros', now(), 5, now()) RETURNING id").fetchone()["id"]
    assert listas_ia.sugerir(None, i, 2) == "done"
    with db.conn() as c:
        ev = c.execute("SELECT detail FROM ai_events WHERE kind = 'lista_local' AND name = 'cascata-d.com'").fetchone()
    assert ev and ev["detail"].startswith("2|lista jogos 60% · Portal X — parece jogo") and "segue p/ a fase 3" in ev["detail"], ev


def test_todo_site_vai_p_uma_fila_whitelist(env, monkeypatch):
    """Liberar = entrar numa whitelist por categoria. IA sozinha: na categoria, sem publicar no DNS; dois modelos
    online, catálogo ou pessoa: publicado (/whitelist/<cat>.txt)."""
    from psycopg.types.json import Jsonb

    from dnsanalyzer import config, db, listas_ia, whitelist
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    assert "wl:financas" in listas_ia._schema()["properties"]["lista"]["enum"] and "nenhuma" not in listas_ia._schema()["properties"]["lista"]["enum"]
    with db.conn() as c:
        ids = {}
        for n, cls, cat in (("banco-wlf.com.br", "TRABALHO", "financas"), ("escola-wlf.com.br", "TRABALHO", "educacao"),
                            ("decidir-wlf.com.br", "TRABALHO", "outros")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, "
                               "web_search_at) VALUES (%s, %s, %s, now(), 5, now(), now()) RETURNING id", (n, cls, cat)).fetchone()["id"]
        listas_ia.salvar(c, ids["banco-wlf.com.br"], "wl:financas", 0.95, "banco digital", "Banco X", "local", 2)
        # (liberação da IA local de antes da validação: entrada provisória, que a resposta da IA online substitui)
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES ('comunicacao', 'banco-wlf.com.br', "
                  "'IA local (fase 2)', false)")
        listas_ia.salvar(c, ids["escola-wlf.com.br"], "wl:educacao", 0.9, "escola", "Escola Y", "online:gemini", 4)
        c.execute("UPDATE domains SET online_resp = %s WHERE id = %s", (Jsonb({"classificacao": "TRABALHO", "reconhecido": True,
                  "categoria": "educacao", "_meta": {"antes": {"lista": "wl:educacao", "confianca": 0.95, "classificacao": "TRABALHO"}}}),
                  ids["escola-wlf.com.br"]))
        listas_ia.aplicar(c)
        assert c.execute("SELECT lista_duvida FROM domains WHERE id = %s", (ids["banco-wlf.com.br"],)).fetchone()["lista_duvida"], \
            "liberação da IA local vai p/ a IA online"
    with db.conn() as c:   # (resposta da IA online noutra transação, como em produção: now() muda)
        listas_ia.salvar(c, ids["banco-wlf.com.br"], "wl:financas", 0.9, "banco digital", "Banco X", "online:gemini", 4)
        listas_ia.aplicar(c)
        wl = {r["domain"]: r for r in c.execute("SELECT domain, category, publicar, added_by FROM whitelist_domains WHERE domain LIKE '%%-wlf.com.br'")}
        assert wl["banco-wlf.com.br"]["category"] == "financas" and not wl["banco-wlf.com.br"]["publicar"], wl
        assert wl["banco-wlf.com.br"]["added_by"] == "IA online", "a categoria da IA online substitui a provisória da IA local"
        assert wl["escola-wlf.com.br"]["category"] == "educacao" and not wl["escola-wlf.com.br"]["publicar"]
        whitelist.aplicar(c)   # dois modelos online de acordo (TRABALHO, whitelist): passa a valer no DNS
        pub = {r["domain"]: r["publicar"] for r in c.execute("SELECT domain, publicar FROM whitelist_domains WHERE domain LIKE '%%-wlf.com.br'")}
        assert pub == {"banco-wlf.com.br": False, "escola-wlf.com.br": True}, pub
        assert "banco-wlf.com.br" not in whitelist.dominios(c, "financas") and "escola-wlf.com.br" in whitelist.dominios(c, "educacao")
        ev = c.execute("SELECT detail, origem, classification FROM ai_events WHERE kind = 'aprovado' AND name = 'banco-wlf.com.br'").fetchone()
        assert ev["origem"] == "f4:online" and ev["detail"].startswith("wl:financas|Bancos") and ev["classification"] == "TRABALHO", ev
        # Decisão Humana: aprovar a sugestão "wl:..." libera na whitelist (publicada) e registra a decisão
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', 'decidir-wlf.com.br', 'IA com dúvida (nenhuma)')")
        listas_ia.salvar(c, ids["decidir-wlf.com.br"], "wl:logistica", 0.6, "transportadora", "Transp Z", "online:gemini", 4)
    r = env.post("/listas-aprovar", json={"domains": ["decidir-wlf.com.br"], "de": "para_revisar", "by": "tec@2d"}, headers=H).json()
    assert r["liberados"] == {"logistica": ["decidir-wlf.com.br"]}, r
    # pessoa liberando noutra categoria: muda de categoria (uma só) e fica publicado
    assert env.post("/whitelist/rh_beneficios", json={"domains": ["banco-wlf.com.br"], "by": "tec@2d"}, headers=H).status_code == 200
    with db.conn() as c:
        wl = {(r["domain"], r["category"]): r["publicar"] for r in c.execute("SELECT domain, category, publicar FROM whitelist_domains WHERE domain LIKE '%%-wlf.com.br'")}
        g = c.execute("SELECT status FROM global_reviews g JOIN domains d ON d.id = g.domain_id WHERE d.name = 'decidir-wlf.com.br'").fetchone()
        rev = c.execute("SELECT 1 FROM category_lists WHERE category = 'para_revisar' AND domain = 'decidir-wlf.com.br'").fetchone()
    assert wl[("decidir-wlf.com.br", "logistica")] is True and not rev and g["status"] == "allowed", (wl, g)
    assert ("banco-wlf.com.br", "financas") not in wl and wl[("banco-wlf.com.br", "rh_beneficios")] is True, wl


def test_coletor_conta_respostas_sem_ip():
    """Pelo log do Technitium: só consulta A não bloqueada conta; sem IP = NXDOMAIN, SERVFAIL, REFUSED ou NoError vazio."""
    from dnsanalyzer.collector import sem_ip
    assert sem_ip({"qtype": "A", "responseType": "Recursive", "rcode": "NoError", "answer": ""}) == (True, True)   # hbgamesnm.com
    assert sem_ip({"qtype": "A", "responseType": "Recursive", "rcode": "NoError", "answer": "1.2.3.4"}) == (True, False)
    assert sem_ip({"qtype": "A", "responseType": "Recursive", "rcode": "ServerFailure", "answer": ""}) == (True, True)
    assert sem_ip({"qtype": "AAAA", "responseType": "Recursive", "rcode": "NoError", "answer": ""}) == (False, False), "sem IPv6 é normal"
    assert sem_ip({"qtype": "A", "responseType": "Blocked", "rcode": "NoError", "answer": "0.0.0.0"}) == (False, False)
    assert sem_ip({"qtype": "A", "responseType": "Authoritative", "rcode": "Refused", "answer": ""}) == (False, False), "política"
    assert sem_ip({"qtype": "A", "responseType": "Cached", "rcode": "NoError", "answer": ""}) == (True, True)


def test_modelo_aprovado_decide_sozinho(env, monkeypatch):
    """gemma4 (passou na prova) decide sozinho com confiança alta — bloqueio ou whitelist; qwen3:8b vai p/ a IA online;
    as travas (DoH: dois modelos online) valem p/ qualquer modelo."""
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n, cls, cat in (("jogo-gm.com", "NAO_TRABALHO", "jogos"), ("escola-gm.com.br", "TRABALHO", "educacao"),
                            ("jogo-8b.com", "NAO_TRABALHO", "jogos"), ("doh-gm.net", "NAO_TRABALHO", "infraestrutura")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, "
                               "web_search_at) VALUES (%s, %s, %s, now(), 5, now(), now()) RETURNING id", (n, cls, cat)).fetchone()["id"]
        listas_ia.salvar(c, ids["jogo-gm.com"], "jogos", 0.95, "jogo online", "Jogo", "local", 1, "gemma4:26b")
        listas_ia.salvar(c, ids["escola-gm.com.br"], "wl:educacao", 0.95, "escola", "Escola", "local", 2, "gemma4:26b")
        listas_ia.salvar(c, ids["jogo-8b.com"], "jogos", 0.95, "jogo online", "Jogo", "local", 1, "qwen3:8b")
        listas_ia.salvar(c, ids["doh-gm.net"], "doh_dns", 1.0, "DoH", "DoH", "local", 1, "gemma4:26b")
        listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists WHERE domain LIKE '%%-gm.%%' OR domain LIKE '%%-8b.%%'")}
        wl = c.execute("SELECT category, added_by FROM whitelist_domains WHERE domain = 'escola-gm.com.br'").fetchone()
        duv = {r["name"]: r["lista_duvida"] for r in c.execute("SELECT name, lista_duvida FROM domains WHERE id = ANY(%s)", (list(ids.values()),))}
        ev = c.execute("SELECT origem FROM ai_events WHERE kind = 'lista_add' AND name = 'jogo-gm.com'").fetchone()
    assert ("jogos", "jogo-gm.com") in em and not duv["jogo-gm.com"] and ev["origem"] == "f1:local", (em, duv)
    assert wl and wl["category"] == "educacao" and wl["added_by"] == "IA local (fase 2)" and not duv["escola-gm.com.br"], wl
    assert ("jogos", "jogo-8b.com") not in em and duv["jogo-8b.com"], "qwen3:8b não decide sozinho: IA online"
    assert ("doh_dns", "doh-gm.net") not in em and duv["doh-gm.net"], "DoH: trava de dois modelos online vale p/ qualquer modelo"


def test_confianca_alta_com_trava_passa_pelas_fases_2_e_3(env, monkeypatch):
    """Nenhum domínio vai da fase 1 direto p/ a 4 (pedido do usuário 27/09): gemma4 com 100% mas com trava (ameaça num
    SUSPEITO) segue p/ o WHOIS e a busca na web; só depois da fase 3 vai p/ a IA online. O log diz o destino real."""
    from types import SimpleNamespace

    from dnsanalyzer import config, db, listas_ia
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    monkeypatch.setattr(cfg, "web_search_url", "http://searx")
    with db.conn() as c:
        i = c.execute("INSERT INTO domains (name, tld, kind, classification, category, analyzed_at, total_queries, lista_duvida) "
                      "VALUES ('trava-f1.vip', 'vip', 'public', 'SUSPEITO', 'outros', now() - interval '1 minute', 5, true) "
                      "RETURNING id").fetchone()["id"]
    resp = SimpleNamespace(lista="ameaca", confianca=1.0, motivo="typosquat", servico="")
    monkeypatch.setattr(listas_ia, "perguntar", lambda client, d: (resp, {"seconds": 1.0}))
    cliente = SimpleNamespace(model="gemma4:26b")
    with db.conn() as c:
        d = c.execute("SELECT id, name, classification, whois_at, web_search_at FROM domains WHERE id = %s", (i,)).fetchone()
    listas_ia._sugerir(cliente, d, 1)
    with db.conn() as c:
        r = c.execute("SELECT lista_duvida, lista_segue, (" + listas_ia.incerta_sql() + ") AS incerta FROM domains WHERE id = %s",
                      (i,)).fetchone()
        ev = c.execute("SELECT detail FROM ai_events WHERE kind = 'lista_local' AND name = 'trava-f1.vip'").fetchone()
        em = c.execute("SELECT 1 FROM category_lists WHERE domain = 'trava-f1.vip'").fetchone()
    assert not r["lista_duvida"] and r["lista_segue"] and r["incerta"] and not em, r
    assert "confiança alta, trava: ameaça sem classificação maliciosa (SUSPEITO): segue p/ a fase 2" in ev["detail"], ev
    assert "a IA local decide" not in ev["detail"]
    with db.conn() as c:   # fases 2 e 3 feitas, trava continua: IA online
        c.execute("UPDATE domains SET whois_at = now(), web_search_at = now(), lista_aplicada_at = NULL WHERE id = %s", (i,))
    with db.conn() as c:
        ap = listas_ia.aplicar(c)
        r = c.execute("SELECT lista_duvida FROM domains WHERE id = %s", (i,)).fetchone()
    assert r["lista_duvida"] and ("trava-f1.vip", "ameaca") in ap["online"] and ap["local"][i][0] == "online", ap
    with db.conn() as c:   # nova resposta (ex.: fase 3 viu que é malicioso) zera o "segue"
        listas_ia.salvar(c, i, "ameaca", 1.0, "", "", "local", 3, "gemma4:26b")
        assert not c.execute("SELECT lista_segue FROM domains WHERE id = %s", (i,)).fetchone()["lista_segue"]


def test_decisao_da_ia_local_que_nao_muda_nada_aparece_e_o_log_diz_a_verdade(env, monkeypatch):
    """gemma4 confirmando a whitelist/lista em que o site já está = decisão (evento na coluna Decisão); resposta nova
    substitui a categoria provisória posta pela IA local; "manter liberado" de uma pessoa: o log não diz "decide"."""
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n in ("ja-wl.com", "prov-wl.com", "ja-bl.com", "humano-lib.com"):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                               "VALUES (%s, 'NAO_TRABALHO', 'outros', now() - interval '1 minute', 5, now(), now()) RETURNING id",
                               (n,)).fetchone()["id"]
        c.execute("UPDATE domains SET classification = 'TRABALHO' WHERE name IN ('ja-wl.com', 'prov-wl.com')")
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES ('produtividade', 'ja-wl.com', 'IA online', false), "
                  "('comunicacao', 'prov-wl.com', 'IA local (fase 1)', false)")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'ja-bl.com', 'IA automática (jogos)')")
        c.execute("INSERT INTO policies (scope, lists) VALUES ('pol-humano', ARRAY['publicidade'])")
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'allowed', 'ti@empresa')", (ids["humano-lib.com"],))
        for n, lista in (("ja-wl.com", "wl:produtividade"), ("prov-wl.com", "wl:produtividade"), ("ja-bl.com", "jogos"),
                         ("humano-lib.com", "publicidade")):
            listas_ia.salvar(c, ids[n], lista, 0.95, "", "", "local", 1, "gemma4:26b")
        ap = listas_ia.aplicar(c)
        ev = {(r["name"], r["kind"]): r["detail"] for r in c.execute("SELECT name, kind, detail FROM ai_events WHERE name = ANY(%s)",
                                                                     (list(ids),))}
        wl = {r["domain"]: (r["category"], r["added_by"]) for r in c.execute("SELECT domain, category, added_by FROM whitelist_domains")}
    assert "confirmou" in ev[("ja-wl.com", "aprovado")] and wl["ja-wl.com"] == ("produtividade", "IA online"), ev
    assert wl["prov-wl.com"] == ("produtividade", "IA local (fase 1)") and ("prov-wl.com", "aprovado") in ev, wl
    assert "confirmou" in ev[("ja-bl.com", "lista_add")] and ap["local"][ids["ja-bl.com"]] == ("decide",)
    assert ap["local"][ids["humano-lib.com"]] == ("humano",), ap["local"]
    assert listas_ia._proximo(("humano",), True) == " · decisão humana mantida (liberado)"


def test_decisao_humana_vale_sem_fase5(env, monkeypatch):
    """Sem fase 5 (27/09): a IA não desfaz o que uma pessoa decidiu ("manter liberado" -> whitelist como decisão humana;
    lista posta por pessoa -> fica). Pôr numa lista à mão vira a decisão global p/ "bloqueado"."""
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n in ("lib-pessoa.com", "bl-pessoa.com", "lib-incerto.com", "lib-online.com"):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                               "VALUES (%s, 'NAO_TRABALHO', 'outros', now() - interval '1 minute', 5, now(), now()) RETURNING id",
                               (n,)).fetchone()["id"]
        c.execute("INSERT INTO policies (scope, lists) VALUES ('pol-rever', ARRAY['publicidade', 'jogos'])")
        for n in ("lib-pessoa.com", "lib-incerto.com", "lib-online.com"):
            c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'allowed', 'ti@empresa')", (ids[n],))
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'bl-pessoa.com', 'ti@empresa')")
        listas_ia.salvar(c, ids["lib-pessoa.com"], "publicidade", 0.95, "rede de anúncios", "", "local", 1, "gemma4:26b")
        listas_ia.salvar(c, ids["bl-pessoa.com"], "wl:produtividade", 0.95, "editor online", "", "local", 1, "gemma4:26b")
        listas_ia.salvar(c, ids["lib-incerto.com"], "publicidade", 0.6, "talvez", "", "local", 1, "gemma4:26b")
        listas_ia.salvar(c, ids["lib-online.com"], "jogos", 0.95, "jogo", "", "online:gemini", 4)
        c.execute("UPDATE domains SET online_resp = '{\"classificacao\": \"NAO_TRABALHO\"}' WHERE id = %s", (ids["lib-online.com"],))
        c.execute("UPDATE domains SET reanalise_pedida = true WHERE id = ANY(%s)", (list(ids.values()),))
        ap = listas_ia.aplicar(c)
        pedida = {r["name"] for r in c.execute("SELECT name FROM domains WHERE reanalise_pedida AND id = ANY(%s)", (list(ids.values()),))}
        rev = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category = 'para_revisar'")}
        bl = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists WHERE category <> 'para_revisar'")}
        wl = {r["domain"]: r["added_by"] for r in c.execute("SELECT domain, added_by FROM whitelist_domains")}
    assert not set(ids) & rev, rev
    for n in ("lib-pessoa.com", "lib-incerto.com", "lib-online.com"):
        assert ap["local"][ids[n]] == ("humano",) and wl.get(n) == "decisão humana (liberado)" and not any(d == n for _, d in bl), n
    assert ("jogos", "bl-pessoa.com") in bl and "bl-pessoa.com" not in wl, "lista posta por pessoa: fica"
    assert not pedida, f"reanálise pedida termina mesmo com a decisão humana mantida: {pedida}"
    assert listas_ia._proximo(("humano",), True) == " · decisão humana mantida (liberado)"
    r = env.post("/listas/publicidade", json={"domain": "lib-pessoa.com", "by": "ti@empresa"}, headers=H)
    assert r.status_code == 200, r.text
    with db.conn() as c:
        g = c.execute("SELECT status, reviewed_by FROM global_reviews WHERE domain_id = %s", (ids["lib-pessoa.com"],)).fetchone()
        w = c.execute("SELECT 1 FROM whitelist_domains WHERE domain = 'lib-pessoa.com'").fetchone()
    assert g["status"] == "blocked" and g["reviewed_by"] == "ti@empresa" and not w, g


def test_ia_online_sem_resposta_valida_nao_prende_a_fila(env, monkeypatch):
    """Resposta sem JSON de todos os modelos (filtro de segurança do Gemini): o domínio não volta p/ o topo da fila na
    hora (naticr.com prendeu a fase 4 com 212 respostas vazias); na 3ª rodada vai p/ a Decisão Humana."""
    from dnsanalyzer import config, db, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    monkeypatch.setattr(config.settings(), "web_search_url", "")
    monkeypatch.setattr(online._Cota, "esperar", lambda self: True)
    chamadas = []

    def vazio(d, cats, b, m):
        chamadas.append(m)
        raise ValueError("sem JSON: ")
    monkeypatch.setattr(online, "perguntar", vazio)
    with db.conn() as c:   # (o que outros testes deixaram na fila da fase 4 fica de fora)
        c.execute("UPDATE domains SET online_claimed_at = now() + interval '1 day'")
        i = c.execute("INSERT INTO domains (name, tld, kind, classification, category, analyzed_at, total_queries, lista_ia, lista_conf, "
                      "lista_fonte, lista_at, lista_duvida, whois_at, web_search_at) VALUES ('filtrado-adulto.com', 'com', 'public', "
                      "'NAO_TRABALHO', 'adulto', now() - interval '1 hour', 5, 'adulto', 0.7, 'local', now(), true, now(), now()) "
                      "RETURNING id").fetchone()["id"]
    assert online.fase(["adulto"]) == "done" and chamadas, "não é 'unavailable' (o worker não para 60 s)"
    with db.conn() as c:
        r = c.execute("SELECT online_falhas, online_claimed_at IS NOT NULL AS reservado FROM domains WHERE id = %s", (i,)).fetchone()
    assert r["online_falhas"] == 1 and r["reservado"], "fica reservado 10 min em vez de voltar p/ o topo da fila"
    n = len(chamadas)
    assert online.fase(["adulto"]) == "idle" and len(chamadas) == n, "reservado: não pergunta de novo na hora"
    for _ in range(2):   # passam os 10 min
        with db.conn() as c:
            c.execute("UPDATE domains SET online_claimed_at = now() - interval '11 minutes' WHERE id = %s", (i,))
        online.fase(["adulto"])
    with db.conn() as c:
        r = c.execute("SELECT online_falhas, online_at, lista_duvida, online_resp FROM domains WHERE id = %s", (i,)).fetchone()
        em = {r["category"] for r in c.execute("SELECT category FROM category_lists WHERE domain = 'filtrado-adulto.com'")}
        f = c.execute("SELECT lista_fonte FROM domains WHERE id = %s", (i,)).fetchone()["lista_fonte"]
    assert r["online_at"] and not r["lista_duvida"] and r["online_falhas"] == 0 and "erro" in r["online_resp"], r
    assert em == {"adulto"} and f == "online:sem_resposta", "sem fase 5: na 3ª rodada vale a sugestão da IA local"
    with db.conn() as c:
        c.execute("UPDATE domains SET online_claimed_at = NULL WHERE id = %s", (i,))
    assert online.fase(["adulto"]) == "idle", "saiu da fila da fase 4"


def test_429_do_minuto_nao_para_o_modelo_o_dia_todo():
    """27/09: um 429 do limite por minuto parou o 3.5 Flash-Lite até a meia-noite do Pacífico com 264/500 usados."""
    from types import SimpleNamespace

    from dnsanalyzer import online

    def resp(quota, retry="23s"):
        corpo = {"error": {"code": 429, "message": "Quota exceeded ... per day usage https://ai.dev/usage", "details": [
            {"@type": "type.googleapis.com/google.rpc.QuotaFailure", "violations": [{"quotaId": quota}]},
            {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": retry}]}}
        return SimpleNamespace(json=lambda: corpo, text=str(corpo))
    assert online._limite_429(resp("GenerateRequestsPerMinutePerProjectPerModel-FreeTier")) == (False, 25.0, None)
    dia = online._limite_429(resp("GenerateRequestsPerDayPerProjectPerModel-FreeTier", "3600s"))
    assert dia[0] is True and dia[2] is None
    sem = SimpleNamespace(json=lambda: (_ for _ in ()).throw(ValueError()), text="Resource exhausted per day")
    assert online._limite_429(sem) == (False, 65.0, None), "sem detalhe: minuto (o contador próprio cuida do dia)"
    # quotaValue do dia = limite aprendido
    corpo = {"error": {"code": 429, "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailure", "violations": [
        {"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier", "quotaValue": "20"}]}]}}
    assert online._limite_429(SimpleNamespace(json=lambda: corpo, text="")) == (True, 65.0, 20)


def test_cota_do_gemini_sobrevive_ao_reinicio(env, monkeypatch):
    """27/09: 32 reinícios num dia zeravam o contador em memória e os Flash (20/dia) passaram do limite. A conta,
    a pausa do dia e o limite informado pelo Google ficam em online_cota, por chave e modelo."""
    from dnsanalyzer import online
    monkeypatch.setattr(online, "_COTAS", {})
    monkeypatch.setattr(online, "_PERSIST_ATE", 0.0)
    ct = online.cota("gemini-3.8-flash")
    ct.rpm = 10 ** 6   # (sem esperar o minuto no teste)
    assert ct.esperar() and ct.esperar() and ct.n == 2
    monkeypatch.setattr(online, "_COTAS", {})   # "reinício" do processo
    ct2 = online.cota("gemini-3.8-flash")
    ct2.rpm = 10 ** 6
    assert ct2.esperar() and ct2.n == 3, "continuou a conta do banco"
    ct2.aprender_limite(20)
    ct2.pausar_dia()
    monkeypatch.setattr(online, "_COTAS", {})
    ct3 = online.cota("gemini-3.8-flash")
    assert not ct3.esperar() and ct3.rpd == 19 and ct3.n == 3, "pausa do dia e limite voltaram do banco"
    ct4 = online.cota("gemini-3.8-flash", 1)   # chave 2: conta própria
    ct4.rpm = 10 ** 6
    assert ct4.esperar() and ct4.n == 1
    with online.db.conn() as c:
        rows = {(r["chave"], r["n"], r["limite"], r["esgotou_at"] is not None) for r in
                c.execute("SELECT chave, n, limite, esgotou_at FROM online_cota WHERE modelo = 'gemini-3.8-flash'")}
    assert rows == {(1, 3, 20, True), (2, 1, None, False)}, rows


def test_segunda_chave_gemini_tem_cota_propria(monkeypatch):
    """Cota do plano grátis é por projeto e modelo: com a da chave 1 esgotada, o mesmo modelo segue pela chave 2."""
    from dnsanalyzer import config, online
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "k1")
    monkeypatch.setattr(cfg, "gemini_api_keys_extra", ["k2", "k1"])
    assert online._chaves() == ["k1", "k2"]
    monkeypatch.setattr(online, "_COTAS", {})
    online.cota("gemini-3.5-flash-lite").pausar_dia()   # chave 1 esgotada
    usadas = []

    def falso(d, cats, b, m, chave=0):
        usadas.append((m, chave))
        return {"lista": "jogos", "confianca": 0.9}, {"model": m}
    monkeypatch.setattr(online, "perguntar", falso)
    r = online._consultar([("gemini-3.5-flash-lite", 14, 490)], {"name": "x.com"}, [], False)
    assert r and usadas == [("gemini-3.5-flash-lite", 1)], usadas
    assert online.cota("gemini-3.5-flash-lite", 1).modelo == "gemini-3.5-flash-lite (chave 2)"


def test_chave_formato_novo_vai_na_url(monkeypatch):
    """Chave AQ.… só autentica por ?key= (no cabeçalho dá 403); a AIza… segue no cabeçalho x-goog-api-key."""
    from dnsanalyzer import config, online
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "AIza-k1")
    monkeypatch.setattr(cfg, "gemini_api_keys_extra", ["AQ.k2"])
    monkeypatch.setattr(online, "contexto_completo", lambda d: "")
    monkeypatch.setattr(online, "cota", lambda m, chave=0: online._Cota(m, 10 ** 6, 10 ** 6))
    chamadas = []

    class Resp:
        status_code = 200

        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": '{"lista": "jogos", "confianca": 0.9}'}]}}]}

    monkeypatch.setattr(online.httpx, "post", lambda url, **kw: chamadas.append(kw) or Resp())
    for chave in (0, 1):
        online.perguntar({"name": "x.com"}, [], False, "gemini-3.5-flash-lite", chave)
    assert chamadas[0].get("headers") == {"x-goog-api-key": "AIza-k1"} and "params" not in chamadas[0]
    assert chamadas[1].get("params") == {"key": "AQ.k2"} and "headers" not in chamadas[1]


def test_liberar_site_suspeito(env, monkeypatch):
    """Liberar um SUSPEITO: a IA local não decide sozinha (trava -> IA online); a resposta da IA online vale (sem fase 5):
    whitelist só na lista (SUSPEITO não sai da whitelist, só não vale no DNS)."""
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n in ("susp-local.com", "susp-online.com"):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                               "VALUES (%s, 'SUSPEITO', 'outros', now() - interval '1 minute', 5, now(), now()) RETURNING id", (n,)).fetchone()["id"]
        listas_ia.salvar(c, ids["susp-local.com"], "wl:produtividade", 0.95, "", "", "local", 1, "gemma4:26b")
        listas_ia.salvar(c, ids["susp-online.com"], "wl:produtividade", 0.95, "", "", "online:gemini", 4)
        ap = listas_ia.aplicar(c)
        wl = {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains WHERE domain LIKE 'susp-%%'")}
        rev = {r["domain"]: r["added_by"] for r in c.execute("SELECT domain, added_by FROM category_lists WHERE category = 'para_revisar'")}
    assert wl == {"susp-online.com"}, "sem fase 5: a IA online liberou -> whitelist (só na lista)"
    assert ap["local"][ids["susp-local.com"]][0] == "online" and "SUSPEITO" in ap["local"][ids["susp-local.com"]][-1], ap["local"]
    assert "susp-online.com" not in rev, rev


def test_pai_de_algo_bloqueado_fica_na_whitelist_sem_publicar(env):
    """amazonaws.com/fastly.net na whitelist: no DNS liberaria o subdomínio bloqueado, mas a entrada da IA (só na lista)
    fica — antes saía e o site ficava sem categoria ("Aprovados"). O próprio domínio numa blocklist: sai."""
    from dnsanalyzer import db, whitelist
    with db.conn() as c:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'jogo.plataforma-pai.com', 'op@2d'), "
                  "('jogos', 'bloqueado-e-wl.com', 'op@2d')")
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES "
                  "('infraestrutura', 'plataforma-pai.com', 'IA local (fase 1)', false), "
                  "('infraestrutura', 'plataforma-pai2.com', 'IA online', true), "
                  "('produtividade', 'bloqueado-e-wl.com', 'IA online', false)")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'x.plataforma-pai2.com', 'op@2d')")
        whitelist.aplicar(c)
        w = {r["domain"]: r["publicar"] for r in c.execute("SELECT domain, publicar FROM whitelist_domains "
                                                          "WHERE domain IN ('plataforma-pai.com', 'plataforma-pai2.com', 'bloqueado-e-wl.com')")}
    assert w == {"plataforma-pai.com": False, "plataforma-pai2.com": False}, w


def test_nada_fica_solto_sem_destino(env):
    """27/09: "Aprovados" deixou de existir — quem terminou a análise sem lista vai p/ a whitelist (liberado por pessoa;
    só na lista, não vai ao DNS) ou p/ a Decisão Humana (suspeito, ou sem decisão humana)."""
    from dnsanalyzer import db, listas
    with db.conn() as c:
        ids = {}
        for n, cls, cat, wl in (("solto-trab.com.br", "TRABALHO", "produtividade", "erp_gestao"),
                                ("solto-desc.com", "DESCONHECIDO", "desconhecido", None),
                                ("solto-susp.com", "SUSPEITO", "outros", None),
                                ("solto-ninguem.com", "NAO_TRABALHO", "jogos", None)):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at, "
                               "lista_wl, lista_at, lista_fonte, lista_conf, online_at) VALUES (%s, %s, %s, now() - interval '1 hour', 3, now(), now(), "
                               "%s, now(), 'online:gemini', 0.9, now()) RETURNING id", (n, cls, cat, wl)).fetchone()["id"]
        for n in ("solto-trab.com.br", "solto-desc.com", "solto-susp.com"):
            c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'allowed', 'op@2d')", (ids[n],))
        antes = {x["domain"] for x in listas.sem_lista(c, limit=5000)["items"]}
        assert set(ids) <= antes, antes
        listas.sem_destino(c)
        wl = {r["domain"]: (r["category"], r["publicar"]) for r in c.execute("SELECT domain, category, publicar FROM whitelist_domains")}
        rev = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category = 'para_revisar'")}
        depois = {x["domain"] for x in listas.sem_lista(c, limit=5000)["items"]}
    assert wl["solto-trab.com.br"] == ("erp_gestao", False) and wl["solto-desc.com"] == ("outros_liberados", False), wl
    assert not {"solto-susp.com", "solto-ninguem.com"} & rev, "sem fase 5"
    assert wl["solto-susp.com"] == ("outros_liberados", False) and wl["solto-ninguem.com"] == ("outros_liberados", False), wl
    assert not set(ids) & depois, depois


def test_desconhecido_na_fase4_vai_p_nao_identificados(env, monkeypatch):
    """Não identificado depois das 4 fases não é liberado (27/09: cs8sp.com, espelho de cassino, ia p/ Outros liberados):
    DESCONHECIDO + Outros liberados -> lista Não identificados; DESCONHECIDO reconhecido como CDN segue na whitelist."""
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n in ("x7k2q9.com", "cdn-aleatorio.cloudfront.net", "r5k9x2.com", "4-u-h-f.com", "appshield-sec.workers.dev"):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                               "VALUES (%s, 'DESCONHECIDO', 'outros', now() - interval '1 minute', 1, now(), now()) RETURNING id", (n,)).fetchone()["id"]
        listas_ia.salvar(c, ids["x7k2q9.com"], "wl:outros_liberados", 0.3, "", "", "online:gemini", 4)
        listas_ia.salvar(c, ids["cdn-aleatorio.cloudfront.net"], "wl:cdn", 0.8, "", "", "online:gemini", 4)
        listas_ia.salvar(c, ids["r5k9x2.com"], "wl:cdn", 0.6, "", "", "online:gemini", 4)   # nome próprio chamado de "CDN"
        for n in ("4-u-h-f.com", "appshield-sec.workers.dev"):   # 28/09: qualquer whitelist (aqui Outros (trabalho))
            listas_ia.salvar(c, ids[n], "wl:outros_trabalho", 0.9, "", "", "online:gemini", 4)
        c.execute("UPDATE domains SET online_resp = '{\"classificacao\": \"DESCONHECIDO\"}' WHERE id = ANY(%s)", (list(ids.values()),))
        listas_ia.aplicar(c)
        ni = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category = 'nao_identificado' "
                                             "AND domain = ANY(%s)", (list(ids),))}
        wl = {r["domain"]: r["category"] for r in c.execute("SELECT domain, category FROM whitelist_domains")}
    assert ni == {"x7k2q9.com", "r5k9x2.com", "4-u-h-f.com", "appshield-sec.workers.dev"}, ni
    assert not ni & set(wl)
    assert wl.get("cdn-aleatorio.cloudfront.net") == "cdn"


def test_ia_local_nao_poe_sozinha_em_nao_identificados(env, monkeypatch):
    """A IA local (fase 1) com 95% em "nao_identificado" não decide: o domínio segue p/ as fases 2-4."""
    from dnsanalyzer import config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        did = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries) "
                        "VALUES ('q1z7p.com', 'DESCONHECIDO', 'outros', now() - interval '1 minute', 1) RETURNING id").fetchone()["id"]
        listas_ia.salvar(c, did, "nao_identificado", 0.95, "", "", "local", 1, "gemma4:26b")
        listas_ia.aplicar(c)
        ni = c.execute("SELECT count(*) AS n FROM category_lists WHERE category = 'nao_identificado' AND domain = 'q1z7p.com'").fetchone()["n"]
        segue = c.execute("SELECT lista_segue FROM domains WHERE id = %s", (did,)).fetchone()["lista_segue"]
    assert ni == 0 and segue


def test_etapa_local_unica(env, monkeypatch):
    """LOCAL_ETAPA_UNICA (27/09): a fase 1 junta site + busca + WHOIS numa pergunta que já diz a lista; com certeza a IA
    local decide, sem certeza vai direto p/ a IA online (fases 2 e 3 já feitas)."""
    from dnsanalyzer import classifier, config, db
    from dnsanalyzer.llm import LLMResult
    cfg = config.settings()
    monkeypatch.setattr(cfg, "local_etapa_unica", True)
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    pedidos, real = [], classifier.build_dossier
    monkeypatch.setattr(classifier, "build_dossier", lambda c, drow, **kw: pedidos.append(kw) or real(c, drow))

    class IA:
        model, extra = "gemma4:26b", False

        def __init__(self, lista, conf):
            self.lista, self.conf, self.listas = lista, conf, None

        def classify(self, name, ev, cats, scats, regras=None, listas=None):
            self.listas, self.regras = listas, regras
            return LLMResult(service="Cassino 81G", category="", classification="NAO_TRABALHO", recognized=True, topic="cassino",
                             risk_score=20, work_score=0, confidence=0.9, reasons=[{"evidence_id": "E0", "text": "cassino"}],
                             recommended_action="BLOCK_CANDIDATE", corp_action="BLOQUEAR", lista=self.lista,
                             lista_confianca=self.conf, lista_motivo="página de slots"), {"model": self.model, "seconds": 1.0}
    with db.conn() as c:
        ids = {n: c.execute("INSERT INTO domains (name, tld, classification, llm_pending, total_queries) VALUES (%s, 'com', "
                            "'DESCONHECIDO', true, 5) RETURNING id", (n,)).fetchone()["id"] for n in ("81g-certo.com", "81g-duvida.com")}
    for nome, ia in (("81g-certo.com", IA("apostas", 0.95)), ("81g-duvida.com", IA("apostas", 0.6))):
        with db.conn() as c:
            d = c.execute("SELECT * FROM domains WHERE id = %s", (ids[nome],)).fetchone()
        assert classifier._refine(ia, [{"code": "NAO_TRABALHO", "description": "x"}], d) == "done"
        assert "apostas" in ia.listas and "wl:outros_liberados" in ia.listas and "Listas de bloqueio" in ia.regras
    assert pedidos[0].get("with_search") and pedidos[0].get("with_whois"), "site + busca + WHOIS na mesma etapa"
    with db.conn() as c:
        r = {x["name"]: x for x in c.execute("SELECT name, lista_ia, lista_fase, lista_duvida, web_search_at IS NOT NULL AS busca, "
                                             "whois_at IS NOT NULL AS whois FROM domains WHERE id = ANY(%s)", (list(ids.values()),))}
        em = {x["domain"] for x in c.execute("SELECT domain FROM category_lists WHERE category = 'apostas' AND domain LIKE '81g-%%'")}
    assert r["81g-certo.com"]["lista_ia"] == "apostas" and r["81g-certo.com"]["lista_fase"] == 1 and em == {"81g-certo.com"}
    assert r["81g-duvida.com"]["busca"] and r["81g-duvida.com"]["whois"] and r["81g-duvida.com"]["lista_duvida"], \
        "sem certeza: direto p/ a IA online (fase 4)"


def test_ia_ao_vivo_lista_o_que_esta_em_analise(env, monkeypatch):
    """Várias análises ao mesmo tempo (workers + reforço; IA online em paralelo): todas aparecem, por etapa.
    Reservas "de espera" (claimed_at recuado; IA online após resposta inválida) não contam."""
    from dnsanalyzer import db, llm
    monkeypatch.setattr(llm.OllamaClient, "available", lambda self: (True, "ok"))
    with db.conn() as c:   # reservas deixadas pelos testes anteriores (banco compartilhado) não entram na conta
        c.execute("UPDATE domains SET claimed_at = NULL, online_claimed_at = NULL, lista_claimed_at = NULL")
        c.execute("INSERT INTO domains (name, llm_pending, claimed_at) VALUES "
                  "('local-a.com', true, now() - interval '40 seconds'), ('local-b.com', true, now() - interval '5 seconds'), "
                  "('esperando.com', true, now() + interval '5 minutes')")
        c.execute("INSERT INTO domains (name, online_claimed_at, online_falhas) VALUES "
                  "('online-a.com', now() - interval '12 seconds', 0), ('invalida.com', now(), 1)")
        # local-b.com já tem resposta da IA no histórico: é reavaliação; local-a.com nunca passou pela IA: novo
        c.execute("INSERT INTO classification_history (domain_id, classification, source, model) "
                  "SELECT id, 'DESCONHECIDO', 'llm', 'teste' FROM domains WHERE name = 'local-b.com'")
    j = env.get("/ai/events", headers=H).json()
    em = {(r["name"], r["fase"]) for r in j["em_analise"]}
    ent = {r["name"]: r["entrada"] for r in j["em_analise"]}
    assert ent["local-a.com"] == "novo" and ent["local-b.com"] == "reavaliacao" and ent["online-a.com"] == "novo", ent
    assert {("local-a.com", "1"), ("local-b.com", "1"), ("online-a.com", "4")} <= em, em
    assert not {n for n, _ in em} & {"esperando.com", "invalida.com"}, em
    assert j["current"]["name"] == "local-b.com"   # o mais recente (console antigo)
    with db.conn() as c:
        c.execute("UPDATE domains SET claimed_at = NULL, online_claimed_at = NULL "
                  "WHERE name IN ('local-a.com', 'local-b.com', 'online-a.com')")


def test_endereco_de_provedor_liberado_pela_ia_local_nao_vai_p_ia_online(env, monkeypatch):
    """28/09: ec2-*.compute.amazonaws.com (DESCONHECIDO: o cliente da AWS) ia p/ a IA online mesmo com a IA local
    decidindo wl:infraestrutura com 100%. Endereço dentro de provedor: dispensa a fase 4. Domínio próprio desconhecido
    segue p/ a IA online (ela pode identificar)."""
    from dnsanalyzer import config, db, listas_ia, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n in ("ec2-18-1-2-3.eu-west-3.compute.amazonaws.com", "k8x2p0zz.com"):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                               "VALUES (%s, 'DESCONHECIDO', 'outros', now() - interval '1 minute', 3, now(), now()) RETURNING id",
                               (n,)).fetchone()["id"]
        for n in ids:
            listas_ia.salvar(c, ids[n], "wl:infraestrutura", 1.0, "infraestrutura de nuvem", "AWS", "local", 1, "gemma4:26b")
        listas_ia.aplicar(c)
        fila = {n for n, i in ids.items() if online.na_fila(c, i)}
        wl = {r["domain"]: r["category"] for r in c.execute("SELECT domain, category FROM whitelist_domains WHERE domain = ANY(%s)", (list(ids),))}
    assert "ec2-18-1-2-3.eu-west-3.compute.amazonaws.com" not in fila, "endereço de provedor: sem fase 4"
    assert wl.get("ec2-18-1-2-3.eu-west-3.compute.amazonaws.com") == "infraestrutura"
    assert "k8x2p0zz.com" in fila and "k8x2p0zz.com" not in wl, "domínio próprio desconhecido: IA online (e não fica liberado)"


def test_maquina_ec2_nunca_vai_p_nao_identificados(env, monkeypatch):
    """28/09: ec2-*.compute-1.amazonaws.com (curinga da PSL) era "domínio próprio" e ia p/ Não identificados (bloqueado
    em todas as empresas); o Gemini também respondia "nao_identificado" p/ EC2 de outras regiões. Máquina EC2 vai p/
    Infraestrutura (só ameaça bloqueia); site de usuário em plataforma (workers.dev) continua não identificado."""
    from dnsanalyzer import config, db, listas_ia
    from dnsanalyzer.features import analyze_name
    i = analyze_name("ec2-3-4-5-6.compute-1.amazonaws.com")
    assert i.private_suffix and i.icann_registrable == "amazonaws.com" and i.registrable == "ec2-3-4-5-6.compute-1.amazonaws.com"
    assert not listas_ia._dominio_proprio("ec2-3-4-5-6.compute-1.amazonaws.com")
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n, cls in (("ec2-96-0-48-215.compute-1.amazonaws.com", "DESCONHECIDO"), ("ec2-16-162-21-148.ap-east-1.compute.amazonaws.com", "DESCONHECIDO"),
                       ("ec2-1-1-1-9.compute-1.amazonaws.com", "SUSPEITO"), ("golpe-app.workers.dev", "DESCONHECIDO")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries, whois_at, web_search_at) "
                               "VALUES (%s, %s, 'outros', now() - interval '1 minute', 3, now(), now()) RETURNING id", (n, cls)).fetchone()["id"]
        listas_ia.salvar(c, ids["ec2-96-0-48-215.compute-1.amazonaws.com"], "wl:infraestrutura", 1.0, "", "AWS EC2", "local", 1, "gemma4:26b")
        for n in ("ec2-16-162-21-148.ap-east-1.compute.amazonaws.com", "ec2-1-1-1-9.compute-1.amazonaws.com", "golpe-app.workers.dev"):
            listas_ia.salvar(c, ids[n], "nao_identificado", 1.0, "", "", "online:gemini", 4)
        c.execute("UPDATE domains SET online_resp = jsonb_build_object('classificacao', classification) WHERE id = ANY(%s)", (list(ids.values()),))
        listas_ia.aplicar(c)
        ni = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category = 'nao_identificado' AND domain = ANY(%s)", (list(ids),))}
        wl = {r["domain"]: r["category"] for r in c.execute("SELECT domain, category FROM whitelist_domains WHERE domain = ANY(%s)", (list(ids),))}
    assert wl.get("ec2-96-0-48-215.compute-1.amazonaws.com") == "infraestrutura" and wl.get("ec2-16-162-21-148.ap-east-1.compute.amazonaws.com") == "infraestrutura", wl
    assert ni == {"ec2-1-1-1-9.compute-1.amazonaws.com", "golpe-app.workers.dev"}, ni


def test_busca_em_todas_as_listas(env):
    """Página Domínios bloqueados: procura o domínio em todas as listas de bloqueio (exato primeiro; whitelist não entra)."""
    from dnsanalyzer import db
    with db.conn() as c:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('apostas', 'qrofertas.com', 't'), "
                  "('ameaca', 'qrofertas.com', 't'), ('compras', 'loja.qrofertas.com.br', 't'), ('para_revisar', 'qrofertas.net', 't')")
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by) VALUES ('fornecedores', 'qrofertas.com.br', 't')")
    r = env.get("/listas-busca", params={"q": "QROFERTAS.com"}, headers=H)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j[0]["domain"] == "qrofertas.com" and j[0]["listas"] == ["ameaca", "apostas"]
    por = {x["domain"]: x for x in j}
    assert por["loja.qrofertas.com.br"]["listas"] == ["compras"] and "qrofertas.com.br" not in por, "whitelist não entra"
    assert "qrofertas.net" not in por, "Para revisar (fila antiga) não entra"
    assert env.get("/listas-busca", params={"q": "qr"}, headers=H).json() == [], "mínimo 3 letras"
    sub = env.get("/listas-busca", params={"q": "cdn.qrofertas.com"}, headers=H).json()   # subdomínio: acha o pai que bloqueia
    assert sub[0]["domain"] == "qrofertas.com" and sub[0]["pai"] and sub[0]["listas"] == ["ameaca", "apostas"], sub
    assert not j[0]["pai"]


def test_liberados_autorizacao_e_historico(env):
    """IPs liberados: quem da empresa autorizou (mantido na edição sem o campo) e histórico com o usuário do console."""
    ip = "10.77.20.5/32"
    r = env.put("/console/liberados-meta", json={"ip": ip, "usuario": "Caixa 1", "autorizado_por": "Maria (gerente)",
                                                  "acao": "liberar", "by": "ti@2d"}, headers=H)
    assert r.status_code == 200, r.text
    env.put("/console/liberados-meta", json={"ip": ip, "usuario": "Caixa 2", "by": "outro@2d"}, headers=H)
    m = next(x for x in env.get("/console/liberados-meta", headers=H).json() if x["ip"] == ip)
    assert m["autorizado_por"] == "Maria (gerente)" and m["created_by"] == "ti@2d" and m["updated_by"] == "outro@2d"
    assert env.delete("/console/liberados-meta", params={"ip": ip, "by": "chefe@2d"}, headers=H).json()["removed"] == 1
    log = env.get("/console/liberados-log", params={"ip": ip}, headers=H).json()
    assert [(x["acao"], x["por"], x["autorizado_por"]) for x in log] == [
        ("revogar", "chefe@2d", "Maria (gerente)"), ("editar", "outro@2d", "Maria (gerente)"), ("liberar", "ti@2d", "Maria (gerente)")]
    assert log[1]["detalhe"] == {"usuario": "Caixa 2"}


def test_aws_e_cloudfront_vao_p_infraestrutura_sem_ia(env, monkeypatch):
    """28/09: amazonaws.com e cloudfront.net -> whitelist Infraestrutura pelo catálogo, sem perguntar à IA (client=None
    quebraria se chamasse); ameaça (MALICIOSO) e quem já está numa lista de bloqueio seguem como estão."""
    from dnsanalyzer import catalog, config, db, listas_ia
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    assert catalog.match("meu-bucket.s3.us-east-1.amazonaws.com")["lista"] == "wl:infraestrutura"
    assert catalog.match("d1abcxyz.cloudfront.net")["category"] == "infraestrutura" and not catalog.match("d1abcxyz.cloudfront.net")["protected"]
    with db.conn() as c:
        ids = {}
        for n, cls in (("meu-bucket.s3.us-east-1.amazonaws.com", "TRABALHO"), ("d1abcxyz.cloudfront.net", "TRABALHO"),
                       ("golpe.s3.amazonaws.com", "MALICIOSO")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, classified_by, analyzed_at, total_queries) "
                               "VALUES (%s, %s, 'infraestrutura', 'catalog', now(), 2) RETURNING id", (n, cls)).fetchone()["id"]
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('nao_identificado', 'd1abcxyz.cloudfront.net', "
                  "'IA automática (nao_identificado)')")
        ids["apostas.cloudfront.net"] = c.execute("INSERT INTO domains (name, classification, category, classified_by, analyzed_at) "
                                                  "VALUES ('apostas.cloudfront.net', 'TRABALHO', 'infraestrutura', 'catalog', now()) RETURNING id").fetchone()["id"]
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('apostas', 'apostas.cloudfront.net', "
                  "'IA automática (apostas)')")
    assert listas_ia.sugerir(None, ids["meu-bucket.s3.us-east-1.amazonaws.com"]) == "done"
    assert listas_ia.sugerir(None, ids["d1abcxyz.cloudfront.net"]) == "done"
    assert not listas_ia.lista_do_catalogo({"id": ids["apostas.cloudfront.net"], "name": "apostas.cloudfront.net",
                                            "classification": "TRABALHO"}), "já está numa lista de bloqueio: não desbloqueia"
    ids.pop("apostas.cloudfront.net")
    assert not listas_ia.lista_do_catalogo({"id": ids["golpe.s3.amazonaws.com"], "name": "golpe.s3.amazonaws.com",
                                            "classification": "MALICIOSO"}), "ameaça segue o fluxo normal"
    with db.conn() as c:
        wl = {r["domain"]: r["category"] for r in c.execute("SELECT domain, category FROM whitelist_domains WHERE domain = ANY(%s)", (list(ids),))}
        bl = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE domain = ANY(%s)", (list(ids),))}
        f = c.execute("SELECT lista_fonte, lista_wl, lista_conf FROM domains WHERE id = %s", (ids["d1abcxyz.cloudfront.net"],)).fetchone()
    assert wl == {"meu-bucket.s3.us-east-1.amazonaws.com": "infraestrutura", "d1abcxyz.cloudfront.net": "infraestrutura"}, wl
    assert not bl, "saiu de Não identificados (não é identificação)"
    assert (f["lista_fonte"], f["lista_wl"], f["lista_conf"]) == ("catalogo", "infraestrutura", 1.0)


def test_ia_chat_repassa_ao_ollama_local(env, monkeypatch):
    """Atendente virtual (2D-Suporte -> ERP API -> /ia/chat): repassa ao Ollama local com o num_ctx/keep_alive do
    classificador (senão recarrega o modelo), sem raciocínio; valida a conversa; exige token."""
    import httpx
    from dnsanalyzer import config
    enviado = {}

    class R:
        status_code = 200
        text = ""

        def json(self):
            return {"message": {"content": " Olá! "}, "done_reason": "stop", "prompt_eval_count": 40, "eval_count": 3}

    def post(url, json=None, timeout=None):
        enviado.update(url=url, json=json)
        return R()
    monkeypatch.setattr(httpx, "post", post)
    cfg = config.settings()
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "oi"}]
    assert env.post("/ia/chat", json={"messages": msgs}).status_code == 401
    r = env.post("/ia/chat", json={"messages": msgs, "max_tokens": 9999}, headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["content"] == "Olá!" and r.json()["completion_tokens"] == 3
    j = enviado["json"]
    assert enviado["url"] == f"{cfg.ollama_url}/api/chat" and j["think"] is False and j["keep_alive"] == cfg.llm_keep_alive
    from dnsanalyzer.llm import OllamaClient
    cli = OllamaClient()
    esperado = {"num_ctx": cli.num_ctx, "num_predict": 600, **({"num_thread": cli.num_thread} if cli.num_thread else {})}
    assert j["options"] == esperado and j["model"] == cli.model, j["options"]   # mesmas opções de carga do classificador
    assert env.post("/ia/chat", json={"messages": [{"role": "x", "content": "a"}]}, headers=H).status_code == 400

    def lento(*a, **k):
        raise httpx.ReadTimeout("lento")
    monkeypatch.setattr(httpx, "post", lento)
    assert env.post("/ia/chat", json={"messages": msgs}, headers=H).status_code == 504


def test_infra_de_terceiros_entra_na_whitelist_e_e_verificada_na_etapa_2(env, monkeypatch):
    """01/10: a infraestrutura de terceiros do catálogo (Cloud Run, Azure, S3…) entra na whitelist na etapa 1, sem
    esperar; a etapa 2 verifica (listas de ameaça, VirusTotal, URLScan) os mais acessados primeiro: limpo fica,
    malicioso sai da whitelist p/ a Blacklist (SUSPEITO), suspeito vai p/ a IA online, fonte no limite = tenta depois."""
    from dnsanalyzer import catalog, classifier, config, db, investigacao, listas, listas_ia
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    monkeypatch.setattr(cfg, "virustotal_api_key", "vt")
    monkeypatch.setattr(classifier, "event", lambda *a, **k: None)
    assert catalog.match("app-x.run.app")["verificar"] and catalog.match("x.blob.core.windows.net")["verificar"]
    assert not catalog.match("windows.net").get("verificar") and catalog.match("windows.net")["protected"]
    assert catalog.match("da-frwiki-wiki.translate.goog") is None and catalog.match("nel.goog")["lista"] == "wl:infraestrutura"
    estados = {"limpo-x.run.app": {"estado": "limpo", "resumo": "sem listas de ameaça; VirusTotal: 0 de 94"},
               "golpe-x.run.app": {"estado": "malicioso", "resumo": "VirusTotal: 7 de 94 marcam como malicioso"},
               "meio-x.run.app": {"estado": "suspeito", "resumo": "VirusTotal: 1 de 94 marcam como malicioso"}}
    acessos = {"golpe-x.run.app": 90, "meio-x.run.app": 50, "limpo-x.run.app": 10}
    with db.conn() as c:
        c.execute("DELETE FROM lookup_cache WHERE kind = 'verif_infra'")
        c.execute("UPDATE domains SET lista_fonte = 'local' WHERE lista_fonte = 'catalogo'")   # (só os deste teste na fila)
        ids = {n: c.execute("INSERT INTO domains (name, classification, category, classified_by, analyzed_at, total_queries) "
                            "VALUES (%s, 'TRABALHO', 'infraestrutura', 'catalog', now(), %s) RETURNING id", (n, acessos[n])).fetchone()["id"]
               for n in estados}
    for n in estados:   # etapa 1: whitelist na hora (client=None: nunca pergunta à IA; nem chama a verificação)
        assert listas_ia.sugerir(None, ids[n]) == "done", n
    with db.conn() as c:
        assert {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains WHERE domain = ANY(%s)", (list(ids),))} == set(ids)

    def verificar(did, nome):   # (a de verdade grava o resultado em cache: quem foi verificado sai da fila)
        with db.conn() as c:
            c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES ('verif_infra', %s, true, '{}')", (nome,))
        return estados[nome]
    monkeypatch.setattr(investigacao, "verificar_infra", verificar)
    assert [investigacao.verificacao_fase() for _ in range(4)] == ["done", "done", "done", "idle"]
    with db.conn() as c:
        wl = {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains WHERE domain = ANY(%s)", (list(ids),))}
        bl = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists WHERE domain = ANY(%s)", (list(ids),))}
        d = {r["name"]: r for r in c.execute("SELECT name, classification, lista_ia, lista_wl, lista_duvida, reasons "
                                             "FROM domains WHERE id = ANY(%s)", (list(ids.values()),))}
    assert "golpe-x.run.app" not in wl and "limpo-x.run.app" in wl
    assert bl == {(listas.BLACKLIST, "golpe-x.run.app")}
    assert d["golpe-x.run.app"]["classification"] == "SUSPEITO" and d["golpe-x.run.app"]["lista_ia"] == "blacklist"
    assert d["meio-x.run.app"]["lista_duvida"] and d["meio-x.run.app"]["reasons"][0]["by"] == "verificação"
    # fonte no limite (cota do VirusTotal): não grava nada e tenta depois
    with db.conn() as c:
        c.execute("DELETE FROM lookup_cache WHERE kind = 'verif_infra' AND key = 'limpo-x.run.app'")
    monkeypatch.setattr(investigacao, "verificar_infra", lambda did, nome: {"estado": "adiar", "resumo": "cota do dia"})
    assert investigacao.verificacao_fase() == "unavailable"

def test_camuflagem_e_traducao_do_google_sem_ia(env, monkeypatch):
    """30/09: camuflagem (regras) -> Ameaças sem IA; x.translate.goog -> a lista já aplicada ao site original."""
    from dnsanalyzer import config, db, listas_ia
    from dnsanalyzer.rules import CAMUFLAGEM_TOPIC
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        cam = c.execute("INSERT INTO domains (name, classification, topic, classified_by, analyzed_at) VALUES "
                        "('h3gu39r4.com', 'SUSPEITO', %s, 'rules', now()) RETURNING id", (CAMUFLAGEM_TOPIC,)).fetchone()["id"]
        c.execute("INSERT INTO domains (name, classification, lista_ia, lista_at, lista_aplicada_at, analyzed_at) VALUES "
                  "('cassino-x.com', 'NAO_TRABALHO', 'apostas', now(), now(), now())")
        tr = c.execute("INSERT INTO domains (name, classification, analyzed_at) VALUES "
                       "('www-cassino--x-com.translate.goog', 'NAO_TRABALHO', now()) RETURNING id").fetchone()["id"]
        nada = c.execute("INSERT INTO domains (name, classification, analyzed_at) VALUES "
                         "('novo-site-com.translate.goog', 'NAO_TRABALHO', now()) RETURNING id").fetchone()["id"]
    assert listas_ia._traduzido("www-cassino--x-com.translate.goog") == "cassino-x.com"
    assert listas_ia.lista_do_catalogo({"id": cam, "name": "h3gu39r4.com", "classification": "SUSPEITO", "topic": CAMUFLAGEM_TOPIC})
    assert listas_ia.lista_do_catalogo({"id": tr, "name": "www-cassino--x-com.translate.goog", "classification": "NAO_TRABALHO"})
    assert not listas_ia.lista_do_catalogo({"id": nada, "name": "novo-site-com.translate.goog", "classification": "NAO_TRABALHO"}), \
        "site original sem lista decidida: segue p/ a IA"
    with db.conn() as c:
        em = {(r["category"], r["domain"]) for r in c.execute(
            "SELECT category, domain FROM category_lists WHERE domain IN ('h3gu39r4.com', 'www-cassino--x-com.translate.goog')")}
        wl = c.execute("SELECT 1 FROM whitelist_domains WHERE domain = 'h3gu39r4.com'").fetchone()
    assert em == {("ameaca", "h3gu39r4.com"), ("apostas", "www-cassino--x-com.translate.goog")}, em
    assert not wl, "camuflagem nunca vai p/ a whitelist"


def test_ia_online_exige_busca_na_web(env, monkeypatch):
    """30/09 (pedido do usuário): a IA online só responde com a busca na web feita — pelo SearXNG (a do Google pelo
    Gemini é paga). SearXNG fora do ar: a fila espera sem reservar; a busca falhou: devolve o domínio e espera."""
    import time
    from dnsanalyzer import config, db, online, webintel
    cfg = config.settings()
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    monkeypatch.setattr(cfg, "online_exige_busca", True)
    monkeypatch.setattr(cfg, "web_search_url", "http://sx1")
    monkeypatch.setattr(cfg, "web_search_urls", ["http://sx1", "http://sx2"])
    monkeypatch.setattr(webintel, "_fora_ate", {})
    with db.conn() as c:
        assert online.espera_busca(c) is None
    monkeypatch.setattr(webintel, "_fora_ate", {"http://sx1": time.monotonic() + 300, "http://sx2": time.monotonic() + 300})
    with db.conn() as c:
        assert "fora do ar" in online.espera_busca(c)
    reservou = []
    monkeypatch.setattr(online, "_reservar", lambda c: reservou.append(1))
    assert online.fase([]) == "unavailable" and not reservou
    monkeypatch.setattr(webintel, "_fora_ate", {})
    with db.conn() as c:
        did = c.execute("INSERT INTO domains (name, classification, online_claimed_at) VALUES ('busca-falhou.com', 'DESCONHECIDO', now()) "
                        "RETURNING id").fetchone()["id"]
    monkeypatch.setattr(online, "_reservar", lambda c: {"id": did, "name": "busca-falhou.com", "classification": "TRABALHO",
                                                        "investigado_at": None, "online_resp": None, "pedido": False})

    def falha(*a, **k):
        raise webintel.BuscaIndisponivel("captcha")
    monkeypatch.setattr(webintel, "search", falha)
    perguntou = []
    monkeypatch.setattr(online, "perguntar", lambda *a, **k: perguntou.append(1))
    assert online.fase([]) == "unavailable" and not perguntou
    with db.conn() as c:
        assert c.execute("SELECT online_claimed_at FROM domains WHERE id = %s", (did,)).fetchone()["online_claimed_at"] is None

"""Etapa "lista": a IA diz a qual lista cada site pertence; certeza -> direto na lista, dúvida -> Para
revisar; aprovação da sugestão; etapa 4. PostgreSQL real (pgserver); a IA é simulada."""

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-lia"
H = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def _sem_exigir_busca(monkeypatch):
    """Os testes da IA online são do fluxo por níveis (sem a exigência de busca na web de 30/09); quem testa a
    exigência liga de novo."""
    from dnsanalyzer import config
    monkeypatch.setattr(config.settings(), "online_exige_busca", False, raising=False)


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


def test_dns_inativo_na_etapa_1(env, monkeypatch):
    """01/10: domínio que não resolve (DNS público, 2 resolvedores, sem MX) e sem resposta com IP nos logs vai p/ a
    lista DNS Inativo sem IA; nome interno (os logs têm IP), só-subdomínio, só-e-mail e falha de rede não vão; quem
    volta a resolver sai da lista."""
    from dnsanalyzer import db, dnsativo
    resp = {"morto.com": "vazio", "www.morto.com": "vazio", "so-email.com": "vazio", "www.so-email.com": "vazio",
            "raiz-sem-ip.com": "vazio", "www.raiz-sem-ip.com": "vazio", "app.raiz-sem-ip.com": "ip",
            "rede-fora.com": "erro", "www.rede-fora.com": "erro", "interno.com.br": "vazio", "www.interno.com.br": "vazio"}
    mx = {"so-email.com": "ip"}
    monkeypatch.setattr(dnsativo, "consulta", lambda nome, res, tipo="A": (mx.get(nome, "vazio") if tipo == "MX" else resp.get(nome, "vazio")))
    with db.conn() as c:
        ids = {n: c.execute("INSERT INTO domains (name, kind, classification, llm_pending) VALUES (%s, 'public', 'DESCONHECIDO', true) "
                            "RETURNING id, name, kind, classification, ti_signature", (n,)).fetchone()
               for n in ("morto.com", "so-email.com", "raiz-sem-ip.com", "rede-fora.com", "interno.com.br")}
        c.execute("INSERT INTO fqdns (domain_id, name) VALUES (%s, 'app.raiz-sem-ip.com')", (ids["raiz-sem-ip.com"]["id"],))
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('nao_identificado', 'morto.com', 'IA automática (nao_identificado)')")
    monkeypatch.setattr(dnsativo, "_com_ip", lambda c, did: 5 if did == ids["interno.com.br"]["id"] else 0)
    assert dnsativo.etapa1(ids["morto.com"]) is True
    for n in ("so-email.com", "raiz-sem-ip.com", "rede-fora.com", "interno.com.br"):
        assert dnsativo.etapa1(ids[n]) is False, n
    with db.conn() as c:
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists WHERE domain = ANY(%s)", (list(ids),))}
        d = c.execute("SELECT kind, llm_pending, lista_ia FROM domains WHERE name = 'morto.com'").fetchone()
    assert em == {("dns_inativo", "morto.com")}, "saiu de Não identificados e entrou em DNS Inativo"
    assert (d["kind"], d["llm_pending"], d["lista_ia"]) == ("inexistente", False, "dns_inativo")
    # voltou a resolver: sai da lista e a análise segue
    resp["morto.com"] = "ip"
    assert dnsativo.etapa1({**ids["morto.com"], "kind": "public"}) is False
    with db.conn() as c:
        assert not c.execute("SELECT 1 FROM category_lists WHERE domain = 'morto.com'").fetchone()


def test_teste_de_dns_desiste_no_primeiro_timeout(monkeypatch):
    """01/10: domínio com o DNS mudo (timeout) não pode custar minutos: a 1ª consulta sem resposta já encerra ("não sei")."""
    from dnsanalyzer import dnsativo
    feitas = []
    monkeypatch.setattr(dnsativo, "consulta", lambda nome, res, tipo="A": feitas.append((nome, res, tipo)) or "erro")
    assert dnsativo.resolve("mudo.com") is None and len(feitas) == 1
    assert dnsativo.inativo(["mudo.com", "www.mudo.com", "a.mudo.com"]) is False and len(feitas) == 2


def test_pedido_sem_resposta_nao_gasta_a_cota(env, monkeypatch):
    """07/10: a conta sobe antes do pedido; 503 e tempo esgotado gastavam os 19/dia de cada Flash completo sem o Google
    ter respondido (~205 de 228 num dia). Sem resposta: o pedido volta p/ a cota e o modelo descansa cada vez mais."""
    import time
    from types import SimpleNamespace

    from dnsanalyzer import online
    monkeypatch.setattr(online, "_COTAS", {})
    monkeypatch.setattr(online, "_PERSIST_ATE", 0.0)
    ct = online.cota("gemini-3.7-flash")
    ct.rpm = 10 ** 6
    respostas = iter([503, "tempo", 200])

    def post(url, **kw):
        r = next(respostas)
        if r == "tempo":
            raise online.httpx.ReadTimeout("t")
        return SimpleNamespace(status_code=r, text="", json=lambda: {"candidates": [{"content": {"parts": [
            {"text": '{"lista": "jogos", "confianca": 0.9}'}]}}]})
    monkeypatch.setattr(online.httpx, "post", post)
    monkeypatch.setattr(online, "contexto_completo", lambda d: "contexto")

    def no_banco():
        with online.db.conn() as c:
            return c.execute("SELECT n FROM online_cota WHERE modelo = 'gemini-3.7-flash' AND chave = %s", (ct.chave,)).fetchone()["n"]
    pausas = []
    for _ in range(2):
        ct.pausa_ate = 0.0
        assert ct.esperar() and ct.n == 1 and no_banco() == 1
        with pytest.raises(online.OnlineIndisponivel):
            online.perguntar({"name": "x.com"}, [], False, "gemini-3.7-flash")
        assert ct.n == 0 and no_banco() == 0, "pedido sem resposta não conta"
        pausas.append(ct.pausa_ate - time.time())
    assert 80 < pausas[0] < 95 and 170 < pausas[1] < 185 and ct.falhas == 2, "descanso dobra a cada falha seguida"
    ct.pausa_ate = 0.0
    assert ct.esperar()
    obj, _ = online.perguntar({"name": "x.com"}, [], False, "gemini-3.7-flash")
    assert obj["lista"] == "jogos" and ct.n == 1 and no_banco() == 1 and ct.falhas == 0, "respondido conta"


def test_tld_abusado_sozinho_nao_impede_abrir_o_site(env, monkeypatch):
    """07/10: 1wcpdd.life (espelho de casa de apostas; o título da página diz "Cassino e Apostas") ficou "não
    identificado" porque o site nunca era aberto em TLD da lista de abusados. Só a lista de ameaça impede."""
    from dnsanalyzer import classifier, db, webintel
    visto = {}
    monkeypatch.setattr(webintel, "lookup", lambda c, name, fetch, allow_site: visto.__setitem__(name, allow_site))
    monkeypatch.setattr(webintel, "search", lambda *a, **k: None)
    with db.conn() as c:
        sid = c.execute("INSERT INTO ti_sources (name, label, kind, url, threat, confidence, weight) VALUES "
                        "('tlds-t', 'TLDs abusados', 'tld_adblock', 'u', 'abused_tld', 'low', 10) RETURNING id").fetchone()["id"]
        amea = c.execute("INSERT INTO ti_sources (name, label, kind, url, threat, confidence, weight) VALUES "
                         "('ameaca-t', 'Ameaças', 'plain', 'u', 'malware', 'high', 80) RETURNING id").fetchone()["id"]
        c.execute("INSERT INTO ti_indicators (source_id, domain) VALUES (%s, 'life'), (%s, 'golpe-t.life')", (sid, amea))
        for n in ("espelho-t.life", "golpe-t.life"):
            row = c.execute("INSERT INTO domains (name, kind, tld) VALUES (%s, 'public', 'life') RETURNING *", (n,)).fetchone()
            c.execute("INSERT INTO fqdns (name, domain_id, candidates) VALUES (%s, %s, %s)", (n, row["id"], [n]))
            d = classifier.build_dossier(c, row, with_web=True)
            assert d["abused_tld"], "o TLD continua contando como sinal de risco nas regras"
    assert visto == {"espelho-t.life": True, "golpe-t.life": False}


def test_dns_inativo_aproveita_a_resposta_do_technitium(env, monkeypatch):
    """07/10 (pedido do usuário): o que o Technitium acabou de responder vale antes de perguntar de novo. Nome com
    NXDOMAIN no log não é consultado outra vez; nome que recebeu IP = o domínio resolve, sem consulta nenhuma — mesmo
    estando numa lista de bloqueio (a resposta de verdade vem de um grupo que não aplica a lista). Resposta de
    bloqueio (0.0.0.0) não conta. Raiz, www e MX continuam testados fora."""
    from datetime import datetime, timedelta, timezone

    from dnsanalyzer import collector, db, dnsativo
    consultados = []
    monkeypatch.setattr(dnsativo, "consulta", lambda nome, res, tipo="A": consultados.append((nome, tipo)) or "vazio")
    agora = datetime.now(timezone.utc)
    with db.conn() as c:
        collector.ensure_log_partitions(c, agora - timedelta(days=1), agora)
        tid = c.execute("INSERT INTO tenants (slug, name) VALUES ('t-dnslog', 'T') RETURNING id").fetchone()["id"]
        ids = {n: c.execute("INSERT INTO domains (name, kind, classification, llm_pending) VALUES (%s, 'public', 'DESCONHECIDO', true) "
                            "RETURNING id, name, kind, classification, ti_signature", (n,)).fetchone()
               for n in ("morto-log.com", "voltou-log.com", "bloqueado-log.com", "velho-log.com")}

        def log(dom, qname, rtype, rcode, answer, ha=timedelta(minutes=3), qtype="A"):
            c.execute("INSERT INTO fqdns (domain_id, name) VALUES (%s, %s) ON CONFLICT DO NOTHING", (ids[dom]["id"], qname))
            c.execute("INSERT INTO query_log (ts, tenant_id, client_ip, domain_id, qname, qtype, rtype, rcode, answer) "
                      "VALUES (%s, %s, '10.9.0.1', %s, %s, %s, %s, %s, %s)", (agora - ha, tid, ids[dom]["id"], qname, qtype, rtype, rcode, answer))
        log("morto-log.com", "api.morto-log.com", "Recursive", "NxDomain", None)
        log("morto-log.com", "api.morto-log.com", "Cached", "NxDomain", None, qtype="AAAA")
        log("voltou-log.com", "voltou-log.com", "Blocked", "NoError", "A 0.0.0.0")
        log("voltou-log.com", "voltou-log.com", "Cached", "NoError", "CNAME x.cdn.net., A 203.0.113.9")
        log("bloqueado-log.com", "bloqueado-log.com", "Blocked", "NoError", "A 0.0.0.0")
        log("velho-log.com", "app.velho-log.com", "Recursive", "NxDomain", None, ha=timedelta(hours=5))
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('dns_inativo', 'voltou-log.com', %s), "
                  "('nao_identificado', 'bloqueado-log.com', 'IA automática (nao_identificado)')", (dnsativo.POR,))
        assert dnsativo.pelos_logs(c, [r["id"] for r in ids.values()]) == {
            ids["morto-log.com"]["id"]: {"api.morto-log.com": False}, ids["voltou-log.com"]["id"]: {"voltou-log.com": True}}
    # NXDOMAIN no log: só a raiz, o www e o MX são consultados fora
    assert dnsativo.etapa1(ids["morto-log.com"]) is True
    assert {n for n, _ in consultados} == {"morto-log.com", "www.morto-log.com"} and ("morto-log.com", "MX") in consultados
    # recebeu IP há pouco (de quem não aplica a lista): sai de DNS Inativo sem consulta nenhuma
    consultados.clear()
    assert dnsativo.etapa1(ids["voltou-log.com"]) is False and consultados == []
    # só resposta de bloqueio, ou NXDOMAIN antigo: o log não diz nada — teste ativo completo
    assert dnsativo.etapa1(ids["bloqueado-log.com"]) is True and ("bloqueado-log.com", "A") in consultados
    consultados.clear()
    assert dnsativo.etapa1(ids["velho-log.com"]) is True and ("app.velho-log.com", "A") in consultados
    with db.conn() as c:
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists WHERE domain LIKE '%%-log.com'")}
        motivo = c.execute("SELECT lista_motivo FROM domains WHERE name = 'morto-log.com'").fetchone()["lista_motivo"]
    assert em == {("dns_inativo", "morto-log.com"), ("dns_inativo", "bloqueado-log.com"), ("dns_inativo", "velho-log.com")}
    assert "NXDOMAIN no log do Technitium: api.morto-log.com" in motivo
