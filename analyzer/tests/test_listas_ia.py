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
    assert ("para_revisar", "whatsapp.com") not in em and ("mensageiros", "whatsapp.com") not in em, "decisão humana: não volta"
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
    assert "talvez-jogo.com" not in nomes and "whatsapp.com" not in nomes
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
    assert ("jogos", "duv1.com") in em and ("para_revisar", "duv2.com") in em
    assert ("compras", "misterio.com.br") in em, "Compras conta como trabalho"
    assert m == {"classification": "TRABALHO", "classified_by": "online", "topic": "Loja de ferramentas"}
    assert ("para_revisar", "ninguem-sabe.com") in em, "nem a IA online sabe: fase 5 (Decisões)"
    assert env.get("/online/pendentes", headers=H).json() == []


def test_gemini_valida_sugestoes(env, monkeypatch):
    from dnsanalyzer import config, db, listas_ia, online
    monkeypatch.setattr(config.settings(), "gemini_api_key", "k")
    with db.conn() as c:
        ids = {}
        for n, cls in (("v-certo.com", "NAO_TRABALHO"), ("v-errado.com", "NAO_TRABALHO"), ("playrix.com", "TRABALHO"),
                       ("v-sobra.com", "TRABALHO"), ("v-talvez.com", "NAO_TRABALHO")):
            ids[n] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries) "
                               "VALUES (%s, %s, 'outros', now(), 5) RETURNING id", (n, cls)).fetchone()["id"]
        # v-errado: a IA local já tinha posto sozinha em Compras (antes da validação)
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('compras', 'v-errado.com', 'IA automática (compras)'), "
                  "('para_revisar', 'v-sobra.com', 'migração dos grupos antigos'), ('streaming', 'v-talvez.com', 'IA automática (streaming)')")
        listas_ia.salvar(c, ids["v-certo.com"], "jogos", 1.0, "", "", "local")
        listas_ia.salvar(c, ids["playrix.com"], "jogos", 1.0, "", "", "local")
        ids["slatic.net"] = c.execute("INSERT INTO domains (name, classification, category, analyzed_at, total_queries) "
                                      "VALUES ('slatic.net', 'TRABALHO', 'infraestrutura', now(), 9) RETURNING id").fetchone()["id"]
        listas_ia.salvar(c, ids["slatic.net"], "compras", 0.9, "CDN da Lazada", "", "local")
        ap = listas_ia.aplicar(c)
        em = {(r["category"], r["domain"]) for r in c.execute("SELECT category, domain FROM category_lists")}
    assert ("jogos", "v-certo.com") not in em and ("v-certo.com", "jogos") in ap["online"], "certeza local espera a IA online"
    assert ("para_revisar", "playrix.com") not in em and ("playrix.com", "jogos") in ap["online"], "incoerência local também"
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
    assert ("para_revisar", "v-sobra.com") not in em and "v-sobra.com" in ap["resolvidos"], "nenhuma com certeza: sai de Decisões"
    assert ("streaming", "v-talvez.com") in em and ("para_revisar", "v-talvez.com") not in em, "sem certeza: fica onde a IA pôs"
    assert ("publicidade", "cookiefirst.com") in em and ("para_revisar", "cookiefirst.com") not in em, \
        "IA online: TRABALHO + publicidade 0,8 = lista (a lista diz o que o site é)"


def test_eventos_da_coluna_decisao(env, monkeypatch):
    from dnsanalyzer import db, llm
    monkeypatch.setattr(llm.OllamaClient, "available", lambda self: (True, "ok"))
    with db.conn() as c:
        kinds = {r["kind"] for r in c.execute("SELECT kind FROM ai_events")}
        ev = {(r["kind"], r["name"]): r["detail"] for r in c.execute("SELECT kind, name, detail FROM ai_events")}
    assert {"lista_add", "fase5", "decisao"} <= kinds, kinds
    assert ev[("lista_add", "roblox.com")].startswith("jogos|IA local")
    assert ev[("fase5", "talvez-jogo.com")].startswith("jogos|nenhuma fase teve certeza")
    assert any(k == "decisao" and d.startswith("jogos|op: aprovou a sugestão") for (k, _), d in ev.items())
    with db.conn() as c:   # muita classificação depois: a carga inicial ainda traz a coluna "Decisão"
        for i in range(80):
            c.execute("INSERT INTO ai_events (kind, name) VALUES ('llm_done', %s)", (f"x{i}.com",))
    j = env.get("/ai/events", headers=H, params={"limit": 30}).json()
    ks = [e["kind"] for e in j["events"]]
    assert ks.count("llm_done") == 30 and any(k in ("lista_add", "fase5", "decisao") for k in ks)


def test_decisoes_so_fase5_e_contexto_completo(env):
    import json as _j

    from dnsanalyzer import db, online
    j = env.get("/listas/para_revisar/detalhes", headers=H, params={"fase5": True, "limit": 500}).json()
    nomes = {r["domain"] for r in j["items"]}
    assert "duv2.com" in nomes, "a IA online avaliou e ficou sem certeza: fase 5"
    assert "talvez-jogo.com" not in nomes and "duvida-sobra.com" not in nomes, "sem passar pela fase 4: fora de Decisões"
    assert j["aguardando_ia"] >= 1
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
            r = c.execute("SELECT whois_tries, whois_at, claimed_at > now() - interval '30 minutes' AS adiado "
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
    """Plano de confiabilidade, fase 1: protegido/trabalho/popular não entram sozinhos; bloqueio automático
    espera a IA online; "nenhuma" sem certeza em não trabalho vai p/ Decisões; DoH popular entra."""
    from dnsanalyzer import config, db, listas, listas_ia
    cfg = config.settings()

    def novo(c, nome, cls, cat, rank=None, corp=None):
        return c.execute("INSERT INTO domains (name, classification, category, popularity_rank, corp_action, analyzed_at, "
                         "total_queries) VALUES (%s, %s, %s, %s, %s, now(), 5) RETURNING id", (nome, cls, cat, rank, corp)).fetchone()["id"]

    def em(c, nome):
        return {r["category"]: r["added_by"] for r in c.execute("SELECT category, added_by FROM category_lists WHERE domain=%s", (nome,))}

    # 1) protegido do catálogo com resposta online "streaming" 0,95 -> Decisões
    monkeypatch.setattr(cfg, "gemini_api_key", "k")
    with db.conn() as c:
        i = novo(c, "microsoft.com", "NAO_TRABALHO", "streaming")
        listas_ia.salvar(c, i, "streaming", 0.95, "", "", "online:gemini")
        listas_ia.aplicar(c)
        m = em(c, "microsoft.com")
    assert "streaming" not in m and "trava: infraestrutura protegida" in m.get("para_revisar", ""), m
    # 2) categoria de trabalho (financas), IA local "compras" 0,95, IA online DESLIGADA -> Decisões
    monkeypatch.setattr(cfg, "gemini_api_key", "")
    with db.conn() as c:
        i = novo(c, "banco-x.com.br", "NAO_TRABALHO", "financas")
        listas_ia.salvar(c, i, "compras", 0.95, "", "", "local")
        listas_ia.aplicar(c)
        m = em(c, "banco-x.com.br")
    assert "compras" not in m and "trava: categoria de trabalho (financas)" in m.get("para_revisar", ""), m
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
        m = em(c, "talvez-nada.com")
    assert "IA online sem certeza" in m.get("para_revisar", ""), m
    # 5) DoH/DNS nunca entra sozinha (incidente: impervadns.net/apple-dns.net pareciam resolvedor) -> Decisões
    with db.conn() as c:
        i = novo(c, "dns.google", "TRABALHO", "infraestrutura", rank=50)
        listas_ia.salvar(c, i, "doh_dns", 0.9, "", "", "online:gemini")
        j2 = novo(c, "impervadns.net", "TRABALHO", "infraestrutura", rank=506)
        listas_ia.salvar(c, j2, "doh_dns", 1.0, "", "", "online:gemini")
        listas_ia.aplicar(c)
        m, m2 = em(c, "dns.google"), em(c, "impervadns.net")
    assert "doh_dns" not in m and "DoH/DNS só com revisão" in m.get("para_revisar", ""), m
    assert "doh_dns" not in m2 and "para_revisar" in m2, m2
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
    # travado aparece em Decisões (fase 5) mesmo sem a IA online ter avaliado
    j = env.get("/listas/para_revisar/detalhes", headers=H, params={"fase5": True, "limit": 1000}).json()
    assert {"banco-x.com.br", "microsoft.com", "talvez-nada.com"} <= {r["domain"] for r in j["items"]}
