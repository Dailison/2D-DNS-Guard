"""Páginas das listas: detalhes da IA/revisão, "sem lista", mover entre listas e nova análise em lote,
num PostgreSQL real (pgserver). Sem pgserver instalado, os testes são pulados."""

from datetime import datetime, timezone

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-listas"
H = {"Authorization": f"Bearer {TOKEN}"}
AGORA = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def api(tmp_path_factory):
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


def _dados(c):
    t = c.execute("INSERT INTO tenants (slug, name) VALUES ('a', 'Empresa A') RETURNING id").fetchone()["id"]
    ids = {}
    for name, cls, cat, q, by, locked in (
            ("jogo.com", "NAO_TRABALHO", "jogos", 50, "llm", False),
            ("duvida.com", "DESCONHECIDO", "desconhecido", 5, "llm", False),
            ("erp.com.br", "TRABALHO", "produtividade", 90, "llm", False),
            ("travado.com", "TRABALHO", "produtividade", 3, "manual", True),
            ("fornecedor.com.br", "TRABALHO", "produtividade", 40, "llm", False),
            ("cdn.fornecedor.com.br", "TRABALHO", "infraestrutura", 1, "llm", False),
            ("liberado.com", "TRABALHO", "comunicacao", 7, "llm", False),
            ("pendente.com", None, None, 2, None, False),
            ("aposta.bet.br", "NAO_TRABALHO", "apostas", 8, "llm", False)):
        ids[name] = c.execute(
            "INSERT INTO domains (name, classification, category, total_queries, classified_by, locked, analyzed_at, "
            "llm_pending) VALUES (%s,%s,%s,%s,%s,%s,now(),%s) RETURNING id",
            (name, cls, cat, q, by, locked, cls is None)).fetchone()["id"]
    c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES "
              "('para_revisar','jogo.com','migração dos grupos antigos'), ('para_revisar','duvida.com','migração dos grupos antigos'),"
              "('para_revisar','erp.com.br','op@2d'), ('para_revisar','nunca-visto.com','migração dos grupos antigos'),"
              "('outros_bloqueios','fornecedor.com.br','op@2d')")
    c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('apostas', 'aposta.bet.br', 'bloqueio automático (apostas)')")
    c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', 'bloqueio automático (apostas)')",
              (ids["aposta.bet.br"],))
    c.execute("INSERT INTO allow_list_domains (list_slug, domain) VALUES ('instagram', 'liberado.com')")
    c.execute("INSERT INTO tenant_domains (tenant_id, domain_id, first_seen, last_seen, review_status, reviewed_by, reviewed_at) "
              "VALUES (%s, %s, now(), now(), 'blocked', 'ana@2d', now())", (t, ids["duvida.com"]))


def test_detalhes_da_lista_traz_ia_revisao_e_facetas(api):
    j = api.get("/listas/para_revisar/detalhes", headers=H).json()
    assert j["total"] == 4 and j["total_geral"] == 4
    it = {r["domain"]: r for r in j["items"]}
    assert it["jogo.com"]["cat_ia"] == "jogos" and it["jogo.com"]["revisao"] == "ia"
    assert it["duvida.com"]["revisao"] == "manual" and it["duvida.com"]["ult_por"] == "ana@2d" and it["duvida.com"]["n_decisoes"] == 1
    assert it["erp.com.br"]["revisao"] == "manual", "posto na lista por um operador"
    assert it["nunca-visto.com"]["revisao"] == "pendente" and it["nunca-visto.com"].get("classification") is None
    assert "id" not in it["jogo.com"]
    assert j["facetas"]["cat_ia"] == {"jogos": 1, "desconhecido": 1, "produtividade": 1, "_sem": 1}
    assert j["facetas"]["revisao"] == {"ia": 1, "manual": 2, "pendente": 1}


def test_bloqueio_automatico_nao_conta_como_revisao_manual(api):
    it = api.get("/listas/apostas/detalhes", headers=H).json()["items"]
    assert [(x["domain"], x["revisao"], x["g_by"]) for x in it] == [("aposta.bet.br", "ia", "bloqueio automático (apostas)")]


def test_filtro_por_empresa_e_empresas_que_acessaram(api):
    from dnsanalyzer import db
    with db.conn() as c:
        tid = c.execute("SELECT id FROM tenants WHERE slug='a'").fetchone()["id"]
    j = api.get("/listas/para_revisar/detalhes", headers=H, params={"tid": tid}).json()
    assert [r["domain"] for r in j["items"]] == ["duvida.com"] and j["items"][0]["empresas"] == [{"id": tid, "name": "Empresa A"}]
    todos = {r["domain"]: r["empresas"] for r in api.get("/listas/para_revisar/detalhes", headers=H).json()["items"]}
    assert todos["jogo.com"] == []


def test_filtros_e_paginacao(api):
    j = api.get("/listas/para_revisar/detalhes", headers=H, params={"cat_ia": "jogos"}).json()
    assert [r["domain"] for r in j["items"]] == ["jogo.com"]
    assert j["facetas"]["cat_ia"]["desconhecido"] == 1, "a faceta do próprio filtro ignora o filtro"
    assert j["facetas"]["revisao"] == {"ia": 1}
    j = api.get("/listas/para_revisar/detalhes", headers=H, params={"ordem": "consultas", "limit": 2, "offset": 1}).json()
    assert j["total"] == 4 and [r["domain"] for r in j["items"]] == ["jogo.com", "duvida.com"]
    assert api.get("/listas/xx/detalhes", headers=H).status_code == 404
    j = api.get("/listas/para_revisar/detalhes", headers=H, params={"rec": "_sem"}).json()
    assert j["total"] == 4 and j["facetas"]["recomendacao"] == {"_sem": 4}
    assert api.get("/listas/para_revisar/detalhes", headers=H, params={"rec": "LIBERAR"}).json()["total"] == 0


def test_sem_lista_exclui_listas_e_dominio_pai(api):
    j = api.get("/sem-lista", headers=H, params={"cls": "TRABALHO"}).json()
    nomes = {r["domain"] for r in j["items"]}
    # fornecedor.com.br está em outros_bloqueios -> cdn.fornecedor.com.br (filho) também fica de fora
    assert nomes == {"travado.com"}, nomes
    assert j["items"][0]["revisao"] == "manual"
    assert "pendente.com" not in {r["domain"] for r in api.get("/sem-lista", headers=H).json()["items"]}


def test_mover_e_reanalisar(api):
    r = api.post("/listas-mover", headers=H, json={"domains": ["jogo.com"], "de": "para_revisar", "para": ["jogos"], "by": "op@2d"}).json()
    assert r == {"ok": True, "movidos": 1, "removidos": 1}
    j = api.get("/listas/jogos/detalhes", headers=H).json()
    assert [(x["domain"], x["added_by"], x["revisao"]) for x in j["items"]] == [("jogo.com", "op@2d", "manual")]
    assert api.get("/listas/para_revisar/detalhes", headers=H).json()["total"] == 3
    assert api.post("/listas-mover", headers=H, json={"domains": ["a.com"], "de": "para_revisar", "para": ["zz"]}).status_code == 422
    r = api.post("/domains-reanalyze", headers=H, json={"domains": ["erp.com.br", "travado.com", "nada.com"]}).json()
    assert r["enviados"] == 1 and r["ignorados"] == 2
