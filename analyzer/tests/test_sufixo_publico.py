"""Incidente de 07/10: a regra DNS Inativo pôs "com.br" na lista de bloqueio (o nome com.br não resolve), todo *.com.br
ficou bloqueado e a trava da whitelist apagou 2.308 domínios. Sufixo público nunca entra nem é publicado, um
domínio-pai não derruba a whitelist em massa, e a migração 079 devolve o que foi apagado. PostgreSQL real (pgserver)."""

from pathlib import Path

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-suf"
H = {"Authorization": f"Bearer {TOKEN}"}
M079 = Path(__file__).resolve().parent.parent / "migrations" / "079_restaura_whitelist_com_br.sql"


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


def test_o_que_e_sufixo_publico():
    from dnsanalyzer import dnsativo, listas
    for n in ("com.br", "gov.br", "br", "co.uk", "com"):
        assert listas.sufixo_publico(n) and not dnsativo.testavel(n), n
    for n in ("sicredi.com.br", "www.com.br", "exemplo.com", "d1abc.cloudfront.net"):
        assert not listas.sufixo_publico(n) and dnsativo.testavel(n), n
    for n in ("cloudfront.net", "blogspot.com", "update", "ec2-1-2-3-4.compute-1.amazonaws.com"):
        assert not dnsativo.testavel(n), f"{n}: raiz de plataforma / nome de máquina nunca é 'DNS inativo'"
    assert not listas.sufixo_publico("cloudfront.net"), "plataforma de uma empresa: uma pessoa pode bloquear inteira"


def test_dns_inativo_nunca_marca_sufixo_publico(api, monkeypatch):
    """com.br (e a raiz de uma plataforma) não resolve mesmo: não é domínio de ninguém, não vai p/ a lista."""
    from dnsanalyzer import db, dnsativo
    monkeypatch.setattr(dnsativo, "consulta", lambda nome, res, tipo="A": "vazio")   # nada resolve
    monkeypatch.setattr(dnsativo, "_com_ip", lambda c, did: 0)
    with db.conn() as c:
        ids = {n: c.execute("INSERT INTO domains (name, kind, classification) VALUES (%s, 'public', 'DESCONHECIDO') "
                            "RETURNING id, name, kind, classification, ti_signature", (n,)).fetchone()
               for n in ("com.br", "plataforma.web.app", "web.app", "morto-de-verdade.com.br")}
    assert dnsativo.etapa1(ids["com.br"]) is False and dnsativo.etapa1(ids["web.app"]) is False
    with db.conn() as c:
        assert dnsativo.confirmar(c, ids["com.br"]) is False
        dnsativo.marcar(c, ids["com.br"], "chamada direta")          # última barreira
    assert dnsativo.etapa1(ids["morto-de-verdade.com.br"]) is True and dnsativo.etapa1(ids["plataforma.web.app"]) is True
    with db.conn() as c:
        em = {r["domain"] for r in c.execute("SELECT domain FROM category_lists WHERE category = 'dns_inativo'")}
        kind = c.execute("SELECT kind FROM domains WHERE name = 'com.br'").fetchone()["kind"]
    assert em == {"morto-de-verdade.com.br", "plataforma.web.app"} and kind == "public"


def test_sufixo_publico_na_tabela_nao_e_publicado(api):
    """Rede de segurança: mesmo que alguém grave direto no banco, o sufixo não vai p/ o DNS nem p/ o índice do console."""
    from dnsanalyzer import db, listas
    with db.conn() as c:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('jogos', 'com.br', 'psql'), ('jogos', 'jogo.com.br', 'op')")
        assert listas.dominios(c, "jogos") == ["jogo.com.br"]
    assert api.get("/listas-dominios", headers=H, params={"cats": ["jogos"]}).json() == {"jogos": ["jogo.com.br"]}
    with db.conn() as c:
        c.execute("DELETE FROM category_lists WHERE domain = 'com.br'")


def test_api_recusa_sufixo_publico_em_lista_de_bloqueio(api):
    r = api.post("/listas/jogos", headers=H, json={"domain": "com.br", "by": "op"})
    assert r.status_code == 400 and "sufixo público" in r.json()["detail"]
    assert api.post("/listas-lote", headers=H, json={"cats": ["jogos"], "domains": ["ok.com.br", "gov.br"], "by": "op"}).status_code == 400
    assert api.post("/listas-mover", headers=H, json={"de": "jogos", "para": ["apostas"], "domains": ["co.uk"], "by": "op"}).status_code == 400
    from dnsanalyzer import db
    with db.conn() as c:
        assert not c.execute("SELECT 1 FROM category_lists WHERE domain IN ('com.br', 'gov.br', 'co.uk', 'ok.com.br')").fetchone()
    assert api.post("/listas-remover", headers=H, json={"cats": ["jogos"], "domains": ["com.br"], "by": "op"}).status_code == 200, \
        "tirar continua valendo (limpeza)"


def test_dominio_pai_bloqueado_nao_derruba_a_whitelist_em_massa(api):
    from dnsanalyzer import db, whitelist
    filhos = [f"loja{i}.plataforma-grande.com" for i in range(whitelist._MAX_POR_PAI + 5)]
    with db.conn() as c:
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) SELECT 'fornecedores', d, 'IA local (fase 1)', false "
                  "FROM unnest(%s::text[]) d", (filhos + ["a.pequena.com", "b.pequena.com", "banco.com.br", "direto.com"],))
        # com.br gravado direto (as travas de entrada não deixariam), um pai com muitos filhos, um com poucos, e o próprio domínio
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('dns_inativo', 'com.br', 'psql'), "
                  "('jogos', 'plataforma-grande.com', 'op'), ('jogos', 'pequena.com', 'op'), ('jogos', 'direto.com', 'op')")
        whitelist.aplicar(c)
        ficou = {r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains")}
        aviso = c.execute("SELECT detail FROM ai_events WHERE kind = 'lista_recusada' AND name = 'plataforma-grande.com'").fetchone()
        c.execute("DELETE FROM category_lists WHERE domain IN ('com.br', 'plataforma-grande.com', 'pequena.com', 'direto.com')")
    assert "banco.com.br" in ficou, "sufixo público numa lista não é conflito do site"
    assert set(filhos) <= ficou, "pai que derrubaria mais de _MAX_POR_PAI: ninguém sai"
    assert not ({"a.pequena.com", "b.pequena.com", "direto.com"} & ficou), "conflito de verdade continua tirando da whitelist"
    assert aviso and "nada foi removido" in aviso["detail"]


def test_migracao_079_devolve_o_que_a_trava_apagou(api):
    from dnsanalyzer import db, listas
    with db.conn() as c:
        c.execute("DELETE FROM whitelist_domains")
        c.execute("DELETE FROM list_audit")
        listas.contexto(c, "IA local (fase 1)", "liberado: Finanças · IA local 100%")
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, added_at, publicar) VALUES "
                  "('financas', 'sicredi.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('educacao', 'escola.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('saude', 'ja-voltou.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('saude', 'agora-bloqueado.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('saude', 'sub.pai-bloqueado.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('saude', 'outro-motivo.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('saude', 'fora-da-janela.com.br', 'IA local (fase 1)', '2026-09-27 01:00-03', false), "
                  "('saude', 'nao-e-com-br.com', 'IA local (fase 1)', '2026-09-27 01:00-03', false)")
        c.execute("UPDATE list_audit SET at = '2026-09-27 01:00-03'")
    with db.conn() as c:   # o ciclo das 15:29
        listas.contexto(c, "whitelist (trava)", "está numa lista de bloqueio")
        c.execute("DELETE FROM whitelist_domains WHERE domain NOT IN ('outro-motivo.com.br')")
        listas.contexto(c, "whitelist (trava)", "feed de ameaça (urlhaus)")
        c.execute("DELETE FROM whitelist_domains WHERE domain = 'outro-motivo.com.br'")
        c.execute("UPDATE list_audit SET at = '2026-10-07 15:29:10-03' WHERE acao = 'remove'")
        c.execute("UPDATE list_audit SET at = '2026-10-06 10:00-03' WHERE acao = 'remove' AND domain = 'fora-da-janela.com.br'")
    with db.conn() as c:   # depois do incidente: um voltou sozinho, dois ficaram bloqueados
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES ('essenciais', 'ja-voltou.com.br', 'catálogo (protegido)', true)")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('apostas', 'agora-bloqueado.com.br', 'op'), "
                  "('apostas', 'pai-bloqueado.com.br', 'op'), ('dns_inativo', 'com.br', 'regras (DNS inativo)')")
    with db.conn() as c:
        c.execute(M079.read_text(encoding="utf-8"))
    with db.conn() as c:
        c.execute(M079.read_text(encoding="utf-8"))   # rodar de novo não duplica
        w = {r["domain"]: r for r in c.execute("SELECT domain, category, added_by, added_at::date::text AS em, publicar FROM whitelist_domains")}
        assert not c.execute("SELECT 1 FROM category_lists WHERE domain = 'com.br'").fetchone()
        aud = c.execute("SELECT por, motivo FROM list_audit WHERE domain = 'sicredi.com.br' ORDER BY id DESC LIMIT 1").fetchone()
        c.execute("DELETE FROM category_lists WHERE domain LIKE '%%bloqueado.com.br'")
    assert set(w) == {"sicredi.com.br", "escola.com.br", "ja-voltou.com.br"}, set(w)
    assert (w["sicredi.com.br"]["category"], w["sicredi.com.br"]["added_by"], w["sicredi.com.br"]["em"], w["sicredi.com.br"]["publicar"]) == \
        ("financas", "IA local (fase 1)", "2026-09-27", False)
    assert w["ja-voltou.com.br"]["category"] == "essenciais", "quem já voltou fica como voltou"
    assert aud["por"] == "correção 079" and "incidente do com.br" in aud["motivo"]
