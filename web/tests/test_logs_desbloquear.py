"""Logs DNS (22/10, pedido do usuário): "Desbloquear…" mostra as listas que contêm o domínio (ele ou um domínio-pai) e
deixa tirar só das marcadas ou mover para uma whitelist; o nome do domínio abre a página dele em nova aba."""

from types import SimpleNamespace

import pytest


@pytest.fixture()
def cli(app, monkeypatch):
    from app import analyzer_client as api
    feitos = []

    def get(path, **params):
        if path.startswith("/listas-dominio/"):
            return [{"category": "streaming", "domain": "cdn.exemplo.com", "added_by": "IA automática (streaming)"},
                    {"category": "ameaca", "domain": "exemplo.com", "added_by": "op@2d"}]
        if path.startswith("/whitelist-dominio/"):
            return []
        return []

    def post(path, json=None, timeout=30):
        feitos.append((path, json))
        return {"removidos": 1}
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(api, "post", post)
    adm = SimpleNamespace(email="ti@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    return SimpleNamespace(c=app.test_client(), feitos=feitos)


def test_onde_lista_as_listas_e_o_dominio_pai(cli):
    j = cli.c.get("/bloqueios/onde?d=CDN.Exemplo.com.").get_json()
    assert j["ok"] and j["dominio"] == "cdn.exemplo.com"
    assert [(x["lista"], x["entrada"]) for x in j["listas"]] == [("ameaca", "exemplo.com"), ("streaming", "cdn.exemplo.com")]
    assert j["listas"][0]["rotulo"] != "ameaca", "nome da lista para a tela"


def test_tira_so_das_marcadas(cli):
    r = cli.c.post("/bloqueios/desbloquear", data={"dominio": "cdn.exemplo.com", "acao": "listas",
                                                          "itens": ["streaming|cdn.exemplo.com"], "voltar": "/logs-dns?f=1"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/logs-dns?f=1")
    movidos = [j for p, j in cli.feitos if p == "/listas-mover"]
    assert movidos == [{"domains": ["cdn.exemplo.com"], "de": "streaming", "para": [], "by": "ti@2d"}]
    assert any(p == "/domains/cdn.exemplo.com/review" and j["status"] == "allowed" for p, j in cli.feitos)


def test_move_para_whitelist(cli):
    cli.c.post("/bloqueios/desbloquear", data={"dominio": "cdn.exemplo.com", "acao": "whitelist", "wl": "produtividade"})
    assert ("/whitelist/produtividade", {"domains": ["cdn.exemplo.com"], "by": "ti@2d"}) in cli.feitos
    assert not [p for p, _ in cli.feitos if p == "/listas-mover"]


def test_whitelist_invalida_nao_chama_o_analisador(cli):
    cli.c.post("/bloqueios/desbloquear", data={"dominio": "cdn.exemplo.com", "acao": "whitelist", "wl": "xx"})
    assert cli.feitos == []


def test_tabela_tem_link_do_dominio_e_botao_do_modal(app, monkeypatch):
    from flask import render_template

    from app import technitium as dnslib
    adm = SimpleNamespace(email="ti@2d", is_super=True, ativo=True, nome="TI")
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    linha = {"ultima": "2026-10-22T10:00:00", "dominio": "www.exemplo.com", "n": 3, "nclientes": 1, "empresas": ["X"],
             "blocked": True, "bloqueadas": 3, "answer": "", "culpados": ["exemplo.com"], "tipo": "Blocked"}
    with app.test_request_context("/logs-dns"):
        html = render_template("admin/logs_dns.html", linhas=[], agrupado=[linha], agrupar=True, vista="dominio",
                               grupos=[], lista_empresas=[], respostas=dnslib.RESPONSE_TYPES, wl_cats=dnslib.CATEGORIAS_WHITELIST,
                               voltar="/logs-dns?f=1", inicio="", fim="", scanned=None, cap=False, locais=[], categorias=[])
    assert 'href="/analise/dominio/www.exemplo.com?t=0" target="_blank" rel="noopener"' in html
    assert 'data-desb="exemplo.com"' in html and 'id="dlgDesb"' in html and 'value="produtividade"' in html
