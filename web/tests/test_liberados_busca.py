"""Busca na página Domínios liberados (08/10, pedido do usuário): em todas as whitelists e listas de liberação de uma
vez, como a de Domínios bloqueados."""

from types import SimpleNamespace

import pytest


@pytest.fixture()
def tela(app, monkeypatch):
    from app import analyzer_client as api
    est = SimpleNamespace(buscas=[])
    achados = [{"domain": "teams.microsoft.com", "whitelists": ["produtividade"], "servicos": [], "publicado": True,
                "classification": "TRABALHO", "total_queries": 900, "pai": False},
               {"domain": "microsoft.com", "whitelists": ["essenciais"], "servicos": [{"slug": "ms-365", "name": "Microsoft 365"}],
                "publicado": False, "classification": "TRABALHO", "total_queries": 5000, "pai": True}]

    def get(path, **p):
        if path == "/whitelist-busca":
            est.buscas.append(p["q"])
            return achados
        return {"categorias": [], "revisados": 0} if path == "/whitelist" else []
    monkeypatch.setattr(api, "get", get)
    adm = SimpleNamespace(email="op@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    app.config.update(ANALYZER_ENABLED=True)
    est.c = app.test_client()
    return est


def test_campo_de_busca_na_pagina(tela):
    html = tela.c.get("/dominios-liberados").get_data(as_text=True)
    assert 'name="busca"' in html and "buscar em todas as listas" in html and "lbRes" not in html
    assert tela.buscas == [], "sem termo não consulta nada"


def test_busca_mostra_onde_o_dominio_esta_liberado(tela):
    html = tela.c.get("/dominios-liberados?busca=Teams.Microsoft.com.").get_data(as_text=True)
    assert tela.buscas == ["teams.microsoft.com"]
    assert "em todas as listas de liberação: 2 domínio(s)" in html
    assert "Produtividade e escritório" in html and "📋 Microsoft 365" in html
    assert "(domínio-pai: cobre teams.microsoft.com)" in html and "não publicado no DNS" in html
    assert "/dominios-liberados?wl=produtividade&amp;q=teams.microsoft.com" in html


def test_termo_curto_nao_busca(tela):
    html = tela.c.get("/dominios-liberados?busca=ab").get_data(as_text=True)
    assert tela.buscas == [] and "lbRes" not in html
