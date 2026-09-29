"""Painel da Análise DNS com zero loading (29/09): a página abre sem consultar o resumo do analisador (25-50 s em
"Todos os clientes") e o conteúdo vem de /analise/painel/conteudo."""

from types import SimpleNamespace

import pytest

TENANTS = [{"id": 5, "name": "Empresa X", "active": True, "auto_created": False, "networks": []}]
RESUMO = {"counts": {"TRABALHO": 10, "NAO_TRABALHO": 4, "SUSPEITO": 1, "MALICIOSO": 0, "DESCONHECIDO": 2},
          "total_domains": 17, "pending_ai": 3,
          "top_nonwork": [{"name": "tiktok.com", "classification": "NAO_TRABALHO", "category": "redes_sociais",
                           "queries": 90, "clients": 3, "tenants": 1}],
          "top_risk": [], "top_domains": [], "new_domains": [], "alerts": [], "anomalous_clients": [],
          "by_tenant": [{"id": 5, "name": "Empresa X", "auto_created": False, "clients": 3, "queries": 100,
                         "domains": 17, "nonwork_q": 90, "risky": 1, "open_alerts": 0}]}


@pytest.fixture()
def painel(app, monkeypatch):
    from app import analise
    from app import analyzer_client as api
    chamadas = []

    def get(path, **params):
        chamadas.append(path)
        if path == "/tenants":
            return TENANTS
        if path.endswith("/summary"):
            return RESUMO
        if path.endswith("/domains"):
            return {"total": 1, "items": [{"name": "tiktok.com", "category": "redes_sociais", "total_queries": 90}]}
        if path == "/site-categories":
            return [{"code": "redes_sociais", "label": "Redes sociais", "nonwork": True}]
        raise AssertionError(path)

    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=True, ativo=True))
    monkeypatch.setattr(analise, "_status", lambda nomes, tenant: {})
    return SimpleNamespace(c=app.test_client(), chamadas=chamadas)


def test_pagina_abre_sem_consultar_o_resumo(painel):
    r = painel.c.get("/analise?t=0&dias=7")
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert not [p for p in painel.chamadas if p.endswith("/summary") or p.endswith("/domains")], painel.chamadas
    assert 'id="painelConteudo"' in html and "/analise/painel/conteudo?t=0&amp;dias=7" in html
    assert "painelCarregar()" in html


def test_conteudo_traz_o_painel(painel):
    r = painel.c.get("/analise/painel/conteudo?t=0&dias=7", headers={"X-Requested-With": "fetch"})
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "/tenants/0/summary" in painel.chamadas
    assert "Domínios analisados" in html and "tiktok.com" in html and "Empresa X" in html
    assert "<html" not in html.lower()   # só o fragmento, sem o layout


def test_conteudo_com_analisador_fora_mostra_erro_no_lugar(painel, monkeypatch):
    from app import analyzer_client as api
    from app.analyzer_client import AnalyzerError
    base = api.get

    def get(path, **params):
        if path.endswith("/summary"):
            raise AnalyzerError("timeout <script>")
        return base(path, **params)
    monkeypatch.setattr(api, "get", get)
    html = painel.c.get("/analise/painel/conteudo?t=0&dias=1").get_data(as_text=True)
    assert "Falha ao carregar o painel" in html and "Tentar de novo" in html
    assert "<script>" not in html   # mensagem escapada
