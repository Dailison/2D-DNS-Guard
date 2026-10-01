"""Listas por empresa/unidade (01/10): em Domínios bloqueados escolhe-se a empresa e a filial e o ajuste vale só ali."""

from types import SimpleNamespace

import pytest

DET = {"items": [{"domain": "fornecedor.com.br", "classification": "NAO_TRABALHO", "total_queries": 9},
                 {"domain": "loja.com", "classification": "NAO_TRABALHO", "total_queries": 3}],
       "total": 2, "total_geral": 2, "facetas": {"cat_ia": {}, "classificacao": {}, "revisao": {}}}
AJ = {"scope": "unit:7:Filial Sul", "proprios": [{"scope": "unit:7:Filial Sul", "domain": "fornecedor.com.br", "acao": "liberar",
                                                  "por": "ti@2d", "em": "2026-10-01T10:00:00+00:00"}],
      "herdados": [{"scope": "tenant:7", "domain": "loja.com", "acao": "liberar", "por": "chefe@2d", "em": "2026-09-30T10:00:00+00:00"}],
      "efetivo": {"liberar": ["fornecedor.com.br", "loja.com"], "bloquear": []}}


@pytest.fixture()
def pagina(app, monkeypatch):
    from app import analyzer_client as api
    from app import politicas
    chamadas = []

    def get(path, **params):
        chamadas.append(("GET", path, params))
        if path == "/tenants":
            return [{"id": 7, "name": "Moral", "active": True, "auto_created": False,
                     "networks": [{"cidr": "10.7.0.0/24", "unit": "Matriz"}, {"cidr": "10.7.1.0/24", "unit": "Filial Sul"}]}]
        if path == "/ajustes":
            return AJ if params.get("scope") else {"escopos": {"unit:7:Filial Sul": {"liberar": 1, "bloquear": 0}}}
        if path.endswith("/detalhes"):
            return DET
        if path == "/listas":
            return {"categorias": [], "auto": [], "auto_24h": 0}
        return {} if path in ("/listas-dominios", "/whitelist-dominios") else []
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(api, "put", lambda path, body: chamadas.append(("PUT", path, body)) or {"gravados": len(body["domains"])})
    monkeypatch.setattr(api, "post", lambda path, body: chamadas.append(("POST", path, body)) or {"desfeitos": 1})
    monkeypatch.setattr(politicas, "sincronizar", lambda: chamadas.append(("SYNC", "", {})) or {})
    adm = SimpleNamespace(email="chefe@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    return SimpleNamespace(c=app.test_client(), chamadas=chamadas, adm=adm)


def test_pagina_com_empresa_e_filial_mostra_ajustes(pagina):
    html = pagina.c.get("/dominios-bloqueados?cat=compras&empresa=7&unidade=Filial+Sul").get_data(as_text=True)
    assert "Ajustes de Moral · Filial Sul" in html and "Liberar só em Moral · Filial Sul" in html
    assert 'data-escopo="unit:7:Filial Sul"' in html
    assert "liberado aqui" in html and "liberado na empresa" in html and "empresa inteira (herdado)" in html
    assert ("GET", "/ajustes", {"scope": "unit:7:Filial Sul"}) in pagina.chamadas


def test_pagina_sem_empresa_segue_global(pagina):
    html = pagina.c.get("/dominios-bloqueados?cat=compras").get_data(as_text=True)
    assert "Ajustes de" not in html and "Liberar só em" not in html and 'data-escopo=""' in html
    assert not [c for c in pagina.chamadas if c[1] == "/ajustes"]


def test_ajuste_grava_no_escopo_e_sincroniza(pagina):
    r = pagina.c.post("/dominios-bloqueados/ajuste", json={"escopo": "unit:7:Filial Sul", "nome": "Moral · Filial Sul",
                                                           "acao": "liberar", "dominios": ["Fornecedor.com.br."]})
    assert r.status_code == 200 and "liberado(s) só em Moral · Filial Sul" in r.get_json()["msg"]
    assert ("PUT", "/ajustes", {"scope": "unit:7:Filial Sul", "domains": ["fornecedor.com.br"], "acao": "liberar", "by": "chefe@2d"}) in pagina.chamadas
    assert pagina.chamadas[-1][0] == "SYNC"
    r = pagina.c.post("/dominios-bloqueados/ajuste", json={"escopo": "unit:7:Filial Sul", "acao": "desfazer", "dominios": ["fornecedor.com.br"]})
    assert r.status_code == 200 and ("POST", "/ajustes/desfazer", {"scope": "unit:7:Filial Sul", "domains": ["fornecedor.com.br"], "by": "chefe@2d"}) in pagina.chamadas


def test_ajuste_so_para_super(pagina):
    pagina.adm.is_super = False
    r = pagina.c.post("/dominios-bloqueados/ajuste", json={"escopo": "tenant:7", "acao": "liberar", "dominios": ["x.com"]})
    assert r.status_code == 403 and not [c for c in pagina.chamadas if c[0] == "PUT"]
