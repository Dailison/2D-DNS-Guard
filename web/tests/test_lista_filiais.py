"""Modal "Quem aplica a lista …" com filiais (01/10): a lista vale na empresa inteira ou só em algumas filiais."""

from types import SimpleNamespace

import pytest

EMP = [{"id": 7, "name": "Moral", "auto_created": False,
        "networks": [{"cidr": "10.7.0.0/24", "unit": "Matriz"}, {"cidr": "10.7.1.0/24", "unit": "Filial Sul"}]},
       {"id": 8, "name": "Norte", "auto_created": False, "networks": [{"cidr": "10.8.0.0/24", "unit": ""}]}]


@pytest.fixture()
def modal(app, monkeypatch):
    from app import analyzer_client as api
    from app import empresas, politicas
    est = SimpleNamespace(pol={"default": {"lists": ["ameaca"], "services": [], "services_blocked": []},
                               "tenant:7": {"lists": ["ameaca", "compras"], "services": ["instagram"], "services_blocked": []}},
                          chamadas=[])
    monkeypatch.setattr(empresas, "lista", lambda: EMP)
    monkeypatch.setattr(politicas, "por_escopo", lambda: est.pol)
    monkeypatch.setattr(politicas, "sincronizar", lambda: est.chamadas.append(("SYNC",)) or {})
    monkeypatch.setattr(api, "put", lambda path, body: est.chamadas.append(("PUT", path, body["lists"], body["services"])) or {})
    monkeypatch.setattr(api, "delete", lambda path, **k: est.chamadas.append(("DELETE", path)) or {})
    adm = SimpleNamespace(email="chefe@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    est.c = app.test_client()
    est.post = lambda **b: est.c.post("/listas-categoria/empresas", json={"cat": "compras", "default": False, **b})
    return est


def test_filial_diferente_da_empresa_ganha_politica_propria(modal):
    """Compras vale na Moral, menos na Filial Sul: a filial ganha a política da empresa sem a lista."""
    r = modal.post(tenants=[7], unidades=[{"tid": 7, "unidade": "Matriz", "liga": True}, {"tid": 7, "unidade": "Filial Sul", "liga": False}])
    assert r.status_code == 200
    assert modal.chamadas == [("PUT", "/policies/unit%3A7%3AFilial%20Sul", ["ameaca"], ["instagram"]), ("SYNC",)]


def test_filial_que_volta_a_igualar_perde_a_politica_propria(modal):
    modal.pol["unit:7:Filial Sul"] = {"lists": ["ameaca"], "services": ["instagram"], "services_blocked": []}
    modal.post(tenants=[7], unidades=[{"tid": 7, "unidade": "Matriz", "liga": True}, {"tid": 7, "unidade": "Filial Sul", "liga": True}])
    assert modal.chamadas == [("DELETE", "/policies/unit%3A7%3AFilial%20Sul"), ("SYNC",)]


def test_filial_com_politica_propria_so_troca_a_lista(modal):
    """A filial tem outras listas próprias: liga/desliga só esta, o resto dela fica."""
    modal.pol["unit:7:Matriz"] = {"lists": ["jogos"], "services": [], "services_blocked": []}
    modal.post(tenants=[7], unidades=[{"tid": 7, "unidade": "Matriz", "liga": True}, {"tid": 7, "unidade": "Filial Sul", "liga": True}])
    assert modal.chamadas == [("PUT", "/policies/unit%3A7%3AMatriz", ["compras", "jogos"], []), ("SYNC",)]


def test_so_uma_filial_de_empresa_sem_a_lista(modal):
    """A empresa não aplica Compras; só a Matriz passa a aplicar (parte da política da empresa)."""
    modal.pol["tenant:7"]["lists"] = ["ameaca"]
    modal.post(tenants=[], unidades=[{"tid": 7, "unidade": "Matriz", "liga": True}, {"tid": 7, "unidade": "Filial Sul", "liga": False}])
    assert modal.chamadas == [("PUT", "/policies/unit%3A7%3AMatriz", ["ameaca", "compras"], ["instagram"]), ("SYNC",)]


def test_nada_muda_nao_grava(modal):
    r = modal.post(tenants=[7], unidades=[{"tid": 7, "unidade": "Matriz", "liga": True}, {"tid": 7, "unidade": "Filial Sul", "liga": True}])
    assert r.get_json()["msg"] == "Nada mudou." and modal.chamadas == []


def test_modal_mostra_as_filiais(modal, monkeypatch):
    from app import analyzer_client as api
    modal.pol["unit:7:Filial Sul"] = {"lists": ["ameaca"], "services": [], "services_blocked": []}
    det = {"items": [], "total": 0, "total_geral": 0, "facetas": {"cat_ia": {}, "classificacao": {}, "revisao": {}}}
    monkeypatch.setattr(api, "get", lambda path, **p: det if path.endswith("/detalhes") else
                        {"categorias": [], "auto": [], "auto_24h": 0} if path == "/listas" else
                        EMP if path == "/tenants" else {} if path in ("/listas-dominios", "/whitelist-dominios") else [])
    html = modal.c.get("/dominios-bloqueados?cat=compras").get_data(as_text=True)
    assert 'class="eUni" data-tid="7" value="Matriz" checked' in html, "segue a empresa (que aplica)"
    assert 'class="eUni" data-tid="7" value="Filial Sul" >' in html and "· própria" in html
    assert 'data-tid="8"' not in html, "empresa sem filiais: só a caixa dela"
