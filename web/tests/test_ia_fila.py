"""Botão "Fila" do IA ao vivo (30/09): modal com as filas da etapa 1, da investigação e da etapa 2."""

from types import SimpleNamespace

import pytest

FILA = {"e1": {"total": 1, "itens": [{"name": "novo.com.br", "total_queries": 40, "classification": None,
                                      "pouco_acesso": False, "entrada": "novo", "analisando": True, "desde_s": 60}]},
        "e2": {"total": 1, "itens": [{"name": "x.com", "total_queries": 3, "classification": "DESCONHECIDO", "lista_ia": None,
                                      "entrada": "investigacao", "analisando": False, "aguardando": False}], "habilitado": True},
        "investigacao": {"total": 0, "itens": [], "habilitado": True, "espera_etapa1": True}}


@pytest.fixture()
def cli(app, monkeypatch):
    from app import analyzer_client as api
    chamadas = []

    def get(path, **params):
        chamadas.append((path, params))
        if path == "/ai/fila":
            return FILA
        if path == "/tenants":
            return []
        return {}
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=False, ativo=True))
    return SimpleNamespace(c=app.test_client(), chamadas=chamadas)


def test_botao_fila_ao_lado_do_pausar(cli):
    html = cli.c.get("/analise/ia").get_data(as_text=True)
    assert "☰ Fila" in html and html.index("☰ Fila") < html.index("⏸ Pausar")
    assert 'x-ref="fila"' in html and "/analise/ia/fila" in html


def test_rota_da_fila_repassa_o_analisador(cli):
    r = cli.c.get("/analise/ia/fila")
    assert r.status_code == 200 and r.get_json()["e2"]["itens"][0]["entrada"] == "investigacao"
    assert ("/ai/fila", {"limit": 150}) in cli.chamadas


def test_rota_da_fila_com_analisador_fora(cli, monkeypatch):
    from app import analyzer_client as api
    from app.analyzer_client import AnalyzerError

    def falha(path, **params):
        raise AnalyzerError("fora do ar")
    monkeypatch.setattr(api, "get", falha)
    r = cli.c.get("/analise/ia/fila")
    assert r.status_code == 502 and "fora do ar" in r.get_json()["error"]


def test_pausar_tem_as_tres_filas_e_so_super_altera(cli, monkeypatch):
    from app import analyzer_client as api
    html = cli.c.get("/analise/ia").get_data(as_text=True)
    assert "Fila local" in html and "Fila online" in html and "Reforço (GPU)" in html and "Atualização da tela" in html
    enviados = []
    monkeypatch.setattr(api, "put", lambda path, body: enviados.append((path, body)) or {"online": {"pausado": True}})
    r = cli.c.post("/analise/ia/controle/online", json={"pausado": True})
    assert r.status_code == 403 and not enviados                     # operador comum
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="chefe@2d", is_super=True, ativo=True))
    monkeypatch.setattr("app.analise.admin_atual", lambda: SimpleNamespace(email="chefe@2d", is_super=True, ativo=True))
    r = cli.c.post("/analise/ia/controle/online", json={"pausado": True})
    assert r.status_code == 200 and enviados == [("/ai/controle/online", {"pausado": True, "by": "chefe@2d"})]
