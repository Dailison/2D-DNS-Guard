"""Computadores com filtro "Última hora" (29/09): dias=0 no console vira hours=1 na API do analisador; só as telas de
computadores oferecem a opção — nas outras abas o período volta para 24h."""

from types import SimpleNamespace

import pytest


@pytest.fixture()
def cli(app, monkeypatch):
    from app import analise
    from app import analyzer_client as api
    chamadas = []

    def get(path, **params):
        chamadas.append((path, params))
        if path == "/tenants":
            return [{"id": 5, "name": "Empresa X", "active": True, "auto_created": False, "networks": []}]
        if path.endswith("/clients"):
            return [{"ip": "10.0.0.9", "tenant_id": 5, "tenant_name": "Empresa X", "queries": 12, "domains": 3,
                     "nonwork_share": 0.1, "anomaly_score": 4, "susp": 0, "mal": 0, "new_domains_24h": 0,
                     "open_alerts": 0, "last_seen": "2026-09-29T03:10:00+00:00", "label": None}]
        if "/clients/" in path:
            return {"client": {"ip": "10.0.0.9", "tenant_id": 5, "tenant_name": "Empresa X", "queries": 12,
                               "domains": 3, "nonwork_share": 0.1, "anomaly_score": 4, "susp": 0, "mal": 0,
                               "new_domains_24h": 0, "open_alerts": 0, "last_seen": None, "label": None},
                    "domains": [], "alerts": []}
        return []

    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=True, ativo=True))
    monkeypatch.setattr(analise, "_status", lambda nomes, tenant: {})
    return SimpleNamespace(c=app.test_client(), chamadas=chamadas)


def _periodo(chamadas, sufixo):
    return [p for path, p in chamadas if path.endswith(sufixo)][-1]


def test_ultima_hora_nos_computadores(cli):
    r = cli.c.get("/analise/computadores?t=0&dias=0")
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    p = _periodo(cli.chamadas, "/clients")
    assert p.get("hours") == 1 and "days" not in p, p
    assert '<option value="0" selected' in html and "Última hora" in html


def test_detalhe_do_computador_segue_a_ultima_hora(cli):
    cli.c.get("/analise/computadores?t=0&dias=0")
    cli.c.get("/analise/computador/10.0.0.9?t=0")
    assert _periodo(cli.chamadas, "/clients/10.0.0.9") == {"hours": 1}


def test_periodo_em_dias_continua_igual(cli):
    cli.c.get("/analise/computadores?t=0&dias=7")
    assert _periodo(cli.chamadas, "/clients") == {"limit": 500, "days": 7}


def test_outras_abas_nao_oferecem_e_voltam_para_24h(cli):
    cli.c.get("/analise/computadores?t=0&dias=0")
    html = cli.c.get("/analise?t=0").get_data(as_text=True)
    assert "Última hora" not in html
    assert '<option value="1" selected' in html
