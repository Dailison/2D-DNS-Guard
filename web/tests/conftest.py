"""Console em modo de teste: Technitium e analisador fictícios (nada sai da máquina)."""

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.update(TECHNITIUM_URL="http://technitium.teste", TECHNITIUM_TOKEN="t", ANALYZER_URL="http://10.100.10.4:8088",
                  ANALYZER_TOKEN="a", SESSION_COOKIE_SECURE="false", SECRET_KEY="teste")


@pytest.fixture()
def app():
    from app import create_app
    a = create_app()
    a.config.update(TESTING=True, TECHNITIUM_LIBERADOS_GROUP="Liberados")
    with a.app_context():
        yield a


@pytest.fixture()
def tech(monkeypatch):
    """Technitium e analisador em memória: tech.cfg (config atual), tech.gravados, tech.backups."""
    from app import analyzer_client as api
    from app import technitium as dnslib

    class T:
        cfg: dict = {}
        gravados: list = []
        backups: list = []
        falha_backup = False
        releituras: list = []   # configs devolvidos nas próximas leituras (simula outro operador)

    t = T()
    t.gravados, t.backups, t.releituras = [], [], []

    def get():
        if t.releituras:
            t.cfg = t.releituras.pop(0)
        return copy.deepcopy(t.cfg)

    def post_tech(path, data, timeout=25):
        assert path == "apps/config/set"
        import json
        t.cfg = json.loads(data["config"])
        t.gravados.append(copy.deepcopy(t.cfg))
        return {"status": "ok"}

    def post_api(path, body=None, **kw):
        if path == "/console/technitium-backups":
            if t.falha_backup:
                raise RuntimeError("analisador fora")
            t.backups.append(copy.deepcopy(body))
            return {"ok": True, "id": len(t.backups)}
        raise AssertionError(path)

    monkeypatch.setattr(dnslib, "_get_config", get)
    monkeypatch.setattr(dnslib, "_api_post", post_tech)
    monkeypatch.setattr(api, "post", post_api)
    return t
