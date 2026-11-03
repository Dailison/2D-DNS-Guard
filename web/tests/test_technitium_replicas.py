"""Réplicas do Technitium (03/11: Technitium Cloud na VPS): recebem a mesma config do Advanced Blocking."""

import json

R = "http://10.250.100.1:5380"


def _replica(monkeypatch, dnslib, falha=False):
    """Réplica em memória (rep["cfg"], rep["sets"]); o espelho roda na hora (sem thread)."""
    rep = {"cfg": {}, "sets": 0, "gets": 0}

    def chamar(base, token, path, data=None, timeout=15):
        assert base == R and token == "t", "réplica usa o token do principal quando não há um próprio"
        if falha:
            raise OSError("timed out")
        if path.startswith("apps/config/get"):
            rep["gets"] += 1
            return {"config": json.dumps(rep["cfg"])}
        assert path == "apps/config/set" and data["name"] == "Advanced Blocking"
        rep["cfg"] = json.loads(data["config"])
        rep["sets"] += 1
        return {}
    monkeypatch.setattr(dnslib, "_chamar", chamar)
    monkeypatch.setattr(dnslib, "_em_segundo_plano", lambda fn, *a: fn(*a))
    dnslib._ESPELHO["estado"].clear()
    return rep


def test_gravacao_no_principal_vai_para_a_replica(app, tech, monkeypatch):
    from app import technitium as dnslib
    app.config["TECHNITIUM_REPLICAS"] = [R]
    rep = _replica(monkeypatch, dnslib)
    tech.cfg = {"groups": [{"name": "Liberados", "enableBlocking": False}], "networkGroupMap": {}}
    dnslib.liberar("10.39.20.5", por="teste")
    assert tech.gravados and rep["cfg"] == tech.cfg, "a réplica recebe exatamente a config gravada no principal"
    assert rep["cfg"]["networkGroupMap"] == {"10.39.20.5/32": "Liberados"}
    assert dnslib.estado_replicas()[R]["ok"] is True


def test_replica_fora_nao_falha_o_principal(app, tech, monkeypatch):
    from app import technitium as dnslib
    app.config["TECHNITIUM_REPLICAS"] = [R]
    _replica(monkeypatch, dnslib, falha=True)
    tech.cfg = {"groups": [{"name": "Liberados", "enableBlocking": False}], "networkGroupMap": {}}
    ip, msg = dnslib.liberar("10.39.20.6", por="teste")
    assert ip == "10.39.20.6/32" and tech.gravados, "o principal grava mesmo com a réplica fora do ar"
    est = dnslib.estado_replicas()[R]
    assert est["ok"] is False and "timed out" in est["erro"]


def test_reconciliacao_so_grava_quando_difere(app, monkeypatch):
    from app import technitium as dnslib
    rep = _replica(monkeypatch, dnslib)
    principal = {"groups": [{"name": "default"}], "networkGroupMap": {"0.0.0.0/0": "default"}}
    rep["cfg"] = json.loads(json.dumps(principal))
    dnslib._espelhar([(R, "t")], json.dumps(principal), True)
    assert rep["sets"] == 0 and dnslib.estado_replicas()[R]["acao"] == "igual ao principal"
    rep["cfg"] = {"groups": [], "networkGroupMap": {}}   # ficou para trás (estava fora do ar)
    dnslib._espelhar([(R, "t")], json.dumps(principal), True)
    assert rep["sets"] == 1 and rep["cfg"] == principal


def test_sem_replicas_nada_muda(app, tech, monkeypatch):
    from app import technitium as dnslib
    app.config["TECHNITIUM_REPLICAS"] = []
    chamadas = []
    monkeypatch.setattr(dnslib, "_em_segundo_plano", lambda fn, *a: chamadas.append(a))
    tech.cfg = {"groups": [{"name": "Liberados", "enableBlocking": False}], "networkGroupMap": {}}
    dnslib.liberar("10.39.20.7", por="teste")
    assert tech.gravados and not chamadas


def test_health_mostra_as_replicas(app, monkeypatch):
    from app import technitium as dnslib
    dnslib._ESPELHO["estado"].clear()
    assert "technitium_replicas" not in app.test_client().get("/health").get_json()
    dnslib._ESPELHO["estado"][R] = {"ok": True, "acao": "igual ao principal", "em": "2026-11-03T19:00:00+00:00"}
    assert app.test_client().get("/health").get_json()["technitium_replicas"][R]["ok"] is True
    dnslib._ESPELHO["estado"].clear()
