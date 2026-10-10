"""Página do domínio mostra o dossiê da investigação profunda (fase 6, 29/09)."""

from types import SimpleNamespace

import pytest

INV = {"at": "2026-09-29T04:00:00+00:00", "segundos": 108.4, "aplicado": True, "sem_aplicar": None,
       "veredito": {"service": "Ecocentauro (ERP)", "classification": "TRABALHO", "category": "produtividade",
                    "lista": "wl:erp_gestao", "confidence": 0.9, "motivo": "Portal de clientes da Ecocentauro.",
                    "evidencias": ["E1", "E17"]},
       "revisao": {"sustentado": True, "problema": ""}, "etapas": [{"etapa": "fontes"}],
       "plano": {"hipotese": "sistema de gestão"}, "rodadas": [{"modelo": "gemma4:26b", "gpu": True}],
       "evidencias": [{"id": "E17", "kind": "certs", "text": "6 certificado(s) públicos desde 2026-07-14"}],
       "antes": {"classification": "DESCONHECIDO", "category": "desconhecido", "lista_ia": "nao_identificado"}}


def _dominio(inv):
    return {"domain": {"id": 1, "name": "sistema.eco.br", "classification": "TRABALHO", "category": "produtividade",
                       "risk_score": 5, "work_score": 90, "confidence": 0.9, "reasons": [], "evidence": [],
                       "ti_hits": [], "investigacao": inv},
            "tenant_view": None, "clients": [], "fqdns": [], "timeline": [], "history": [], "by_tenant": [],
            "global_review": None}


@pytest.fixture()
def pagina(app, monkeypatch):
    from app import analise
    from app import analyzer_client as api
    estado = {"inv": INV}

    def get(path, **params):
        if path == "/tenants":
            return [{"id": 5, "name": "Empresa X", "active": True, "auto_created": False, "networks": []}]
        if "/domains/" in path and path.startswith("/tenants/"):
            return _dominio(estado["inv"])
        return []
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=False, ativo=True))
    monkeypatch.setattr(analise, "_bloqueio_ctx", lambda *a: None)
    monkeypatch.setattr(analise, "_whitelist_do_dominio", lambda n: [])
    return SimpleNamespace(c=app.test_client(), estado=estado)


def test_mostra_o_dossie_aplicado(pagina):
    html = pagina.c.get("/analise/dominio/sistema.eco.br?t=0").get_data(as_text=True)
    assert "Investigação profunda" in html and "bi-check-lg\"></i> aplicado" in html
    assert "Ecocentauro (ERP)" in html and "wl:erp_gestao" in html and "6 certificado(s)" in html
    assert "Antes: DESCONHECIDO" in html and "gemma4:26b (GPU)" in html
    assert "Revisor: concordou" in html


def test_sem_certeza_mostra_o_motivo(pagina):
    pagina.estado["inv"] = {**INV, "aplicado": False, "sem_aplicar": "confiança 0.6/0.6 abaixo de 0.85"}
    html = pagina.c.get("/analise/dominio/sistema.eco.br?t=0").get_data(as_text=True)
    assert "só dossiê" in html and "abaixo de 0.85" in html and "Antes:" not in html


def test_sem_investigacao_nao_mostra_o_cartao(pagina):
    pagina.estado["inv"] = None
    html = pagina.c.get("/analise/dominio/sistema.eco.br?t=0").get_data(as_text=True)
    assert "Investigação profunda" not in html
