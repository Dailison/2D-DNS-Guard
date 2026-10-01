from dnsanalyzer.llm import LLMResult
from dnsanalyzer.policy import combine
from dnsanalyzer.rules import evaluate
from dnsanalyzer.webintel import _clean


def dossier(name, web=None, **kw):
    d = {"name": name, "kind": "public", "tld": name.rsplit(".", 1)[-1], "features": {}, "ti_hits": [],
         "logs": {}, "web": web or {}}
    d.update(kw)
    return d


def llm_citing(kind_id, cls="TRABALHO", work=80):
    return LLMResult(service="serviço X", classification=cls, recognized=True, topic="t", risk_score=2,
                     work_score=work, confidence=0.9, reasons=[{"evidence_id": kind_id, "text": "x"}],
                     recommended_action="NONE")


def _ev_id(rule, kind):
    return next(e.id for e in rule.evidence if e.kind == kind)


WD = {"wikidata": {"label": "Ubiquiti", "description": "empresa de redes", "qid": "Q1"}}
SITE = {"site": {"title": "Loja do Zé", "final_host": "lojadoze.com.br"}}


def test_wikidata_becomes_evidence():
    r = evaluate(dossier("ui.com", WD, popularity_rank=5000))
    txt = [e.text for e in r.evidence if e.kind == "wikidata"][0]
    assert "Ubiquiti" in txt and "ui.com" in txt


def test_site_text_is_marked_as_self_declared():
    r = evaluate(dossier("lojadoze.com.br", SITE))
    txt = [e.text for e in r.evidence if e.kind == "site"][0]
    assert "DECLARADO" in txt and "Loja do Zé" in txt


def test_unranked_with_wikidata_citation_is_trusted():
    r = evaluate(dossier("fornecedor-x.com.br", WD))          # fora do top 1M
    f = combine(r, llm_citing(_ev_id(r, "wikidata")), [e.as_dict() for e in r.evidence])
    assert f.classification == "TRABALHO"


def test_unranked_with_only_site_citation_is_not_trusted():
    r = evaluate(dossier("lojadoze.com.br", SITE))
    f = combine(r, llm_citing(_ev_id(r, "site")), [e.as_dict() for e in r.evidence])
    assert f.classification == "DESCONHECIDO"


def test_unverified_certificate_is_ignored():
    r = evaluate(dossier("x.com.br", {"cert": {"verified": False}}))
    assert not [e for e in r.evidence if e.kind == "cert"]


def test_verified_cert_sans_become_evidence():
    r = evaluate(dossier("kslawin.com", {"cert": {"verified": True, "issuer": "GlobalSign",
                                                  "san_domains": ["kuaishou.com", "kwai.com"], "san_total": 2}}))
    txt = [e.text for e in r.evidence if e.kind == "cert"][0]
    assert "kwai.com" in txt and "mesmo dono" in txt


def test_clean_sanitizes():
    assert _clean("  A &amp; B\x00\n  C ") == "A & B C"
    assert _clean("x" * 500, 10) == "x" * 10
    assert _clean(None) is None


def test_busca_leve_e_completa_pedem_buscadores_diferentes(monkeypatch):
    """30/09: busca do dia a dia com poucos buscadores; a completa (investigação) com todos, inclusive o Yandex."""
    from types import SimpleNamespace
    from dnsanalyzer import webintel
    pedidos = []

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"results": [], "unresponsive_engines": []}
    monkeypatch.setattr(webintel.httpx, "get", lambda url, timeout=None, params=None: pedidos.append(params) or R())
    cfg = SimpleNamespace(web_search_url="http://sx", web_search_results=6, web_search_motores=["bing", "yahoo"])
    webintel._consulta(cfg, "x")
    webintel._consulta(cfg, "x", motores=["yandex", "google"])
    assert pedidos[0]["engines"] == "bing,yahoo" and pedidos[1]["engines"] == "yandex,google"


def test_busca_completa_respeita_o_intervalo_por_instancia(monkeypatch):
    """01/10: o intervalo da busca completa vale por instância (IPs diferentes): duas saem na hora, a 3ª espera."""
    import time
    from types import SimpleNamespace
    from dnsanalyzer import webintel
    monkeypatch.setattr(webintel, "_completa_ultima", {})
    monkeypatch.setattr(webintel, "_ultima", {})
    monkeypatch.setattr(webintel, "_fora_ate", {})
    cfg = SimpleNamespace(web_search_intervalo_completo=0.3, web_search_min_interval=0, web_search_url="http://vm",
                          web_search_urls=["http://vm", "http://vps"])
    t0 = time.monotonic()
    usados = [webintel.reservar_completa(cfg), webintel.reservar_completa(cfg)]
    assert sorted(usados) == ["http://vm", "http://vps"] and time.monotonic() - t0 < 0.2
    webintel.reservar_completa(cfg)
    assert time.monotonic() - t0 >= 0.29
