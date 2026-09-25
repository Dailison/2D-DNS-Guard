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
