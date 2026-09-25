import pytest
from pydantic import ValidationError

from dnsanalyzer.llm import LLMResult, build_messages, json_schema
from dnsanalyzer.policy import combine
from dnsanalyzer.rules import evaluate

CATS = [{"code": c, "description": c} for c in ["TRABALHO", "NAO_TRABALHO", "SUSPEITO", "MALICIOSO", "DESCONHECIDO"]]


def base(name="fornecedor.com.br", **kw):
    d = {"name": name, "kind": "public", "tld": "br", "features": {}, "ti_hits": [], "logs": {}}
    d.update(kw)
    return evaluate(d)


def llm(cls="TRABALHO", risk=5, work=80, conf=0.8, reasons=None, action="NONE", recognized=True):
    return LLMResult(classification=cls, recognized=recognized, topic="ERP", risk_score=risk, work_score=work,
                     confidence=conf, reasons=reasons or [{"evidence_id": "E0", "text": "fornecedor de software"}],
                     recommended_action=action)


def test_unrecognized_service_becomes_unknown():
    # modelo "chutou" NAO_TRABALHO sem conhecer o serviço -> DESCONHECIDO, work neutro
    r = base("kslawin.com")
    f = combine(r, llm("NAO_TRABALHO", work=35, recognized=False), ev(r))
    assert f.classification == "DESCONHECIDO" and f.work == 50
    assert any("não reconhece" in n for n in f.notes)


def test_recognized_service_is_kept():
    r = base("fornecedor.com.br", popularity_rank=5000)
    f = combine(r, llm("TRABALHO", work=80, recognized=True), ev(r))
    assert f.classification == "TRABALHO" and f.work == 80


def test_unranked_recognition_is_not_trusted():
    # fora do top 1M: o modelo não tem como conhecer — "reconhecimento" é chute
    r = base("tradti.com.br")
    f = combine(r, llm("NAO_TRABALHO", work=30, recognized=True), ev(r))
    assert f.classification == "DESCONHECIDO" and f.work == 50
    assert any("top 1M" in n for n in f.notes)


def ev(rule):
    return [e.as_dict() for e in rule.evidence]


def test_invented_evidence_is_dropped():
    r = base()
    res = llm(reasons=[{"evidence_id": "E99", "text": "domínio registrado ontem"},
                       {"evidence_id": "E0", "text": "é um ERP"}])
    f = combine(r, res, ev(r))
    assert all(x["evidence_id"] != "E99" for x in f.reasons)
    assert any("descartada" in n for n in f.notes)
    assert f.confidence < 0.8


def test_all_invented_falls_back_to_rules():
    r = base()
    f = combine(r, llm(reasons=[{"evidence_id": "E42", "text": "inventado"}]), ev(r))
    assert f.classified_by != "llm"
    assert f.classification == r.classification


def test_malicious_requires_high_ti():
    r = base()
    f = combine(r, llm("MALICIOSO", risk=95, work=0, action="BLOCK_CANDIDATE",
                       reasons=[{"evidence_id": "E0", "text": "nome estranho"}]), ev(r))
    assert f.classification != "MALICIOSO"
    assert f.action != "BLOCK_CANDIDATE"


def test_risk_is_anchored_to_rules():
    r = base()
    f = combine(r, llm("NAO_TRABALHO", risk=90, work=5), ev(r))
    assert f.risk <= r.risk + 15


def test_suspicious_without_risk_evidence_is_downgraded():
    r = base()
    f = combine(r, llm("SUSPEITO", risk=60, work=10, conf=0.4,
                       reasons=[{"evidence_id": "E0", "text": "não conheço"}]), ev(r))
    assert f.classification == "DESCONHECIDO"


def test_rules_suspicious_is_kept():
    r = base("xjq7k2vbz9wpl3mqr8t.top", features={"sld_dga": 0.8}, age_days=2, abused_tld={"s": 1})
    assert r.classification == "SUSPEITO"
    f = combine(r, llm("NAO_TRABALHO", risk=10, work=10), ev(r))
    assert f.classification == "SUSPEITO" and f.risk >= 50


def test_llm_result_validation():
    with pytest.raises(ValidationError):
        LLMResult(classification="X", risk_score=150, work_score=1, confidence=0.5,
                  reasons=[{"evidence_id": "E0", "text": "a"}], recommended_action="NONE")
    with pytest.raises(ValidationError):
        llm(action="DELETE_EVERYTHING")


def test_schema_and_prompt():
    s = json_schema(["TRABALHO", "SUSPEITO"])
    assert s["properties"]["classification"]["enum"] == ["TRABALHO", "SUSPEITO"]
    msgs = build_messages("x.com", [{"id": "E0", "text": "nome do domínio: x.com"}], CATS)
    assert "E0: nome do domínio: x.com" in msgs[1]["content"]
    assert "NUNCA invente" in msgs[0]["content"]
