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


def _busca(*hosts):
    return [{"title": f"sobre em {h}", "snippet": "Dell SupportAssist", "host": h, "url": f"https://{h}/x"}
            for h in hosts]


def test_web_search_two_sites_allow_recognition():
    # etapa 2: fora do top 1M, 2 resultados de sites diferentes citados valem como identificação
    r = base("platinumai.net", search=_busca("dell.com", "reddit.com"))
    ids = [e.id for e in r.evidence if e.kind == "websearch"]
    f = combine(r, llm("TRABALHO", work=80, recognized=True,
                       reasons=[{"evidence_id": i, "text": "Dell SupportAssist"} for i in ids]), ev(r))
    assert f.classification == "TRABALHO"


def test_web_search_single_site_is_not_enough():
    r = base("platinumai.net", search=_busca("dell.com", "dell.com"))
    ids = [e.id for e in r.evidence if e.kind == "websearch"]
    f = combine(r, llm("TRABALHO", work=80, recognized=True,
                       reasons=[{"evidence_id": i, "text": "Dell"} for i in ids]), ev(r))
    assert f.classification == "DESCONHECIDO"


def test_web_search_cited_one_of_several_sites_is_enough():
    # a IA leu a busca (4 sites diferentes) mas citou só um resultado: vale (antes caía em DESCONHECIDO)
    r = base("kudabibi.com", search=_busca("blox-fruits.fandom.com", "mobilegamer.com.br", "youtube.com"))
    ids = [e.id for e in r.evidence if e.kind == "websearch"]
    f = combine(r, llm("NAO_TRABALHO", work=5, recognized=True,
                       reasons=[{"evidence_id": ids[0], "text": "jogo online"}]), ev(r))
    assert f.classification == "NAO_TRABALHO"


def test_web_search_available_but_not_used_is_not_enough():
    # busca com 2+ sites no dossiê, mas a IA só citou o nome (E0): continua sem apoio -> DESCONHECIDO
    r = base("kudabibi.com", search=_busca("a.com", "b.com"))
    f = combine(r, llm("NAO_TRABALHO", work=5, recognized=True), ev(r))
    assert f.classification == "DESCONHECIDO"


def test_vaga_da_vm_uma_chamada_por_vez():
    """29/09: Ollama da VM com 2 vagas — a análise usa no máximo 1 (a outra é do atendente virtual). Reforço (GPU)
    não espera."""
    import threading
    import time
    from types import SimpleNamespace
    from dnsanalyzer.llm import vaga

    def pico(client):
        dentro, maior, lock = [0], [0], threading.Lock()

        def chamada():
            with vaga(client):
                with lock:
                    dentro[0] += 1
                    maior[0] = max(maior[0], dentro[0])
                time.sleep(0.05)
                with lock:
                    dentro[0] -= 1
        ts = [threading.Thread(target=chamada) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        return maior[0]
    assert pico(SimpleNamespace(extra=False)) == 1
    assert pico(SimpleNamespace(extra=True)) > 1


def test_pagina_do_site_basta_para_nao_trabalho_fora_do_top_1m():
    """09/10 (pedido do usuário): a página do próprio site já bastava p/ a LISTA de bloqueio (30/09), mas a
    classificação exigia também busca na web com 2 sites — 1.734 domínios ficaram em apostas/compras/adulto e ainda
    "desconhecidos" (e na fila da investigação). NAO_TRABALHO apoiado na página vale; TRABALHO (o lado que libera)
    continua exigindo identificação externa; chute só pelo nome continua desconhecido."""
    r = base("hhbet12.com")
    pagina = {"id": "E9", "kind": "site", "text": "página inicial: 'Apostas e cassino online'", "risk": False, "data": {}}
    evid = ev(r) + [pagina]
    cita_pagina = [{"evidence_id": "E9", "text": "a página mostra um cassino online"}]
    f = combine(r, llm("NAO_TRABALHO", work=10, recognized=True, reasons=cita_pagina), evid)
    assert f.classification == "NAO_TRABALHO" and not any("não é confiável" in n for n in f.notes)
    f = combine(r, llm("TRABALHO", work=80, recognized=True, reasons=cita_pagina), evid)
    assert f.classification == "DESCONHECIDO", "liberar pela página sozinha continua exigindo confirmação"
    f = combine(r, llm("NAO_TRABALHO", work=10, recognized=True), evid)   # cita só o nome (E0)
    assert f.classification == "DESCONHECIDO", "sem se apoiar na página é chute"
