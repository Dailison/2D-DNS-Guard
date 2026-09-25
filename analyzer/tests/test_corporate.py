from dnsanalyzer.corporate import recommend
from dnsanalyzer.llm import LLMResult
from dnsanalyzer.policy import combine, rules_only
from dnsanalyzer.rules import evaluate
from dnsanalyzer.catalog import match


def test_defaults_by_category():
    assert recommend("NAO_TRABALHO", "redes_sociais", 2)[0] == "BLOQUEAR"
    assert recommend("TRABALHO", "produtividade", 1)[0] == "LIBERAR"
    assert recommend("NAO_TRABALHO", "publicidade", 3)[0] == "REVISAR"
    assert recommend("DESCONHECIDO", "desconhecido", 10)[0] == "REVISAR"
    assert recommend("NAO_TRABALHO", None, 0) is None          # ainda sem categoria


def test_guards():
    assert recommend("MALICIOSO", "outros", 90)[0] == "BLOQUEAR"
    assert recommend("SUSPEITO", "outros", 80)[0] == "BLOQUEAR"
    assert recommend("SUSPEITO", "outros", 55)[0] == "REVISAR"
    # IA não pode mandar bloquear infraestrutura nem liberar apostas/lazer
    assert recommend("NAO_TRABALHO", "infraestrutura", 5, ai_action="BLOQUEAR", ai_reason="x") == \
        ("LIBERAR", recommend("NAO_TRABALHO", "infraestrutura", 5)[1], "politica")
    assert recommend("NAO_TRABALHO", "apostas", 5, ai_action="LIBERAR", ai_reason="x")[0] == "BLOQUEAR"
    assert recommend("NAO_TRABALHO", "redes_sociais", 5, ai_action="LIBERAR", ai_reason="x")[0] == "BLOQUEAR"
    # protegido nunca bloqueia; trabalho + lazer diverge -> revisar
    assert recommend("NAO_TRABALHO", "redes_sociais", 5, protected=True)[0] == "LIBERAR"
    assert recommend("TRABALHO", "jogos", 5)[0] == "REVISAR"


def test_ai_opinion_kept_when_allowed():
    r = recommend("NAO_TRABALHO", "streaming", 2, ai_action="REVISAR", ai_reason="YouTube pode ser usado em treinamentos")
    assert r == ("REVISAR", "YouTube pode ser usado em treinamentos", "ia")


def _d(name, **kw):
    d = {"name": name, "kind": "public", "tld": "com", "features": {}, "ti_hits": [], "logs": {}}
    d.update(kw)
    return d


def test_policy_fills_corp():
    f = rules_only(evaluate(_d("x.com", catalog=match("tiktok.com"))), pending_llm=False)
    assert f.corp_action == "BLOQUEAR" and f.corp_by == "politica"
    r = evaluate(_d("kwai-novo.com", popularity_rank=3000))
    llm = LLMResult(service="s", category="redes_sociais", classification="NAO_TRABALHO", recognized=True, topic="t",
                    risk_score=2, work_score=5, confidence=0.9, reasons=[{"evidence_id": "E0", "text": "x"}],
                    recommended_action="NONE", corp_action="BLOQUEAR", corp_reason="rede social pessoal")
    f = combine(r, llm, [e.as_dict() for e in r.evidence])
    assert (f.corp_action, f.corp_reason, f.corp_by) == ("BLOQUEAR", "rede social pessoal", "ia")
