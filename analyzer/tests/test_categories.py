from dnsanalyzer.catalog import match
from dnsanalyzer.categories import catalog_category, from_topic
from dnsanalyzer.llm import LLMResult
from dnsanalyzer.policy import combine, rules_only
from dnsanalyzer.rules import evaluate


def test_from_topic():
    assert from_topic("Rede social (vídeos curtos)") == "redes_sociais"
    assert from_topic("Streaming de música") == "streaming"
    assert from_topic("Jogos") == "jogos"
    assert from_topic("Apostas") == "apostas"
    assert from_topic("Publicidade/rastreamento") == "publicidade"
    assert from_topic("Compras online") == "compras"
    assert from_topic("Banco") == "financas"
    assert from_topic("ERP") == "produtividade"
    assert from_topic("CDN (infraestrutura compartilhada)") == "infraestrutura"
    assert from_topic("Judiciário") == "governo"
    assert from_topic(None) is None


def test_short_keys_need_word_start():
    # "api"/"bet" não podem casar no meio de outra palavra
    assert from_topic("Terapia ocupacional") != "infraestrutura"
    assert from_topic("Alphabet holding") != "apostas"


def test_catalog_categories():
    assert catalog_category(match("instagram.com")) == "redes_sociais"
    assert catalog_category(match("office365.com")) == "produtividade"
    assert catalog_category(match("gov.br")) == "governo"
    assert catalog_category(match("akamai.net")) == "infraestrutura"


def _d(name, **kw):
    d = {"name": name, "kind": "public", "tld": "com", "features": {}, "ti_hits": [], "logs": {}}
    d.update(kw)
    return d


def test_rules_categories():
    assert evaluate(_d("2d.local", kind="internal")).category == "interno"
    assert evaluate(_d("x.com", catalog=match("tiktok.com"))).category == "redes_sociais"
    mal = evaluate(_d("bad.xyz", ti_hits=[{"source": "urlhaus", "label": "u", "threat": "malware",
                                            "confidence": "high", "weight": 90, "matched": "bad.xyz", "fqdns": []}]))
    assert mal.category == "ameaca"


def _llm(cat, recognized=True, cls="NAO_TRABALHO"):
    return LLMResult(service="s", category=cat, classification=cls, recognized=recognized, topic="t",
                     risk_score=2, work_score=5, confidence=0.9,
                     reasons=[{"evidence_id": "E0", "text": "x"}], recommended_action="NONE")


def test_policy_uses_llm_category_when_trusted():
    r = evaluate(_d("kwai-novo.com", popularity_rank=3000))
    f = combine(r, _llm("redes_sociais"), [e.as_dict() for e in r.evidence])
    assert f.category == "redes_sociais"


def test_policy_unknown_when_not_trusted():
    r = evaluate(_d("fornecedor-x.com.br"))            # fora do top 1M, sem identidade externa
    f = combine(r, _llm("compras"), [e.as_dict() for e in r.evidence])
    assert f.classification == "DESCONHECIDO" and f.category == "desconhecido"


def test_rules_only_pending_has_no_category_yet():
    r = evaluate(_d("fornecedor-x.com.br"))
    assert rules_only(r, pending_llm=True).category is None
    assert rules_only(r, pending_llm=False).category == "desconhecido"
