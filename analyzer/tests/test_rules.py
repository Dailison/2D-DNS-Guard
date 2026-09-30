from dnsanalyzer.catalog import match
from dnsanalyzer.rules import evaluate


def dossier(name, **kw):
    d = {"name": name, "kind": "public", "tld": name.rsplit(".", 1)[-1], "features": {}, "ti_hits": [],
         "popularity_rank": None, "catalog": None, "logs": {}}
    d.update(kw)
    return d


def hit(source="urlhaus", conf="high", weight=90, matched=None, name="x", threat="malware"):
    return {"source": source, "label": source, "threat": threat, "confidence": conf, "weight": weight,
            "matched": matched or name, "fqdns": []}


def test_internal_is_final_work():
    r = evaluate(dossier("2d.local", kind="internal"))
    assert r.classification == "TRABALHO" and r.final and not r.needs_llm


def test_catalog_nonwork_is_not_malicious():
    r = evaluate(dossier("facebook.com", catalog=match("facebook.com")))
    assert r.classification == "NAO_TRABALHO"
    assert r.risk < 30 and r.final


def test_high_confidence_ti_is_malicious():
    n = "bad-payload.xyz"
    r = evaluate(dossier(n, ti_hits=[hit(name=n)]))
    assert r.classification == "MALICIOSO" and r.risk >= 85
    assert r.action == "BLOCK_CANDIDATE" and r.final


def test_protected_infra_is_never_flagged_by_lists():
    n = "microsoft.com"
    r = evaluate(dossier(n, catalog=match(n), ti_hits=[hit(name=n)], popularity_rank=5))
    assert r.classification == "TRABALHO"
    assert r.risk <= 30
    assert r.action == "REVIEW"            # registra provável falso positivo


def test_popular_domain_capped_on_medium_list():
    n = "gravatar.com"
    r = evaluate(dossier(n, ti_hits=[hit("phishing_db", "low", 30, name=n, threat="phishing")],
                         popularity_rank=900))
    assert r.classification not in ("SUSPEITO", "MALICIOSO")
    assert r.risk <= 45


def test_popular_domain_high_list_is_review_not_malicious():
    n = "popular-site.com"
    r = evaluate(dossier(n, ti_hits=[hit(name=n)], popularity_rank=5000))
    assert r.classification == "SUSPEITO"
    assert r.risk <= 70


def test_dga_unknown_is_suspicious():
    n = "xjq7k2vbz9wpl3mqr8t.top"
    r = evaluate(dossier(n, features={"sld_dga": 0.8, "sld_entropy": 3.9}, abused_tld={"source": "t"},
                         age_days=3))
    assert r.classification == "SUSPEITO" and r.needs_llm
    assert r.risk >= 50


def test_unknown_goes_to_llm_with_negative_evidence():
    r = evaluate(dossier("fornecedor-local.com.br"))
    assert r.classification == "DESCONHECIDO" and r.needs_llm
    kinds = [e.kind for e in r.evidence]
    assert "negative" in kinds
    assert r.evidence[0].id == "E0" and r.evidence[0].kind == "identity"
    assert [e.id for e in r.evidence] == [f"E{i}" for i in range(len(r.evidence))]


def test_hash_ignores_volatile_counts():
    a = evaluate(dossier("site.com", logs={"total_queries": 10, "clients": 1, "tenants": 1}))
    b = evaluate(dossier("site.com", logs={"total_queries": 999, "clients": 50, "tenants": 3}))
    assert a.evidence_hash == b.evidence_hash
    c = evaluate(dossier("site.com", ti_hits=[hit("hagezi_tif", "medium", 60, name="site.com")]))
    assert c.evidence_hash != a.evidence_hash


def test_bet_br_e_tlds_de_apostas_pelo_catalogo():
    from dnsanalyzer.features import analyze_name
    for nome in ("brazino777.bet.br", "betano.bet.br", "qualquer.bet", "sorte.casino"):
        reg = analyze_name(nome, []).registrable
        r = evaluate({"name": reg, "kind": "public", "tld": reg.rsplit(".", 1)[-1], "features": {}, "ti_hits": [],
                      "logs": {}, "catalog": __import__("dnsanalyzer.catalog", fromlist=["x"]).match(reg)})
        assert r.final and r.classification == "NAO_TRABALHO" and r.category == "apostas", (nome, reg, r.category)
    assert __import__("dnsanalyzer.catalog", fromlist=["x"]).match("betfair.com.br") is None


def test_camuflagem_decide_sem_ia():
    """30/09: página que imita erro do navegador (190 de 190 viraram Ameaças na IA online) -> SUSPEITO final, sem IA;
    no Tranco ou com página longa (artigo que ensina a corrigir o erro) continua indo p/ a IA."""
    from dnsanalyzer.rules import CAMUFLAGEM_TOPIC, evaluate
    sinal = "imita a tela de erro do navegador, mas o site responde (camuflagem)"
    base = {"name": "h3gu39r4.com", "kind": "public", "tld": "com", "features": {}, "ti_hits": [], "catalog": None,
            "fqdn_stats": {}, "logs": {}, "web": {"site": {"texto": "DNS_PROBE_FINISHED_NXDOMAIN", "sinais": [sinal]}}}
    r = evaluate(base)
    assert r.classification == "SUSPEITO" and r.final and not r.needs_llm and r.topic == CAMUFLAGEM_TOPIC
    assert r.category == "ameaca" and r.risk >= 70
    assert evaluate({**base, "popularity_rank": 5000}).needs_llm
    assert evaluate({**base, "web": {"site": {"texto": "x" * 3000, "sinais": [sinal]}}}).needs_llm
