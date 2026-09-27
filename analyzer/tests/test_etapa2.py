from types import SimpleNamespace

from dnsanalyzer import classifier


def _d(**kw):
    d = {"kind": "public", "popularity_rank": None, "web": {}, "catalog": None, "private_suffix": None}
    d.update(kw)
    return d


def test_busca_antes_so_fora_do_top1m_sem_identificacao(monkeypatch):
    monkeypatch.setattr(classifier, "settings", lambda: SimpleNamespace(web_search_url="http://127.0.0.1:8888",
                                                                         web_search_before_llm_todos=False))
    assert classifier._buscar_antes(_d())
    assert not classifier._buscar_antes(_d(popularity_rank=5000))                       # IA conhece
    assert not classifier._buscar_antes(_d(web={"wikidata": {"label": "Dell"}}))        # já identificado
    assert not classifier._buscar_antes(_d(web={"cert": {"verified": True, "org": "Dell Inc."}}))
    assert not classifier._buscar_antes(_d(catalog={"topic": "x"}))
    assert not classifier._buscar_antes(_d(kind="internal"))


def test_busca_antes_todos(monkeypatch):
    """WEB_SEARCH_BEFORE_LLM=todos (27/09): busca em todo domínio público da fase 1, até nos conhecidos."""
    monkeypatch.setattr(classifier, "settings", lambda: SimpleNamespace(web_search_url="http://127.0.0.1:8888",
                                                                         web_search_before_llm_todos=True))
    assert classifier._buscar_antes(_d(popularity_rank=5000))
    assert classifier._buscar_antes(_d(web={"wikidata": {"label": "Dell"}}))
    assert not classifier._buscar_antes(_d(kind="internal"))


def test_sem_searxng_nao_busca(monkeypatch):
    monkeypatch.setattr(classifier, "settings", lambda: SimpleNamespace(web_search_url=""))
    assert not classifier._buscar_antes(_d())
