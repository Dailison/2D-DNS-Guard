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


def test_busca_pelas_palavras_do_nome_composto(monkeypatch):
    """Nome composto sem resultado (27/09: herosistemas-storage.s3.amazonaws.com): busca pelas palavras do
    nome e só fica com o que cita a mais distintiva."""
    from dnsanalyzer import webintel
    monkeypatch.setattr(webintel, "settings", lambda: SimpleNamespace(web_search_url="http://x", web_search_min_interval=0,
                                                                     web_search_results=6))
    monkeypatch.setattr(webintel, "_ultima_busca", 0.0, raising=False)
    consultas = []

    def falsa(cfg, q, relevante=None):
        consultas.append(q)
        if q == "herosistemas storage":
            res = [{"title": "Hero Sistemas - ERP", "snippet": "software de gestão herosistemas", "host": "herosistemas.com.br", "url": "u"},
                   {"title": "Storage barato", "snippet": "nada a ver", "host": "outro.com", "url": "u2"}]
            return [r for r in res if relevante(f"{r['url']} {r['title']} {r['snippet']}".lower())], []
        return [], []
    monkeypatch.setattr(webintel, "_consulta", falsa)

    class C:
        def execute(self, sql, *a):
            return self

        def fetchone(self):
            return None
    out = webintel.search(C(), "herosistemas-storage.s3.amazonaws.com", fetch=True)
    assert consultas == ['"herosistemas-storage.s3.amazonaws.com"', "herosistemas-storage.s3.amazonaws.com", "herosistemas storage"]
    assert [r["host"] for r in out] == ["herosistemas.com.br"]


def test_pagina_vazia_no_cache_e_reaberta(monkeypatch):
    """Página vazia no cache (site fora do ar na hora) é aberta de novo depois de 6 h; com página, fica o cache."""
    from datetime import datetime, timedelta, timezone
    from dnsanalyzer import webintel
    monkeypatch.setattr(webintel, "settings", lambda: SimpleNamespace(web_cache_days=30, web_intel_enabled=True, web_fetch_site=True))
    abertas = []
    monkeypatch.setattr(webintel, "homepage", lambda d: abertas.append(d) or {"title": "78K.COM", "description": "GANHE ATÉ R$788"})
    antigo = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
    gravado = []

    class C:
        def __init__(self, value):
            self.value = value

        def execute(self, sql, params=()):
            if sql.startswith("UPDATE"):
                gravado.append(params[0].obj)
            return self

        def fetchone(self):
            return {"value": self.value, "fetched_at": datetime.now(timezone.utc) - timedelta(days=1)}
    v = webintel.lookup(C({"fetched": antigo, "site": None, "cert": None}), "jiluio3u500.com", fetch=True, allow_site=True)
    assert abertas == ["jiluio3u500.com"] and v["site"]["title"] == "78K.COM" and gravado
    webintel.lookup(C({"fetched": antigo, "site": {"title": "x"}}), "tem-site.com", fetch=True, allow_site=True)
    webintel.lookup(C({"fetched": datetime.now(timezone.utc).isoformat(), "site": None}), "vazio-recente.com", fetch=True, allow_site=True)
    webintel.lookup(C({"fetched": antigo, "site": None}), "so-cache.com", fetch=False, allow_site=True)
    assert abertas == ["jiluio3u500.com"]
