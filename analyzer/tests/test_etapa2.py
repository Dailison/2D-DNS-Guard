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

    def falsa(cfg, q, relevante=None, url=None, motores=None):
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


class _SemCache:
    def execute(self, sql, *a):
        return self

    def fetchone(self):
        return None


def _varios_searxng(monkeypatch, intervalo=8):
    from dnsanalyzer import webintel
    monkeypatch.setattr(webintel, "settings", lambda: SimpleNamespace(
        web_search_url="http://vm:8888", web_search_urls=["http://vm:8888", "http://pc:8888"],
        web_search_min_interval=intervalo, web_search_results=6))
    monkeypatch.setattr(webintel, "_ultima", {})
    monkeypatch.setattr(webintel, "_fora_ate", {})
    return webintel


def test_varios_searxng_cada_um_com_o_seu_intervalo(monkeypatch):
    """(28/09) VM + PC do reforço: o intervalo mínimo vale para cada SearXNG — a 2ª busca vai para o outro sem
    esperar, e a 3ª (os dois ocupados) é BuscaOcupada quando o worker não espera."""
    webintel = _varios_searxng(monkeypatch)
    usados = []
    monkeypatch.setattr(webintel, "_consulta", lambda cfg, q, rel=None, url=None, motores=None: (usados.append(url) or
                        ([{"title": "t", "snippet": "s", "host": "h", "url": "u"}], [])))
    webintel.search(_SemCache(), "a.com", fetch=True, wait=False)
    webintel.search(_SemCache(), "b.com", fetch=True, wait=False)
    assert usados == ["http://vm:8888", "http://pc:8888"]
    import pytest
    with pytest.raises(webintel.BuscaOcupada):
        webintel.search(_SemCache(), "c.com", fetch=True, wait=False)


def test_searxng_fora_do_ar_fica_de_lado(monkeypatch):
    """PC do reforço desligado: a busca vai para o outro SearXNG e o que falhou fica FORA_S de lado."""
    import httpx
    webintel = _varios_searxng(monkeypatch, intervalo=0)
    usados = []

    def consulta(cfg, q, rel=None, url=None, motores=None):
        usados.append(url)
        if url == "http://pc:8888":
            raise httpx.ConnectError("desligado")
        return [{"title": "t", "snippet": "s", "host": "h", "url": "u"}], []
    monkeypatch.setattr(webintel, "_consulta", consulta)
    webintel._ultima.update({"http://vm:8888": 1.0, "http://pc:8888": 0.0})   # a vez é do PC
    out = webintel.search(_SemCache(), "a.com", fetch=True)
    assert out and usados == ["http://pc:8888", "http://vm:8888"]
    assert webintel._fora_ate.get("http://pc:8888", 0) > 0
    usados.clear()
    webintel.search(_SemCache(), "b.com", fetch=True)
    assert usados == ["http://vm:8888"]   # o PC segue de lado


def test_fase1_pula_busca_do_top_do_tranco(monkeypatch):
    monkeypatch.setattr(classifier, "settings", lambda: SimpleNamespace(web_search_skip_rank=100000))
    assert classifier._pular_busca({"popularity_rank": 5000})
    assert classifier._pular_busca({"popularity_rank": 100000})
    assert not classifier._pular_busca({"popularity_rank": 100001})
    assert not classifier._pular_busca({"popularity_rank": None})
    monkeypatch.setattr(classifier, "settings", lambda: SimpleNamespace(web_search_skip_rank=0))
    assert not classifier._pular_busca({"popularity_rank": 5})


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
    # (07/10) "site" ausente = nunca foi aberto (o TLD abusado impedia): abre já, sem esperar as 6 h
    webintel.lookup(C({"fetched": datetime.now(timezone.utc).isoformat(), "cert": None}), "nunca-aberto.life", fetch=True, allow_site=True)
    webintel.lookup(C({"fetched": datetime.now(timezone.utc).isoformat(), "cert": None}), "com-ameaca.life", fetch=True, allow_site=False)
    assert abertas == ["jiluio3u500.com", "nunca-aberto.life"]


def test_pagina_segue_redirecionamento_por_script_e_marca_sinais(monkeypatch):
    """"Redirecting..." com window.location p/ outra página (27/09: plataformas de tigrinho): segue e marca os sinais
    de camuflagem (erro falso do navegador, prende o botão Voltar)."""
    from dnsanalyzer import webintel
    paginas = {
        "/": '<html><title>Redirecting...</title><script>window.location.href = "https://x7.com/unAvailable.html";</script></html>',
        "/unAvailable.html": "<html><script>function preventBack(){history.pushState(null,'',location.href)}</script>"
                             "<body>无法访问此网站 DNS_PROBE_FINISHED_NXDOMAIN</body></html>",
    }

    class Resp:
        def __init__(self, caminho):
            self.caminho, self.headers, self.encoding = caminho, {"content-type": "text/html"}, "utf-8"
            self.url, self.status_code = SimpleNamespace(host="x7.com"), 200

        def iter_bytes(self):
            yield paginas[self.caminho].encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Cliente:
        def __init__(self, **kw):
            pass

        def stream(self, metodo, url):
            return Resp(url.split("x7.com", 1)[1] or "/")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(webintel.httpx, "Client", Cliente)
    r = webintel.homepage("x7.com")
    assert r["via"] == "x7.com" and "DNS_PROBE" in r["texto"]
    assert any("Voltar" in s for s in r["sinais"]) and any("camuflagem" in s for s in r["sinais"])


def test_raiz_sem_pagina_tenta_o_www_e_busca_do_proprio_dominio_e_marcada(monkeypatch):
    """27/09: pixio.co (jogos) virou "loja de arte de parede": a raiz dá 403 do S3 em XML e o site está no www; sem a
    página, a busca trouxe homônimos (pixio.com.co, Instagram) que pesaram mais que o resultado do próprio domínio."""
    from dnsanalyzer import rules, webintel
    respostas = {"pixio.co": (403, "application/xml", "<Error><Code>AccessDenied</Code></Error>"),
                 "www.pixio.co": (200, "text/html", "<html><title>Pixio Ltd</title><body>fun games for mobile</body></html>")}

    class Resp:
        def __init__(self, host):
            self.status_code, ct, self.corpo = respostas[host]
            self.headers, self.encoding, self.url = {"content-type": ct}, "utf-8", SimpleNamespace(host=host)

        def iter_bytes(self):
            yield self.corpo.encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Cliente:
        def __init__(self, **kw):
            pass

        def stream(self, metodo, url):
            return Resp(url.split("//", 1)[1].split("/", 1)[0])

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(webintel.httpx, "Client", Cliente)
    r = webintel.homepage("pixio.co")
    assert r["title"] == "Pixio Ltd" and "games" in r["texto"] and webintel.site_com_conteudo(r)
    respostas["www.pixio.co"] = (403, "application/xml", "<Error/>")
    assert webintel.homepage("pixio.co") == {"final_host": "pixio.co", "status": 403}, "nenhum dos dois: fica a resposta da raiz"
    assert not webintel.site_com_conteudo({"final_host": "pixio.co", "status": 403})

    ev = rules.evaluate({"name": "pixio.co", "kind": "public", "search": [
        {"host": "pixio.co", "title": "Pixio Ltd", "snippet": "fun games"},
        {"host": "pixio.com.co", "title": "Home page", "snippet": "wall art store"}]}).evidence
    txt = [e.text for e in ev if e.kind == "websearch"]
    assert "PRÓPRIO domínio" in txt[0] and "TERCEIROS" in txt[1] and "PRÓPRIO" not in txt[1]
