"""Página do domínio: bloco "Whitelist" (em qual está e, para super, mover para outra ou tirar)."""

from flask import render_template


def _render(app, wl_atual, super_=True):
    from types import SimpleNamespace

    from app import technitium as dnslib
    with app.test_request_context("/analise/dominio/quizonline.com.br"):
        return render_template("admin/analise/_whitelist_dominio.html", blq={"nome": "quizonline.com.br"}, wl_atual=wl_atual,
                               wls=dnslib.CATEGORIAS_WHITELIST_DNS, adm=SimpleNamespace(is_super=super_))


def test_fora_de_whitelist_super_ve_o_seletor(app):
    h = _render(app, [])
    assert "Não está em nenhuma whitelist" in h
    assert 'id="sWl"' in h and "Escolha a whitelist" in h and 'value="educacao"' in h
    assert 'value="sem_resposta"' not in h, "Sem resposta não vai para o DNS: não é destino"
    assert "id=\"bWlTirar\"" not in h


E = {"category": "educacao", "domain": "quizonline.com.br", "publicar": True, "pai": False}


def test_na_whitelist_mostra_e_preseleciona(app):
    h = _render(app, [E])
    assert "Na whitelist" in h and "Educação e cursos" in h and "domínio-pai" not in h
    assert 'value="educacao" selected' in h and 'id="bWlTirar"' in h


def test_quem_nao_e_super_so_ve(app):
    h = _render(app, [E], super_=False)
    assert "Educação e cursos" in h and 'id="sWl"' not in h


def test_so_pelo_pai_nao_preseleciona_nem_oferece_tirar(app):
    h = _render(app, [{"category": "essenciais", "domain": "gov.br", "publicar": True, "pai": True}])
    assert "pelo domínio-pai" in h and "gov.br" in h
    assert "Escolha a whitelist" in h and 'id="bWlTirar"' not in h, "a entrada é do pai: aqui só dá para pôr o próprio domínio"


def test_whitelist_do_dominio(app, monkeypatch):
    from app import analise
    from app import analyzer_client as api
    from app.analyzer_client import AnalyzerError
    monkeypatch.setattr(api, "get", lambda path, **kw: [E] if path == "/whitelist-dominio/quizonline.com.br" else None)
    assert analise._whitelist_do_dominio("quizonline.com.br") == [E]

    def falha(path, **kw):
        raise AnalyzerError("fora")
    monkeypatch.setattr(api, "get", falha)
    assert analise._whitelist_do_dominio("quizonline.com.br") == []


def test_acao_mover_para_whitelist(app, monkeypatch):
    """O botão usa a ação em lote "wl": grava na whitelist escolhida (a API tira das listas de bloqueio)."""
    from types import SimpleNamespace

    from app import analyzer_client as api
    from app import dns
    chamadas = []
    monkeypatch.setattr(api, "post", lambda path, body=None, **kw: chamadas.append((path, body)) or {"ok": True})
    monkeypatch.setattr(dns, "admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=True, ativo=True))
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=True, ativo=True))
    monkeypatch.setattr(dns, "_antes", lambda doms: {})
    monkeypatch.setattr(dns, "_libera_agora", lambda doms, antes: " ok")
    c = app.test_client()
    r = c.post("/listas-lote-dominios", json={"acao": "wl", "dominios": ["QuizOnline.com.br."], "para": ["educacao"]})
    assert r.status_code == 200 and r.get_json()["ok"], r.get_json()
    assert chamadas == [("/whitelist/educacao", {"domains": ["quizonline.com.br"], "by": "ti@2d"})], chamadas
    r = c.post("/listas-lote-dominios", json={"acao": "wl", "dominios": ["quizonline.com.br"], "para": []})
    assert r.status_code == 400 and "Escolha a whitelist" in r.get_json()["msg"]
