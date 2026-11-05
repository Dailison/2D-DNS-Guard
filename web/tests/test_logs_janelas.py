"""Tela de Logs DNS: só a cópia dos logs no analisador (05/11: o Technitium não é mais consultado pela tela)."""

import pytest


@pytest.fixture()
def tela(app, monkeypatch):
    from types import SimpleNamespace
    from app import analyzer_client as api
    from app import empresas, technitium as dnslib
    chamadas = []
    resp = {"rows": [{"ts": "2026-10-07T14:40:02+00:00", "ip": "10.7.0.5", "tenant_id": 7, "dominio": "site.com", "tipo": "A",
                      "resposta": "Recursive", "rcode": "NoError", "answer": "1.2.3.4", "classificacao": "TRABALHO",
                      "ajustada": False, "categoria": "produtividade"}],
            "cap": True, "coletado_ate": "2026-10-07T14:41:00+00:00", "disponivel_desde": "2026-10-07T09:00:00+00:00",
            "mais_antigos": "2026-10-07T14:40:02+00:00"}

    def get(path, **p):
        chamadas.append((path, p))
        return resp if path == "/logs/detalhe" else {"rows": [], "cap": False} if path == "/logs/grouped" else []
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(dnslib, "networkgroupmap", lambda: {})
    monkeypatch.setattr(dnslib, "zonas_locais", lambda: ["2d.local"])
    # qualquer chamada à API do Technitium (logs) fica registrada: a tela não deve fazer nenhuma
    monkeypatch.setattr(dnslib, "_api_get", lambda path, *a, **k: chamadas.append(("technitium", path)) or {})
    monkeypatch.setattr(empresas, "lista", lambda: [{"id": 7, "name": "Moral", "networks": [{"cidr": "10.7.0.0/24", "unit": ""}]}])
    monkeypatch.setattr(empresas, "resolver", lambda ips: {"10.7.0.5": {"tenant_id": 7, "tenant": "Moral"}})
    monkeypatch.setattr(empresas, "rotulo", lambda i: (i or {}).get("tenant"))
    monkeypatch.setattr("app.auth.admin_atual", lambda: SimpleNamespace(email="ti@2d", is_super=True, ativo=True))
    app.config.update(TECHNITIUM_ENABLED=True, ANALYZER_ENABLED=True)
    return app.test_client(), chamadas


def test_detalhado_le_do_analisador(tela):
    c, chamadas = tela
    html = c.get("/logs-dns?empresa=7&inicio=2026-10-07T00%3A00&fim=2026-10-07T23%3A59&vista=detalhado").get_data(as_text=True)
    path, p = next(x for x in chamadas if x[0] == "/logs/detalhe")
    assert p["tid"] == 7 and p["start"] == "2026-10-07T03:00:00+00:00" and p["excluir"] == ["2d.local"]
    assert not [x for x in chamadas if x[0] == "technitium"], "o Technitium não é consultado"
    assert "site.com" in html and "11:40:02" in html and "Moral" in html, "horário no fuso de São Paulo"
    assert "fonte: analisador" in html and "mais antigos" in html and "fim=2026-10-07T11:40:03" in html, "ao segundo, +1 s"
    assert "guardado desde 07/10 06:00" in html and "fonte=technitium" not in html, "sem o link ao vivo"


def test_fonte_technitium_tambem_le_do_analisador(tela):
    """Link antigo do "ao vivo" (?fonte=technitium): lê a cópia do analisador como qualquer outro."""
    c, chamadas = tela
    c.get("/logs-dns?empresa=7&inicio=2026-10-07T00%3A00&fim=2026-10-07T23%3A59&vista=detalhado&fonte=technitium")
    assert [x for x in chamadas if x[0] == "/logs/detalhe"] and not [x for x in chamadas if x[0] == "technitium"]


def test_agrupado_com_tipo_de_resposta_vai_ao_analisador(tela):
    """Agrupado com resposta Cached/Recursive... ia ao Technitium (o agregado não guarda o tipo): vai ao analisador."""
    c, chamadas = tela
    c.get("/logs-dns?inicio=2026-10-07T00%3A00&fim=2026-10-07T23%3A59&vista=agrupado&resposta=Cached")
    path, p = next(x for x in chamadas if x[0] == "/logs/grouped")
    assert p["resposta"] == "Cached" and p["blocked"] is None
    assert not [x for x in chamadas if x[0] == "technitium"]


def test_pedaco_de_ip_no_campo_ip_exato_vale_como_faixa(tela):
    """07/10: "10.24." no campo IP exato ia como IP exato e o analisador respondia 500. Passa a valer como parte do IP."""
    c, chamadas = tela
    html = c.get("/logs-dns?ip=10.24.&resposta=Blocked&inicio=2026-10-07T00%3A00&fim=2026-10-07T23%3A59&vista=agrupado").get_data(as_text=True)
    path, p = next(x for x in chamadas if x[0] == "/logs/grouped")
    assert p["ip"] is None and p["ip_like"] == "10.24." and p["cidr"] is None
    assert 'name="cidr" value="10.24."' in html and 'name="ip" value=""' in html, "o formulário mostra onde o filtro ficou"
    chamadas.clear()
    c.get("/logs-dns?ip=10.7.0.0/24&vista=agrupado")                      # faixa no campo IP exato
    assert next(p for path, p in chamadas if path == "/logs/grouped")["cidr"] == ["10.7.0.0/24"]
    chamadas.clear()
    c.get("/logs-dns?ip=10.7.0.5&vista=agrupado")                         # IP completo: segue exato
    p = next(p for path, p in chamadas if path == "/logs/grouped")
    assert p["ip"] == "10.7.0.5" and p["ip_like"] is None
    chamadas.clear()
    html = c.get("/logs-dns?ip=abc&cidr=10.7.0.0/24&vista=agrupado").get_data(as_text=True)   # os dois: ignora o inválido
    p = next(p for path, p in chamadas if path == "/logs/grouped")
    assert p["ip"] is None and p["cidr"] == ["10.7.0.0/24"] and "não é um IP completo" in html


CATS = [{"code": "apostas", "label": "Apostas"}, {"code": "jogos", "label": "Jogos"}, {"code": "streaming", "label": "Vídeo e streaming"}]


def test_categorias_em_lista_de_marcar(tela, monkeypatch):
    """10/10 (pedido do usuário): o filtro de categoria é uma lista de marcar/desmarcar. Várias marcadas vão todas p/ o
    analisador; todas marcadas (ou nenhuma) = sem filtro."""
    c, chamadas = tela
    monkeypatch.setattr("app.dns._site_categorias", lambda: CATS)
    html = c.get("/logs-dns?vista=detalhado&categoria=apostas&categoria=jogos&categoria=inventada").get_data(as_text=True)
    assert [p for path, p in chamadas if path == "/logs/detalhe"][-1]["categoria"] == ["apostas", "jogos"]
    assert 'value="apostas" data-n="Apostas" checked' in html and 'value="jogos" data-n="Jogos" checked' in html
    assert 'value="streaming" data-n="Vídeo e streaming" >' in html and "<summary>Apostas, Jogos</summary>" in html
    assert 'select name="categoria"' not in html
    chamadas.clear()
    html = c.get("/logs-dns?vista=detalhado&categoria=apostas&categoria=jogos&categoria=streaming").get_data(as_text=True)
    assert [p for path, p in chamadas if path == "/logs/detalhe"][-1].get("categoria") is None, "todas marcadas = sem filtro"
    assert "<summary>— Todas —</summary>" in html and html.count('name="categoria" value=') == 3 and html.count(" checked>") >= 3


def test_filtros_ficam_guardados_no_navegador(tela, monkeypatch):
    """10/10: os filtros do formulário (menos o período) ficam na sessão; abrir a tela sem parâmetros volta com eles.
    Link de outra tela (sem o campo do formulário) não mexe no que está guardado; Limpar esquece."""
    c, chamadas = tela
    monkeypatch.setattr("app.dns._site_categorias", lambda: CATS)
    assert c.get("/logs-dns").status_code == 200, "nada guardado: abre com o padrão"
    c.get("/logs-dns?f=1&empresa=7&vista=detalhado&dominio=bet&categoria=apostas&categoria=jogos&locais=1"
          "&inicio=2026-10-07T00%3A00&fim=2026-10-07T23%3A59")
    r = c.get("/logs-dns")
    assert r.status_code == 302
    loc = r.headers["Location"]
    for parte in ("empresa=7", "vista=detalhado", "dominio=bet", "categoria=apostas", "categoria=jogos", "locais=1", "f=1"):
        assert parte in loc, parte
    assert "inicio" not in loc and "fim=" not in loc, "o período não é guardado: vale o dia de hoje"
    chamadas.clear()
    html = c.get(loc).get_data(as_text=True)
    p = [p for path, p in chamadas if path == "/logs/detalhe"][-1]
    assert p["tid"] == 7 and p["dominio"] == "bet" and p["categoria"] == ["apostas", "jogos"] and p["start"] and p["end"]
    assert 'name="f" value="1"' in html and "limpar=1" in html
    c.get("/logs-dns?vista=agrupado&dominio=outro")          # link vindo de outra tela: não guarda
    assert "dominio=bet" in c.get("/logs-dns").headers["Location"]
    r = c.get("/logs-dns?limpar=1")
    assert r.status_code == 302 and r.headers["Location"].endswith("/logs-dns")
    assert c.get("/logs-dns").status_code == 200, "esquecido: volta ao padrão"
