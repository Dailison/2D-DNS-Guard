"""Busca de Domínios bloqueados seguindo o CNAME (06/10): estacio.saladeavaliacoes.com.br era bloqueado pelo destino
dele (d102xe4mjihvqq.cloudfront.net, na lista Adulto) e a busca pelo nome não achava nada."""

from types import SimpleNamespace

import pytest

NOME, ALVO = "estacio.saladeavaliacoes.com.br", "d102xe4mjihvqq.cloudfront.net"
ENTRADA = {"domain": ALVO, "listas": ["adulto"], "classification": "NAO_TRABALHO", "total_queries": 24, "pai": False}
LISTAS = {ALVO: [ENTRADA],
          "x.edgekey.net": [{"domain": "edgekey.net", "listas": ["streaming"], "classification": None, "total_queries": 0, "pai": True},
                            {"domain": "ax.edgekey.net.br", "listas": ["jogos"], "classification": None, "total_queries": 0, "pai": False}]}


@pytest.fixture()
def busca(app, monkeypatch):
    from app import analyzer_client as api
    from app import technitium as dnslib
    est = SimpleNamespace(cadeia=[ALVO], wl=set(), buscas=[], resolvidos=[])

    def get(path, **p):
        assert path == "/listas-busca"
        est.buscas.append(p["q"])
        return [dict(x) for x in LISTAS.get(p["q"], [])]

    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(dnslib, "cadeia_cname", lambda n: est.resolvidos.append(n) or list(est.cadeia))
    monkeypatch.setattr(dnslib, "dominios_whitelist", lambda: est.wl)
    return est


def test_acha_a_entrada_que_bloqueia_o_destino_do_cname(app, busca):
    from app import dns
    achados, cadeia = dns._busca_listas(NOME)
    assert cadeia == [ALVO] and busca.buscas == [NOME, ALVO]
    assert achados == [{**ENTRADA, "via": ALVO, "pai": False, "wl": None}]


def test_dominio_pai_do_destino_e_so_o_que_cobre_o_elo(app, busca):
    from app import dns
    busca.cadeia = ["x.edgekey.net"]
    achados, _ = dns._busca_listas("www.exemplo.com")
    assert [(a["domain"], a["via"], a["pai"]) for a in achados] == [("edgekey.net", "x.edgekey.net", True)], \
        "parecido no nome (ax.edgekey.net.br) não bloqueia o elo"


def test_whitelist_vence_o_bloqueio_por_cname(app, busca):
    from app import dns
    busca.wl = {"saladeavaliacoes.com.br"}                    # a do nome buscado
    assert dns._busca_listas(NOME)[0][0]["wl"] == "saladeavaliacoes.com.br"
    busca.wl = {"cloudfront.net"}                             # a do destino
    assert dns._busca_listas(NOME)[0][0]["wl"] == "cloudfront.net"
    assert dns._busca_listas(ALVO)[0][0]["wl"] == "cloudfront.net", "busca direta pela entrada: também avisa"
    busca.wl = {"outro.cloudfront.net", "net"}
    assert dns._busca_listas(NOME)[0][0]["wl"] is None


def test_pedaco_de_nome_nao_resolve_dns(app, busca):
    from app import dns
    achados, cadeia = dns._busca_listas("saladeavaliacoes")
    assert achados == [] and cadeia == [] and busca.resolvidos == [], "só nome completo vai ao DNS"


def test_cadeia_cname_le_a_resposta_do_technitium(app, monkeypatch):
    from app import technitium as dnslib
    resp = {"result": {"RCODE": "NoError", "Answer": [
        {"Name": "www.microsoft.com", "Type": "CNAME", "RDATA": {"Domain": "WWW.microsoft.com-c-3.edgekey.net."}},
        {"Name": "www.microsoft.com-c-3.edgekey.net", "Type": "CNAME", "RDATA": {"Domain": "e13678.dscb.akamaiedge.net"}},
        {"Name": "e13678.dscb.akamaiedge.net", "Type": "A", "RDATA": {"IPAddress": "23.201.217.217"}}]}}
    pedidos = []
    monkeypatch.setattr(dnslib, "_api_get", lambda path, timeout=15: pedidos.append(path) or resp)
    assert dnslib.cadeia_cname("www.microsoft.com") == ["www.microsoft.com-c-3.edgekey.net", "e13678.dscb.akamaiedge.net"]
    assert "server=this-server" in pedidos[0] and "domain=www.microsoft.com" in pedidos[0]

    def falha(path, timeout=15):
        raise RuntimeError("fora")
    monkeypatch.setattr(dnslib, "_api_get", falha)
    assert dnslib.cadeia_cname("www.microsoft.com") == [], "sem resposta: a busca segue só pelo nome"


def test_tela_mostra_a_cadeia_e_o_motivo(app, busca):
    from app import dns
    from app import technitium as dnslib
    busca.wl = {"cloudfront.net"}
    achados, cadeia = dns._busca_listas(NOME)
    with app.test_request_context("/dominios-bloqueados?busca=" + NOME):
        tpl = app.jinja_env.get_template("admin/listas_categoria.html")
        # a página inteira precisa de muito contexto: renderiza só o cartão da busca
        src = open(tpl.filename, encoding="utf-8").read()
        ini, fim = src.index("{% if achados is not none %}"), src.index("{% if aj_escopo %}")
        h = app.jinja_env.from_string("{% set rot = dict(categorias) %}" + src[ini:fim]).render(
            achados=achados, cadeia=cadeia, busca=NOME, cat="adulto", categorias=dnslib.CATEGORIAS_LISTA, adm=None)
    assert "Aponta por CNAME para: <code>" + ALVO + "</code>" in h and "nenhum deles está em lista" not in h
    assert "bloqueia " + NOME + " por CNAME" in h and "não bloqueia: <b>cloudfront.net</b> está numa whitelist" in h
