"""Logs detalhados (07/10): a busca no Technitium anda p/ trás em janelas curtas — o custo de cada chamada é a
contagem do período pedido (o dia inteiro levava 28 s por chamada e a tela dava timeout)."""

import ipaddress
import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def logs(app, monkeypatch):
    """Technitium de mentira: 1 consulta por segundo nas últimas 6 h; 1 em cada 10 é da empresa (10.7.0.0/24)."""
    from app import technitium as dnslib
    agora = datetime.now(timezone.utc).replace(microsecond=0)
    ents = [{"timestamp": (agora - timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
             "clientIpAddress": "10.7.0.5" if i % 10 == 0 else "10.9.0.9", "qname": f"site{i % 50}.com", "qtype": "A",
             "responseType": "Recursive", "rcode": "NoError", "answer": "1.2.3.4"} for i in range(6 * 3600)]
    chamadas = []

    def api(path, timeout=15):
        q = dict(urllib.parse.parse_qsl(path.split("?", 1)[1]))
        ini, fim = dnslib._parse_utc(q["start"]), dnslib._parse_utc(q["end"])
        chamadas.append((fim - ini).total_seconds())
        sel = [e for e in ents if ini <= dnslib._parse_utc(e["timestamp"]) <= fim]
        n, p = int(q["entriesPerPage"]), int(q["pageNumber"])
        return {"entries": sel[(p - 1) * n:p * n], "totalEntries": len(sel)}
    monkeypatch.setattr(dnslib, "_api_get", api)
    monkeypatch.setattr(dnslib, "resolver_empresa", lambda ip, mapa: "X")
    return dnslib, agora, chamadas


def test_sem_filtro_uma_janela_curta_basta(logs):
    dnslib, agora, chamadas = logs
    ini = (agora - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")
    linhas, scanned, cap, desde = dnslib.consultar_logs({}, inicio=ini, limite=100, scan_max=100, por_pagina=100)
    assert len(linhas) == 100 and cap and desde, "parou antes do início: oferece os mais antigos"
    assert max(chamadas) <= 181, "nunca pede o período inteiro (era o que custava 28 s)"
    ts = [l["timestamp"] for l in linhas]
    assert ts == sorted(ts, reverse=True) and len(set(ts)) == 100, "mais recentes primeiro, sem repetir"


def test_filtro_por_empresa_varre_varias_janelas(logs):
    dnslib, agora, chamadas = logs
    ini = (agora - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")
    redes = [ipaddress.ip_network("10.7.0.0/24")]
    linhas, scanned, cap, desde = dnslib.consultar_logs({}, redes=redes, inicio=ini, limite=300, scan_max=60000, por_pagina=5000)
    assert len(linhas) == 300 and {l["ip"] for l in linhas} == {"10.7.0.5"}
    assert 2900 <= scanned <= 3100 and len(chamadas) >= 2, "1 em 10 é da empresa: ~3000 varridos, em mais de uma janela"
    assert desde and len({l["timestamp"] for l in linhas}) == 300


def test_periodo_coberto_inteiro_nao_oferece_mais_antigos(logs):
    dnslib, agora, chamadas = logs
    ini = (agora - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")
    linhas, scanned, cap, desde = dnslib.consultar_logs({}, redes=[ipaddress.ip_network("10.7.0.0/24")], inicio=ini,
                                                        limite=1000, scan_max=60000, por_pagina=5000)
    assert 59 <= len(linhas) <= 61 and not cap and desde is None and 599 <= scanned <= 602


def test_mais_antigos_continua_de_onde_parou(logs):
    dnslib, agora, chamadas = logs
    ini = (agora - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")
    a, _, _, desde = dnslib.consultar_logs({}, inicio=ini, limite=100, scan_max=100, por_pagina=100)
    fim2 = dnslib.local_para_utc_iso(desde)
    b, _, _, _ = dnslib.consultar_logs({}, inicio=ini, fim=fim2, limite=100, scan_max=100, por_pagina=100)
    ta, tb = {l["timestamp"] for l in a}, {l["timestamp"] for l in b}
    assert b and max(tb) >= min(ta), "sem buraco entre as páginas"
    assert len(ta & tb) <= 2, "só a borda (1 s) pode repetir"


def test_orcamento_de_tempo_encerra_a_busca(logs, monkeypatch):
    dnslib, agora, chamadas = logs
    import time
    relogio = iter(range(0, 10_000, 9))   # cada olhada no relógio "passa" 9 s
    monkeypatch.setattr(time, "monotonic", lambda: next(relogio))
    ini = (agora - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")
    linhas, scanned, cap, desde = dnslib.consultar_logs({}, dominio="nao-existe", inicio=ini, limite=1000, scan_max=10**9,
                                                        por_pagina=5000, orcamento_s=20)
    assert not linhas and desde and len(chamadas) <= 3, "sem achar nada, para pelo tempo e diz até onde foi"


# ---------------------------------------------------------------- vista Detalhado pelo analisador (query_log)
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
        return resp if path == "/logs/detalhe" else []
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(dnslib, "networkgroupmap", lambda: {})
    monkeypatch.setattr(dnslib, "zonas_locais", lambda: ["2d.local"])
    monkeypatch.setattr(dnslib, "consultar_logs", lambda *a, **k: chamadas.append(("technitium", k)) or ([], 0, False, None))
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
    assert "guardado desde 07/10 06:00" in html and "fonte=technitium" in html


def test_ao_vivo_consulta_o_technitium(tela):
    c, chamadas = tela
    html = c.get("/logs-dns?empresa=7&inicio=2026-10-07T00%3A00&fim=2026-10-07T23%3A59&vista=detalhado&fonte=technitium").get_data(as_text=True)
    assert [x for x in chamadas if x[0] == "technitium"] and not [x for x in chamadas if x[0] == "/logs/detalhe"]
    assert "voltar ao analisador" in html


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
