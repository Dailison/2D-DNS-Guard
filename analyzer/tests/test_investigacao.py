"""Fase 6 (29/09): investigação profunda — partes sem rede."""
from datetime import datetime, timezone

from dnsanalyzer import investigacao as inv
from dnsanalyzer import listas_ia

V_OK = {"recognized": True, "classification": "TRABALHO", "confidence": 0.9, "lista": "wl:produtividade",
        "lista_confianca": 0.9}


def test_aplica_so_com_alta_certeza():
    assert inv.pode_aplicar(V_OK, False, 0.85) is None
    assert "não identificado" in inv.pode_aplicar({**V_OK, "recognized": False}, False, 0.85)
    assert "DESCONHECIDO" in inv.pode_aplicar({**V_OK, "classification": "DESCONHECIDO"}, False, 0.85)
    assert "confiança" in inv.pode_aplicar({**V_OK, "confidence": 0.8}, False, 0.85)
    assert "confiança" in inv.pode_aplicar({**V_OK, "lista_confianca": 0.7}, False, 0.85)
    assert "lista inválida" in inv.pode_aplicar({**V_OK, "lista": "qualquer"}, False, 0.85)


def test_nao_limpa_dominio_de_lista_de_ameaca():
    """Lista de ameaça de confiança alta/média: a investigação pode confirmar suspeito, nunca liberar como trabalho."""
    assert "ameaça" in inv.pode_aplicar(V_OK, True, 0.85)
    assert inv.pode_aplicar({**V_OK, "classification": "SUSPEITO", "lista": "ameaca"}, True, 0.85) is None


def test_nao_abre_enderecos_da_rede_interna():
    for url in ("http://10.100.10.15/", "http://127.0.0.1:8088/", "http://192.168.0.1/", "http://[::1]/",
                "http://169.254.169.254/latest/meta-data/", "ftp://example.com/", "file:///etc/passwd", "nada"):
        assert not inv._endereco_publico(url), url


def test_evidencias_novas_seguem_a_numeracao():
    ev = inv.novas_evidencias(5, {
        "dns": {"mx": ["1 aspmx.l.google.com."], "txt": ["google-site-verification=x"], "ns": ["ns1.x.com."],
                "a": ["1.2.3.4"], "asn": "AS16509 AMAZON-02"},
        "certificados": {"certificados": 3, "primeiro": "2021-01-01", "nomes": ["a.x.com"], "outros_dominios": ["y.com"],
                         "emissores": ["Let's Encrypt"]},
        "wayback": {"capturas": 0},
        "coocorrencia": {"amostras": 6, "juntos": [{"dominio": "omie.com.br", "vezes": 5, "servico": "Omie, ERP",
                                                     "classificacao": "TRABALHO"}]},
    })
    assert [e["id"] for e in ev] == [f"E{i}" for i in range(5, 5 + len(ev))]
    txt = " | ".join(e["text"] for e in ev)
    assert "aspmx.l.google.com" in txt and "google-site-verification" in txt and "AS16509" in txt
    assert "y.com (mesmo dono)" in txt and "nunca arquivado" in txt and "omie.com.br (5x, Omie, ERP, TRABALHO)" in txt


def test_sem_dns_vira_evidencia():
    ev = inv.novas_evidencias(0, {"dns": {"mx": [], "txt": [], "ns": [], "a": []}})
    assert ev[0]["text"].startswith("sem registros DNS")


def test_dossie_longo_e_cortado_sem_perder_evidencias():
    ev = [{"id": f"E{i}", "text": "x" * 3000} for i in range(10)]
    t = inv._dossie_texto("a.com", ev, {"classification": "DESCONHECIDO"})
    assert len(t) < inv.MAX_DOSSIE + 1000 and all(f"E{i}:" in t for i in range(10))


def test_coocorrencia_conta_o_que_vem_junto(monkeypatch):
    agora = "2026-09-29T03:00:00.000Z"

    class TC:
        app, cls = "a", "c"

        def __init__(self, timeout=30):
            pass

        def _get(self, path, p):
            if "qname" in p:   # acessos ao domínio investigado: 3 PCs
                return {"entries": [{"clientIpAddress": ip, "timestamp": agora, "qname": p["qname"]}
                                    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")]}
            return {"entries": [{"qname": "cdn.x.com"}, {"qname": "app.omie.com.br"},
                                {"qname": "api.omie.com.br"}, {"qname": "pc1.local"}]
                    + ([{"qname": "raro.net"}] if p["clientIpAddress"] == "10.0.0.1" else [])}

        def close(self):
            pass

    import dnsanalyzer.technitium as tech
    monkeypatch.setattr(tech, "TechnitiumClient", TC)

    class C:
        def execute(self, sql, p):
            return [{"name": "omie.com.br", "classification": "TRABALHO", "category": "produtividade", "topic": "Omie"}]
    out = inv.coocorrencia(C(), "x.com", ["cdn.x.com"], ["local"])
    assert out["amostras"] == 3
    assert [j["dominio"] for j in out["juntos"]] == ["omie.com.br"]   # raro.net (1 de 3) e o próprio x.com ficam de fora
    assert out["juntos"][0]["vezes"] == 3 and out["juntos"][0]["servico"] == "Omie"


def test_listas_trata_investigacao_como_resposta_final():
    r = {"lista_fonte": listas_ia.FONTE_INVESTIGACAO, "lista_conf": 0.9, "lista_fase": 6}
    assert listas_ia._final(r) and listas_ia.origem(r) == "f6:investigacao"
    assert listas_ia._fonte(r) == "investigação profunda 90%"
    assert listas_ia._final({"lista_fonte": "online:gemini"}) and not listas_ia._final({"lista_fonte": "local"})


def test_evidencias_das_fontes_extras():
    ev = inv.novas_evidencias(0, {
        "site": {"paginas": [], "cnpjs": [], "emails": [], "apps": ["https://play.google.com/store/apps/details?id=br.x"]},
        "cnpjs": [{"cnpj": "12345678000190", "razao_social": "X SISTEMAS LTDA", "atividade": "Desenvolvimento de software",
                   "situacao": "ATIVA", "municipio": "Campinas", "uf": "SP"}],
        "urlscan": {"varreduras": 2, "vistos": [{"quando": "2026-09-01", "url": "https://x.com/", "titulo": "X Portal",
                                                 "servidor": "nginx", "asn": "AS1 Y", "idade_dominio_dias": 400}]},
        "bem_conhecidos": {"security": "Contact: mailto:sec@x.com"},
        "subdominios": [{"subdominio": "portal.x.com", "url": "https://portal.x.com/", "titulo": "Login X", "texto": "entrar"}],
    })
    txt = " | ".join(e["text"] for e in ev)
    assert "br.x" in txt and "X SISTEMAS LTDA" in txt and "Desenvolvimento de software" in txt
    assert "URLScan.io (2 varreduras" in txt and "400 dias" in txt and "sec@x.com" in txt and "portal.x.com" in txt


class _Cli:
    extra, model, keep_alive, num_ctx, url = True, "gemma4:26b", "60m", 8192, "http://gpu"


def _simula(monkeypatch, revisor_ok: bool, tempo_max: int = 600):
    """Fontes e IA simuladas; devolve (gravado no domínio, aplicou?, passos pedidos)."""
    from types import SimpleNamespace
    from dnsanalyzer import classifier, config, db
    cfg = config.settings()
    monkeypatch.setattr(inv, "settings", lambda: SimpleNamespace(**{**vars(cfg), "investigacao_tempo_max": tempo_max,
                                                                    "investigacao_confianca_min": 0.85}))
    for f, r in {"registros_dns": {"mx": ["1 aspmx.l.google.com."]}, "certificados": None, "wayback": None,
                 "urlscan": None, "paginas_do_site": None, "bem_conhecidos": {}, "coocorrencia": None,
                 "rastreadores": None, "otx": None, "tls_site": None, "urlscan_detalhe": None, "virustotal": None,
                 "coleta_em_cache": None, "perfil_acesso": {}}.items():
        monkeypatch.setattr(inv, f, lambda *a, _r=r, **k: _r)
    buscas_feitas = []
    monkeypatch.setattr(inv, "buscas", lambda qs, nome: buscas_feitas.extend(qs) or [{"consulta": q, "resultados": []} for q in qs])
    monkeypatch.setattr(inv, "cnpjs", lambda c, ns: [])
    monkeypatch.setattr(inv, "subdominios", lambda ns, http: [])
    monkeypatch.setattr(inv, "paginas_dos_resultados", lambda *a: [])
    monkeypatch.setattr(inv, "tem_visao", lambda c: False)
    passos = iter([{"hipotese": "ERP", "confianca": 0.6, "pronto": False, "buscas": ["x erp"], "paginas": [],
                    "subdominios": [], "cnpjs": []},
                   {"hipotese": "ERP X", "confianca": 0.9, "pronto": True, "buscas": [], "paginas": [],
                    "subdominios": [], "cnpjs": []}])
    monkeypatch.setattr(inv, "_proximo_passo", lambda *a: (next(passos), {"segundos": 1}))
    monkeypatch.setattr(inv, "_veredito", lambda *a: ({**V_OK, "service": "X ERP", "motivo": "m", "evidencias": []},
                                                      {"modelo": "gemma4:26b", "segundos": 1}))
    monkeypatch.setattr(inv, "_revisar", lambda *a: ({"sustentado": revisor_ok, "problema": "" if revisor_ok else "homônimo"},
                                                     {"segundos": 1}))
    aplicou = []
    monkeypatch.setattr(inv, "_aplicar", lambda *a: aplicou.append(True))
    monkeypatch.setattr(classifier, "event", lambda *a, **k: None)
    gravado = {}

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, p=None):
            if "investigacao = %s" in sql:
                gravado.update(p[0].obj)
            return self

    monkeypatch.setattr(db, "conn", lambda: Conn())
    d = {"name": "x.com", "id": 1, "total_queries": 50, "classification": "DESCONHECIDO", "risk_score": 10, "work_score": 50}
    inv._investigar(_Cli(), [{"code": "TRABALHO", "description": ""}], [], d, {"name": "x.com", "kind": "public", "tld": "com", "fqdn_stats": {"sample": ["x.com"]}})
    return gravado, bool(aplicou), buscas_feitas


def test_revisor_discorda_so_guarda_o_dossie(monkeypatch):
    g, aplicou, buscas_feitas = _simula(monkeypatch, revisor_ok=False)
    assert not aplicou and not g["aplicado"] and g["sem_aplicar"].startswith("revisor discordou: homônimo")
    assert '"x"' not in buscas_feitas and "x erp" in buscas_feitas   # a 1ª rodada pediu uma busca nova
    assert [e["etapa"] for e in g["etapas"]][-2:] == ["veredito", "revisão"]


def test_revisor_concorda_aplica(monkeypatch):
    g, aplicou, _ = _simula(monkeypatch, revisor_ok=True)
    assert aplicou and g["aplicado"] and g["revisao"]["sustentado"]


def test_sem_tempo_nao_faz_rodadas_extras(monkeypatch):
    """Prazo menor que a reserva do veredito: nenhuma rodada extra (e o veredito sai mesmo assim)."""
    g, _, buscas_feitas = _simula(monkeypatch, revisor_ok=True, tempo_max=50)
    assert "x erp" not in buscas_feitas and not [e for e in g["etapas"] if e["etapa"].startswith("rodada")]
    assert g["sem_aplicar"] == "sem tempo para a revisão dentro do prazo"


def test_trecho_em_volta_da_citacao():
    texto = "menu " * 200 + "alguém sabe o que é DNOFD.COM? É o antifraude da empresa X usado por bancos." + " rodapé" * 200
    t = inv._trecho(texto, ["dnofd.com", "dnofd"], 900)
    assert "antifraude da empresa X" in t and "rodapé rodapé rodapé rodapé rodapé rodapé rodapé rodapé" not in t[:60]
    assert inv._trecho("nada a ver", ["dnofd"], 900) == ""


def test_paginas_dos_resultados_nao_repete_nem_abre_o_proprio_dominio(monkeypatch):
    abertas = []
    monkeypatch.setattr(inv, "_abrir", lambda u, cli, n=1500: abertas.append(u) or {"url": u, "titulo": "t",
                                                                                  "texto": "fala de dnofd.com aqui"})
    b = [{"consulta": "q", "resultados": [{"url": "https://www.dnofd.com/x"}, {"url": "https://forum.com/a"},
                                          {"url": "https://forum.com/a"}, {"url": "https://blog.com/b"}]}]
    ja = set()
    out = inv.paginas_dos_resultados(b, "dnofd.com", None, ja, 3)
    assert abertas == ["https://forum.com/a", "https://blog.com/b"] and len(out) == 2
    assert inv.paginas_dos_resultados(b, "dnofd.com", None, ja, 3) == []   # já abertas


def test_busca_com_outra_pontuacao_conta_como_repetida():
    assert inv._chave('"dnofd.com" tracking') == inv._chave("'dnofd.com'  \"Tracking\"") == "dnofd.com tracking"


def test_evidencias_de_rastreadores_urlscan_e_virustotal():
    ev = inv.novas_evidencias(0, {
        "rastreadores": {"ghostery": {"dominio": "online-metrix.net", "servico": "ThreatMetrix", "empresa": "LexisNexis",
                                      "site": "https://www.lexisnexis.com", "categoria": "Utilities", "descricao": ""},
                         "tracker_radar": {"empresa": "RELX Group", "site": None, "categorias": ["Fraud Prevention"],
                                           "sites_que_carregam": 1200}},
        "urlscan_detalhe": {"paginas": ["www.bancobmg.com.br", "acesso.pagbank.com.br"],
                            "iniciadores": ["https://www.bancobmg.com.br/static/app.js"],
                            "pistas": [{"script": "https://www.bancobmg.com.br/static/app.js", "cabecalho": "/*! antifraude v2 */",
                                        "fornecedores_citados": ["threatmetrix"], "tamanho_kb": 120}]},
        "virustotal": {"categorias": {"Forcepoint ThreatSeeker": "information technology"}, "maliciosos": 0, "suspeitos": 0,
                       "total_fornecedores": 94, "reputacao": 0, "tags": [], "registrador": None, "criado": "2023-05-01",
                       "ranks": {"Majestic": 40000}},
    })
    txt = " | ".join(e["text"] for e in ev)
    assert "ThreatMetrix" in txt and "LexisNexis" in txt and "Fraud Prevention" in txt
    assert "carregado pelas páginas de acesso.pagbank.com.br, www.bancobmg.com.br" in txt
    assert "cita fornecedores: threatmetrix" in txt
    assert "0 de 94 fornecedores" in txt and "information technology" in txt and "Majestic #40000" in txt


def test_rastreadores_consulta_ghostery_e_radar(monkeypatch):
    base = {"domains": {"x.net": "px"}, "patterns": {"px": {"name": "X SDK", "organization": "ox", "category": "utilities"}},
            "organizations": {"ox": {"name": "Empresa X", "website_url": "https://x.com"}},
            "categories": {"utilities": {"name": "Utilities"}}}
    monkeypatch.setattr(inv, "_base_ghostery", lambda cli: base)

    class R:
        def __init__(self, code, j=None):
            self.status_code, self._j = code, j

        def json(self):
            return self._j

    class Cli:
        pedidos = []

        def get(self, url, **k):
            self.pedidos.append(url)
            return R(200, {"owner": {"displayName": "Dono Y", "url": "y.com"}, "categories": ["Analytics"], "sites": 5}) \
                if url.endswith("/GB/x.net.json") else R(404)
    out = inv.rastreadores("cdn.x.net", Cli())
    assert out["ghostery"]["empresa"] == "Empresa X" and out["ghostery"]["dominio"] == "x.net"
    assert "tracker_radar" not in out   # o radar é consultado pelo nome exato (cdn.x.net): 404 em todas
    assert inv.rastreadores("x.net", Cli())["tracker_radar"]["empresa"] == "Dono Y"
    assert inv.rastreadores("nada.com", Cli()) is None


def test_evidencia_das_imagens():
    ev = inv.novas_evidencias(0, {"imagens": {"origens": ["captura de tela (URLScan) de https://x.com/"], "urls": ["u"],
                                              "olhar": {"descricao": "Página de login com logotipo 'Ecocentauro'", "marca": "Ecocentauro",
                                                        "tipo_de_site": "portal de clientes/ERP", "idioma": "português",
                                                        "sinais": [], "confianca": 0.9}}})
    assert ev[0]["kind"] == "imagem" and "marca lida: Ecocentauro" in ev[0]["text"] and "portal de clientes" in ev[0]["text"]


def test_imagens_do_site(monkeypatch):
    import base64
    png = b"\x89PNG" + b"\0" * 2000
    html = ('<html><head><meta property="og:image" content="/share.jpg">'
            '<link rel="icon" href="/fav.ico"><link rel="apple-touch-icon" href="/touch.png"></head>'
            '<body><img class="logo" src="/img/logo.png"></body></html>')

    class R:
        def __init__(self, code, content=b"", ct="", j=None):
            self.status_code, self.content, self._j = code, content, j
            self.headers = {"content-type": ct}
            self.text = content.decode(errors="ignore")
            self.url = type("U", (), {"host": "x.com"})()

        def json(self):
            return self._j

    baixadas = []

    class Cli:
        def get(self, url, **k):
            baixadas.append(url)
            if "urlscan.io/api" in url:
                return R(200, j={"results": [{"task": {"uuid": "abc"}, "page": {"url": "https://x.com/"}}]})
            if url.endswith(".png") or url.endswith(".jpg") or url.endswith(".ico"):
                return R(200, png, "image/png")
            return R(200, html.encode(), "text/html")
    monkeypatch.setattr(inv, "_endereco_publico", lambda u: True)
    out = inv.imagens("x.com", Cli(), abre_site=True)
    assert [o["origem"].split(" (")[0] for o in out] == ["captura de tela", "imagem de compartilhamento", "logotipo da página inicial"]
    assert out[0]["url"] == "https://urlscan.io/screenshots/abc.png" and out[0]["b64"] == base64.b64encode(png).decode()
    assert "https://x.com/touch.png" not in baixadas and "https://x.com/fav.ico" not in baixadas   # 3 no máximo; .ico nunca
    sem_site = inv.imagens("x.com", Cli(), abre_site=False)   # com sinal de ameaça: só a captura pública, sem visitar o site
    assert len(sem_site) == 1


def test_sem_visao_nao_olha(monkeypatch):
    class Cli:
        url, model = "http://vm", "modelo-sem-visao"
    monkeypatch.setattr(inv.httpx, "post", lambda *a, **k: type("R", (), {"status_code": 200, "json": lambda s: {"capabilities": ["completion"]}})())
    assert not inv.tem_visao(Cli())
    inv._visao[("http://vm", "gemma4:26b")] = True
    Cli.model = "gemma4:26b"
    assert inv.tem_visao(Cli())


def test_chat_usa_as_mesmas_opcoes_de_carga(monkeypatch):
    """29/09: sem num_thread a fase 6 alternava com o classificador (-t 22) e o Ollama da VM recarregava o modelo
    a cada chamada (3-6 min). Mesmas opções de carga do OllamaClient."""
    import httpx
    from types import SimpleNamespace
    from dnsanalyzer import investigacao
    enviado = {}

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "{}"}, "eval_count": 1, "prompt_eval_count": 1}

    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=None: enviado.update(json) or R())
    cli = SimpleNamespace(model="m", keep_alive="60m", num_ctx=8192, num_thread=22, url="http://x", extra=False)
    investigacao._chat(cli, [{"role": "user", "content": "oi"}], {"type": "object"}, False, 10)
    assert enviado["options"]["num_thread"] == 22 and enviado["options"]["num_ctx"] == 8192
    cli.num_thread = None   # GPU (reforço): o Ollama de lá decide as threads
    investigacao._chat(cli, [{"role": "user", "content": "oi"}], {"type": "object"}, False, 10)
    assert "num_thread" not in enviado["options"]


def test_fase6_so_na_gpu(monkeypatch):
    """Sem GPU no ar, a fase 6 fica parada (não cai para a VM, que fica p/ a fase 1 e o atendente virtual)."""
    from types import SimpleNamespace
    from dnsanalyzer import classifier, investigacao
    chamadas, passos = [], []
    monkeypatch.setattr(investigacao, "fase", lambda *a, **k: chamadas.append(a) or "done")
    monkeypatch.setattr(classifier, "_fase_worker", lambda stop, passo, nome: passos.append(passo))
    reforco = SimpleNamespace(cliente=lambda: SimpleNamespace(extra=False))
    classifier._investigacao_worker(lambda: False, [], reforco)
    assert passos[0]() == "idle" and not chamadas


def test_evidencias_das_fontes_novas():
    ev = inv.novas_evidencias(0, {
        "tls": {"valido": True, "organizacao": "X Sistemas Ltda", "pais": "BR", "cn": "x.com", "emissor": "DigiCert",
                "outros_dominios": ["x.com.br"]},
        "wayback": {"primeira": "20150101", "ultima": "20260901", "enderecos": 120, "caminhos": ["x.com/wp-content (80)"]},
        "otx": {"alertas": 0, "nomes_alertas": [], "tags": [], "validacao": ["Majestic"],
                "dns_passivo": {"registros": 4, "desde": "2019-01-01", "nomes": ["api.x.com"], "asns": ["AS1 Y"]}, "urls": []},
        "perfil": {"empresas": 3, "computadores": 12, "consultas_14d": 900, "horas_ativas": 10, "expediente_pct": 95,
                   "madrugada_pct": 0, "fim_de_semana_pct": 1},
        "site": {"paginas": [], "cnpjs": [], "emails": [], "apps": [],
                 "ecossistema": {"tecnologia": {"server": "nginx"}, "gerador": "WordPress 6.5", "scripts": ["google.com"]}},
    })
    txt = " | ".join(e["text"] for e in ev)
    assert "ORGANIZAÇÃO" in txt and "X Sistemas Ltda" in txt and "x.com.br" in txt
    assert "wp-content" in txt and "Majestic" in txt and "api.x.com" in txt
    assert "3 empresa(s)" in txt and "95% em horário de expediente" in txt and "WordPress 6.5" in txt


def test_ecossistema_do_site():
    import httpx
    cab = httpx.Headers([("server", "cloudflare"), ("set-cookie", "PHPSESSID=1; path=/"), ("set-cookie", "_ga=2"),
                         ("content-security-policy", "script-src 'self' https://*.omie.com.br cdn.x.com")])
    html = ('<meta name="generator" content="Wix.com"><script src="https://static.omie.com.br/a.js"></script>'
            '<a href="https://www.omie.com.br/sobre">x</a><a href="/local">y</a>')
    ec = inv.ecossistema("x.com", html, "https://x.com/", cab)
    assert ec["tecnologia"] == {"server": "cloudflare"} and ec["cookies"] == ["PHPSESSID", "_ga"]
    assert ec["gerador"] == "Wix.com" and ec["scripts"] == ["omie.com.br"] and ec["links"] == ["omie.com.br"]
    assert "omie.com.br" in ec["csp"] and "x.com" not in ec["csp"]


def test_ritmo_nao_espera_e_respeita_limites():
    r = inv._Ritmo(2)
    assert r.pode() and r.pode() and not r.pode()          # 2 por hora
    r2 = inv._Ritmo(100, intervalo=60)
    assert r2.pode() and not r2.pode()                     # intervalo mínimo
    r3 = inv._Ritmo(100)
    r3.pausar(60)
    assert not r3.pode()                                   # fonte fora: pausada


def test_dossie_corta_primeiro_buscas_e_paginas():
    ev = ([{"id": "E0", "kind": "tls", "text": "ORGANIZAÇÃO X " + "a" * 350}]
          + [{"id": f"E{i}", "kind": "websearch", "text": "b" * 3000} for i in range(1, 12)])
    t = inv._dossie_texto("a.com", ev, {})
    assert "ORGANIZAÇÃO X " + "a" * 350 in t and len(t) < inv.MAX_DOSSIE + 500
    assert all(f"E{i}:" in t for i in range(12))


def test_revisor_vazio_pergunta_de_novo_sem_raciocinio(monkeypatch):
    respostas = iter([({}, {"segundos": 5}), ({"sustentado": True, "problema": ""}, {"segundos": 2})])
    pensou = []
    monkeypatch.setattr(inv, "_chat", lambda cli, msgs, schema, pensar, n: pensou.append(pensar) or next(respostas))
    r, meta = inv._revisar(_Cli(), "dossiê", {"service": "X"})
    assert r["sustentado"] and pensou == [True, False] and meta["sem_raciocinio"] and meta["segundos"] == 7


def test_sem_certeza_pede_segunda_opiniao_da_ia_online(monkeypatch):
    from dnsanalyzer import online
    monkeypatch.setattr(online, "habilitado", lambda: True)
    g, aplicou, _ = _simula(monkeypatch, revisor_ok=False)
    assert not aplicou and g["segunda_opiniao"]


def test_ia_online_recebe_o_dossie_da_investigacao():
    from dnsanalyzer import online
    inv_ = {"at": "2026-09-30T10:00:00", "veredito": {"service": "X ERP", "classification": "TRABALHO", "lista": "wl:sistemas",
                                                      "confidence": 0.7, "motivo": "certificado"},
            "sem_aplicar": "confiança 0.7/0.7 abaixo de 0.85", "evidencias": [{"kind": "tls", "text": "ORGANIZAÇÃO: X Ltda"}]}
    L = online._secao_investigacao(inv_, None)
    assert "X ERP" in L[1] and "não aplicada" in L[1] and any("X Ltda" in x for x in L)
    L2 = online._secao_investigacao(None, {"perfil": {"empresas": 1, "computadores": 2, "consultas_14d": 10, "horas_ativas": 3,
                                                      "expediente_pct": 0, "madrugada_pct": 80, "fim_de_semana_pct": 30}})
    assert L2[0].startswith("Coleta ampla") and "madrugada" in L2[1]
    assert online._secao_investigacao(None, None) == []


def test_urlscan_malicioso_confere_o_veredito_de_cada_varredura(monkeypatch):
    """Plano grátis: a busca não traz veredito; ele vem da API de resultado de cada varredura da própria página."""
    import httpx
    monkeypatch.setattr(inv, "RITMO", {**inv.RITMO, "urlscan_chave": inv._Ritmo(100)})

    def handler(req):
        if "/search/" in req.url.path:
            assert req.url.params["q"] == "page.domain:app-x.run.app"
            return httpx.Response(200, json={"results": [{"task": {"uuid": "a"}}, {"task": {"uuid": "b"}}]})
        mal = req.url.path.endswith("/a/")
        return httpx.Response(200, json={"verdicts": {"overall": {"malicious": mal}}})
    with httpx.Client(transport=httpx.MockTransport(handler)) as cli:
        assert inv.urlscan_malicioso("app-x.run.app", cli, "k") == 1
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403))) as cli:
        assert inv.urlscan_malicioso("app-x.run.app", cli, "k") is None
