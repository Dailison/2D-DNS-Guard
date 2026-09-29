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
                 "urlscan": None, "paginas_do_site": None, "bem_conhecidos": {}, "coocorrencia": None}.items():
        monkeypatch.setattr(inv, f, lambda *a, _r=r, **k: _r)
    buscas_feitas = []
    monkeypatch.setattr(inv, "buscas", lambda qs, nome: buscas_feitas.extend(qs) or [{"consulta": q, "resultados": []} for q in qs])
    monkeypatch.setattr(inv, "cnpjs", lambda c, ns: [])
    monkeypatch.setattr(inv, "subdominios", lambda ns, http: [])
    monkeypatch.setattr(inv, "paginas_dos_resultados", lambda *a: [])
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
