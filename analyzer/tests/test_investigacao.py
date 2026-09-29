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
