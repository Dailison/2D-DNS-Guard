"""IP liberado só de algumas listas (07/10, pedido do usuário). Antes todo IP liberado ia p/ o grupo de isenção do
Technitium (não bloqueia nada, nem ameaças). Agora cada IP escolhe de quais listas de bloqueio fica livre: ele vai p/
um grupo com a política da rede dele MENOS essas listas ("Empresa: X · sem redes_sociais"), dividido por quem tem a
mesma rede e a mesma escolha. "Tudo" continua sendo o grupo de isenção."""

from types import SimpleNamespace

import pytest

from test_technitium_sync import EMP, POL, U, base

PARC = [{"ip": "10.36.7.7/32", "listas": ["redes_sociais"]},            # Moderna · Filial (política da unidade)
        {"ip": "10.36.7.8", "listas": ["redes_sociais"]},               # mesma rede, mesma escolha: mesmo grupo
        {"ip": "10.36.7.9/32", "listas": ["jogos", "redes_sociais"]},   # outra escolha: outro grupo
        {"ip": "10.35.1.20/32", "listas": ["redes_sociais"]},           # a rede nem bloqueia redes sociais: nada muda p/ ele
        {"ip": "10.60.0.9/32", "listas": ["jogos"]},                    # empresa sem política: a padrão menos jogos
        {"ip": "172.16.5.0/24", "listas": ["jogos", "ameaca"]},         # faixa fora do cadastro
        {"ip": "10.51.0.5/32", "listas": []}, {"ip": "lixo", "listas": ["jogos"]}]


def test_plano_tira_as_listas_escolhidas_da_politica_da_rede(app):
    from app import technitium as dnslib
    grupos, mapa, _ = dnslib.plano_politicas(EMP, POL, parciais=PARC)
    g = "Empresa: Moderna · Filial · sem redes_sociais"
    assert mapa["10.36.7.7/32"] == mapa["10.36.7.8/32"] == g
    assert grupos[g] == {"lists": ["jogos"], "services": [], "blocked": [], "escopo": None}
    assert grupos["Empresa: Moderna · Filial"]["lists"] == ["jogos", "redes_sociais"], "a rede continua com a política dela"
    assert grupos["Empresa: Moderna · Filial · sem jogos+redes_sociais"]["lists"] == []
    assert grupos["Empresa: Moderna · sem redes_sociais"] == {"lists": ["streaming"], "services": ["instagram"],
                                                             "blocked": ["instagram", "tiktok"], "escopo": None}
    assert grupos["Empresa: Sem Política · sem jogos"]["lists"] == ["ameaca"]
    assert mapa["172.16.5.0/24"] == "Empresa: (sem cadastro) · sem ameaca+jogos" and grupos[mapa["172.16.5.0/24"]]["lists"] == []
    assert "10.51.0.5/32" not in mapa, "sem lista escolhida não é liberação parcial"


def test_ip_com_servico_e_listas_fica_no_grupo_dele(app):
    from app import technitium as dnslib
    grupos, mapa, _ = dnslib.plano_politicas(EMP, POL, ips=[{"ip": "10.36.7.7", "slug": "youtube"}], parciais=PARC[:1])
    assert mapa["10.36.7.7/32"] == "Empresa: Moderna · IP 10.36.7.7"
    assert grupos["Empresa: Moderna · IP 10.36.7.7"] == {"lists": ["jogos"], "services": ["youtube"], "blocked": [], "escopo": None}


def test_sincronizacao_tira_o_ip_da_isencao_e_devolve_ao_revogar(app, tech):
    from app import technitium as dnslib
    tech.cfg = base()
    assert tech.cfg["networkGroupMap"]["10.35.20.112/32"] == "Liberados"
    # o IP isento passa a ser liberado só de streaming: sai do grupo de isenção (de propósito) p/ o grupo "… · sem …"
    r = dnslib.sincronizar_politicas(EMP, POL, parciais=[{"ip": "10.35.20.112/32", "listas": ["streaming"]}])
    g = "Empresa: Moderna · sem streaming"
    assert g in r["criados"] and tech.cfg["networkGroupMap"]["10.35.20.112/32"] == g
    grupo = next(x for x in tech.cfg["groups"] if x["name"] == g)
    assert grupo["enableBlocking"] and U + "/listas/streaming.txt" not in grupo["blockListUrls"]
    assert U + "/servico/tiktok.txt" in grupo["blockListUrls"], "o resto da política da rede continua valendo"
    assert any(x["name"] == "Liberados" for x in tech.cfg["groups"])
    # sem a relação dos parciais o IP volta a filtrar pela rede (grupo apagado) — e quem é isento de tudo nunca é tocado
    tech.cfg["networkGroupMap"]["10.35.20.113/32"] = "Liberados"
    r = dnslib.sincronizar_politicas(EMP, POL, parciais=[])
    assert g in r["apagados"] and "10.35.20.112/32" not in tech.cfg["networkGroupMap"]
    assert tech.cfg["networkGroupMap"]["10.35.20.113/32"] == "Liberados"


EMPS = [{"id": 1, "name": "Moderna", "auto_created": False, "networks": [{"cidr": "10.35.0.0/16", "unit": "Matriz"}]}]


@pytest.fixture()
def tela(app, monkeypatch):
    from app import analyzer_client as api
    from app import empresas, politicas
    from app import technitium as dnslib
    est = SimpleNamespace(metas=[], isentos=[], chamadas=[])

    def get(path, **p):
        return est.metas if path == "/console/liberados-meta" else []

    def put(path, body):
        est.chamadas.append(("PUT", body["ip"], body.get("listas"), body.get("definir_listas")))
        if body.get("definir_listas"):
            est.metas[:] = [m for m in est.metas if m["ip"] != body["ip"]] + [{"ip": body["ip"], "listas": body.get("listas")}]
        return {"ok": True}
    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(api, "put", put)
    monkeypatch.setattr(api, "delete", lambda path, **p: est.chamadas.append(("DELETE",)) or {"ok": True})
    monkeypatch.setattr(empresas, "lista", lambda: EMPS)
    monkeypatch.setattr(politicas, "sincronizar", lambda: est.chamadas.append(("SYNC",)) or {})
    monkeypatch.setattr(dnslib, "listar", lambda: list(est.isentos))
    monkeypatch.setattr(dnslib, "liberar", lambda ip, por="": est.chamadas.append(("ISENTAR", ip)) or est.isentos.append(ip) or (ip, "ok"))
    monkeypatch.setattr(dnslib, "revogar", lambda ip, por="": est.chamadas.append(("TIRAR", ip)) or (ip if ip in est.isentos else None))
    adm = SimpleNamespace(email="op@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    app.config.update(TECHNITIUM_ENABLED=True)
    est.c = app.test_client()
    return est


def test_liberar_com_listas_nao_isenta_e_sincroniza(tela):
    tela.c.post("/liberados/liberar", data={"ip": "10.35.1.20", "autorizado_por": "Maria", "listas": ["redes_sociais", "noticias", "inventada"]})
    assert tela.chamadas == [("PUT", "10.35.1.20/32", ["noticias", "redes_sociais"], True), ("SYNC",)], "nada de grupo de isenção"


def test_liberar_tudo_continua_sendo_a_isencao(tela):
    tela.c.post("/liberados/liberar", data={"ip": "10.35.1.21", "autorizado_por": "Maria", "tudo": "1", "listas": ["jogos"]})
    assert tela.chamadas == [("ISENTAR", "10.35.1.21/32"), ("PUT", "10.35.1.21/32", None, True)]


def test_liberar_sem_lista_nenhuma_e_recusado(tela):
    tela.c.post("/liberados/liberar", data={"ip": "10.35.1.22", "autorizado_por": "Maria"})
    tela.c.post("/liberados/liberar", data={"ip": "abc", "autorizado_por": "Maria", "tudo": "1"})
    assert tela.chamadas == []


def test_editar_so_sincroniza_quando_a_escolha_muda(tela):
    tela.isentos.append("10.35.1.30/32")   # isento de tudo, sem descrição
    tela.c.post("/liberados/editar", data={"ip": "10.35.1.30/32", "tudo": "1", "usuario": "João"})
    assert tela.chamadas == [("PUT", "10.35.1.30/32", None, False)], "só a descrição: o Technitium fica como está"
    tela.chamadas.clear()
    tela.c.post("/liberados/editar", data={"ip": "10.35.1.30/32", "listas": ["redes_sociais"]})   # tudo -> só redes sociais
    assert tela.chamadas == [("PUT", "10.35.1.30/32", ["redes_sociais"], True), ("SYNC",)]
    tela.chamadas.clear()
    tela.isentos.clear()
    tela.c.post("/liberados/editar", data={"ip": "10.35.1.30/32", "listas": ["redes_sociais"], "usuario": "José"})
    assert tela.chamadas == [("PUT", "10.35.1.30/32", None, False)]
    tela.chamadas.clear()
    tela.c.post("/liberados/editar", data={"ip": "10.35.1.30/32", "tudo": "1"})   # de volta p/ tudo
    assert tela.chamadas == [("ISENTAR", "10.35.1.30/32"), ("PUT", "10.35.1.30/32", None, True)]


def test_revogar_parcial_sincroniza(tela):
    tela.metas.append({"ip": "10.35.1.40/32", "listas": ["jogos"]})
    tela.c.post("/liberados/revogar", data={"ip": "10.35.1.40/32"})
    assert tela.chamadas == [("TIRAR", "10.35.1.40/32"), ("DELETE",), ("SYNC",)]
    tela.chamadas.clear()
    tela.isentos.append("10.35.1.41/32")
    tela.c.post("/liberados/revogar", data={"ip": "10.35.1.41/32"})
    assert tela.chamadas == [("TIRAR", "10.35.1.41/32"), ("DELETE",)], "isento de tudo: sair do grupo de isenção basta"


def test_pagina_lista_isentos_e_parciais_com_a_escolha(tela):
    tela.isentos.append("10.35.1.50/32")
    tela.metas.append({"ip": "10.35.1.51/32", "listas": ["noticias", "redes_sociais"], "tenant_id": 1, "tenant_name": "Moderna"})
    html = tela.c.get("/liberados").get_data(as_text=True)
    assert "10.35.1.50/32" in html and "10.35.1.51/32" in html and "2 IP(s) liberado(s)" in html
    assert ">Notícias, Redes sociais</summary>" in html and ">Tudo</summary>" in html
    assert ">Notícias, Compras, Redes sociais</summary>" in html, "ao liberar um IP novo, as três já vêm marcadas"
    assert "não bloqueia nada" not in html
