""""IPs que liberam" (03/10): um serviço liberado só para um IP/faixa. O IP ganha um grupo próprio no Technitium com a
política da rede dele (unidade > empresa > padrão) mais o serviço; revogar apaga o grupo e o IP volta para a rede."""

from types import SimpleNamespace

import pytest

from test_technitium_sync import EMP, POL, U, base

IPS = [{"ip": "10.35.1.20/32", "slug": "youtube"}, {"ip": "10.35.1.20", "slug": "spotify"},   # Moderna · Matriz (empresa)
       {"ip": "10.36.7.7/32", "slug": "youtube"},     # Moderna · Filial (política da unidade)
       {"ip": "10.60.0.9/32", "slug": "youtube"},     # empresa sem política: vale a padrão
       {"ip": "172.16.5.0/24", "slug": "youtube"},    # faixa fora do cadastro: padrão
       {"ip": "lixo", "slug": "youtube"}]


def test_plano_ip_herda_a_politica_da_rede_dele(app):
    from app import technitium as dnslib
    grupos, mapa, _ = dnslib.plano_politicas(EMP, POL, ips=IPS)
    assert mapa["10.35.1.20/32"] == "Empresa: Moderna · IP 10.35.1.20" and mapa["10.35.0.0/16"] == "Empresa: Moderna"
    assert grupos["Empresa: Moderna · IP 10.35.1.20"] == {"lists": ["streaming"], "services": ["instagram", "spotify", "youtube"],
                                                         "blocked": ["instagram", "tiktok"], "escopo": None}
    assert grupos["Empresa: Moderna"]["services"] == ["instagram"], "a empresa não ganha o serviço"
    assert grupos["Empresa: Moderna · IP 10.36.7.7"]["lists"] == ["jogos", "redes_sociais"], "IP numa unidade com política própria"
    assert grupos["Empresa: Sem Política · IP 10.60.0.9"] == {"lists": ["ameaca", "jogos"], "services": ["youtube"],
                                                            "blocked": [], "escopo": None}
    assert mapa["172.16.5.0/24"] == "Empresa: (sem cadastro) · IP 172.16.5.0/24"
    assert grupos["Empresa: (sem cadastro) · IP 172.16.5.0/24"]["lists"] == ["ameaca", "jogos"]
    assert len(mapa) == 3 + 4, "IP inválido é ignorado"


def test_plano_ip_assina_os_ajustes_da_rede(app):
    from app import technitium as dnslib
    grupos, _, _ = dnslib.plano_politicas(EMP, POL, ajustes=["unit:1:Matriz", "tenant:3"], ips=IPS)
    assert grupos["Empresa: Moderna · IP 10.35.1.20"]["escopo"] == "unit:1:Matriz"
    assert grupos["Empresa: Sem Política · IP 10.60.0.9"]["escopo"] == "tenant:3"


def test_sincroniza_cria_e_depois_apaga_o_grupo_do_ip(app, tech):
    from app import technitium as dnslib
    tech.cfg = base()
    ips = [{"ip": "10.35.1.20/32", "slug": "youtube"}, {"ip": "10.35.20.112/32", "slug": "youtube"}]
    r = dnslib.sincronizar_politicas(EMP, POL, ips=ips)
    assert "Empresa: Moderna · IP 10.35.1.20" in r["criados"]
    ngm = tech.cfg["networkGroupMap"]
    assert ngm["10.35.1.20/32"] == "Empresa: Moderna · IP 10.35.1.20" and ngm["10.35.0.0/16"] == "Empresa: Moderna"
    assert ngm["10.35.20.112/32"] == "Liberados", "IP isento continua isento"
    g = next(x for x in tech.cfg["groups"] if x["name"] == "Empresa: Moderna · IP 10.35.1.20")
    assert U + "/servico/youtube.txt" in g["allowListUrls"] and U + "/servico/instagram.txt" in g["allowListUrls"]
    assert U + "/listas/streaming.txt" in g["blockListUrls"] and g["enableBlocking"]
    assert dnslib.grupos_da_empresa("Moderna") == ["Empresa: Moderna", "Empresa: Moderna · Filial",
                                                   "Empresa: Moderna · IP 10.35.1.20", "Empresa: Moderna · IP 10.35.20.112"], \
        "exceção só da empresa alcança também os IPs dela"
    r = dnslib.sincronizar_politicas(EMP, POL, ips=[])   # revogado
    assert "Empresa: Moderna · IP 10.35.1.20" in r["apagados"]
    ngm = tech.cfg["networkGroupMap"]
    assert "10.35.1.20/32" not in ngm and ngm["10.35.20.112/32"] == "Liberados" and ngm["10.35.0.0/16"] == "Empresa: Moderna"


SERV = [{"slug": "youtube", "name": "YouTube", "total": 2, "category": None}]
EMPS = [{"id": 1, "name": "Moderna", "auto_created": False, "networks": [{"cidr": "10.35.0.0/16", "unit": "Matriz"}]}]


@pytest.fixture()
def tela(app, monkeypatch):
    from app import analyzer_client as api
    from app import empresas, politicas
    from app import technitium as dnslib
    est = SimpleNamespace(ips=[], chamadas=[], chamadas_log=[], sem_rota=False)

    def get(path, **p):
        if path == "/console/ip-servicos":
            if est.sem_rota:
                raise api.AnalyzerError("404: Not Found")
            return [x for x in est.ips if not p.get("slug") or x["slug"] == p["slug"]]
        if path == "/console/liberados-log":
            est.chamadas_log.append(p.get("servico"))
            return []
        if path == "/console/liberados-meta":
            return []
        return SERV if path == "/liberacao" else [] if path.startswith("/liberacao/") else {"categorias": [], "revisados": 0}

    def put(path, body):
        est.chamadas.append(("PUT", path, body))
        est.ips.append({**body, "ip": body["ip"], "tenant_name": "Moderna", "created_by": body["by"], "created_at": None,
                        "updated_by": None, "updated_at": None})
        return {"ok": True}

    def delete(path, **p):
        est.chamadas.append(("DELETE", path, p))
        est.ips[:] = [x for x in est.ips if not (x["ip"] == p["ip"] and x["slug"] == p["slug"])]
        return {"ok": True}

    monkeypatch.setattr(api, "get", get)
    monkeypatch.setattr(api, "put", put)
    monkeypatch.setattr(api, "delete", delete)
    monkeypatch.setattr(empresas, "lista", lambda: EMPS)
    monkeypatch.setattr(politicas, "por_escopo", lambda: {"default": {"lists": [], "services": []}})
    monkeypatch.setattr(politicas, "sincronizar", lambda: est.chamadas.append(("SYNC",)) or {})
    monkeypatch.setattr(dnslib, "listar", lambda: [])
    adm = SimpleNamespace(email="op@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    est.c = app.test_client()
    return est


def test_liberar_ip_grava_e_sincroniza(tela):
    r = tela.c.post("/servicos/youtube/ips", data={"ip": "10.35.1.20", "tenant_id": "1", "filial": "Matriz", "usuario": "João",
                                                   "autorizado_por": "Maria", "voltar": "/dominios-liberados?slug=youtube#ips"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dominios-liberados?slug=youtube#ips")
    put = tela.chamadas[0]
    assert put[:2] == ("PUT", "/console/ip-servicos") and tela.chamadas[1] == ("SYNC",)
    assert put[2] == {"ip": "10.35.1.20/32", "slug": "youtube", "by": "op@2d", "tenant_id": 1, "filial": "Matriz",
                      "departamento": "", "usuario": "João", "tipo": "", "autorizado_por": "Maria"}


def test_liberar_ip_exige_quem_autorizou_e_ip_valido(tela):
    tela.c.post("/servicos/youtube/ips", data={"ip": "10.35.1.20"})
    tela.c.post("/servicos/youtube/ips", data={"ip": "abc", "autorizado_por": "Maria"})
    assert tela.chamadas == []


def test_editar_ip_ja_liberado_nao_sincroniza(tela):
    tela.ips.append({"ip": "10.35.1.20/32", "slug": "youtube"})
    tela.c.post("/servicos/youtube/ips", data={"ip": "10.35.1.20", "usuario": "José"})
    assert [c[0] for c in tela.chamadas] == ["PUT"], "só os dados mudam: nada a aplicar no Technitium"


def test_revogar_ip(tela):
    tela.ips.append({"ip": "10.35.1.20/32", "slug": "youtube"})
    tela.c.post("/servicos/youtube/ips/revogar", data={"ip": "10.35.1.20/32"})
    assert tela.chamadas == [("DELETE", "/console/ip-servicos", {"ip": "10.35.1.20/32", "slug": "youtube", "by": "op@2d"}), ("SYNC",)]
    assert tela.ips == []


def test_pagina_do_servico_mostra_o_botao_e_os_ips(tela):
    tela.ips.append({"ip": "10.35.1.20/32", "slug": "youtube", "tenant_id": 1, "tenant_name": "Moderna", "filial": "Matriz",
                     "departamento": "Recepção", "usuario": "João", "tipo": "Computador", "autorizado_por": "Maria",
                     "created_by": "op@2d", "created_at": "2026-10-03T12:00:00+00:00", "updated_by": None, "updated_at": None})
    h = tela.c.get("/dominios-liberados?slug=youtube").get_data(as_text=True)
    assert "IPs que liberam… (1)" in h and 'id="dlgIps"' in h and 'id="ip_novo"' in h
    assert "<code>10.35.1.20</code> (Moderna · João)" in h, "resumo no topo"
    assert "Recepção" in h and 'action="/servicos/youtube/ips/revogar"' in h
    assert '<option value="1" >Moderna</option>' in h, "mesmos campos dos IPs liberados"
    assert tela.chamadas_log == ["youtube"], "histórico só das liberações deste serviço"


def test_analisador_sem_a_rota_desliga_o_botao(tela):
    tela.sem_rota = True
    h = tela.c.get("/dominios-liberados?slug=youtube").get_data(as_text=True)
    assert "IPs que liberam…</button>" in h and "disabled" in h and 'id="dlgIps"' not in h
    from app import politicas
    assert politicas.ips_servicos() == [], "sincronização segue sem os IPs (analisador antigo)"


def test_ips_liberados_segue_com_os_mesmos_campos(tela, monkeypatch):
    """Os campos (empresa/filial/tipo) e a sugestão pelo IP saíram para um parcial comum: a tela antiga não muda."""
    from app import technitium as dnslib
    monkeypatch.setattr(dnslib, "listar", lambda: ["10.35.20.112/32"])
    h = tela.c.get("/liberados").get_data(as_text=True)
    assert "1 IP(s) liberado(s)" in h and 'id="ip_novo"' in h and 'id="fil_novo"' in h and 'id="tipo_novo"' in h
    assert 'form="e_1" name="tenant_id" class="lb-emp" data-filial="e_1"' in h and "var EMP = [{" in h
    assert h.count("ipIn.addEventListener") == 1 and tela.chamadas_log == [None], "histórico só das isenções"
