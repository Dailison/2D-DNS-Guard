"""Sincronização das políticas com o Technitium (plano de confiabilidade, fase 2)."""

import copy

import pytest

U = "http://10.100.10.4:8088"


def base():
    return {"groups": [
        {"name": "default", "enableBlocking": True, "blocked": [], "blockListUrls": [U + "/listas/ameaca.txt"],
         "allowListUrls": [], "blockingAddresses": ["0.0.0.0", "::"]},
        {"name": "Liberados", "enableBlocking": False, "blocked": []},
        {"name": "Manual Antigo", "enableBlocking": True, "blocked": ["x.com"]},
        {"name": "Empresa: Velha", "enableBlocking": True, "blockListUrls": []}],
        "networkGroupMap": {"0.0.0.0/0": "default", "10.9.0.0/16": "Empresa: Velha", "10.35.20.112/32": "Liberados",
                            "10.1.0.0/16": "default", "10.2.0.0/16": "default"}}


EMP = [{"id": 1, "name": "Moderna", "networks": [{"cidr": "10.35.0.0/16", "unit": "Matriz"}, {"cidr": "10.36.0.0/16", "unit": "Filial"}]},
       {"id": 2, "name": "Norte", "networks": [{"cidr": "10.51.0.0/16", "unit": ""}, {"cidr": "lixo", "unit": ""}]},
       {"id": 3, "name": "Sem Política", "networks": [{"cidr": "10.60.0.0/16", "unit": ""}]}]
POL = [{"scope": "default", "lists": ["ameaca", "jogos"], "services": []},
       {"scope": "tenant:1", "lists": ["streaming"], "services": ["instagram"], "services_blocked": ["tiktok", "instagram"]},
       {"scope": "unit:1:Filial", "lists": ["jogos", "redes_sociais"], "services": []},
       {"scope": "tenant:2", "lists": ["apostas"], "services": []}]


def test_plano_politicas(app):
    from app import technitium as dnslib
    grupos, mapa, default = dnslib.plano_politicas(EMP, POL)
    assert mapa == {"10.35.0.0/16": "Empresa: Moderna", "10.36.0.0/16": "Empresa: Moderna · Filial", "10.51.0.0/16": "Empresa: Norte"}
    assert "10.60.0.0/16" not in mapa, "empresa sem política fica no default"
    assert grupos["Empresa: Moderna · Filial"]["lists"] == ["jogos", "redes_sociais"]
    assert default["lists"] == ["ameaca", "jogos"]


def test_aplica_politica(app):
    from app import technitium as dnslib
    g = {"blockListUrls": ["https://terceiro.exemplo/lista.txt", U + "/listas/adulto.txt"], "allowListUrls": ["https://outra/allow.txt"]}
    dnslib._aplica_politica(g, ["jogos", "streaming"], ["instagram"], ["tiktok", "instagram"])
    assert g["blockListUrls"][0] == "https://terceiro.exemplo/lista.txt", "URL de terceiro preservada"
    assert U + "/listas/adulto.txt" not in g["blockListUrls"] and U + "/listas/jogos.txt" in g["blockListUrls"]
    assert U + "/servico/tiktok.txt" in g["blockListUrls"] and U + "/servico/instagram.txt" not in g["blockListUrls"], \
        "serviço liberado vence o bloqueado"
    wl = [U + f"/whitelist/{c}.txt" for c, _ in dnslib.CATEGORIAS_WHITELIST_DNS]
    assert g["allowListUrls"] == ["https://outra/allow.txt"] + wl + [U + "/servico/instagram.txt"], "whitelists em todos os grupos"
    dnslib._aplica_politica(g, [], [], [])
    assert g["allowListUrls"] == ["https://outra/allow.txt"] + wl, "reaplicar não duplica"


def test_sincronizar_sem_gravar_nao_toca_isencao(app, tech):
    from app import technitium as dnslib
    tech.cfg = base()
    r = dnslib.sincronizar_politicas(EMP, POL, aplicar=False)
    assert not tech.gravados and not tech.backups
    assert set(r["criados"]) == {"Empresa: Moderna", "Empresa: Moderna · Filial", "Empresa: Norte"}
    assert r["apagados"] == ["Empresa: Velha"]
    ngm = r["cfg"]["networkGroupMap"]
    assert ngm["10.35.20.112/32"] == "Liberados" and ngm["10.35.0.0/16"] == "Empresa: Moderna"
    assert "10.9.0.0/16" not in ngm and "Liberados" in {g["name"] for g in r["cfg"]["groups"]}


def test_sincronizar_grava_com_backup(app, tech):
    from app import technitium as dnslib
    tech.cfg = base()
    dnslib.sincronizar_politicas(EMP, POL, por="op@2d")
    assert len(tech.gravados) == 1 and len(tech.backups) == 1
    assert tech.backups[0]["por"] == "op@2d" and tech.backups[0]["config"] == base(), "backup = o config ANTERIOR"


def test_sem_backup_nao_grava(app, tech):
    from app import technitium as dnslib
    tech.cfg, tech.falha_backup = base(), True
    with pytest.raises(RuntimeError, match="backup"):
        dnslib.sincronizar_politicas(EMP, POL)
    assert not tech.gravados


@pytest.mark.parametrize("estrago, msg", [
    (lambda c: c["groups"].remove(next(g for g in c["groups"] if g["name"] == "Liberados")), "grupo de isenção"),
    (lambda c: c["groups"].remove(next(g for g in c["groups"] if g["name"] == "Manual Antigo")), "não são de empresa"),
    (lambda c: c.__setitem__("networkGroupMap", {"0.0.0.0/0": "default"}), "mapa de redes"),
    (lambda c: c["networkGroupMap"].__setitem__("10.35.20.112/32", "default"), "redes isentas"),
])
def test_recusas(app, tech, monkeypatch, estrago, msg):
    from app import technitium as dnslib
    tech.cfg = base()
    orig = dnslib._sincroniza

    def estragada(cfg, *a):
        r = orig(cfg, *a)
        estrago(cfg)
        return r
    monkeypatch.setattr(dnslib, "_sincroniza", estragada)
    with pytest.raises(RuntimeError, match=msg):
        dnslib.sincronizar_politicas(EMP, POL)
    assert not tech.gravados


def test_releitura_refaz_a_partir_do_config_novo(app, tech):
    from app import technitium as dnslib
    tech.cfg = base()
    novo = base()
    novo["groups"].append({"name": "Criado Por Outro", "enableBlocking": True})
    novo["networkGroupMap"]["10.99.0.0/16"] = "Criado Por Outro"
    # 1ª leitura = base; releitura (antes de gravar) = config alterado por outra pessoa; depois estável
    tech.releituras = [base(), novo, copy.deepcopy(novo), copy.deepcopy(novo)]
    dnslib.sincronizar_politicas(EMP, POL)
    assert len(tech.gravados) == 1
    g = tech.gravados[0]
    assert "Criado Por Outro" in {x["name"] for x in g["groups"]} and g["networkGroupMap"]["10.99.0.0/16"] == "Criado Por Outro"
    assert tech.backups[0]["config"] == novo


def test_releitura_desiste_na_quarta(app, tech):
    from app import technitium as dnslib
    configs = []
    for i in range(8):
        c = base()
        c["groups"].append({"name": f"X{i}"})
        configs.append(c)
    tech.cfg = base()
    tech.releituras = configs   # muda a cada leitura
    with pytest.raises(RuntimeError, match="alterado por outra pessoa"):
        dnslib.sincronizar_politicas(EMP, POL)
    assert not tech.gravados


def test_liberar_e_revogar(app, tech):
    from app import technitium as dnslib
    tech.cfg = base()
    ip, msg = dnslib.liberar("10.1.2.3", por="op@2d")
    assert ip == "10.1.2.3/32" and tech.cfg["networkGroupMap"]["10.1.2.3/32"] == "Liberados" and tech.backups[-1]["motivo"] == "liberar 10.1.2.3/32"
    assert dnslib.revogar("10.1.2.3", por="op@2d") == "10.1.2.3/32" and "10.1.2.3/32" not in tech.cfg["networkGroupMap"]
    n = len(tech.gravados)
    assert dnslib.revogar("10.1.2.3") is None and len(tech.gravados) == n, "nada a revogar: não grava"


def test_excecao_imediata(app, tech, monkeypatch):
    """Fase 3.3: "manter liberado" vale na hora só nos grupos que a mudança libera; tira só as exceções do console."""
    from app import analyzer_client as api
    from app import technitium as dnslib
    app.config["TECHNITIUM_ENABLED"] = True
    tech.cfg = base()
    tech.cfg["groups"] += [{"name": "Empresa: A", "allowed": ["manual.com"]}, {"name": "Empresa: B", "allowed": []}]
    estado = {"antes": {"x.com": ["Empresa: A", "Empresa: B", "default"]}, "depois": {"x.com": ["Empresa: B"]}}
    monkeypatch.setattr(dnslib, "grupos_bloqueando", lambda doms: estado["depois"])
    registrados = {}
    post_orig = api.post

    def post(path, body=None, **kw):
        if path == "/console/excecoes":
            for d, gs in body["excecoes"].items():
                registrados.setdefault(d, []).extend(gs)
            return {"ok": True}
        if path == "/console/excecoes/remover":
            for d in body["domains"]:
                registrados.pop(d, None)
            return {"ok": True}
        return post_orig(path, body, **kw)
    monkeypatch.setattr(api, "post", post)
    monkeypatch.setattr(api, "get", lambda path, **p: {d: gs for d, gs in registrados.items() if d in p.get("domains", [])})
    grupos = dnslib.liberar_agora(["x.com"], estado["antes"], "op@2d")
    assert grupos == ["Empresa: A", "default"], "B segue bloqueado por outra lista: sem exceção lá"
    g = {x["name"]: x for x in tech.cfg["groups"]}
    assert g["Empresa: A"]["allowed"] == ["manual.com", "x.com"] and "x.com" in g["default"]["allowed"]
    assert "x.com" not in g["Empresa: B"]["allowed"] and registrados == {"x.com": ["Empresa: A", "default"]}
    n = len(tech.gravados)
    dnslib.liberar_agora(["x.com"], estado["antes"], "op@2d")
    assert g["Empresa: A"]["allowed"].count("x.com") == 1 or tech.cfg["groups"][4]["allowed"].count("x.com") == 1, "sem duplicar"
    assert "Liberado agora em A, redes sem cadastro" in dnslib.msg_liberado(grupos)
    dnslib.remover_excecao(["x.com"], "op@2d")
    g = {x["name"]: x for x in tech.cfg["groups"]}
    assert g["Empresa: A"]["allowed"] == ["manual.com"] and "x.com" not in g["default"].get("allowed", []), "manual fica"
    assert registrados == {} and len(tech.gravados) > n


def test_nome_local():
    from app import technitium as dnslib
    z = ["2d.local", "empresa.corp"]
    for n in ("srv01", "wpad", "dc.2d.local", "2d.local", "x.empresa.corp", "10.1.168.192.in-addr.arpa", "impressora.local."):
        assert dnslib.nome_local(n, z), n
    for n in ("google.com", "corp.com", "empresa.corp.com.br", "app.delivery"):
        assert not dnslib.nome_local(n, z), n
