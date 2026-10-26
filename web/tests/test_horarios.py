"""Horários livres por empresa/unidade (26/10, pedido do usuário): nos dias e horas, as listas escolhidas não bloqueiam;
o console aplica a política vigente e vira sozinho no começo/fim de cada horário."""

from datetime import datetime
from types import SimpleNamespace

import pytest

SEG_1230 = datetime(2026, 10, 26, 12, 30)   # segunda-feira
SEG_1300 = datetime(2026, 10, 26, 13, 0)
SAB_0300 = datetime(2026, 10, 31, 3, 0)

EMP = [{"id": 1, "name": "Moral", "networks": [{"cidr": "10.1.0.0/16", "unit": "Matriz"}, {"cidr": "10.2.0.0/16", "unit": "Operacao"},
                                               {"cidr": "10.3.0.0/16", "unit": "Loja"}]},
       {"id": 2, "name": "Sem Política", "networks": [{"cidr": "10.9.0.0/16", "unit": ""}]}]
POL = [{"scope": "default", "lists": ["ameaca", "jogos"], "services": [], "services_blocked": []},
       {"scope": "tenant:1", "lists": ["ameaca", "jogos", "redes_sociais"], "services": ["capcut"], "services_blocked": []},
       {"scope": "unit:1:Operacao", "lists": ["ameaca", "compras", "redes_sociais"], "services": [], "services_blocked": []}]
HS = [{"id": 1, "scope": "tenant:1", "dias": [1, 2, 3, 4, 5], "inicio": "12:00", "fim": "13:00", "listas": ["redes_sociais", "ameaca"]},
      {"id": 2, "scope": "unit:1:Loja", "dias": [6], "inicio": "08:00", "fim": "09:00", "listas": ["jogos"]},
      {"id": 3, "scope": "tenant:2", "dias": [5], "inicio": "22:00", "fim": "06:00", "listas": ["jogos"]}]


def test_em_vigor_e_meia_noite():
    from app import horarios as hz
    assert hz.em_vigor(HS[0], SEG_1230) and not hz.em_vigor(HS[0], SEG_1300), "fim não incluso"
    assert hz.em_vigor(HS[2], SAB_0300), "sexta 22:00 até sábado 06:00"
    assert not hz.em_vigor(HS[2], datetime(2026, 10, 30, 3, 0)), "sexta 03:00 é do horário de quinta (não marcado)"
    assert hz.ativos(HS, SEG_1230) == {"tenant:1": {"redes_sociais"}}, "Ameaças nunca é liberada por horário"


def test_politica_vigente_por_empresa_e_unidade():
    from app import horarios as hz
    p = {x["scope"]: x for x in hz.vigentes(EMP, POL, HS, SEG_1230)}
    assert p["tenant:1"]["lists"] == ["ameaca", "jogos"] and p["tenant:1"]["services"] == ["capcut"]
    assert p["unit:1:Operacao"]["lists"] == ["ameaca", "compras"], "unidade com política própria segue o horário da empresa"
    assert "unit:1:Matriz" not in p, "unidade sem política nem horário próprio: segue o grupo da empresa"
    assert p["unit:1:Loja"]["lists"] == ["ameaca", "jogos", "redes_sociais"], "com horários próprios (fora de hora): não libera"
    assert "tenant:2" not in p
    p = {x["scope"]: x for x in hz.vigentes(EMP, POL, HS, SAB_0300)}
    assert p["tenant:2"]["lists"] == ["ameaca"], "empresa sem política: a padrão menos o horário"
    assert hz.vigentes(EMP, POL, HS, SEG_1300) == POL, "fora de qualquer horário: as políticas como estão"


def test_agendador_so_sincroniza_na_virada(app, monkeypatch):
    from app import analyzer_client as api
    from app import horarios as hz
    from app import politicas as pol
    from app import technitium as dnslib
    feitos, mudou = [], {"v": True}
    monkeypatch.setattr(api, "get", lambda path, **p: HS if path == "/horarios" else [])
    monkeypatch.setattr(api, "post", lambda path, json=None, timeout=30: feitos.append((path, json)) or {"mudou": mudou["v"]})
    monkeypatch.setattr(api, "delete", lambda path, timeout=30, **p: feitos.append(("DELETE " + path, None)) or {})
    monkeypatch.setattr(dnslib, "agora_local", lambda: SEG_1230)
    sync = []
    monkeypatch.setattr(pol, "sincronizar", lambda: sync.append(1) or {})
    assert hz.tick() is True and sync == [1] and feitos[0] == ("/horarios/virada", {"chave": "tenant:1=redes_sociais"})
    mudou["v"] = False
    assert hz.tick() is False and sync == [1], "outro processo já virou"
    mudou["v"] = True
    monkeypatch.setattr(pol, "sincronizar", lambda: (_ for _ in ()).throw(RuntimeError("technitium fora")))
    with pytest.raises(RuntimeError):
        hz.tick()
    assert feitos[-1] == ("DELETE /horarios/virada", None), "falhou: o próximo minuto tenta de novo"


def test_rota_cria_horario_da_unidade(app, monkeypatch):
    from app import analyzer_client as api
    from app import politicas as pol
    enviados, sync = [], []
    monkeypatch.setattr(api, "post", lambda path, json=None, timeout=30: enviados.append((path, json)) or {"ok": True, "id": 7})
    monkeypatch.setattr(pol, "sincronizar", lambda: sync.append(1) or {})
    adm = SimpleNamespace(email="ti@2d", is_super=True, ativo=True)
    monkeypatch.setattr("app.auth.admin_atual", lambda: adm)
    monkeypatch.setattr("app.dns.admin_atual", lambda: adm)
    r = app.test_client().post("/empresas/1/horarios", json={"unidade": "Loja", "dias": [1, 2], "inicio": "12:00", "fim": "13:00",
                                                             "listas": ["redes_sociais"]})
    assert r.get_json()["ok"] and sync == [1]
    assert enviados == [("/horarios", {"scope": "unit:1:Loja", "dias": [1, 2], "inicio": "12:00", "fim": "13:00",
                                       "listas": ["redes_sociais"], "by": "ti@2d"})]
