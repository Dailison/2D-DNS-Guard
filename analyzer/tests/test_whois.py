"""Etapa 3: WHOIS/RDAP -> evidência (sem rede)."""
from dnsanalyzer import whois
from dnsanalyzer.policy import combine
from dnsanalyzer.rules import evaluate
from test_policy_llm import ev, llm

RDAP_BR = {"events": [{"eventAction": "registration", "eventDate": "2021-05-03T12:00:00Z"}],
           "nameservers": [{"ldhName": "elias.ns.cloudflare.com"}, {"ldhName": "nena.ns.cloudflare.com"}],
           "entities": [{"roles": ["registrant"], "publicIds": [{"type": "cnpj", "identifier": "22.921.674/0001-61"}],
                         "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["kind", {}, "text", "org"],
                                                  ["fn", {}, "text", "1UP TECHNOLOGY LTDA ME"],
                                                  ["adr", {"cc": "BR"}, "text", ["", "", "", "", "", "", ""]]]]}]}
RDAP_COM = {"events": [{"eventAction": "registration", "eventDate": "2026-03-11T00:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.SEDOPARKING.COM"}, {"ldhName": "NS2.SEDOPARKING.COM"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "HOSTINGER operations, UAB"]]]},
                         {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]}]}


def test_parse_registro_br_pessoa_juridica():
    w = whois.parse_rdap(RDAP_BR)
    assert w["criado"] == "2021-05-03" and w["ns"][0] == "elias.ns.cloudflare.com" and not w["estacionado"]
    assert w["titular"] == {"nome": "1UP TECHNOLOGY LTDA ME", "tipo": "cnpj", "doc": "22.921.674/0001-61",
                            "oculto": False, "pais": "BR"}


def test_parse_gtld_oculto_e_estacionado():
    w = whois.parse_rdap(RDAP_COM)
    assert w["registrador"] == "HOSTINGER operations, UAB" and w["estacionado"]
    assert w["titular"]["oculto"] and w["titular"]["nome"] is None


def test_evidencia_cnpj_com_receita_e_confiavel():
    w = {"encontrado": True, "fonte": "registro.br", **whois.parse_rdap(RDAP_BR)}
    w["titular"]["receita"] = {"razao_social": "1UP TECHNOLOGY LTDA", "nome_fantasia": "1UP TECHNOLOGY",
                               "atividade": "Suporte técnico em TI", "situacao": "ATIVA", "municipio": "SJC", "uf": "SP"}
    txt, data = whois.evidencia(w)
    assert data["confiavel"] and "PESSOA JURÍDICA" in txt and "Suporte técnico em TI" in txt and "fantasia" in txt


def test_evidencia_outros_casos():
    assert whois.evidencia(None) is None and whois.evidencia({"encontrado": False}) is None
    txt, data = whois.evidencia({"encontrado": True, "fonte": "rdap", **whois.parse_rdap(RDAP_COM)})
    assert not data["confiavel"] and data["estacionado"] and "oculto" in txt and "estacionamento" in txt
    cpf = {"encontrado": True, "fonte": "registro.br", "titular": {"tipo": "cpf", "nome": "Fulano", "doc": "***"}}
    assert "PESSOA FÍSICA" in whois.evidencia(cpf)[0] and not whois.evidencia(cpf)[1]["confiavel"]
    decl = {"encontrado": True, "fonte": "rdap", "titular": {"nome": "Acme Corp", "pais": "US", "oculto": False}}
    assert "não verificado" in whois.evidencia(decl)[0] and not whois.evidencia(decl)[1]["confiavel"]


def _dossie(w):
    return evaluate({"name": "iotsuite.com.br", "kind": "public", "tld": "br", "features": {}, "ti_hits": [],
                     "logs": {}, "whois": w})


def test_policy_titular_cnpj_vale_como_identificacao():
    w = {"encontrado": True, "fonte": "registro.br", **whois.parse_rdap(RDAP_BR)}
    r = _dossie(w)
    wid = next(e.id for e in r.evidence if e.kind == "whois")
    f = combine(r, llm("TRABALHO", work=85, recognized=True, reasons=[{"evidence_id": wid, "text": "empresa de TI"}]), ev(r))
    assert f.classification == "TRABALHO"


def test_policy_titular_declarado_nao_vale():
    w = {"encontrado": True, "fonte": "rdap", "titular": {"nome": "Acme Corp", "oculto": False}}
    r = _dossie(w)
    wid = next(e.id for e in r.evidence if e.kind == "whois")
    f = combine(r, llm("TRABALHO", work=85, recognized=True, reasons=[{"evidence_id": wid, "text": "Acme"}]), ev(r))
    assert f.classification == "DESCONHECIDO"


def test_registro_br_sem_documento_e_limite_nao_grava(monkeypatch):
    import copy
    import pytest
    sem_doc = copy.deepcopy(RDAP_BR)
    sem_doc["entities"][0].pop("publicIds")
    monkeypatch.setattr(whois, "_get", lambda *a, **k: sem_doc)
    gravou = []

    class C:
        def execute(self, sql, *a):
            if sql.startswith("INSERT"):
                gravou.append(sql)
            return self

        def fetchone(self):
            return None
    monkeypatch.setattr(whois, "_br_pausa_ate", 0.0)
    with pytest.raises(whois.WhoisIndisponivel):
        whois.lookup(C(), "iotsuite.com.br", fetch=True)
    assert not gravou


def test_titular_estrangeiro_no_registro_br_nao_e_limite(monkeypatch):
    """Empresa estrangeira no .br não tem CPF/CNPJ: o registro.br dá um ID próprio (eid) — não é limite de consultas
    (27/09: ram.com.br = Chrysler Group LLC travava os .br a cada tentativa)."""
    import copy
    estrangeiro = copy.deepcopy(RDAP_BR)
    estrangeiro["entities"][0]["publicIds"] = [{"type": "eid", "identifier": "2634203"}]
    monkeypatch.setattr(whois, "_get", lambda *a, **k: estrangeiro)
    monkeypatch.setattr(whois, "_br_pausa_ate", 0.0)

    class C:
        def execute(self, sql, *a):
            return self

        def fetchone(self):
            return None
    w = whois.lookup(C(), "ram.com.br", fetch=True)
    assert w["titular"]["tipo"] == "estrangeiro" and w["titular"]["doc"] == "2634203"
    assert not whois.br_pausado()
    txt, dados = whois.evidencia(w)
    assert "ENTIDADE ESTRANGEIRA" in txt and not dados["confiavel"]


def test_limite_do_registro_br_pausa_os_br(monkeypatch):
    """Limite do registro.br: .br em pausa (nem consulta, p/ não esticar o bloqueio); os outros TLDs seguem."""
    import copy
    import pytest
    sem_doc = copy.deepcopy(RDAP_BR)
    sem_doc["entities"][0].pop("publicIds")
    chamadas = []
    monkeypatch.setattr(whois, "_get", lambda url, *a, **k: chamadas.append(url) or (sem_doc if ".br/" in url else None))
    monkeypatch.setattr(whois, "_br_pausa_ate", 0.0)

    class C:
        def execute(self, sql, *a):
            return self

        def fetchone(self):
            return None
    with pytest.raises(whois.WhoisIndisponivel):
        whois.lookup(C(), "ram.com.br", fetch=True)
    assert whois.br_pausado()
    with pytest.raises(whois.WhoisIndisponivel, match="pausa"):
        whois.lookup(C(), "outro.com.br", fetch=True)
    assert whois.lookup(C(), "exemplo.com", fetch=True) == {"encontrado": False, "fonte": "rdap"}
    assert [u.rsplit("/", 1)[1] for u in chamadas] == ["ram.com.br", "exemplo.com"]
