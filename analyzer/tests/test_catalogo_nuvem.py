"""Endereços de provedor de nuvem no catálogo com lista fixa (sem IA): AWS, CloudFront e Google Cloud Functions."""

import pytest

from dnsanalyzer import catalog
from dnsanalyzer.features import analyze_name
from dnsanalyzer.rules import evaluate

NOMES = ["us-central1-pertodigital-fe5e0.cloudfunctions.net", "southamerica-east1-b4aprodution.cloudfunctions.net",
         "bucket.s3.amazonaws.com", "d1abc.cloudfront.net"]


@pytest.mark.parametrize("nome", NOMES)
def test_catalogo_com_lista_fixa_nao_protegido(nome):
    e = catalog.match(nome)
    assert e and e["lista"] == "wl:infraestrutura" and e["classification"] == "TRABALHO" and e["category"] == "infraestrutura"
    assert not e["protected"], "não protegido: feed de ameaça de alta confiança ainda condena"


def test_cloudfunctions_e_sufixo_privado_cada_funcao_e_um_dominio():
    i = analyze_name("us-central1-pertodigital-fe5e0.cloudfunctions.net")
    assert i.private_suffix and i.icann_registrable == "cloudfunctions.net"
    assert i.registrable == "us-central1-pertodigital-fe5e0.cloudfunctions.net"
    assert catalog.match("cloudfunctions.net.evil.com") is None, "só casa o sufixo de verdade"


def _dossie(nome, hits=()):
    return {"name": nome, "kind": "public", "tld": "net", "features": {}, "private_suffix": True, "platform": "cloudfunctions.net",
            "catalog": catalog.match(nome), "ti_hits": list(hits), "logs": {"total_queries": 5, "clients": 1, "tenants": 1}}


def test_regras_resolvem_sem_ia():
    r = evaluate(_dossie("us-central1-pertodigital-fe5e0.cloudfunctions.net"))
    assert r.final and not r.needs_llm and r.classification == "TRABALHO" and r.category == "infraestrutura"


def test_feed_de_alta_confianca_ainda_vira_malicioso():
    nome = "us-central1-golpe-123.cloudfunctions.net"
    hit = {"source": "urlhaus", "label": "URLhaus", "threat": "malware", "confidence": "high", "weight": 90, "matched": nome, "fqdns": [nome]}
    r = evaluate(_dossie(nome, [hit]))
    assert r.classification == "MALICIOSO" and r.category == "ameaca"
