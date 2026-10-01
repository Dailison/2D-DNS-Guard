import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


@pytest.fixture(autouse=True)
def _dns_sem_rede(monkeypatch):
    """Os testes não consultam DNS de verdade: sem resposta definida, o teste de DNS da etapa 1 "não sabe" (e ninguém
    vai p/ a lista DNS Inativo por acaso). Quem testa o DNS Inativo define as próprias respostas."""
    from dnsanalyzer import dnsativo
    monkeypatch.setattr(dnsativo, "consulta", lambda nome, resolvedor, tipo="A": "erro")
