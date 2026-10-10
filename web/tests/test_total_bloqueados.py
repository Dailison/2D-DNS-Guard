"""Domínios bloqueados: contador de domínios distintos no título (como o das whitelists em Domínios liberados)."""


def test_total_conta_dominio_uma_vez(app, monkeypatch):
    from app import dns
    from app import technitium as dnslib
    listas = {"jogos": {"a.com", "b.com"}, "apostas": {"b.com", "c.com"}, "ameaca": {"d.com"}}
    monkeypatch.setattr(dnslib, "dominios_das_listas", lambda cats: {c: listas.get(c, set()) for c in cats})
    resumo = {"categorias": [{"categoria": "jogos", "total": 2}, {"categoria": "apostas", "total": 2}, {"categoria": "ameaca", "total": 1}]}
    assert dns._total_bloqueados(resumo) == 4, "b.com está em duas listas e conta uma vez"


def test_sem_a_relacao_dos_dominios_soma_as_listas(app, monkeypatch):
    from app import dns
    from app import technitium as dnslib
    monkeypatch.setattr(dnslib, "dominios_das_listas", lambda cats: {c: set() for c in cats})   # analisador fora: vazio
    resumo = {"categorias": [{"categoria": "jogos", "total": 2}, {"categoria": "apostas", "total": 3},
                             {"categoria": "lista_que_nao_e_da_pagina", "total": 99}]}
    assert dns._total_bloqueados(resumo) == 5
    assert dns._total_bloqueados({"categorias": []}) == 0


def test_titulo_mostra_o_contador(app):
    from flask import render_template_string
    with app.test_request_context("/dominios-bloqueados"):
        h1 = render_template_string(
            "{% set resumo = {'categorias': [{'categoria': 'jogos', 'total': 2}]} %}{% set total_bloqueados = 1234 %}"
            + open("app/templates/admin/listas_categoria.html", encoding="utf-8").read().split("<h1>")[1].split("</h1>")[0])
    assert "Domínios bloqueados" in h1 and ">1234 domínio(s)</span>" in h1 and "domínios distintos" in h1
