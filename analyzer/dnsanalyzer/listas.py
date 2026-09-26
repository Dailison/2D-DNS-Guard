"""Listas de bloqueio por categoria + bloqueio automático.

Cada categoria de baixo risco de impacto (jogos, apostas, adulto, VPN/proxy, ameaça) tem uma
lista publicada em /listas/<categoria>.txt, que as políticas do Technitium ASSINAM
(blockListUrls). O analisador não grava no Technitium: o bloqueio automático só coloca o site
na lista da categoria e registra a decisão global "bloqueio automático (<categoria>)" — o
Technitium baixa a lista de novo no próximo intervalo de atualização.
"""

from __future__ import annotations

import logging

from .config import settings

log = logging.getLogger(__name__)
CATEGORIAS = ("jogos", "apostas", "adulto", "vpn_proxy", "ameaca")
AUTO_BY = "bloqueio automático"

# candidatos: recomendação BLOQUEAR, ninguém decidiu, nenhuma empresa ajustou p/ TRABALHO
CANDIDATOS_SQL = (
    "SELECT d.id, d.name, d.category, d.classification, d.corp_reason FROM domains d "
    "WHERE d.category = ANY(%(cats)s) AND d.corp_action = 'BLOQUEAR' AND d.kind = 'public' AND NOT d.locked "
    " AND d.classification IN ('NAO_TRABALHO', 'SUSPEITO', 'MALICIOSO') AND NOT dominio_decidido(d.id) "
    " AND NOT EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id "
    "                 AND td.override_classification = 'TRABALHO') "
    "ORDER BY d.total_queries DESC LIMIT %(lim)s")


def categorias_auto() -> list[str]:
    return [c for c in settings().auto_block_categories if c in CATEGORIAS]


def candidatos(c, cats: list[str] | None = None, limite: int = 300) -> list[dict]:
    cats = cats if cats is not None else categorias_auto()
    return c.execute(CANDIDATOS_SQL, {"cats": cats, "lim": limite}).fetchall() if cats else []


def bloquear_auto(c, limite: int = 500) -> list[dict]:
    """Coloca os candidatos na lista da categoria e grava a decisão global (sai da fila)."""
    feitos = []
    for r in candidatos(c, limite=limite):
        por = f"{AUTO_BY} ({r['category']})"
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) "
                  "ON CONFLICT DO NOTHING", (r["category"], r["name"], por))
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', %s) "
                  "ON CONFLICT (domain_id) DO NOTHING", (r["id"], por))
        feitos.append(r)
    if feitos:
        log.info("bloqueio automático: %d site(s) nas listas por categoria: %s", len(feitos),
                 ", ".join(f"{r['name']} ({r['category']})" for r in feitos[:20]))
    return feitos
