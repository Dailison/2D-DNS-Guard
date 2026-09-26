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
CATEGORIAS_RISCO = ("jogos", "apostas", "adulto", "vpn_proxy", "ameaca")   # bloqueio automático
# listas CURADAS à mão (pedido do usuário 2026-09-26): a IA só SUGERE a categoria; uma pessoa
# confirma e o site entra na lista. Só as de risco (acima) a IA põe sozinha.
CATEGORIAS_CURADAS = ("redes_sociais", "mensageiros", "streaming", "publicidade", "compras", "noticias")
CATEGORIAS_DINAMICAS = ()   # (listas montadas pela classificação: desligado — ver CATEGORIAS_CURADAS)
# só manual: o que foi bloqueado à mão e não cabe numa categoria (migração dos grupos antigos)
CATEGORIAS_MANUAIS = ("outros_bloqueios", "para_revisar")   # para_revisar: sobras da migração, ninguém aplica
CATEGORIAS = CATEGORIAS_RISCO + CATEGORIAS_CURADAS + CATEGORIAS_MANUAIS
AUTO_BY = "bloqueio automático"

# SUGESTÕES p/ as listas curadas: classificado NAO_TRABALHO na categoria, sem decisão "manter
# liberado" (global ou de alguma empresa) e sem ajuste de alguma empresa p/ TRABALHO
DINAMICA_SQL = (
    "SELECT d.name AS domain, CASE WHEN d.classified_by = 'catalog' THEN 'catálogo' ELSE 'classificação da IA' END "
    " AS added_by, d.analyzed_at AS added_at FROM domains d "
    "WHERE d.category = %(cat)s AND d.classification = 'NAO_TRABALHO' AND d.kind = 'public' "
    " AND NOT EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed') "
    " AND NOT EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id "
    "                 AND (td.review_status = 'allowed' OR td.override_classification = 'TRABALHO'))")


def itens(c, cat: str) -> list[dict]:
    """Conteúdo da lista: entradas gravadas (bloqueio automático / manual) + as da classificação
    (listas dinâmicas). Sem repetir domínio; a entrada gravada prevalece."""
    rows = c.execute("SELECT domain, added_by, added_at FROM category_lists WHERE category=%s", (cat,)).fetchall()
    # domínios dos serviços da categoria (Instagram em Redes sociais...) também fazem parte da lista
    vistos = {r["domain"] for r in rows}
    rows += [r for r in c.execute(
        "SELECT d.domain, 'serviço ' || l.name AS added_by, d.added_at FROM allow_list_domains d "
        "JOIN allow_lists l ON l.slug = d.list_slug WHERE l.category = %s", (cat,)).fetchall() if r["domain"] not in vistos]
    if cat in CATEGORIAS_DINAMICAS:
        vistos = {r["domain"] for r in rows}
        rows += [r for r in c.execute(DINAMICA_SQL, {"cat": cat}).fetchall() if r["domain"] not in vistos]
    return rows


def dominios(c, cat: str) -> list[str]:
    return sorted({r["domain"] for r in itens(c, cat)})


def sugestoes(c, cat: str, limite: int = 500) -> list[dict]:
    """O que a IA sugere p/ a lista curada e ainda não está nela (revisão manual)."""
    if cat not in CATEGORIAS_CURADAS:
        return []
    return c.execute(
        "SELECT x.domain, x.added_at AS analyzed_at, d.total_queries, d.corp_reason FROM (" + DINAMICA_SQL + ") x "
        "JOIN domains d ON d.name = x.domain WHERE NOT EXISTS (SELECT 1 FROM category_lists l "
        "WHERE l.category = %(cat)s AND l.domain = x.domain) ORDER BY d.total_queries DESC LIMIT %(lim)s",
        {"cat": cat, "lim": limite}).fetchall()

# candidatos: recomendação BLOQUEAR, ninguém decidiu, nenhuma empresa ajustou p/ TRABALHO
CANDIDATOS_SQL = (
    "SELECT d.id, d.name, d.category, d.classification, d.corp_reason FROM domains d "
    "WHERE d.category = ANY(%(cats)s) AND d.corp_action = 'BLOQUEAR' AND d.kind = 'public' AND NOT d.locked "
    " AND d.classification IN ('NAO_TRABALHO', 'SUSPEITO', 'MALICIOSO') AND NOT dominio_decidido(d.id) "
    " AND NOT EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id "
    "                 AND td.override_classification = 'TRABALHO') "
    "ORDER BY d.total_queries DESC LIMIT %(lim)s")


def categorias_auto() -> list[str]:
    return [c for c in settings().auto_block_categories if c in CATEGORIAS_RISCO]


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
