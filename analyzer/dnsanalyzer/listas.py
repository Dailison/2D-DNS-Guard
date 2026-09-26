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
# bloqueio automático RÁPIDO pela categoria da classificação principal (sem esperar a etapa "lista")
CATEGORIAS_RISCO = ("jogos", "apostas", "adulto", "vpn_proxy", "ameaca")
# nova organização (pedido do usuário 2026-09-26): a IA põe o site em QUALQUER destas listas quando tem
# certeza (etapa "lista", listas_ia.py); sem certeza, vai p/ Para revisar com a sugestão
CATEGORIAS_CURADAS = ("doh_dns", "redes_sociais", "streaming", "mensageiros", "publicidade", "compras", "noticias",
                      "pirataria", "ia_chatbots", "nuvem_remoto")
CATEGORIAS_DINAMICAS = ()   # (listas montadas pela classificação: desligado)
# Sistema = só manual. infra_bloqueio ("Infraestrutura"): NÃO é a categoria "infraestrutura" da IA (serviços
# de trabalho); outros_bloqueios ("Outros"); para_revisar: dúvidas da IA + sobras da migração, ninguém aplica
CATEGORIAS_MANUAIS = ("infra_bloqueio", "outros_bloqueios", "para_revisar")
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


# ------------------------------------------------------------------ detalhes p/ o console
# O que a IA achou de cada domínio + se alguém já revisou à mão. "manual" = classificação travada,
# decisão (global ou de empresa), ajuste de empresa ou entrada posta na lista por um operador.
_ORIGEM_NAO_MANUAL = (AUTO_BY, "IA automática", "IA com dúvida", "IA sem certeza", "migração", "serviço ", "catálogo", "classificação da IA")
DETALHE_SQL = (
    "SELECT d.name AS domain, d.classification, d.category AS cat_ia, d.corp_action, d.corp_reason, "
    " d.classified_by, d.analyzed_at, d.llm_pending, d.confidence, d.total_queries, d.last_seen, d.locked, "
    " d.lista_ia, d.lista_conf, d.lista_motivo, d.lista_servico, d.lista_fonte, d.lista_at, "
    " g.status AS g_status, g.reviewed_by AS g_by, g.reviewed_at AS g_at, "
    " t.n_decisoes, t.n_ajustes, t.ult_status, t.ult_por, t.ult_em "
    "FROM domains d LEFT JOIN global_reviews g ON g.domain_id = d.id "
    "LEFT JOIN (SELECT td.domain_id, count(*) FILTER (WHERE td.review_status IS NOT NULL) AS n_decisoes, "
    "   count(*) FILTER (WHERE td.override_classification IS NOT NULL) AS n_ajustes, "
    "   (array_agg(td.review_status ORDER BY td.reviewed_at DESC NULLS LAST))[1] AS ult_status, "
    "   (array_agg(td.reviewed_by ORDER BY td.reviewed_at DESC NULLS LAST))[1] AS ult_por, "
    "   max(td.reviewed_at) AS ult_em "
    "  FROM tenant_domains td WHERE td.review_status IS NOT NULL OR td.override_classification IS NOT NULL "
    "  GROUP BY td.domain_id) t ON t.domain_id = d.id "
    "WHERE ")


def _revisao(r: dict, added_by: str | None = None) -> str:
    if not r.get("classification") or r.get("llm_pending"):
        return "pendente"
    manual_lista = bool(added_by) and not any(added_by.startswith(p) for p in _ORIGEM_NAO_MANUAL)
    global_manual = bool(r.get("g_status")) and not (r.get("g_by") or "").startswith((AUTO_BY, "IA automática"))
    if r.get("locked") or r.get("classified_by") == "manual" or global_manual or r.get("n_decisoes") \
            or r.get("n_ajustes") or manual_lista:
        return "manual"
    return "ia"


def _detalhar(c, rows: list[dict]) -> list[dict]:
    """Junta a cada {domain, added_by?, added_at?} os dados da IA e das revisões."""
    info = {r["domain"]: r for r in c.execute(DETALHE_SQL + "d.name = ANY(%s)", ([x["domain"] for x in rows],)).fetchall()}
    out = []
    for x in rows:
        r = {**info.get(x["domain"], {}), **x}
        r["revisao"] = _revisao(r, x.get("added_by"))
        out.append(r)
    return out


def _sugestao(r: dict) -> str:
    """Lista sugerida pela etapa "lista" ('_nenhuma' = a IA disse que não é de lista; '_sem' = ainda não viu)."""
    if r.get("lista_ia"):
        return r["lista_ia"]
    return "_nenhuma" if r.get("lista_at") and r.get("lista_fonte") != "falhou" else "_sem"


_CAMPO = {"classificacao": lambda r: r.get("classification") or "_sem",
          "cat_ia": lambda r: r.get("cat_ia") or "_sem", "revisao": lambda r: r["revisao"], "sugestao": _sugestao,
          "recomendacao": lambda r: r.get("corp_action") or "_sem"}


def _facetar(rows: list[dict]) -> dict:
    fac: dict = {k: {} for k in _CAMPO}
    for r in rows:
        for k, f in _CAMPO.items():
            v = f(r)
            fac[k][v] = fac[k].get(v, 0) + 1
    return fac


def _filtrar_paginar(rows: list[dict], q=None, cls=None, cat_ia=None, revisao=None, sug=None, rec=None, ordem="recentes",
                     offset=0, limit=100) -> dict:
    """Facetas contadas com os OUTROS filtros aplicados (cada filtro mostra o que sobra nele)."""
    q = (q or "").strip().lower()
    filtros = {"classificacao": cls, "cat_ia": cat_ia, "revisao": revisao, "sugestao": sug, "recomendacao": rec}
    campo = _CAMPO

    def passa(r, exceto=None):
        if q and q not in r["domain"]:
            return False
        return all(not v or k == exceto or campo[k](r) == v for k, v in filtros.items())

    fac = {k: _facetar([r for r in rows if passa(r, k)])[k] for k in filtros}
    sel = [r for r in rows if passa(r)]
    chave = {"consultas": lambda r: -(r.get("total_queries") or 0),
             "nome": lambda r: r["domain"],
             "recentes": lambda r: -((r.get("added_at") or r.get("analyzed_at")).timestamp()
                                     if (r.get("added_at") or r.get("analyzed_at")) else 0)}.get(ordem)
    sel.sort(key=chave or (lambda r: -(r.get("total_queries") or 0)))
    return {"total": len(sel), "total_geral": len(rows), "items": sel[offset:offset + limit], "facetas": fac}


def _empresas(c, nomes: list[str]) -> dict[str, list[dict]]:
    """{domínio: [{id, name}]} das empresas que acessaram (mais consultas primeiro)."""
    out: dict[str, list[dict]] = {}
    for r in c.execute("SELECT d.name AS dom, t.id, t.name FROM tenant_domains td JOIN domains d ON d.id = td.domain_id "
                       "JOIN tenants t ON t.id = td.tenant_id WHERE d.name = ANY(%s) ORDER BY td.total_queries DESC", (nomes,)):
        out.setdefault(r["dom"], []).append({"id": r["id"], "name": r["name"]})
    return out


def detalhes(c, cat: str, tid: int | None = None, **filtros) -> dict:
    """Itens de uma lista de bloqueio com a classificação da IA, o estado da revisão manual e as
    empresas que acessaram (tid = só os acessados por aquela empresa)."""
    rows = c.execute("SELECT domain, added_by, added_at FROM category_lists WHERE category=%s", (cat,)).fetchall()
    emp = _empresas(c, [r["domain"] for r in rows])
    if tid:
        rows = [r for r in rows if any(e["id"] == tid for e in emp.get(r["domain"], []))]
    rows = _detalhar(c, rows)
    for r in rows:
        r["empresas"] = emp.get(r["domain"], [])
    return _filtrar_paginar(rows, **filtros)


def _em_lista(nome: str, conjunto: set[str]) -> bool:
    p = nome.split(".")
    return any(".".join(p[i:]) in conjunto for i in range(len(p) - 1))


def sem_lista(c, **filtros) -> dict:
    """Domínios já analisados que não estão em NENHUMA lista (bloqueio ou liberação, nem por domínio
    pai). Não vão p/ o Technitium: só p/ consulta, pedir nova análise ou pôr numa lista."""
    em = {r["domain"] for r in c.execute("SELECT domain FROM category_lists UNION SELECT domain FROM allow_list_domains")}
    rows = [r for r in c.execute(DETALHE_SQL + "d.kind = 'public' AND d.classification IS NOT NULL AND NOT d.llm_pending")
            if not _em_lista(r["domain"], em)]
    for r in rows:
        r["revisao"] = _revisao(r)
    return _filtrar_paginar(rows, **filtros)
