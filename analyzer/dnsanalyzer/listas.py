"""Listas de bloqueio por categoria + bloqueio automático.

Cada categoria de baixo risco de impacto (jogos, apostas, adulto, VPN/proxy, ameaça) tem uma
lista publicada em /listas/<categoria>.txt, que as políticas do Technitium ASSINAM
(blockListUrls). O analisador não grava no Technitium: o bloqueio automático só coloca o site
na lista da categoria e registra a decisão global "bloqueio automático (<categoria>)" — o
Technitium baixa a lista de novo no próximo intervalo de atualização.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .config import settings

log = logging.getLogger(__name__)
# bloqueio automático RÁPIDO pela categoria da classificação principal (sem esperar a etapa "lista")
CATEGORIAS_RISCO = ("jogos", "apostas", "adulto", "vpn_proxy", "ameaca")
# nova organização (pedido do usuário 2026-09-26): a IA põe o site em QUALQUER destas listas quando tem
# certeza (etapa "lista", listas_ia.py); sem certeza, vai p/ Para revisar com a sugestão
CATEGORIAS_CURADAS = ("doh_dns", "adware", "redes_sociais", "streaming", "mensageiros", "cripto_trading", "publicidade",
                      "compras", "noticias", "pirataria", "ia_chatbots", "nuvem_remoto",
                      "nao_identificado")   # (27/09) não identificado depois das 4 fases: bloqueável, nunca whitelist
CATEGORIAS_DINAMICAS = ()   # (listas montadas pela classificação: desligado)
# Sistema = só manual. infra_bloqueio ("Infraestrutura"): NÃO é a categoria "infraestrutura" da IA (serviços
# de trabalho); outros_bloqueios ("Outros"); para_revisar: dúvidas da IA + sobras da migração, ninguém aplica
CATEGORIAS_MANUAIS = ("infra_bloqueio", "outros_bloqueios", "para_revisar")
# (30/09, pedido do usuário) Blacklist: infraestrutura de terceiros (bucket S3, CloudFront, Cloud Run, Azure…) que ia p/ a
# whitelist do catálogo, mas aparece em lista de ameaça, no VirusTotal ou com veredito malicioso no URLScan. Nem a IA
# nem pessoa põem aqui na mão: só a verificação (listas_ia.lista_do_catalogo)
BLACKLIST = "blacklist"
# DNS Inativo (01/10): domínio que não resolve (dnsativo.py) — teste de DNS na etapa 1, sem IA
DNS_INATIVO = "dns_inativo"
CATEGORIAS_VERIFICACAO = (BLACKLIST, DNS_INATIVO)
CATEGORIAS = CATEGORIAS_RISCO + CATEGORIAS_CURADAS + CATEGORIAS_VERIFICACAO + CATEGORIAS_MANUAIS
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


def sufixo_publico(nome: str) -> bool:
    """O nome é um sufixo público de registro (com.br, gov.br, co.uk, br): numa lista de bloqueio valeria p/ TODOS os
    sites sob ele. (07/10: a regra DNS Inativo pôs com.br na lista — o nome "com.br" não resolve mesmo —, todo *.com.br
    ficou bloqueado por meia hora e a trava da whitelist apagou 2.308 domínios .com.br.)"""
    from .features import is_icann_suffix
    return is_icann_suffix(nome)


def itens(c, cat: str) -> list[dict]:
    """Conteúdo da lista: entradas gravadas (bloqueio automático / manual) + as da classificação
    (listas dinâmicas). Sem repetir domínio; a entrada gravada prevalece.
    Sufixo público nunca sai daqui (rede de segurança: é o que vai p/ o DNS e p/ o índice do console), venha de onde vier."""
    rows = c.execute("SELECT domain, added_by, added_at FROM category_lists WHERE category=%s", (cat,)).fetchall()
    ruins = [r["domain"] for r in rows if sufixo_publico(r["domain"])]
    if ruins:
        log.error("lista %s tem sufixo público (%s): ignorado na publicação — tire da lista", cat, ", ".join(ruins[:5]))
        rows = [r for r in rows if r["domain"] not in set(ruins)]
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
    "SELECT d.id, d.name, d.category, d.classification, d.corp_reason, d.popularity_rank, d.lista_fonte, d.lista_ia, "
    " d.lista_conf, d.lista_duvida FROM domains d "
    "WHERE d.category = ANY(%(cats)s) AND d.corp_action = 'BLOQUEAR' AND d.kind = 'public' AND NOT d.locked "
    " AND d.classification IN ('NAO_TRABALHO', 'SUSPEITO', 'MALICIOSO') AND NOT dominio_decidido(d.id) "
    " AND NOT EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id "
    "                 AND td.override_classification = 'TRABALHO') "
    "ORDER BY d.total_queries DESC LIMIT %(lim)s")


def categorias_auto() -> list[str]:
    return [c for c in settings().auto_block_categories if c in CATEGORIAS_RISCO]


def contexto(c, por: str | None, motivo: str | None = None) -> None:
    """Quem e por quê das próximas gravações em category_lists nesta transação (auditoria: list_audit,
    gatilho da migração 035)."""
    c.execute("SELECT set_config('dnsguard.por', %s, true), set_config('dnsguard.motivo', %s, true)",
              ((por or "")[:120], (motivo or "")[:300]))


def expirar_ameacas(c, dias: int = 7) -> list[dict]:
    """Bloqueio automático em Ameaças (bloqueio automático / IA automática) expira quando o domínio saiu dos
    feeds de ameaça há mais de `dias` dias: sai da lista, a decisão automática é desfeita e o domínio volta a
    ser analisado. Entradas postas por pessoa não expiram."""
    from . import eventos
    rows = c.execute(
        "SELECT l.domain, l.added_by, d.id, d.ti_cleared_at FROM category_lists l JOIN domains d ON d.name = l.domain "
        "WHERE l.category = 'ameaca' AND (l.added_by LIKE 'bloqueio automático%%' OR l.added_by LIKE 'IA automática%%') "
        " AND coalesce(d.ti_signature, '') = '' AND d.ti_cleared_at < now() - make_interval(days => %s)", (dias,)).fetchall()
    for r in rows:
        n = (datetime.now(timezone.utc) - r["ti_cleared_at"]).days
        contexto(c, "expiração de ameaça", f"saiu dos feeds de ameaça há {n} dias")
        c.execute("DELETE FROM category_lists WHERE category = 'ameaca' AND domain = %s", (r["domain"],))
        c.execute("DELETE FROM global_reviews WHERE domain_id = %s AND reviewed_by = %s", (r["id"], r["added_by"]))
        c.execute("UPDATE domains SET needs_analysis = true, lista_aplicada_at = NULL WHERE id = %s", (r["id"],))
        eventos.lista("lista_rem", r["domain"], "ameaca", f"saiu dos feeds de ameaça há {n} dias", r["id"], "regras")
    if rows:
        log.info("ameaças expiradas (fora dos feeds há > %d dias): %s", dias, ", ".join(r["domain"] for r in rows))
    return rows


NAO_RESOLVE_SQL = (   # pelo log do Technitium: ≥ 95% NXDOMAIN, ou ≥ 95% das consultas A sem IP (NoError vazio/SERVFAIL)
    "SELECT domain_id FROM query_agg WHERE bucket >= now() - interval '7 days' GROUP BY domain_id "
    "HAVING (sum(queries) >= 3 AND sum(nxdomain) >= 0.95 * sum(queries)) OR (sum(ip_q) >= 3 AND sum(sem_ip) >= 0.95 * sum(ip_q))")


def sem_resposta(c, nomes: list[str], motivo: str) -> None:
    """Não resolve no DNS: fora da IA e da Decisão Humana; entra na whitelist "Sem resposta" (Domínios liberados; não
    publicada) — a menos que esteja numa lista de bloqueio (fica bloqueado)."""
    from . import eventos, whitelist
    if not nomes:
        return
    contexto(c, "regras (DNS)", motivo)
    c.execute("DELETE FROM category_lists WHERE category = 'para_revisar' AND domain = ANY(%s)", (nomes,))
    entrou = [r["domain"] for r in c.execute(
        "INSERT INTO whitelist_domains (category, domain, added_by, publicar) SELECT %s, n, 'regras (DNS)', false "
        "FROM unnest(%s::text[]) n WHERE NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = n) "
        "ON CONFLICT DO NOTHING RETURNING domain", (whitelist.SEM_RESPOSTA, nomes))]
    c.execute("UPDATE domains SET lista_wl = %s, revisado_at = now() WHERE name = ANY(%s)", (whitelist.SEM_RESPOSTA, entrou))
    for n in entrou[:50]:
        eventos.lista("aprovado", n, "wl:" + whitelist.SEM_RESPOSTA, motivo, origem="regras")


def marcar_inexistentes(c) -> dict:
    """Domínio que não resolve (7 dias, ≥ 3 consultas: ≥ 95% NXDOMAIN, ou ≥ 95% das consultas A sem IP — NoError
    vazio, SERVFAIL; erro de digitação, site desativado) e que o teste ativo confirma (dnsativo: DNS público, sem MX):
    kind = 'inexistente' — sai da fila da IA e vai p/ a lista de bloqueio DNS Inativo. Em feed de ameaça fica no fluxo
    (DGA de malware também não resolve; tem o alerta dga_burst). Voltou a resolver (último dia com ≥ 3 respostas com
    IP) -> fase 1 de novo, onde o teste de DNS o tira da lista."""
    from . import dnsativo, eventos, whitelist
    # (01/10) destino único: os candidatos dos logs passam pelo teste ativo (DNS público + MX) e, confirmados, vão p/ a
    # lista de bloqueio DNS Inativo — antes iam, só pelos logs, p/ a whitelist "Sem resposta"
    novos = [{"name": n} for n in dnsativo.dos_logs(c)]
    if novos:
        eventos.registrar("decisao", None, detail="|" + f"{len(novos)} domínio(s) que não resolvem no DNS: lista DNS Inativo: "
                          + ", ".join(r["name"] for r in novos[:15]) + (" …" if len(novos) > 15 else ""), origem="regras")
    voltaram = c.execute(
        "UPDATE domains d SET kind = 'public', needs_analysis = true, revisado_at = NULL, lista_wl = NULL, "
        " reanalise_pedida = dominio_decidido(d.id) WHERE d.kind = 'inexistente' AND d.id IN ("
        " SELECT domain_id FROM query_agg WHERE bucket >= now() - interval '1 day' GROUP BY domain_id "
        " HAVING sum(ip_q) - sum(sem_ip) >= 3 AND sum(nxdomain) < 0.5 * sum(queries)) RETURNING d.name").fetchall()
    if voltaram:
        contexto(c, "regras (DNS)", "voltou a resolver: volta à fase 1")
        c.execute("DELETE FROM whitelist_domains WHERE category = %s AND domain = ANY(%s)",
                  (whitelist.SEM_RESPOSTA, [r["name"] for r in voltaram]))
    if novos or voltaram:
        log.info("não resolvem: %d marcados, %d voltaram a resolver", len(novos), len(voltaram))
    return {"inexistentes": [r["name"] for r in novos], "voltaram": [r["name"] for r in voltaram]}


def candidatos(c, cats: list[str] | None = None, limite: int = 300) -> list[dict]:
    cats = cats if cats is not None else categorias_auto()
    return c.execute(CANDIDATOS_SQL, {"cats": cats, "lim": limite}).fetchall() if cats else []


def bloquear_auto(c, limite: int = 500) -> list[dict]:
    """Coloca os candidatos na lista da categoria e grava a decisão global (sai da fila). Com as travas
    de listas_ia.guardado (protegido/trabalho/popular -> Decisões) e, com a IA online ligada, só depois
    de ela confirmar a mesma lista (senão entra na fila da fase 4 e espera)."""
    from . import eventos, listas_ia, online
    online_ok = online.habilitado()
    feitos = []
    for r in candidatos(c, limite=limite):
        por = f"{AUTO_BY} ({r['category']})"
        motivo = listas_ia.guardado(r, r["category"])
        contexto(c, por, motivo or "recomendação da IA: bloquear")
        if motivo:   # trava: não bloqueia sozinho (sem fase 5: o site segue pelas fases da IA, que decidem)
            continue
        if online_ok and not ((r["lista_fonte"] or "").startswith("online") and r["lista_ia"] == r["category"]
                              and (r["lista_conf"] or 0) >= settings().online_confianca_min):
            if not r["lista_duvida"]:   # a IA online confirma antes (fase 4); até lá, não bloqueia
                c.execute("UPDATE domains SET lista_duvida = true WHERE id = %s", (r["id"],))
            continue
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) "
                  "ON CONFLICT DO NOTHING", (r["category"], r["name"], por))
        c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', %s) "
                  "ON CONFLICT (domain_id) DO NOTHING", (r["id"], por))
        feitos.append(r)
        eventos.lista("lista_add", r["name"], r["category"], "bloqueio automático (recomendação da IA: bloquear)", r["id"], "auto",
                      r["classification"])
    if feitos:
        log.info("bloqueio automático: %d site(s) nas listas por categoria: %s", len(feitos),
                 ", ".join(f"{r['name']} ({r['category']})" for r in feitos[:20]))
    return feitos


# ------------------------------------------------------------------ detalhes p/ o console
# O que a IA achou de cada domínio + se alguém já revisou à mão. "manual" = classificação travada,
# decisão (global ou de empresa), ajuste de empresa ou entrada posta na lista por um operador.
_ORIGEM_NAO_MANUAL = (AUTO_BY, "IA automática", "IA com dúvida", "IA recomenda", "IA sem certeza", "migração", "serviço ", "catálogo", "classificação da IA")
DETALHE_SQL = (
    "SELECT d.name AS domain, d.classification, d.category AS cat_ia, d.corp_action, d.corp_reason, "
    " d.classified_by, d.analyzed_at, d.llm_pending, d.confidence, d.total_queries, d.last_seen, d.locked, "
    " d.lista_ia, d.lista_conf, d.lista_motivo, d.lista_servico, d.lista_fonte, d.lista_at, d.online_at, d.lista_duvida, "
    " d.lista_wl, d.lista_fase, d.online_resp->'_meta'->>'model' AS on_modelo, d.online_resp->>'classificacao' AS on_cls, "
    " d.ti_signature, d.ti_cleared_at, "
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
    if r.get("lista_wl"):
        return "wl:" + r["lista_wl"]
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


# fase 5 = a IA online (fase 4) já avaliou depois da última sugestão local e seguiu sem certeza
# (ou barrado por uma trava de listas_ia.guardado: nenhuma IA tira de lá sozinha)
FASE5_SQL = ("SELECT count(*) AS n FROM category_lists l JOIN domains d ON d.name = l.domain "
             "WHERE l.category = 'para_revisar' AND ((d.online_at IS NOT NULL AND NOT d.lista_duvida) "
             " OR l.added_by LIKE '%%trava:%%')")


def _na_fase5(r: dict) -> bool:
    return (bool(r.get("online_at")) and not r.get("lista_duvida")) or "trava:" in (r.get("added_by") or "")


def detalhes(c, cat: str, tid: int | None = None, fase5: bool = False, **filtros) -> dict:
    """Itens de uma lista de bloqueio com a classificação da IA, o estado da revisão manual e as
    empresas que acessaram (tid = só os acessados por aquela empresa)."""
    rows = c.execute("SELECT domain, added_by, added_at FROM category_lists WHERE category=%s", (cat,)).fetchall()
    emp = _empresas(c, [r["domain"] for r in rows])
    if tid:
        rows = [r for r in rows if any(e["id"] == tid for e in emp.get(r["domain"], []))]
    rows = _detalhar(c, rows)
    aguardando = 0
    if fase5:   # Decisões: só o que já passou pela fase 4 (o resto ainda está com a IA)
        antes = len(rows)
        rows = [r for r in rows if _na_fase5(r)]
        aguardando = antes - len(rows)
    for r in rows:
        r["empresas"] = emp.get(r["domain"], [])
    return {**_filtrar_paginar(rows, **filtros), "aguardando_ia": aguardando}


def detalhes_whitelist(c, cat: str, **filtros) -> dict:
    rows = c.execute("SELECT domain, added_by, added_at, publicar FROM whitelist_domains WHERE category=%s", (cat,)).fetchall()
    emp = _empresas(c, [r["domain"] for r in rows])
    rows = _detalhar(c, rows)
    for r in rows:
        r["empresas"] = emp.get(r["domain"], [])
    return _filtrar_paginar(rows, **filtros)


def _em_lista(nome: str, conjunto: set[str]) -> bool:
    p = nome.split(".")
    return any(".".join(p[i:]) in conjunto for i in range(len(p) - 1))


def _fora_das_filas_sql() -> str:
    """Ainda nas filas da IA (fases 2-4 ou a pergunta de lista) não é "Aprovado": só aparece quando termina (27/09: 417
    dos 429 "Aprovados" estavam no meio do caminho)."""
    from . import listas_ia, online
    from .config import settings
    fila4 = online._FILA.replace("(d.online_claimed_at IS NULL OR d.online_claimed_at < now() - interval '10 minutes') AND ", "")
    fase23 = ("(NOT d.llm_pending AND ((d.classification = 'DESCONHECIDO' AND d.classified_by IN ('llm', 'web')) OR "
              + listas_ia.incerta_sql("d") + ") AND (d.whois_at IS NULL OR d.web_search_at IS NULL) "
              "AND (NOT dominio_decidido(d.id) OR d.reanalise_pedida))")
    pergunta = ("(NOT d.locked AND d.classification <> 'DESCONHECIDO' AND (d.lista_at IS NULL OR d.lista_at < d.analyzed_at))"
                if settings().lista_ia_enabled else "false")
    return f"NOT coalesce(({fila4}), false) AND NOT coalesce({fase23}, false) AND NOT coalesce({pergunta}, false)"   # (NULL não exclui)


SEM_DESTINO_BY = "decisão humana (liberado)"


def sem_destino(c) -> dict:
    """Nada fica solto (pedido do usuário 27/09) e sem fase 5. Quem terminou a análise sem nenhuma lista: malicioso ou
    em feed de ameaça -> Ameaças; DESCONHECIDO sem pessoa -> Não identificados; liberado por pessoa -> whitelist (a categoria que a IA sugeriu, ou Outros
    liberados/de trabalho), só na lista (não vai ao DNS); com resposta de lista da IA -> `listas_ia.aplicar` decide de
    novo (a resposta é a última); sem resposta nenhuma -> whitelist pela classificação."""
    from . import eventos, whitelist
    nomes = [x["domain"] for x in sem_lista(c, limit=5000)["items"]]
    out = {"whitelist": [], "ameaca": [], "reaplicar": [], "nao_identificado": []}
    if not nomes:
        return out
    rows = c.execute(
        "SELECT d.id, d.name, d.classification, d.category, d.lista_wl, d.lista_ia, d.lista_at, d.ti_hits, "
        " (d.locked OR EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed') "
        "  OR EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id "
        "             AND (td.review_status = 'allowed' OR td.override_classification = 'TRABALHO'))) AS humano "
        "FROM domains d WHERE d.name = ANY(%s)", (nomes,)).fetchall()
    for r in rows:
        if r["classification"] == "MALICIOSO" or whitelist._sinais(r["ti_hits"])[0]:
            contexto(c, f"{AUTO_BY} (ameaca)", "terminou a análise sem lista: malicioso/feed de ameaça")
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('ameaca', %s, %s) ON CONFLICT DO NOTHING",
                      (r["name"], f"{AUTO_BY} (ameaca)"))
            out["ameaca"].append(r)
        elif not r["humano"] and r["lista_ia"] and r["lista_at"]:
            out["reaplicar"].append(r["id"])
        elif not r["humano"] and r["classification"] == "DESCONHECIDO":   # não identificado não é liberado
            contexto(c, "IA (não identificado)", "terminou a análise sem identificação: Não identificados")
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('nao_identificado', %s, %s) "
                      "ON CONFLICT DO NOTHING", (r["name"], "IA (não identificado)"))
            out["nao_identificado"].append(r)
        else:
            wl = (r["lista_wl"] if r["lista_wl"] in whitelist.CATEGORIAS and r["lista_wl"] != whitelist.SEM_RESPOSTA else
                  whitelist._categoria(r["category"], r["classification"]) if r["classification"] == "TRABALHO" else "outros_liberados")
            por = SEM_DESTINO_BY if r["humano"] else "IA (sem lista)"
            contexto(c, por, f"terminou a análise sem lista: whitelist {whitelist.CATEGORIAS[wl]}")
            c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES (%s, %s, %s, false) "
                      "ON CONFLICT DO NOTHING", (wl, r["name"], por))
            out["whitelist"].append((r, wl, por))
    if out["reaplicar"]:
        c.execute("UPDATE domains SET lista_aplicada_at = NULL WHERE id = ANY(%s)", (out["reaplicar"],))
    if len(rows) <= 50:
        for r, wl, por in out["whitelist"]:
            eventos.lista("aprovado", r["name"], f"wl:{wl}", f"{por}: sem lista depois da análise", r["id"],
                          "f5:ti" if r["humano"] else "regras", r["classification"])
        for r in out["ameaca"]:
            eventos.lista("lista_add", r["name"], "ameaca", "sem lista depois da análise: malicioso/feed de ameaça", r["id"], "regras",
                          r["classification"])
        for r in out["nao_identificado"]:
            eventos.lista("lista_add", r["name"], "nao_identificado", "sem lista e sem identificação depois da análise", r["id"],
                          "regras", r["classification"])
    else:
        eventos.registrar("decisao", None, detail=f"wl|{len(out['whitelist'])} sem lista foram p/ a whitelist, {len(out['ameaca'])} "
                                                  f"p/ Ameaças, {len(out['nao_identificado'])} p/ Não identificados e {len(out['reaplicar'])} voltaram p/ a IA decidir", origem="regras")
    return out


def sem_lista(c, **filtros) -> dict:
    """Domínios já analisados que não estão em NENHUMA lista (bloqueio ou liberação, nem por domínio
    pai) nem numa fila da IA ("Aprovados"). Não vão p/ o Technitium: só p/ consulta, pedir nova análise ou pôr numa lista."""
    em = {r["domain"] for r in c.execute("SELECT domain FROM category_lists UNION SELECT domain FROM allow_list_domains "
                                         "UNION SELECT domain FROM whitelist_domains")}
    rows = [r for r in c.execute(DETALHE_SQL + "d.kind = 'public' AND d.classification IS NOT NULL AND NOT d.llm_pending AND "
                                 + _fora_das_filas_sql())
            if not _em_lista(r["domain"], em)]
    for r in rows:
        r["revisao"] = _revisao(r)
    return _filtrar_paginar(rows, **filtros)
