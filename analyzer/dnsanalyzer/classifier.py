"""Classificação contínua em duas fases.

Fase A (rápida): todos os domínios pendentes recebem classificação por regras
  (TI + catálogo + léxico + popularidade). Ameaças aparecem em segundos.
Fase B (IA, contínua): domínios que precisam de IA (llm_pending) são refinados
  pelo Qwen3, do maior impacto (volume de consultas) para o menor. A IA só roda
  de novo para um domínio se o hash das evidências relevantes mudar.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import httpx
from psycopg.types.json import Jsonb

from . import catalog, db, enrich, listas, listas_ia, online, ti, webintel, whitelist, whois
from .config import settings
from .features import analyze_name
from .llm import LLMBadOutput, LLMUnavailable, OllamaClient
from .policy import Final, combine, rules_only
from .rules import RuleResult, age_days, evaluate

log = logging.getLogger(__name__)


CLASS_LABEL = {"TRABALHO": "Trabalho", "NAO_TRABALHO": "Não trabalho", "SUSPEITO": "Suspeito",
               "MALICIOSO": "Malicioso", "DESCONHECIDO": "Desconhecido"}


def event(kind: str, name: str | None = None, domain_id: int | None = None, classification: str | None = None,
          risk: int | None = None, work: int | None = None, seconds: float | None = None,
          detail: str | None = None) -> None:
    """Registra um evento no feed "IA ao vivo" (conexão própria: visível na hora)."""
    try:
        with db.conn() as c:
            c.execute("INSERT INTO ai_events (kind, domain_id, name, classification, risk, work, seconds, detail) "
                      "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                      (kind, domain_id, name, classification, risk, work, seconds, (detail or "")[:500] or None))
    except Exception as e:  # noqa: BLE001 — o feed nunca pode derrubar a classificação
        log.debug("falha ao gravar evento: %s", e)


def categories(c) -> list[dict]:
    return [dict(r) for r in c.execute("SELECT code, label, description FROM categories ORDER BY sort_order")]


def site_categories(c) -> list[dict]:
    return [dict(r) for r in c.execute("SELECT code, label, description FROM site_categories ORDER BY sort_order")]


def build_dossier(c, drow: dict, with_rdap: bool = False, with_web: bool = False,
                  with_search: bool = False, with_whois: bool = False) -> dict:
    cfg = settings()
    name = drow["name"]
    info = analyze_name(name, cfg.internal_suffixes)
    d = {
        "name": name, "kind": drow["kind"], "tld": drow["tld"] or info.tld,
        "features": drow["features"] or {},
        "private_suffix": info.private_suffix,
        "platform": info.icann_registrable if info.private_suffix else None,
    }
    if drow["kind"] != "public":
        return d

    d["catalog"] = catalog.match(name)
    if not d["catalog"]:
        from . import adlists
        d["catalog"] = adlists.match(c, name)
    ranks = enrich.popularity(c, [name] + ([info.icann_registrable] if info.private_suffix else []))
    d["popularity_rank"] = ranks.get(name)
    if info.private_suffix:
        d["platform_rank"] = ranks.get(info.icann_registrable)

    d["ti_hits"] = ti.hits_for_domain(c, drow["id"])
    d["abused_tld"] = ti.abused_tld(c, d["tld"])

    # identificação por fontes públicas (Wikidata / certificado / página do site).
    # Fase A só lê o cache; a Fase B busca. Site só é aberto sem sinal de ameaça.
    if not d["catalog"]:
        from . import webintel
        d["web"] = webintel.lookup(c, name, fetch=with_web,
                                   allow_site=not d["ti_hits"] and not d["abused_tld"])
        # etapa 2: resultados de busca (só busca na rede quando with_search; senão usa o cache)
        d["search"] = webintel.search(c, name, fetch=with_search)
        # etapa 3: WHOIS do domínio registrável (na rede só com with_whois; senão o cache).
        # Subdomínio de plataforma (x.myshopify.com): o WHOIS seria o da plataforma — não vale.
        if not info.private_suffix:
            d["whois"] = whois.lookup(c, info.icann_registrable, fetch=with_whois)

    reg = drow.get("registered_at")
    if reg is None and with_rdap and not d["catalog"] and not info.private_suffix and \
            (not d["popularity_rank"] or d["popularity_rank"] > cfg.rdap_skip_top_rank):
        reg = enrich.rdap_registered(c, info.icann_registrable)
    d["registered_at"] = reg.isoformat() if reg else None
    d["age_days"] = age_days(reg)

    fs = c.execute(
        "SELECT count(*) AS n, "
        " count(*) FILTER (WHERE (features->>'sub_dga')::float >= 0.6 "
        "                    OR ((features->>'sub_entropy')::float >= 3.6 AND (features->>'sub_max_len')::int >= 12)) AS rnd "
        "FROM fqdns WHERE domain_id=%s", (drow["id"],)).fetchone()
    sample = [r["name"] for r in c.execute(
        "SELECT f.name FROM fqdns f LEFT JOIN query_agg q ON q.fqdn_id=f.id "
        "WHERE f.domain_id=%s GROUP BY f.name ORDER BY sum(q.queries) DESC NULLS LAST LIMIT 8",
        (drow["id"],))]
    d["fqdn_stats"] = {"count": fs["n"], "random_subs": fs["rnd"], "sample": sample}

    lg = c.execute(
        "SELECT COALESCE(sum(total_queries),0) AS q, count(*) AS tenants, COALESCE(sum(clients_count),0) AS clients, "
        " min(first_seen) AS first FROM tenant_domains WHERE domain_id=%s", (drow["id"],)).fetchone()
    nx = c.execute("SELECT COALESCE(sum(nxdomain),0) AS nx, COALESCE(sum(queries),0) AS q "
                   "FROM client_domains WHERE domain_id=%s", (drow["id"],)).fetchone()
    d["logs"] = {
        "total_queries": int(lg["q"]), "tenants": int(lg["tenants"]), "clients": int(lg["clients"]),
        "first_seen_str": lg["first"].strftime("%d/%m/%Y") if lg["first"] else "?",
        # sum() do Postgres volta Decimal: converte para float (JSON)
        "nx_ratio": round(float(nx["nx"]) / float(nx["q"]), 4) if nx["q"] else 0.0,
    }
    return d


def save(c, drow: dict, dossier: dict, rule: RuleResult, fin: Final, pending: bool,
         model: str | None, meta: dict | None = None) -> None:
    ev = [e.as_dict() for e in rule.evidence]
    hits = dossier.get("ti_hits") or []
    reasons = fin.reasons + [{"evidence_id": None, "text": n, "by": "sistema"} for n in fin.notes]
    prev = c.execute("SELECT classification, risk_score, work_score FROM domains WHERE id=%s",
                     (drow["id"],)).fetchone()
    c.execute(
        """UPDATE domains SET classification=%s, risk_score=%s, work_score=%s, confidence=%s, topic=%s,
           category=COALESCE(%s, category),
           corp_action=COALESCE(%s, corp_action), corp_reason=CASE WHEN %s::text IS NULL THEN corp_reason ELSE %s END,
           corp_by=CASE WHEN %s::text IS NULL THEN corp_by ELSE %s END,
           reasons=%s, evidence=%s, recommended_action=%s, classified_by=%s, model=%s, analyzed_at=now(),
           needs_analysis=false, llm_pending=%s, aguarda_recorrencia=false, evidence_hash=%s, ti_hits=%s, ti_signature=%s,
           ti_cleared_at=CASE WHEN %s <> '' THEN NULL WHEN ti_signature <> '' THEN now() ELSE ti_cleared_at END,
           popularity_rank=%s, registered_at=COALESCE(%s::date, registered_at), claimed_at=NULL,
           last_error=NULL, llm_attempts=CASE WHEN %s THEN llm_attempts ELSE 0 END
           WHERE id=%s""",
        (fin.classification, fin.risk, fin.work, fin.confidence, fin.topic, fin.category,
         fin.corp_action, fin.corp_action, fin.corp_reason, fin.corp_action, fin.corp_by, Jsonb(reasons), Jsonb(ev),
         fin.action, fin.classified_by, model, pending, rule.evidence_hash, Jsonb(hits), ti.signature(hits), ti.signature(hits),
         dossier.get("popularity_rank"), dossier.get("registered_at"), pending, drow["id"]))
    changed = prev is None or (prev["classification"], prev["risk_score"], prev["work_score"]) != \
        (fin.classification, fin.risk, fin.work)
    if changed or fin.classified_by == "llm":
        c.execute(
            "INSERT INTO classification_history (domain_id, classification, risk_score, work_score, confidence, "
            "topic, reasons, evidence, source, model, note) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (drow["id"], fin.classification, fin.risk, fin.work, fin.confidence, fin.topic, Jsonb(reasons),
             Jsonb(ev), fin.classified_by, model, "; ".join(fin.notes)[:500] or None))
        if meta:
            log.info("IA %s -> %s risco=%s trabalho=%s (%.1fs)", drow["name"], fin.classification,
                     fin.risk, fin.work, meta.get("seconds") or 0)


def phase_a(limit: int = 2000) -> int:
    """Regras em todos os pendentes. Retorna quantos processou."""
    from collections import Counter
    cfg = settings()
    n = 0
    tally: Counter = Counter()
    alerts: list[tuple] = []
    with db.conn() as c:
        rows = c.execute(
            "SELECT * FROM domains WHERE needs_analysis AND NOT locked "
            "ORDER BY total_queries DESC LIMIT %s FOR UPDATE SKIP LOCKED", (limit,)).fetchall()
        # antes da IA: o log do Technitium diz que o nome não resolve (todas as consultas A sem IP, ou NXDOMAIN)
        nao_resolve = {r["domain_id"] for r in c.execute(
            "SELECT domain_id FROM query_agg WHERE domain_id = ANY(%s) AND bucket >= now() - interval '7 days' "
            "GROUP BY domain_id HAVING (sum(ip_q) >= 1 AND sum(sem_ip) = sum(ip_q)) "
            " OR (sum(queries) >= 1 AND sum(nxdomain) = sum(queries))", ([r["id"] for r in rows],))}
        for drow in rows:
            dossier = build_dossier(c, drow, with_rdap=False)
            rule = evaluate(dossier)
            if drow["id"] in nao_resolve and drow["kind"] == "public" and not dossier.get("ti_hits") \
                    and rule.classification not in ("SUSPEITO", "MALICIOSO"):
                save(c, drow, dossier, rule, rules_only(rule, False), False, None)
                c.execute("UPDATE domains SET kind = 'inexistente', llm_pending = false WHERE id = %s", (drow["id"],))
                listas.sem_resposta(c, [drow["name"]], "não resolve no DNS (log do Technitium): fora da IA")
                tally["não resolve (Sem resposta)"] += 1
                n += 1
                continue
            skip_llm = (not rule.needs_llm) or (cfg.llm_skip_hosting_subdomains and dossier.get("private_suffix"))
            # IA só se for necessária E se as evidências relevantes mudaram desde a última IA
            already = drow["classified_by"] == "llm" and drow["evidence_hash"] == rule.evidence_hash
            hits = dossier.get("ti_hits") or []
            if already:
                c.execute("UPDATE domains SET needs_analysis=false, ti_hits=%s, ti_signature=%s WHERE id=%s",
                          (Jsonb(hits), ti.signature(hits), drow["id"]))
            elif drow["classified_by"] == "llm" and not rule.final and rule.classification != "SUSPEITO" \
                    and cfg.llm_enabled and not skip_llm:
                # evidências mudaram, mas sem risco novo: mantém a classificação da IA e reenfileira
                # (pouco acesso: vai para o fim da fila até o site recorrer)
                raro = _pouco_acesso(cfg, drow, dossier, rule)
                c.execute("UPDATE domains SET needs_analysis=false, llm_pending=true, aguarda_recorrencia=%s, ti_hits=%s, "
                          "ti_signature=%s WHERE id=%s", (raro, Jsonb(hits), ti.signature(hits), drow["id"]))
                if raro:
                    tally["aguarda recorrência"] += 1
            else:
                pending = bool(cfg.llm_enabled and not skip_llm)
                save(c, drow, dossier, rule, rules_only(rule, pending), pending, None)
                if pending and _pouco_acesso(cfg, drow, dossier, rule):
                    # quase ninguém acessou: fica só com as regras até recorrer (a IA vai para o que importa)
                    c.execute("UPDATE domains SET aguarda_recorrencia=true WHERE id=%s", (drow["id"],))
                    tally["aguarda recorrência"] += 1
                else:
                    tally["→ fila da IA" if pending and rule.classification == "DESCONHECIDO"
                          else CLASS_LABEL.get(rule.classification, rule.classification)] += 1
                if rule.classification in ("SUSPEITO", "MALICIOSO"):
                    motivo = next((r["text"] for r in rule.reasons if r.get("evidence_id") != "E0"), "")
                    alerts.append((drow["name"], drow["id"], rule.classification, rule.risk, rule.work, motivo))
            n += 1
    if tally:
        resumo = ", ".join(f"{v} {k}" for k, v in tally.most_common())
        event("rules_batch", detail=f"{sum(tally.values())} domínio(s) avaliados pelas regras: {resumo}")
    for name, did, cls, risk, work, motivo in alerts[:50]:
        event("rules_alert", name, did, cls, risk, work, detail=motivo)
    return n


def _pouco_acesso(cfg, drow: dict, dossier: dict, rule: RuleResult) -> bool:
    """Triagem por acesso: domínio consultado menos de LLM_MIN_QUERIES vezes por menos de LLM_MIN_CLIENTS
    computadores fica só com as regras e vai para o FIM da fila da IA (aguarda_recorrencia): é analisado quando a
    fila ativa esvazia, ou antes se recorrer — a IA local trabalha primeiro no que as pessoas realmente acessam.
    Nunca para risco (feed de ameaça, SUSPEITO/MALICIOSO) nem quando uma pessoa pediu a análise (reanalise_pedida)."""
    if cfg.llm_min_queries <= 0 or drow.get("reanalise_pedida") or drow.get("kind") != "public":
        return False
    if rule.classification in ("SUSPEITO", "MALICIOSO") or dossier.get("ti_hits"):
        return False
    # (as mesmas contagens que `reenfileirar_recorrentes` usa: domains.total_queries e a soma de clients_count)
    lg = dossier.get("logs") or {}
    return (drow.get("total_queries") or 0) < cfg.llm_min_queries and (lg.get("clients") or 0) < cfg.llm_min_clients


def reenfileirar_recorrentes(c) -> int:
    """Domínios do fim da fila (pouco acesso) que voltaram a ser acessados (consultas ou computadores chegaram ao
    mínimo) voltam à fila normal da IA. Retorna quantos."""
    cfg = settings()
    if cfg.llm_min_queries <= 0:
        return 0
    return c.execute(
        "UPDATE domains d SET aguarda_recorrencia = false WHERE aguarda_recorrencia AND NOT locked "
        "AND (total_queries >= %s OR (SELECT coalesce(sum(clients_count), 0) FROM tenant_domains td "
        "                             WHERE td.domain_id = d.id) >= %s)",
        (cfg.llm_min_queries, cfg.llm_min_clients)).rowcount


def _claim_llm(c) -> dict | None:
    return c.execute(
        """UPDATE domains SET claimed_at=now() WHERE id = (
             SELECT id FROM domains WHERE llm_pending AND NOT locked
               AND (NOT dominio_decidido(id) OR reanalise_pedida)   -- decidido: só com revisão pedida
               AND (claimed_at IS NULL OR claimed_at < now() - interval '30 minutes')
             ORDER BY aguarda_recorrencia ASC, (classification IS NOT DISTINCT FROM 'SUSPEITO') DESC, (model IS NULL) DESC,
               total_queries DESC
             LIMIT 1 FOR UPDATE SKIP LOCKED)
           RETURNING *""").fetchone()
    # (27/09) nunca passou pela IA (domínio novo) vai antes do backlog de reanálise; os de pouco acesso
    # (aguarda_recorrencia) ficam por último: só quando a fila ativa esvazia (pedido do usuário: todo site acaba
    # numa lista, sem atrasar o que as pessoas acessam de fato)


def phase_b(client: OllamaClient, cats: list[dict]) -> str:
    """Refina UM domínio com a IA. Retorna 'done' | 'deferred' | 'idle' | 'unavailable' | 'error'."""
    with db.conn() as c:
        drow = _claim_llm(c)
    if not drow:
        return "idle"
    return _refine(client, cats, drow)


def _refine(client: OllamaClient, cats: list[dict], drow: dict, etapa2: bool = False,
            esperar_busca: bool = False, etapa3: bool = False) -> str:
    """Regras + fontes externas + IA para um domínio já reservado (claimed).
    etapa2 = domínio que a IA deixou DESCONHECIDO: busca na web antes de reclassificar.
    esperar_busca = espera a vez da busca na web (1 domínio pedido na mão) em vez de adiar."""
    cfg = settings()
    name, did = drow["name"], drow["id"]
    if etapa2:
        event("search_start", name, did, detail=f"fase 3 · busca na web · {drow['total_queries']} consultas")
    if etapa3:
        event("whois_start", name, did, detail=f"fase 2 · WHOIS/RDAP · {drow['total_queries']} consultas")
    with db.conn() as c:
        try:
            dossier = build_dossier(c, drow, with_rdap=True, with_web=True, with_search=etapa2, with_whois=etapa3)
        except (httpx.HTTPError, webintel.BuscaIndisponivel) as e:   # SearXNG fora/bloqueado: depois
            c.execute("UPDATE domains SET claimed_at=NULL WHERE id=%s", (did,))
            event("search_error", name, did, detail=f"busca indisponível: {e.__class__.__name__}")
            return "unavailable"
        except whois.WhoisIndisponivel as e:   # RDAP/Receita fora ou limitando
            if "registro.br" in str(e) or "brasilapi" in str(e):   # limite/queda do serviço (vale p/ todos): depois
                c.execute("UPDATE domains SET claimed_at=NULL WHERE id=%s", (did,))
                event("whois_error", name, did, detail=f"WHOIS indisponível: {e}")
                return "unavailable"
            tries = (drow.get("whois_tries") or 0) + 1
            if tries >= 3:   # falha sempre p/ este domínio (ex.: RDAP do TLD fora): desiste e segue p/ a fase 3
                c.execute("UPDATE domains SET claimed_at=NULL, whois_tries=%s, whois_at=now() WHERE id=%s", (tries, did))
                event("whois_error", name, did, detail=f"WHOIS indisponível pela {tries}ª vez ({e}); segue sem WHOIS")
                return "done"
            # tenta de novo em ~10 min (claimed_at "vence" em 30 min) e pega outro domínio agora
            c.execute("UPDATE domains SET claimed_at=now() - interval '20 minutes', whois_tries=%s WHERE id=%s", (tries, did))
            event("whois_error", name, did, detail=f"WHOIS indisponível: {e}; tentativa {tries} de 3")
            return "deferred"
        if etapa3:
            c.execute("UPDATE domains SET whois_at=now() WHERE id=%s", (did,))
            if not whois.evidencia(dossier.get("whois")):
                c.execute("UPDATE domains SET claimed_at=NULL, lista_aplicada_at=NULL WHERE id=%s", (did,))
                event("whois_done", name, did, drow["classification"],
                      detail="fase 2: WHOIS sem dados úteis (titular oculto/sem registro) — IA local não reavaliou; segue p/ a fase 3")
                return "done"
        if etapa2:
            c.execute("UPDATE domains SET web_search_at=now() WHERE id=%s", (did,))
            if not dossier.get("search"):
                c.execute("UPDATE domains SET claimed_at=NULL, lista_aplicada_at=NULL WHERE id=%s", (did,))
                event("search_done", name, did, drow["classification"],
                      detail="fase 3: nenhum resultado na web — IA local não reavaliou; segue p/ a fase 4 (IA online)")
                return "done"
        elif cfg.web_search_before_llm and _buscar_antes(dossier):
            # fora do top 1M e sem Wikidata/certificado: a IA sozinha "não reconhece" em ~98%
            # dos casos. Busca ANTES e chama a IA uma vez só (ou nenhuma, se não há nada na web).
            try:
                dossier["search"] = webintel.search(c, name, fetch=True, wait=esperar_busca)
                c.execute("UPDATE domains SET web_search_at=now() WHERE id=%s", (did,))
            except webintel.BuscaOcupada:
                # 1 busca a cada WEB_SEARCH_MIN_INTERVAL p/ todos: em vez de esperar a vez (com o
                # reforço, 8+ workers ficavam minutos parados), adia ~2 min e pega outro domínio.
                # O dossiê (certificado/site) já ficou no cache.
                c.execute("UPDATE domains SET claimed_at = now() - interval '28 minutes' WHERE id=%s", (did,))
                return "deferred"
            except (httpx.HTTPError, webintel.BuscaIndisponivel) as e:
                log.info("busca antes da IA indisponível p/ %s: %s", name, e)   # segue só com a IA
            else:
                if not dossier["search"]:
                    rule0 = evaluate(dossier)
                    if rule0.classification == "DESCONHECIDO":
                        fin = rules_only(rule0, False)
                        fin.classified_by = "web"
                        fin.notes.append("nenhum resultado na busca na web e fora do top 1M: serviço não "
                                         "identificado; IA dispensada")
                        save(c, drow, dossier, rule0, fin, False, None)
                        event("rules_final", name, did, fin.classification, fin.risk, fin.work,
                              detail="sem resultado na busca na web — IA dispensada (economia de ~40 s)")
                        return "done"
        rule = evaluate(dossier)
    if not etapa2 and not etapa3:   # (fases 2 e 3 já anunciaram o início)
        event("llm_start", name, did, detail=f"{drow['total_queries']} consultas · pelas regras: "
                                             f"{CLASS_LABEL.get(drow['classification'], '—')}")
    if rule.final:  # (ex.: RDAP/TI mudou o quadro) regras bastam
        with db.conn() as c:
            save(c, drow, dossier, rule, rules_only(rule, False), False, None)
        event("rules_final", name, did, rule.classification, rule.risk, rule.work,
              detail="resolvido pelas regras (evidência nova); IA não foi necessária")
        if rule.classification != "DESCONHECIDO" and cfg.lista_ia_enabled:   # a lista também faz parte da fase (antes
            try:                                                             # ia p/ uma fila que só andava c/ tudo vazio)
                listas_ia.sugerir(client, did, 2 if etapa3 else 3 if etapa2 else 1)
            except Exception:  # noqa: BLE001 — a fila de listas pega depois
                log.exception("lista da IA para %s", name)
        return "done"
    ev = [e.as_dict() for e in rule.evidence]
    with db.conn() as c:
        scats = site_categories(c)
    try:
        res, meta = client.classify(name, ev, cats, scats)
    except LLMUnavailable as e:
        with db.conn() as c:
            c.execute("UPDATE domains SET claimed_at=NULL WHERE id=%s", (did,))
        log.warning("IA indisponível: %s", e)
        event("llm_unavailable", name, did, detail=str(e)[:200])
        return "unavailable"
    except (LLMBadOutput, Exception) as e:  # noqa: BLE001
        with db.conn() as c:
            att = drow["llm_attempts"] + 1
            give_up = att >= cfg.llm_max_attempts
            c.execute("UPDATE domains SET claimed_at=NULL, llm_attempts=%s, last_error=%s, "
                      "llm_pending=%s WHERE id=%s", (att, str(e)[:500], not give_up, did))
        log.error("IA falhou em %s (tentativa %d): %s", name, drow["llm_attempts"] + 1, e)
        event("llm_error", name, did, detail=f"tentativa {drow['llm_attempts'] + 1}: {str(e)[:180]}")
        return "error"
    fin = combine(rule, res, ev)
    with db.conn() as c:
        save(c, drow, dossier, rule, fin, False, meta["model"], meta)
    if fin.classification != "DESCONHECIDO":   # a lista faz parte da fase (antes era uma fila separada, "Listas")
        try:
            listas_ia.sugerir(client, did, 2 if etapa3 else 3 if etapa2 else 1)
        except Exception:  # noqa: BLE001 — a fila de listas pega depois
            log.exception("lista da IA para %s", name)
    svc = (res.service or "").strip() if res.recognized else "não reconhecido pela IA"
    extra = "; ".join(fin.notes)
    scat = next((s["label"] for s in scats if s["code"] == fin.category), fin.category or "")
    event("whois_done" if etapa3 else "search_done" if etapa2 else "llm_done", name, did, fin.classification, fin.risk, fin.work,
          meta.get("seconds"),
          detail=" · ".join(x for x in (("fase 2 (WHOIS)" if etapa3 else "fase 3 (busca na web)" if etapa2 else
                                         f"com busca na web ({len(dossier['search'])} resultados)"
                                         if dossier.get("search") else ""),
                                        "reforço (GPU)" if meta.get("extra") else "", svc, scat,
                                        _achado(dossier, etapa2, etapa3), _razao(fin), extra) if x))
    return "done"


def _achado(dossier: dict, etapa2: bool, etapa3: bool) -> str:
    """O que a fase 2 (WHOIS) / 3 (busca na web) trouxe para a IA local avaliar (p/ o log)."""
    if etapa3:
        ev = whois.evidencia(dossier.get("whois"))
        return ("WHOIS: " + ev[0][:200]) if ev else ""
    if etapa2 and dossier.get("search"):
        res = dossier["search"]
        tops = "; ".join(f"{r.get('host')}: {r.get('title')}" for r in res[:2] if r.get("title"))
        return f"busca: {len(res)} resultado(s)" + (f" — {tops[:200]}" if tops else "")
    return ""


def _razao(fin) -> str:
    """Principal razão da IA local (p/ o log)."""
    r = next((x.get("text") for x in fin.reasons if x.get("by") != "sistema" and x.get("text")), "")
    return ("IA local: " + r[:160]) if r else ""


def _buscar_antes(d: dict) -> bool:
    """Etapa 1: buscar na web antes da IA? Só p/ o que a IA não teria como reconhecer."""
    if not settings().web_search_url or d.get("kind") != "public" or d.get("popularity_rank"):
        return False
    web = d.get("web") or {}
    cert = web.get("cert") or {}
    ident = bool((web.get("wikidata") or {}).get("label")) or bool(
        cert.get("verified") and (cert.get("org") or cert.get("san_domains")))
    return not ident and not d.get("catalog") and not d.get("private_suffix")


# decidido não volta à IA sozinho; "Reanalisar" (reanalise_pedida) o leva pelas fases de novo
DECIDIDO_FORA = "(NOT dominio_decidido(id) OR reanalise_pedida)"


def _claim_etapa2(c) -> dict | None:
    """Fase 3: próximo DESCONHECIDO p/ busca na web — DEPOIS do WHOIS (fase 2; a busca aproveita o WHOIS do
    cache). Em paralelo com a fase 1 (pedido do usuário 27/09: fases 1-4 não esperam a fila da fase 1)."""
    return c.execute(
        """UPDATE domains SET claimed_at=now() WHERE id = (
             SELECT id FROM domains WHERE ((classification = 'DESCONHECIDO' AND classified_by = 'llm') OR """
        + listas_ia.incerta_sql() + """)
               AND web_search_at IS NULL AND NOT llm_pending AND NOT locked AND kind = 'public'
               AND (whois_at IS NOT NULL OR NOT %(whois)s)
               AND (NOT dominio_decidido(id) OR reanalise_pedida)
               AND (claimed_at IS NULL OR claimed_at < now() - interval '30 minutes')
             ORDER BY total_queries DESC LIMIT 1 FOR UPDATE SKIP LOCKED)
           RETURNING *""", {"whois": settings().whois_enabled}).fetchone()


def phase_c(client: OllamaClient, cats: list[dict]) -> str:
    """Etapa 2: busca na web + IA para UM desconhecido. 'done' | 'idle' | 'unavailable' | 'error'."""
    if not settings().web_search_url:
        return "idle"
    with db.conn() as c:
        drow = _claim_etapa2(c)
    if not drow:
        return "idle"
    return _refine(client, cats, drow, etapa2=True)


def _claim_etapa3(c) -> dict | None:
    """Fase 2: próximo DESCONHECIDO p/ WHOIS (antes da busca na web), em paralelo com a fase 1.
    .br primeiro (titular com CNPJ no registro.br identifica a empresa)."""
    return c.execute(
        """UPDATE domains SET claimed_at=now() WHERE id = (
             SELECT id FROM domains WHERE ((classification = 'DESCONHECIDO' AND classified_by IN ('llm', 'web')) OR """
        + listas_ia.incerta_sql() + """)
               AND whois_at IS NULL AND NOT llm_pending AND NOT locked AND kind = 'public'
               AND (NOT dominio_decidido(id) OR reanalise_pedida)
               AND (claimed_at IS NULL OR claimed_at < now() - interval '30 minutes')
             ORDER BY (name LIKE '%.br') DESC, total_queries DESC LIMIT 1 FOR UPDATE SKIP LOCKED)
           RETURNING *""").fetchone()


def _workers_reforco(cfg, url: str) -> int:
    return cfg.llm_extra_workers_url.get(url, cfg.llm_extra_workers)


class _Reforco:
    """Escolhe o cliente da IA das fases 2/3 e da pergunta de lista: um reforço com GPU que responde (checado a cada
    60 s), em rodízio entre os de OLLAMA_ETAPAS_URLS (vazio = todos); nenhum deles no ar: outro reforço; nenhum: a VM.
    (27/09: em rodízio com o PC, que enfileira ~30 s por pedido, os 3 workers das fases 2/3 ficavam presos nele.)"""

    def __init__(self, vm: OllamaClient):
        cfg = settings()
        self.vm, self.ok, self.vez = vm, {}, 0
        todos = [OllamaClient(u) for u in cfg.ollama_extra_urls]
        pref = set(cfg.ollama_etapas_urls)
        self.extras = [x for x in todos if not pref or x.url in pref] or todos
        self.reserva = [x for x in todos if x not in self.extras]

    def _no_ar(self, x: OllamaClient) -> bool:
        t, ok = self.ok.get(x.url, (0.0, False))
        if time.monotonic() - t > 60:
            ok = x.available()[0]
            self.ok[x.url] = (time.monotonic(), ok)
        return ok

    def cliente(self) -> OllamaClient:
        for i in range(len(self.extras)):
            x = self.extras[(self.vez + i) % len(self.extras)]
            if self._no_ar(x):
                self.vez = (self.vez + i + 1) % len(self.extras)
                return x
        return next((x for x in self.reserva if self._no_ar(x)), self.vm)


def _whois_worker(stop, cats: list[dict], reforco: "_Reforco", wid: int) -> None:
    """Fase 2 em paralelo com as outras: WHOIS/RDAP (+ CNPJ) + IA, no reforço com GPU se no ar."""
    _fase_worker(stop, lambda: phase_d(reforco.cliente(), cats), f"worker {wid} do WHOIS")


def _busca_worker(stop, cats: list[dict], reforco: "_Reforco") -> None:
    """Fase 3 em paralelo com as outras: busca na web + IA (a busca tem 1 vaga a cada WEB_SEARCH_MIN_INTERVAL
    p/ todos). Sem fila: lista dos classificados pelo catálogo/regras (senão só andaria com a fase 1 vazia)."""
    def passo():
        st = phase_c(reforco.cliente(), cats)
        return listas_ia.fase(reforco.cliente()) if st == "idle" else st
    _fase_worker(stop, passo, "worker da busca na web")


def _fase_worker(stop, passo, nome: str) -> None:
    backoff = 0
    while not stop():
        try:
            st = passo()
            if st == "idle":
                time.sleep(30)
            elif st == "unavailable":
                backoff = min(backoff + 30, 300)
                time.sleep(backoff)
            else:
                backoff = 0
        except Exception:  # noqa: BLE001
            log.exception("erro no %s", nome)
            time.sleep(30)


def _online_worker(stop) -> None:
    """Fase 4: IA online (Gemini/Gemma) — ONLINE_WORKERS em paralelo; a cota (RPM/RPD) é por modelo."""
    while not stop():
        try:
            with db.conn() as c:
                scats = [r["code"] for r in site_categories(c)]
            st = online.fase(scats)
            if st != "done":
                time.sleep(60)
        except Exception:  # noqa: BLE001
            log.exception("erro na fase 3 (IA online)")
            time.sleep(60)


def phase_d(client: OllamaClient, cats: list[dict]) -> str:
    """Etapa 3: WHOIS/RDAP (+ CNPJ) + IA para UM desconhecido (com a fila da IA vazia)."""
    if not settings().whois_enabled:
        return "idle"
    with db.conn() as c:
        drow = _claim_etapa3(c)
    if not drow:
        return "idle"
    return _refine(client, cats, drow, etapa3=True)


def classify_one(name: str) -> str:
    """Classifica UM domínio agora (fura a fila): regras + fontes externas + IA."""
    from .features import analyze_name
    reg = analyze_name(name, settings().internal_suffixes).registrable
    with db.conn() as c:
        r = c.execute("UPDATE domains SET llm_pending=true, needs_analysis=false, claimed_at=NULL, "
                      "evidence_hash='' WHERE name=%s AND NOT locked RETURNING id", (reg,)).fetchone()
        if not r:
            return f"domínio {reg} não encontrado (ou travado)"
    client = OllamaClient()
    with db.conn() as c:
        cats = categories(c)
        drow = c.execute("UPDATE domains SET claimed_at=now() WHERE name=%s RETURNING *", (reg,)).fetchone()
    return _refine(client, cats, drow, esperar_busca=True)


def reanalyze_stale(days: int) -> int:
    with db.conn() as c:
        return c.execute(
            "UPDATE domains SET needs_analysis=true WHERE NOT needs_analysis AND NOT locked "
            "AND revisado_at IS NULL "   # Sites Revisados: só com pedido (feeds de ameaça seguem pelo caminho próprio)
            "AND analyzed_at < now() - make_interval(days => %s)", (days,)).rowcount


def _llm_worker(stop, cats: list[dict], wid: int, url: str | None = None) -> None:
    """Worker extra da IA (a Fase A e a manutenção ficam no laço principal). Com url = reforço
    (ex.: PC com GPU): só reserva domínio quando aquele Ollama responde — desligado, só espera."""
    client = OllamaClient(url)
    backoff, no_ar = 0, None
    while not stop():
        try:
            if client.extra:
                ok, motivo = client.available()
                if ok != no_ar and wid % 100 == 0:   # 1 aviso por servidor, não por worker
                    log.info("reforço da IA %s: %s", url, "no ar" if ok else motivo)
                    event("llm_extra", detail=f"reforço {url}: {'no ar' if ok else 'fora — ' + motivo[:150]}")
                no_ar = ok
                if not ok:
                    time.sleep(60)
                    continue
            if wid % 100 == 1:   # um worker do reforço atende primeiro a pergunta de lista (catálogo/regras): com a fila da
                st = listas_ia.fase(client)   # fase 1 cheia ela não andava (214 esperando, 27/09)
                if st == "idle":
                    st = phase_b(client, cats)
            else:
                st = phase_b(client, cats)
                if st == "idle":            # fila da IA vazia: etapa "lista" (qual lista de bloqueio)
                    st = listas_ia.fase(client)
            if st == "idle":
                time.sleep(20)
            elif st == "unavailable":
                backoff = min(backoff + 30, 300)
                time.sleep(backoff)
            else:
                backoff = 0
        except Exception:  # noqa: BLE001
            log.exception("erro no worker %d da IA", wid)
            time.sleep(30)


def run_forever(stop=lambda: False) -> None:
    import threading
    cfg = settings()
    db.set_max_size(7 + cfg.online_workers + cfg.llm_workers + sum(_workers_reforco(cfg, u) for u in cfg.ollama_extra_urls)
                    + cfg.whois_workers)
    client = OllamaClient()
    if cfg.llm_enabled and cfg.llm_workers > 1:
        with db.conn() as c:
            cats0 = categories(c)
        for i in range(1, cfg.llm_workers):
            threading.Thread(target=_llm_worker, args=(stop, cats0, i), daemon=True, name=f"ia-{i}").start()
        log.info("IA com %d análises simultâneas", cfg.llm_workers)
    if cfg.llm_enabled and cfg.ollama_extra_urls:
        with db.conn() as c:
            cats0 = categories(c)
        for s, url in enumerate(cfg.ollama_extra_urls, start=1):
            for j in range(_workers_reforco(cfg, url)):
                threading.Thread(target=_llm_worker, args=(stop, cats0, s * 100 + j, url), daemon=True,
                                 name=f"ia-extra{s}-{j}").start()
        log.info("reforço da IA: %s", ", ".join(f"{u} ({_workers_reforco(cfg, u)} análises simultâneas)" for u in cfg.ollama_extra_urls))
    last_stale = 0.0
    last_auto = 0.0
    backoff = 0
    reforco = _Reforco(client)
    cliente_etapa2 = reforco.cliente   # etapa 2 (busca na web + IA) no reforço com GPU se no ar
    with db.conn() as c:
        cats = categories(c)
    if cfg.llm_enabled and cfg.whois_enabled:
        for i in range(cfg.whois_workers):
            threading.Thread(target=_whois_worker, args=(stop, cats, reforco, i), daemon=True,
                             name=f"whois-{i}").start()
        log.info("fase 2 (WHOIS) em paralelo: %d worker(s)", cfg.whois_workers)
    if cfg.llm_enabled and cfg.web_search_url:
        threading.Thread(target=_busca_worker, args=(stop, cats, reforco), daemon=True, name="busca").start()
        log.info("fase 3 (busca na web) em paralelo")
    for i in range(cfg.online_workers):
        threading.Thread(target=_online_worker, args=(stop,), daemon=True, name=f"online-{i}").start()
    log.info("fase 4 (IA online): %s", " | ".join(",".join(f"{m} {r}/min {d}/dia" for m, r, d in n) for n in online.niveis())
             if online.habilitado() else "desligada (sem GEMINI_API_KEY)")
    while not stop():
        try:
            n = phase_a()
            if n:
                log.info("fase A (regras): %d domínio(s)", n)
            if time.monotonic() - last_auto > 300:   # bloqueio automático -> listas por categoria
                last_auto = time.monotonic()
                with db.conn() as c:   # (um evento por domínio na coluna "Decisão" do IA ao vivo)
                    listas.bloquear_auto(c)
                with db.conn() as c:
                    listas.expirar_ameacas(c)
                with db.conn() as c:
                    listas_ia.aplicar(c)
                with db.conn() as c:
                    whitelist.aplicar(c)
                with db.conn() as c:   # nada fica solto: quem terminou sem lista vai p/ a whitelist ou a Decisão Humana
                    listas.sem_destino(c)
                with db.conn() as c:   # pouco acesso que recorreu: volta à fila normal da IA
                    m = reenfileirar_recorrentes(c)
                if m:
                    log.info("%d domínio(s) de pouco acesso recorreram: de volta à fila da IA", m)
            if time.monotonic() - last_stale > 3600:
                with db.conn() as c:   # domínios que não existem (NXDOMAIN) saem da IA e de Decisões
                    listas.marcar_inexistentes(c)
                m = reanalyze_stale(cfg.reanalyze_days)
                if m:
                    log.info("%d domínio(s) antigos marcados para reanálise", m)
                last_stale = time.monotonic()
            if not cfg.llm_enabled:
                time.sleep(30)
                continue
            # IA da VM (só CPU) como reserva: com o reforço (GPU) no ar, o laço principal também usa a GPU
            status = phase_b(cliente_etapa2() if cfg.llm_vm_reserva else client, cats)
            if status == "idle":            # fase 1 vazia: lista dos classificados pelo catálogo/regras
                status = listas_ia.fase(cliente_etapa2())   # (fases 2, 3 e 4 têm workers próprios)
            if status == "idle":
                time.sleep(20)
            elif status == "unavailable":
                backoff = min(backoff + 30, 300)
                time.sleep(backoff)
            else:
                backoff = 0
        except Exception:  # noqa: BLE001
            log.exception("erro no ciclo do classificador")
            time.sleep(30)


def status() -> dict:
    with db.conn() as c:
        r = c.execute(
            "SELECT count(*) FILTER (WHERE needs_analysis) AS fase_a, count(*) FILTER (WHERE llm_pending AND NOT aguarda_recorrencia AND " + DECIDIDO_FORA + ") AS fila_ia, "
            "count(*) FILTER (WHERE aguarda_recorrencia) AS aguarda, "
            "count(*) FILTER (WHERE classified_by='llm') AS por_ia, count(*) AS total FROM domains").fetchone()
    return dict(r) | {"at": datetime.now(timezone.utc).isoformat()}
