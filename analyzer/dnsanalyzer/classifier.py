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

from psycopg.types.json import Jsonb

from . import catalog, db, enrich, ti
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


def build_dossier(c, drow: dict, with_rdap: bool = False, with_web: bool = False) -> dict:
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
           needs_analysis=false, llm_pending=%s, evidence_hash=%s, ti_hits=%s, ti_signature=%s,
           popularity_rank=%s, registered_at=COALESCE(%s::date, registered_at), claimed_at=NULL,
           last_error=NULL, llm_attempts=CASE WHEN %s THEN llm_attempts ELSE 0 END
           WHERE id=%s""",
        (fin.classification, fin.risk, fin.work, fin.confidence, fin.topic, fin.category,
         fin.corp_action, fin.corp_action, fin.corp_reason, fin.corp_action, fin.corp_by, Jsonb(reasons), Jsonb(ev),
         fin.action, fin.classified_by, model, pending, rule.evidence_hash, Jsonb(hits), ti.signature(hits),
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
        for drow in rows:
            dossier = build_dossier(c, drow, with_rdap=False)
            rule = evaluate(dossier)
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
                c.execute("UPDATE domains SET needs_analysis=false, llm_pending=true, ti_hits=%s, "
                          "ti_signature=%s WHERE id=%s", (Jsonb(hits), ti.signature(hits), drow["id"]))
            else:
                pending = bool(cfg.llm_enabled and not skip_llm)
                save(c, drow, dossier, rule, rules_only(rule, pending), pending, None)
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


def _claim_llm(c) -> dict | None:
    return c.execute(
        """UPDATE domains SET claimed_at=now() WHERE id = (
             SELECT id FROM domains WHERE llm_pending AND NOT locked
               AND (classification = 'SUSPEITO' OR NOT dominio_decidido(id))   -- decidido: IA não reavalia
               AND (claimed_at IS NULL OR claimed_at < now() - interval '30 minutes')
             ORDER BY (classification = 'SUSPEITO') DESC, total_queries DESC
             LIMIT 1 FOR UPDATE SKIP LOCKED)
           RETURNING *""").fetchone()


def phase_b(client: OllamaClient, cats: list[dict]) -> str:
    """Refina UM domínio com a IA. Retorna 'done' | 'idle' | 'unavailable' | 'error'."""
    with db.conn() as c:
        drow = _claim_llm(c)
    if not drow:
        return "idle"
    return _refine(client, cats, drow)


def _refine(client: OllamaClient, cats: list[dict], drow: dict) -> str:
    """Regras + fontes externas + IA para um domínio já reservado (claimed)."""
    cfg = settings()
    name, did = drow["name"], drow["id"]
    event("llm_start", name, did, detail=f"{drow['total_queries']} consultas · pelas regras: "
                                         f"{CLASS_LABEL.get(drow['classification'], '—')}")
    with db.conn() as c:
        dossier = build_dossier(c, drow, with_rdap=True, with_web=True)
        rule = evaluate(dossier)
    if rule.final:  # (ex.: RDAP/TI mudou o quadro) regras bastam
        with db.conn() as c:
            save(c, drow, dossier, rule, rules_only(rule, False), False, None)
        event("rules_final", name, did, rule.classification, rule.risk, rule.work,
              detail="resolvido pelas regras (evidência nova); IA não foi necessária")
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
    svc = (res.service or "").strip() if res.recognized else "não reconhecido pela IA"
    extra = "; ".join(fin.notes)
    scat = next((s["label"] for s in scats if s["code"] == fin.category), fin.category or "")
    event("llm_done", name, did, fin.classification, fin.risk, fin.work, meta.get("seconds"),
          detail=" · ".join(x for x in (svc, scat, extra) if x))
    return "done"


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
    return _refine(client, cats, drow)


def reanalyze_stale(days: int) -> int:
    with db.conn() as c:
        return c.execute(
            "UPDATE domains SET needs_analysis=true WHERE NOT needs_analysis AND NOT locked "
            "AND analyzed_at < now() - make_interval(days => %s)", (days,)).rowcount


def _llm_worker(stop, cats: list[dict], wid: int) -> None:
    """Worker extra da IA (a Fase A e a manutenção ficam no laço principal)."""
    client = OllamaClient()
    backoff = 0
    while not stop():
        try:
            st = phase_b(client, cats)
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
    client = OllamaClient()
    if cfg.llm_enabled and cfg.llm_workers > 1:
        with db.conn() as c:
            cats0 = categories(c)
        for i in range(1, cfg.llm_workers):
            threading.Thread(target=_llm_worker, args=(stop, cats0, i), daemon=True, name=f"ia-{i}").start()
        log.info("IA com %d análises simultâneas", cfg.llm_workers)
    last_stale = 0.0
    backoff = 0
    with db.conn() as c:
        cats = categories(c)
    while not stop():
        try:
            n = phase_a()
            if n:
                log.info("fase A (regras): %d domínio(s)", n)
            if time.monotonic() - last_stale > 3600:
                m = reanalyze_stale(cfg.reanalyze_days)
                if m:
                    log.info("%d domínio(s) antigos marcados para reanálise", m)
                last_stale = time.monotonic()
            if not cfg.llm_enabled:
                time.sleep(30)
                continue
            status = phase_b(client, cats)
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
            "SELECT count(*) FILTER (WHERE needs_analysis) AS fase_a, count(*) FILTER (WHERE llm_pending AND NOT dominio_decidido(id)) AS fila_ia, "
            "count(*) FILTER (WHERE classified_by='llm') AS por_ia, count(*) AS total FROM domains").fetchone()
    return dict(r) | {"at": datetime.now(timezone.utc).isoformat()}
