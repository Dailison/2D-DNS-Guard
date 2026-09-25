"""CLI: python -m dnsanalyzer <comando>

Serviços (systemd):
  run-collector   coleta contínua + atualização de feeds TI/Tranco + comportamento + retenção
  run-classifier  classificação contínua (regras + IA local)
  api             API interna para o console (dns-guard)

Operação:
  migrate | import-tenants ARQ | collect | ti-refresh [--force] [--source NOME]
  tranco-refresh [--force] | classify [--rules-only] | behavior | status
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone

from . import db
from .config import settings
from .logs import setup_logging

log = logging.getLogger("dnsanalyzer")
_STOP = False


def _on_term(*_):
    global _STOP
    _STOP = True
    log.info("sinal de parada recebido; encerrando após o passo atual")


def _run_step(kind: str, fn, *a, **kw):
    rid = db.begin_run(kind)
    try:
        res = fn(*a, **kw)
        db.end_run(rid, True, res if isinstance(res, dict) else {"result": res})
        return res
    except Exception as e:  # noqa: BLE001
        log.exception("%s falhou", kind)
        db.end_run(rid, False, error=str(e))
        return None


def cmd_import_tenants(path: str, replace: bool) -> None:
    """JSON: [{"empresa": "...", "unidade": "...", "cidr": "10.9.0.0/16"}, ...] (idempotente).

    --replace: redes de empresas cadastradas que não estão no arquivo são removidas
    (os dados daqueles IPs vão para empresas automáticas "Rede ...")."""
    from .registry import import_rows
    rows = json.loads(open(path, encoding="utf-8").read())
    with db.conn() as c:
        print(json.dumps(import_rows(c, rows, replace), indent=2, ensure_ascii=False))


def cmd_backfill_categories() -> None:
    """Preenche a categoria dos domínios classificados antes dela existir.
    Catálogo/regras: a fase A recalcula. IA: mapeia o assunto; sem mapa -> volta p/ IA."""
    from .categories import from_topic
    with db.conn() as c:
        fase_a = c.execute("UPDATE domains SET needs_analysis=true WHERE category IS NULL "
                           "AND COALESCE(classified_by,'') <> 'llm'").rowcount
        mapped = requeued = 0
        for r in c.execute("SELECT id, topic, classification FROM domains WHERE category IS NULL "
                           "AND classified_by='llm'").fetchall():
            cat = "ameaca" if r["classification"] == "MALICIOSO" else from_topic(r["topic"])
            if not cat and r["classification"] == "DESCONHECIDO":
                cat = "desconhecido"
            if cat:
                c.execute("UPDATE domains SET category=%s WHERE id=%s", (cat, r["id"]))
                mapped += 1
            else:
                c.execute("UPDATE domains SET llm_pending=true, evidence_hash='' WHERE id=%s", (r["id"],))
                requeued += 1
    print(f"fase A (catálogo/regras): {fase_a} | IA mapeados pelo assunto: {mapped} | de volta à IA: {requeued}")


def cmd_backfill_corp() -> None:
    """Recomendação corporativa p/ domínios já classificados (padrão da política por categoria;
    a justificativa da IA chega quando o domínio for reanalisado)."""
    from .corporate import recommend
    n = 0
    with db.conn() as c:
        for r in c.execute("SELECT id, classification, category, risk_score, evidence FROM domains "
                           "WHERE corp_action IS NULL AND classification IS NOT NULL").fetchall():
            prot = any(e.get("kind") == "catalog" and (e.get("data") or {}).get("protected")
                       for e in (r["evidence"] or []))
            rec = recommend(r["classification"], r["category"], r["risk_score"], prot)
            if rec:
                c.execute("UPDATE domains SET corp_action=%s, corp_reason=%s, corp_by=%s WHERE id=%s", (*rec, r["id"]))
                n += 1
    print(f"recomendação corporativa preenchida: {n}")


def run_collector() -> None:
    from . import adlists, behavior, collector, enrich, ti
    from .technitium import TechnitiumClient
    cfg = settings()
    client = TechnitiumClient()
    last_behavior = last_purge = last_ti = 0.0
    while not _STOP:
        # 1) coleta: processa janelas até alcançar o "agora - lag" (limite por ciclo)
        total = {"entries": 0, "rows": 0, "windows": 0}
        caught_up = True
        rid = db.begin_run("collect")
        try:
            for _ in range(48):
                if _STOP:
                    break
                st = collector.collect_once(client)
                if st.get("window_end") is None:
                    break
                total["entries"] += st.get("entries", 0)
                total["rows"] += st.get("rows", 0)
                total["windows"] += 1
                total["cursor"] = st["window_end"]
                caught_up = st.get("caught_up", True)
                if caught_up:
                    break
            db.end_run(rid, True, total)
            if total["entries"]:
                log.info("coleta: %d consultas em %d janela(s) -> %d agregados (cursor %s)",
                         total["entries"], total["windows"], total["rows"], total.get("cursor"))
        except Exception as e:  # noqa: BLE001
            log.exception("coleta falhou")
            db.end_run(rid, False, total, str(e))
            caught_up = True

        now = time.monotonic()
        # 2) feeds de TI e Tranco (cada fonte tem seu intervalo)
        if now - last_ti > 900:
            _run_step("ti_refresh", ti.refresh_due)
            _run_step("tranco_refresh", enrich.refresh_tranco)
            _run_step("adlist_refresh", adlists.refresh)
            last_ti = now
        # 3) comportamento
        if now - last_behavior > cfg.behavior_interval:
            since = datetime.fromtimestamp(time.time() - cfg.behavior_interval - 300, tz=timezone.utc)
            res = _run_step("behavior", behavior.run, since)
            if res and any(res.values()):
                log.info("alertas novos: %s", res)
            last_behavior = now
        # 4) retenção (diária)
        if now - last_purge > 86400:
            def _purge():
                with db.conn() as c:
                    ev = c.execute("DELETE FROM ai_events WHERE created_at < now() - interval '7 days'").rowcount
                    return {"dropped": collector.purge_old(c, cfg.retention_days), "ai_events_removed": ev}
            _run_step("purge", _purge)
            last_purge = now

        if caught_up:
            for _ in range(cfg.ingest_interval):
                if _STOP:
                    break
                time.sleep(1)
    client.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dnsanalyzer")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    it = sub.add_parser("import-tenants")
    it.add_argument("path")
    it.add_argument("--replace", action="store_true")
    sub.add_parser("collect")
    tr = sub.add_parser("ti-refresh")
    tr.add_argument("--force", action="store_true")
    tr.add_argument("--source")
    tc = sub.add_parser("tranco-refresh")
    tc.add_argument("--force", action="store_true")
    cl = sub.add_parser("classify")
    cl.add_argument("--rules-only", action="store_true")
    cl.add_argument("--limit", type=int, default=5)
    cl.add_argument("--domain", help="classifica só este domínio, agora (fura a fila)")
    sub.add_parser("behavior")
    sub.add_parser("backfill-categories")
    sub.add_parser("backfill-corp")
    al = sub.add_parser("adlist-refresh")
    al.add_argument("--force", action="store_true")
    sub.add_parser("status")
    sub.add_parser("run-collector")
    sub.add_parser("run-classifier")
    sub.add_parser("api")
    args = p.parse_args(argv)

    cfg = settings()
    service = {"run-collector": "collector", "run-classifier": "classifier", "api": "api"}.get(args.cmd, "cli")
    setup_logging(service, cfg.log_level, cfg.log_dir if service != "cli" else "")
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)

    if args.cmd == "migrate":
        from .migrate import migrate
        print("aplicadas:", migrate() or "nenhuma (já atualizado)")
    elif args.cmd == "import-tenants":
        cmd_import_tenants(args.path, args.replace)
    elif args.cmd == "collect":
        from .collector import collect_once
        print(json.dumps(collect_once(), default=str, indent=2))
    elif args.cmd == "ti-refresh":
        from .ti import refresh_due
        print(json.dumps(refresh_due(force=args.force, only=args.source), indent=2))
    elif args.cmd == "tranco-refresh":
        from .enrich import refresh_tranco
        print(json.dumps(refresh_tranco(force=args.force)))
    elif args.cmd == "classify":
        from . import classifier
        if args.domain:
            print(f"{args.domain}:", classifier.classify_one(args.domain))
            db.close()
            return 0
        print("fase A (regras):", classifier.phase_a())
        if not args.rules_only:
            from .llm import OllamaClient
            client = OllamaClient()
            with db.conn() as c:
                cats = classifier.categories(c)
            for _ in range(args.limit):
                st = classifier.phase_b(client, cats)
                print("fase B (IA):", st)
                if st in ("idle", "unavailable"):
                    break
    elif args.cmd == "backfill-categories":
        cmd_backfill_categories()
    elif args.cmd == "adlist-refresh":
        from .adlists import refresh
        print(json.dumps(refresh(force=args.force), indent=2, ensure_ascii=False))
    elif args.cmd == "backfill-corp":
        cmd_backfill_corp()
    elif args.cmd == "behavior":
        from .behavior import run
        print(json.dumps(run(), indent=2))
    elif args.cmd == "status":
        from .classifier import status
        print(json.dumps(status(), indent=2))
    elif args.cmd == "run-collector":
        log.info("coletor iniciado (Technitium %s)", cfg.technitium_url)
        run_collector()
    elif args.cmd == "run-classifier":
        from .classifier import run_forever
        log.info("classificador iniciado (IA: %s, modelo %s)", "ligada" if cfg.llm_enabled else "desligada",
                 cfg.ollama_model)
        run_forever(stop=lambda: _STOP)
    elif args.cmd == "api":
        import uvicorn
        uvicorn.run("dnsanalyzer.api:app", host=cfg.api_host, port=cfg.api_port, log_level="warning",
                    access_log=False)
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
