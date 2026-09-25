"""Listas curadas de anúncios/rastreadores, baixadas e comparadas LOCALMENTE.

Um domínio registrável listado (ou um "pai" dele) vira publicidade/rastreamento
pelas regras, sem gastar IA — o modelo local pequeno não conhece bem a cauda da
adtech e chutava "infraestrutura". Só entram regras de domínio inteiro (||x^);
exceções (@@) e sufixos públicos são descartados. Nunca conclui risco: só a categoria.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import httpx
from psycopg.types.json import Jsonb

from . import db
from .features import is_public_suffix

log = logging.getLogger(__name__)

SOURCES = {
    "adguard_dns": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "peter_lowe": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
    "easylist": "https://easylist.to/easylist/easylist.txt",
    "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
}
LABEL = "lista de anúncios/rastreadores"
REFRESH = timedelta(hours=24)
_RULE = re.compile(r"^\|\|([a-z0-9.-]+\.[a-z0-9-]{2,})\^(\$important)?$")
_EXC = re.compile(r"^@@\|\|([a-z0-9.-]+)\^")
_PLAIN = re.compile(r"^[a-z0-9.-]+\.[a-z0-9-]{2,}$")


def parse(text: str) -> tuple[set[str], set[str]]:
    add, exc = set(), set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line[0] in "!#[":
            continue
        if m := _RULE.match(line):
            add.add(m.group(1))
        elif m := _EXC.match(line):
            exc.add(m.group(1))
        elif _PLAIN.match(line):
            add.add(line)
    return add, exc


def refresh(force: bool = False) -> dict:
    with db.conn() as c:
        st = c.execute("SELECT refreshed_at FROM adlist_state WHERE id=1").fetchone()
    if not force and st and st["refreshed_at"] and datetime.now(timezone.utc) - st["refreshed_at"] < REFRESH:
        return {"skipped": True}
    per: dict[str, set[str]] = {}
    exc: set[str] = set()
    detail = {}
    for name, url in SOURCES.items():
        try:
            r = httpx.get(url, timeout=120, follow_redirects=True, headers={"User-Agent": "2d-dnsanalyzer"})
            r.raise_for_status()
            a, e = parse(r.text)
            per[name] = a
            exc |= e
            detail[name] = len(a)
        except Exception as e:  # noqa: BLE001
            log.warning("lista de anúncios %s falhou: %s", name, e)
            detail[name] = f"erro: {e}"[:200]
    if not per:
        return {"error": detail}
    rows: dict[str, list[str]] = {}
    for name, doms in per.items():
        for d in doms - exc:
            if not is_public_suffix(d):
                rows.setdefault(d, []).append(name)
    with db.conn() as c:
        with c.transaction():
            c.execute("CREATE TEMP TABLE _ad (name text, sources text[]) ON COMMIT DROP")
            with c.cursor().copy("COPY _ad (name, sources) FROM STDIN") as cp:
                for d, s in rows.items():
                    cp.write_row((d, s))
            # só as fontes que baixaram agora são trocadas (falha de uma não apaga a lista)
            c.execute("DELETE FROM ad_domains WHERE sources <@ %s::text[]", (list(per),))
            c.execute("INSERT INTO ad_domains SELECT name, sources FROM _ad "
                      "ON CONFLICT (name) DO UPDATE SET sources = EXCLUDED.sources")
            c.execute("INSERT INTO adlist_state (id, refreshed_at, entries, detail) VALUES (1, now(), %s, %s) "
                      "ON CONFLICT (id) DO UPDATE SET refreshed_at=now(), entries=EXCLUDED.entries, "
                      "detail=EXCLUDED.detail", (len(rows), Jsonb(detail)))
        marked = c.execute(
            "UPDATE domains d SET needs_analysis = true WHERE d.kind = 'public' AND NOT d.locked "
            "AND COALESCE(d.category, '') <> 'publicidade' AND d.classification IS DISTINCT FROM 'MALICIOSO' "
            "AND EXISTS (SELECT 1 FROM ad_domains a WHERE a.name = ANY(_parents(d.name)))").rowcount
    log.info("listas de anúncios: %d domínios (%s); %d domínio(s) para reavaliar", len(rows), detail, marked)
    return {"entries": len(rows), "sources": detail, "reavaliar": marked}


def parents(name: str) -> list[str]:
    """nome e seus pais, sem chegar ao sufixo público."""
    p = name.lower().rstrip(".").split(".")
    return [x for x in (".".join(p[i:]) for i in range(len(p) - 1)) if not is_public_suffix(x)]


def match(c, name: str) -> dict | None:
    """Entrada de catálogo sintética (publicidade) se o domínio está nas listas."""
    cands = parents(name)
    if not cands:
        return None
    r = c.execute("SELECT name, sources FROM ad_domains WHERE name = ANY(%s) ORDER BY length(name) DESC LIMIT 1",
                  (cands,)).fetchone()
    if not r:
        return None
    return {"suffix": r["name"], "exact": False, "classification": "NAO_TRABALHO", "work": 10,
            "topic": "Publicidade/rastreamento", "category": "publicidade", "protected": False,
            "label": f"{LABEL} ({', '.join(sorted(r['sources']))})"}
