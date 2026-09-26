"""Enriquecimento com dados públicos: popularidade (Tranco) e idade (RDAP).

* Tranco: lista pública top-1M baixada por inteiro (nada é enviado).
* RDAP: consulta pública do registro do domínio (só o NOME do domínio sai da
  rede; nunca IPs ou logs). Pode ser desligado (RDAP_ENABLED=false). Resultado
  em cache (lookup_cache) por RDAP_CACHE_DAYS.
"""

from __future__ import annotations

import csv
import io
import logging
import time
import zipfile
from datetime import date, datetime, timedelta, timezone

import httpx
from psycopg.types.json import Jsonb

from . import db
from .config import settings

log = logging.getLogger(__name__)
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_KEY = "tranco_fetched_at"
_last_rdap_call = 0.0


def refresh_tranco(force: bool = False) -> dict:
    last = db.get_state(TRANCO_KEY)
    if not force and last:
        if datetime.fromisoformat(last) > datetime.now(timezone.utc) - timedelta(hours=24):
            return {"skipped": True}
    r = httpx.get(TRANCO_URL, timeout=300, follow_redirects=True)
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    name = zf.namelist()[0]
    n = 0
    with db.conn() as c:
        c.execute("CREATE TEMP TABLE pop_new (domain text, rank int) ON COMMIT DROP")
        with c.cursor().copy("COPY pop_new (domain, rank) FROM STDIN") as cp:
            with zf.open(name) as f:
                for row in csv.reader(io.TextIOWrapper(f, encoding="utf-8")):
                    if len(row) >= 2 and row[0].isdigit():
                        cp.write_row((row[1].strip().lower(), int(row[0])))
                        n += 1
        c.execute("TRUNCATE popularity")
        c.execute("INSERT INTO popularity (domain, rank) SELECT DISTINCT ON (domain) domain, rank "
                  "FROM pop_new ORDER BY domain, rank")
        c.execute(
            "INSERT INTO ingest_state (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()",
            (TRANCO_KEY, datetime.now(timezone.utc).isoformat()))
    log.info("Tranco atualizado: %d domínios", n)
    return {"domains": n}


def popularity(c, names: list[str]) -> dict[str, int]:
    rows = c.execute("SELECT domain, rank FROM popularity WHERE domain = ANY(%s)", (names,)).fetchall()
    return {r["domain"]: r["rank"] for r in rows}


def _rdap_date(data: dict) -> date | None:
    for ev in data.get("events", []) or []:
        if (ev.get("eventAction") or "").lower() == "registration" and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00")).date()
            except ValueError:
                return None
    return None


def rdap_registered(c, domain: str) -> date | None:
    """Data de registro via RDAP (com cache). None = desconhecida."""
    global _last_rdap_call
    cfg = settings()
    row = c.execute("SELECT ok, value, fetched_at FROM lookup_cache WHERE kind='rdap' AND key=%s",
                    (domain,)).fetchone()
    if row and row["fetched_at"] > datetime.now(timezone.utc) - timedelta(days=cfg.rdap_cache_days):
        v = (row["value"] or {}).get("registered")
        return date.fromisoformat(v) if v else None
    if not cfg.rdap_enabled:
        return None
    # respeita os serviços públicos: no máximo ~1 consulta/s
    wait = 1.0 - (time.monotonic() - _last_rdap_call)
    if wait > 0:
        time.sleep(wait)
    _last_rdap_call = time.monotonic()
    reg, ok = None, False
    try:
        r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=8, follow_redirects=True,
                      headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            reg, ok = _rdap_date(r.json()), True
        elif r.status_code == 404:
            ok = True
    except Exception as e:  # noqa: BLE001
        log.debug("RDAP %s falhou: %s", domain, e)
    c.execute(
        "INSERT INTO lookup_cache (kind, key, ok, value) VALUES ('rdap', %s, %s, %s) "
        "ON CONFLICT (kind, key) DO UPDATE SET ok=EXCLUDED.ok, value=EXCLUDED.value, fetched_at=now()",
        (domain, ok, Jsonb({"registered": reg.isoformat() if reg else None})))
    return reg
