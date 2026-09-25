"""Threat Intelligence por feeds públicos baixados e comparados LOCALMENTE.

Nenhum domínio dos clientes é enviado para fora: baixamos as listas públicas e
fazemos o cruzamento no PostgreSQL. As fontes ficam na tabela `ti_sources`
(adicionar/desligar fonte = INSERT/UPDATE, sem mudar código).

Proteções contra falso positivo:
* entradas que são sufixos públicos/plataformas (ex.: s3.us-east-1.amazonaws.com,
  github.io) são descartadas — listar a plataforma não torna seus clientes maliciosos;
* o casamento sobe do FQDN só até o domínio registrável (nunca até a plataforma);
* supressões manuais (falso positivo) por domínio e por fonte;
* o peso de cada fonte e o que ela pode concluir dependem de `confidence`.
"""

from __future__ import annotations

import logging
import re
import tempfile
from datetime import datetime, timedelta, timezone

import httpx

from . import db
from .features import is_public_suffix, normalize

log = logging.getLogger(__name__)
_DOMAIN_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$")
_ADBLOCK_RE = re.compile(r"^\|\|([^\^/$|]+)\^(\$.*)?$")
_SKIP_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0", "ip6-localhost"}
MAX_FEED_BYTES = 300 * 1024 * 1024


def parse_line(kind: str, line: str) -> str | None:
    """Extrai o domínio (ou TLD, p/ tld_adblock) de uma linha de feed. None = ignorar."""
    s = line.strip()
    if not s or s[0] in "#!;[":
        return None
    if kind == "hosts":
        parts = s.split()
        if len(parts) < 2 or parts[1] in _SKIP_HOSTS:
            return None
        cand = parts[1]
    elif kind in ("adblock", "tld_adblock"):
        m = _ADBLOCK_RE.match(s)
        if not m:
            return None
        cand = m.group(1)
        if kind == "tld_adblock":
            if not cand.startswith("*."):
                return None
            tld = normalize(cand[2:])
            return tld if tld and re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)*", tld) else None
        if m.group(2):          # modificadores ($denyallow etc.) = regra condicional, ignora
            return None
        if "*" in cand:
            return None
    elif kind == "plain":
        cand = s.split()[0]
    else:
        return None
    d = normalize(cand)
    if not _DOMAIN_RE.match(d):
        return None
    if is_public_suffix(d):     # plataforma/sufixo público: nunca é "o domínio malicioso"
        return None
    return d


def _download(url: str) -> str:
    """Baixa o feed em streaming para arquivo temporário (sem estourar RAM)."""
    tmp = tempfile.NamedTemporaryFile(prefix="ti-", suffix=".txt", delete=False)
    size = 0
    with httpx.stream("GET", url, timeout=180, follow_redirects=True,
                      headers={"User-Agent": "2D-DNSAnalyzer/0.1 (+https://www.2dtecnologia.com)"}) as r:
        r.raise_for_status()
        for chunk in r.iter_bytes(1 << 16):
            size += len(chunk)
            if size > MAX_FEED_BYTES:
                raise RuntimeError(f"feed maior que {MAX_FEED_BYTES} bytes")
            tmp.write(chunk)
    tmp.close()
    return tmp.name


def refresh_source(src: dict) -> int:
    """Atualiza uma fonte (substitui o conjunto de indicadores dela). Retorna nº de entradas."""
    path = _download(src["url"])
    items: set[str] = set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                d = parse_line(src["kind"], line)
                if d:
                    items.add(d)
    finally:
        import os
        os.unlink(path)
    if not items:
        raise RuntimeError("feed vazio ou formato não reconhecido")

    with db.conn() as c:
        c.execute("CREATE TEMP TABLE ti_new (domain text PRIMARY KEY) ON COMMIT DROP")
        with c.cursor().copy("COPY ti_new (domain) FROM STDIN") as cp:
            for d in items:
                cp.write_row((d,))
        c.execute("ANALYZE ti_new")
        c.execute(
            "DELETE FROM ti_indicators t WHERE t.source_id=%s "
            "AND NOT EXISTS (SELECT 1 FROM ti_new n WHERE n.domain=t.domain)", (src["id"],))
        c.execute(
            "INSERT INTO ti_indicators (source_id, domain) SELECT %s, domain FROM ti_new "
            "ON CONFLICT (source_id, domain) DO NOTHING", (src["id"],))
        c.execute(
            "UPDATE ti_sources SET last_fetch=now(), last_status='ok', entries=%s WHERE id=%s",
            (len(items), src["id"]))
    return len(items)


def refresh_due(force: bool = False, only: str | None = None) -> dict:
    """Atualiza as fontes vencidas; ao final marca para reanálise os domínios cujo
    conjunto de acertos mudou."""
    with db.conn() as c:
        srcs = c.execute("SELECT * FROM ti_sources WHERE enabled ORDER BY id").fetchall()
    now = datetime.now(timezone.utc)
    done, errors = {}, {}
    for s in srcs:
        if only and s["name"] != only:
            continue
        due = force or s["last_fetch"] is None or s["last_fetch"] < now - timedelta(hours=s["refresh_hours"])
        if not due:
            continue
        try:
            n = refresh_source(s)
            done[s["name"]] = n
            log.info("TI %s: %d indicadores", s["name"], n)
        except Exception as e:  # noqa: BLE001
            errors[s["name"]] = str(e)[:300]
            log.error("TI %s falhou: %s", s["name"], e)
            with db.conn() as c:
                c.execute("UPDATE ti_sources SET last_status=%s WHERE id=%s", (f"erro: {e}"[:300], s["id"]))
    marked = mark_changed_domains() if done else 0
    return {"refreshed": done, "errors": errors, "marked_for_reanalysis": marked}


# Consulta usada tanto no recheck em massa quanto por domínio
_HITS_SQL = """
SELECT f.domain_id, s.name AS source, s.label, s.threat, s.confidence, s.weight,
       t.domain AS matched, f.name AS fqdn
FROM fqdns f
JOIN ti_indicators t ON t.domain = ANY(f.candidates)
JOIN ti_sources s ON s.id = t.source_id AND s.enabled AND s.kind <> 'tld_adblock'
JOIN domains d ON d.id = f.domain_id
WHERE {where}
  AND NOT EXISTS (SELECT 1 FROM ti_suppressions x
                  WHERE x.domain IN (t.domain, d.name) AND (x.source_id IS NULL OR x.source_id = s.id))
"""


def signature(hits: list[dict]) -> str:
    return ",".join(sorted({h["source"] for h in hits}))


def mark_changed_domains() -> int:
    """Domínios cujo conjunto de fontes com acerto mudou -> needs_analysis."""
    with db.conn() as c:
        r = c.execute(
            "WITH h AS (" + _HITS_SQL.format(where="true") + "), "
            "sig AS (SELECT domain_id, string_agg(DISTINCT source, ',' ORDER BY source) AS s FROM h GROUP BY domain_id) "
            "UPDATE domains d SET needs_analysis = true "
            "FROM (SELECT d2.id, COALESCE(sig.s, '') AS s FROM domains d2 LEFT JOIN sig ON sig.domain_id = d2.id "
            "      WHERE d2.kind = 'public') x "
            "WHERE d.id = x.id AND d.ti_signature <> x.s AND NOT d.locked"
        )
        return r.rowcount


def hits_for_domain(c, domain_id: int) -> list[dict]:
    rows = c.execute(_HITS_SQL.format(where="f.domain_id = %s"), (domain_id,)).fetchall()
    # uma linha por (fonte, entrada casada); guarda os FQDNs de exemplo
    out: dict[tuple, dict] = {}
    for r in rows:
        k = (r["source"], r["matched"])
        h = out.get(k)
        if h is None:
            h = out[k] = {"source": r["source"], "label": r["label"], "threat": r["threat"],
                          "confidence": r["confidence"], "weight": r["weight"],
                          "matched": r["matched"], "fqdns": []}
        if len(h["fqdns"]) < 3:
            h["fqdns"].append(r["fqdn"])
    return list(out.values())


def abused_tld(c, tld: str) -> dict | None:
    r = c.execute(
        "SELECT s.name AS source, s.label, s.weight FROM ti_indicators t "
        "JOIN ti_sources s ON s.id=t.source_id AND s.enabled AND s.kind='tld_adblock' "
        "WHERE t.domain=%s LIMIT 1", (tld,)).fetchone()
    return dict(r) if r else None
