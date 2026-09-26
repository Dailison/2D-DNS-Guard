"""Identificação do serviço por fontes públicas (só o NOME do domínio sai da rede).

Fontes, da mais confiável para a menos:
1. Wikidata — entidade cujo "site oficial" (P856) é o domínio (base curada).
2. Certificado TLS VERIFICADO — organização (OV/EV) e outros domínios cobertos
   pelo mesmo certificado (SAN): a CA validou que o dono controla todos eles.
   Certificado não verificado é ignorado (poderia ser forjado).
3. Página inicial — título/descrição/og:site_name. Texto DECLARADO pelo próprio
   site: pista, nunca prova; a IA é instruída a ignorar instruções contidas nele.
   Só é buscada se o domínio não tiver sinal de ameaça.

Resultado em cache (lookup_cache, kind='web') por WEB_CACHE_DAYS.
"""

from __future__ import annotations

import html
import json
import logging
import re
import socket
import ssl
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone

import httpx
import tldextract
from psycopg.types.json import Jsonb

from .config import settings

log = logging.getLogger(__name__)
UA = "2D-DNSAnalyzer/0.1 (+https://www.2dtecnologia.com; identificacao de dominios)"
_EXT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


def _clean(s: str | None, n: int = 160) -> str | None:
    if not s:
        return None
    s = _CTRL.sub(" ", html.unescape(s))
    s = re.sub(r"\s+", " ", s).strip().strip('"').strip()
    return s[:n] if s else None


def wikidata(domain: str) -> dict | None:
    urls = [f"{s}://{w}{domain}{e}" for s in ("https", "http") for w in ("", "www.") for e in ("", "/")]
    q = ("SELECT ?item ?label ?desc WHERE { VALUES ?u { " + " ".join(f"<{u}>" for u in urls) + " } "
         "?item wdt:P856 ?u . "
         'OPTIONAL { ?item rdfs:label ?label FILTER(lang(?label) IN ("pt","en")) } '
         'OPTIONAL { ?item schema:description ?desc FILTER(lang(?desc) IN ("pt","en")) } } LIMIT 10')
    r = httpx.get("https://query.wikidata.org/sparql", params={"format": "json", "query": q},
                  headers={"User-Agent": UA}, timeout=15)
    r.raise_for_status()
    rows = r.json().get("results", {}).get("bindings", [])
    if not rows:
        return None

    def pick(key):
        vals = [(b[key]["value"], b[key].get("xml:lang")) for b in rows if key in b]
        for lang in ("pt", "en"):
            for v, lg in vals:
                if lg == lang:
                    return v
        return vals[0][0] if vals else None
    item = rows[0]["item"]["value"].rsplit("/", 1)[-1]
    return {"label": _clean(pick("label"), 80), "description": _clean(pick("desc"), 160), "qid": item}


def certificate(domain: str) -> dict | None:
    """Organização e domínios-irmãos (SAN) de um certificado VERIFICADO."""
    for host in (domain, "www." + domain):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
        except ssl.SSLCertVerificationError:
            return {"verified": False}
        except OSError:
            continue
        subj = {k: v for t in c.get("subject", ()) for k, v in t}
        iss = {k: v for t in c.get("issuer", ()) for k, v in t}
        regs = sorted({_EXT(v.lstrip("*.")).registered_domain for k, v in c.get("subjectAltName", ()) if k == "DNS"}
                      - {domain, ""})
        return {"verified": True, "org": _clean(subj.get("organizationName"), 80),
                "issuer": _clean(iss.get("organizationName"), 60), "san_domains": regs[:10],
                "san_total": len(regs)}
    return None


def homepage(domain: str) -> dict | None:
    """Título/descrição da página inicial (texto do próprio site; não confiável).
    Tenta o domínio e, se ele não tiver site (comum: raiz sem endereço), o www."""
    for host in (domain, "www." + domain):
        r = _homepage_host(host)
        if r:
            return r
    return None


def _homepage_host(domain: str) -> dict | None:
    for verify in (True, False):
        try:
            with httpx.Client(timeout=8, follow_redirects=True, verify=verify, max_redirects=5,
                              headers={"User-Agent": UA, "Accept": "text/html"}) as cl:
                with cl.stream("GET", f"https://{domain}/") as r:
                    if "html" not in r.headers.get("content-type", ""):
                        return {"final_host": r.url.host}
                    body = b""
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > 200_000:
                            break
                    text = body.decode(r.encoding or "utf-8", errors="ignore")
                    final = r.url.host
            break
        except httpx.HTTPError as e:
            if verify and "CERTIFICATE_VERIFY_FAILED" in str(e):
                continue
            return None
    else:
        return None

    def meta(*names):
        for n in names:
            m = re.search(r'<meta[^>]+(?:name|property)=["\']' + re.escape(n) + r'["\'][^>]*content=["\']([^"\']{1,400})',
                          text, re.I) or re.search(r'<meta[^>]+content=["\']([^"\']{1,400})["\'][^>]*(?:name|property)=["\']'
                                                   + re.escape(n) + r'["\']', text, re.I)
            if m:
                return m.group(1)
        return None
    t = re.search(r"<title[^>]*>(.{1,300}?)</title>", text, re.S | re.I)
    return {"final_host": final, "tls_verified": verify, "title": _clean(t.group(1) if t else None, 120),
            "description": _clean(meta("description", "og:description"), 160),
            "site_name": _clean(meta("og:site_name", "application-name"), 60)}


class BuscaIndisponivel(Exception):
    """Buscadores bloquearam/suspenderam (captcha, excesso de pedidos): tentar depois.
    NÃO é "sem resultado" — senão o domínio ficaria marcado como sem presença na web."""


_ultima_busca = 0.0
_busca_lock = threading.Lock()


def search(c, domain: str, fetch: bool) -> list[dict] | None:
    """Etapa 2: resultados de busca na web (SearXNG local) sobre o domínio. Texto de
    TERCEIROS (pista, não prova). Cache permanente em lookup_cache kind='search'."""
    cfg = settings()
    row = c.execute("SELECT value FROM lookup_cache WHERE kind='search' AND key=%s", (domain,)).fetchone()
    if row or not (fetch and cfg.web_search_url):
        return row["value"].get("results") if row else None
    import time
    global _ultima_busca
    with _busca_lock:   # vários workers da IA: o intervalo mínimo vale entre todos
        espera = cfg.web_search_min_interval - (time.monotonic() - _ultima_busca)
        if espera > 0:
            time.sleep(espera)
        _ultima_busca = time.monotonic()
    r = httpx.get(cfg.web_search_url.rstrip("/") + "/search", timeout=40,
                  params={"q": f'"{domain}"', "format": "json", "language": "pt-BR", "safesearch": 0})
    r.raise_for_status()
    j = r.json()
    out, hosts = [], set()
    for x in j.get("results", []):
        url = x.get("url") or ""
        host = (urllib.parse.urlsplit(url).hostname or "").lower().removeprefix("www.")
        title, snippet = _clean(x.get("title"), 120), _clean(x.get("content"), 220)
        if not host or not (title or snippet):
            continue
        out.append({"title": title, "snippet": snippet, "host": host, "url": url[:300]})
        hosts.add(host)
        if len(out) >= cfg.web_search_results:
            break
    fora = [e[0] for e in j.get("unresponsive_engines") or []]
    if not out and fora:
        raise BuscaIndisponivel("buscadores sem resposta: " + ", ".join(fora))
    c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES ('search', %s, true, %s) "
              "ON CONFLICT (kind, key) DO UPDATE SET value=EXCLUDED.value, ok=true, fetched_at=now()",
              (domain, Jsonb({"results": out, "fetched": datetime.now(timezone.utc).isoformat()})))
    return out


def lookup(c, domain: str, fetch: bool, allow_site: bool) -> dict | None:
    """Dados de identificação do domínio (cache; busca na rede só se fetch=True)."""
    cfg = settings()
    row = c.execute("SELECT value, fetched_at FROM lookup_cache WHERE kind='web' AND key=%s", (domain,)).fetchone()
    if row and row["fetched_at"] > datetime.now(timezone.utc) - timedelta(days=cfg.web_cache_days):
        return row["value"]
    if not (fetch and cfg.web_intel_enabled):
        return row["value"] if row else None
    out: dict = {"fetched": datetime.now(timezone.utc).isoformat()}
    for key, fn, ok in (("wikidata", wikidata, True), ("cert", certificate, True),
                        ("site", homepage, allow_site and cfg.web_fetch_site)):
        if not ok:
            continue
        try:
            out[key] = fn(domain)
        except Exception as e:  # noqa: BLE001 — fonte externa fora do ar não pode travar a análise
            log.debug("webintel %s %s: %s", key, domain, e)
            out[key] = None
    c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES ('web', %s, true, %s) "
              "ON CONFLICT (kind, key) DO UPDATE SET value=EXCLUDED.value, ok=true, fetched_at=now()",
              (domain, Jsonb(out)))
    return out
