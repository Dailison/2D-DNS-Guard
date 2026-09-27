"""Etapa 3: WHOIS (RDAP) do domínio + atividade da empresa titular (CNPJ -> Receita/BrasilAPI).

.br: o registro.br mostra o titular com CNPJ (pessoa jurídica, validado por eles) ou CPF
mascarado (pessoa física). Com o CNPJ, a BrasilAPI devolve razão social, nome fantasia e a
atividade principal (CNAE) — o que a empresa faz. Demais TLDs: titular quase sempre oculto
(LGPD/GDPR); sobram registrador, servidores DNS (estacionamento) e data de criação.
Cache em lookup_cache (kind='whois' e 'cnpj'); 404 = registro inexistente (também em cache).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
from psycopg.types.json import Jsonb

from .config import settings

log = logging.getLogger(__name__)
UA = "2D-DNS-Guard/1.0 (+https://dns-guard.2dtecnologia.com)"
# ("dns-parking.com" NÃO: é o DNS padrão da Hostinger, usado também por sites ativos)
_PARKING = ("parkingcrew", "sedoparking", "bodis.com", "above.com", "parklogic", "domaincontrol-parking",
            "afternic", "dan.com", "undeveloped")
_OCULTO = ("redacted", "privacy", "private", "proxy", "withheld", "whoisguard", "not disclosed", "gdpr",
           "data protected", "contact privacy", "domains by proxy", "identity protect")
_lock = threading.Lock()
_ultima: dict[str, float] = {}
# limite do registro.br (vale p/ o IP do analisador, todos os workers): pausa os .br e a fase 2 segue com os outros.
# (27/09: sem pausa, os 2 workers se revezavam no mesmo .br a cada 6 s por 50 min e a fase 2 inteira parou)
BR_PAUSA_S = 600
_br_pausa_ate = 0.0


def br_pausado() -> bool:
    return time.monotonic() < _br_pausa_ate


def _pausar_br() -> None:
    global _br_pausa_ate
    _br_pausa_ate = time.monotonic() + BR_PAUSA_S
    log.info("registro.br limitando as consultas: .br em pausa por %d min", BR_PAUSA_S // 60)


class WhoisIndisponivel(Exception):
    """Serviço RDAP/CNPJ fora ou limitando: tentar este domínio mais tarde."""


def _espera(chave: str, intervalo: float) -> None:
    """Respeita os serviços públicos: intervalo mínimo por serviço, entre todos os workers."""
    with _lock:
        falta = intervalo - (time.monotonic() - _ultima.get(chave, 0.0))
        if falta > 0:
            time.sleep(falta)
        _ultima[chave] = time.monotonic()


def _get(url: str, servico: str, intervalo: float) -> dict | None:
    _espera(servico, intervalo)
    try:
        r = httpx.get(url, timeout=15, follow_redirects=True,
                      headers={"Accept": "application/rdap+json, application/json", "User-Agent": UA})
    except httpx.HTTPError as e:
        raise WhoisIndisponivel(f"{servico}: {e.__class__.__name__}") from e
    if r.status_code == 404:
        return None
    if r.status_code == 429 or r.status_code >= 500:
        raise WhoisIndisponivel(f"{servico}: HTTP {r.status_code}")
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def _vcard(ent: dict) -> dict:
    out: dict = {}
    for it in (ent.get("vcardArray") or [None, []])[1] or []:
        if len(it) < 4:
            continue
        if it[0] in ("fn", "org", "kind") and isinstance(it[3], str):
            out[it[0]] = it[3].strip()
        elif it[0] == "adr" and isinstance(it[1], dict) and it[1].get("cc"):
            out["pais"] = it[1]["cc"]
    return out


def parse_rdap(j: dict) -> dict:
    """RDAP -> {criado, registrador, ns, estacionado, titular:{nome, tipo, doc, oculto, pais}}."""
    ev = {(e.get("eventAction") or "").lower(): (e.get("eventDate") or "")[:10] for e in j.get("events") or []}
    ents: list[tuple[list[str], dict]] = []

    def walk(es):
        for e in es or []:
            ents.append((e.get("roles") or [], e))
            walk(e.get("entities"))
    walk(j.get("entities"))
    registrador = next((_vcard(e).get("fn") for r, e in ents if "registrar" in r and _vcard(e).get("fn")), None)
    titular = None
    for r, e in ents:
        if "registrant" not in r:
            continue
        v = _vcard(e)
        nome = v.get("org") or v.get("fn") or ""
        doc_tipo, doc = None, None
        for p in e.get("publicIds") or []:
            t = (p.get("type") or "").lower()
            if t in ("cnpj", "cpf"):
                doc_tipo, doc = t, p.get("identifier")
        oculto = not nome or any(x in nome.lower() for x in _OCULTO)
        titular = {"nome": None if oculto else nome[:120], "tipo": doc_tipo, "doc": doc, "oculto": oculto,
                   "pais": v.get("pais")}
        break
    ns = [(n.get("ldhName") or "").lower() for n in j.get("nameservers") or [] if n.get("ldhName")][:4]
    return {"criado": ev.get("registration") or None, "registrador": registrador, "ns": ns,
            "estacionado": any(p in n for n in ns for p in _PARKING), "titular": titular}


def cnpj_info(c, cnpj: str, fetch: bool = True) -> dict | None:
    """Receita Federal via BrasilAPI (cache 90 dias): razão social, fantasia, CNAE, situação."""
    num = re.sub(r"\D", "", cnpj or "")
    if len(num) != 14:
        return None
    row = c.execute("SELECT value, fetched_at FROM lookup_cache WHERE kind='cnpj' AND key=%s", (num,)).fetchone()
    if row and row["fetched_at"] > datetime.now(timezone.utc) - timedelta(days=90):
        return row["value"] or None
    if not fetch:
        return row["value"] if row else None
    j = _get(f"https://brasilapi.com.br/api/cnpj/v1/{num}", "brasilapi", 1.0)
    out = None if not j else {
        "razao_social": j.get("razao_social"), "nome_fantasia": j.get("nome_fantasia") or None,
        "atividade": j.get("cnae_fiscal_descricao"), "situacao": j.get("descricao_situacao_cadastral"),
        "municipio": j.get("municipio"), "uf": j.get("uf"), "porte": j.get("porte")}
    c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES ('cnpj', %s, %s, %s) "
              "ON CONFLICT (kind, key) DO UPDATE SET ok=EXCLUDED.ok, value=EXCLUDED.value, fetched_at=now()",
              (num, out is not None, Jsonb(out or {})))
    return out


def lookup(c, domain: str, fetch: bool) -> dict | None:
    """WHOIS do domínio registrável (cache). fetch=False só lê o cache. None = ainda sem consulta.
    {"encontrado": False} = registro inexistente/sem RDAP."""
    cfg = settings()
    row = c.execute("SELECT value, fetched_at FROM lookup_cache WHERE kind='whois' AND key=%s", (domain,)).fetchone()
    if row and row["fetched_at"] > datetime.now(timezone.utc) - timedelta(days=cfg.rdap_cache_days):
        return row["value"]
    if not fetch:
        return row["value"] if row else None
    br = domain.endswith(".br")
    if br and br_pausado():
        raise WhoisIndisponivel("registro.br em pausa (limite de consultas)")
    try:
        j = _get(f"https://rdap.registro.br/domain/{domain}" if br else f"https://rdap.org/domain/{domain}",
                 "registro.br" if br else "rdap.org", 6.0 if br else 1.5)
    except WhoisIndisponivel:
        if br:
            _pausar_br()
        raise
    out: dict = {"encontrado": False, "fonte": "registro.br" if br else "rdap"}
    if j:
        out.update(parse_rdap(j), encontrado=True)
        t = out.get("titular") or {}
        if br and t.get("nome") and not t.get("tipo"):
            # todo titular .br tem CPF/CNPJ: sem o documento = o registro.br limitou as consultas
            # (medido: ~2 consultas/10 s bastam p/ ele omitir). Não grava; tenta de novo depois da pausa.
            _pausar_br()
            raise WhoisIndisponivel("registro.br omitiu o documento do titular (limite de consultas)")
        if t.get("tipo") == "cnpj":
            try:
                t["receita"] = cnpj_info(c, t.get("doc") or "")
            except WhoisIndisponivel as e:   # sem a Receita segue só com o WHOIS
                log.info("CNPJ %s indisponível: %s", t.get("doc"), e)
    c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES ('whois', %s, true, %s) "
              "ON CONFLICT (kind, key) DO UPDATE SET value=EXCLUDED.value, ok=true, fetched_at=now()",
              (domain, Jsonb(out)))
    return out


def evidencia(w: dict | None) -> tuple[str, dict] | None:
    """Texto + dados da evidência 'whois' (None = nada útil). confiavel=True só p/ titular pessoa
    jurídica com CNPJ no registro.br (o registro.br valida o documento)."""
    if not w or not w.get("encontrado"):
        return None
    t = w.get("titular") or {}
    partes, confiavel = [], False
    if w.get("fonte") == "registro.br" and t.get("tipo") == "cnpj" and t.get("nome"):
        confiavel = True
        partes.append(f"titular PESSOA JURÍDICA '{t['nome']}' (CNPJ {t.get('doc')}, validado pelo registro.br)")
        rf = t.get("receita") or {}
        if rf.get("razao_social"):
            partes.append("Receita Federal: " + f"'{rf['razao_social']}'"
                          + (f" (fantasia '{rf['nome_fantasia']}')" if rf.get("nome_fantasia") else "")
                          + (f", atividade principal: {rf['atividade']}" if rf.get("atividade") else "")
                          + (f", situação {rf['situacao']}" if rf.get("situacao") else "")
                          + (f", {rf['municipio']}/{rf['uf']}" if rf.get("municipio") else ""))
    elif t.get("tipo") == "cpf":
        partes.append("titular PESSOA FÍSICA (CPF) — site pessoal ou de profissional autônomo")
    elif t.get("nome"):
        partes.append(f"titular declarado '{t['nome']}'" + (f" ({t['pais']})" if t.get("pais") else "")
                      + " — informado pelo próprio dono, não verificado")
    else:
        partes.append("titular oculto (serviço de privacidade/LGPD)")
    if w.get("registrador"):
        partes.append(f"registrador {w['registrador']}")
    if w.get("criado"):
        partes.append(f"criado em {w['criado']}")
    if w.get("estacionado"):
        partes.append("DNS de estacionamento (" + ", ".join(w.get("ns") or [])[:80] + "): domínio sem site próprio ou à venda")
    elif w.get("ns"):
        partes.append("DNS: " + ", ".join(w["ns"][:2]))
    return ("WHOIS/RDAP: " + "; ".join(partes),
            {"confiavel": confiavel, "titular_tipo": t.get("tipo"), "estacionado": bool(w.get("estacionado"))})
