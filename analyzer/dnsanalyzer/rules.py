"""Evidências + regras determinísticas (funções puras sobre um "dossiê" do domínio).

As evidências recebem ids (E0, E1, ...). A IA só pode justificar citando esses
ids; o módulo `policy` descarta qualquer razão sem evidência correspondente.
As regras têm a palavra final sobre o risco — a IA atua como camada de
correlação (tópico, relação com trabalho, leitura do conjunto).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

THREAT_TOPIC = {"malware": "Malware", "c2": "Comando e controle (C2)", "phishing": "Phishing",
                "threat": "Ameaça (feed agregado)", "badware": "Hospedagem de badware",
                "dyndns": "DNS dinâmico", "bypass": "VPN/Proxy/DoH (contorno de filtro)"}


@dataclass
class Evidence:
    id: str
    kind: str            # identity|catalog|ti|tld|lexical|age|popularity|logs|tunnel|negative|platform|internal
    text: str
    risk: bool = False   # evidência que sustenta aumento de risco
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "text": self.text, "risk": self.risk, "data": self.data}


@dataclass
class RuleResult:
    classification: str
    risk: int
    work: int | None
    topic: str | None
    confidence: float
    final: bool                 # True = não precisa de IA
    needs_llm: bool
    action: str
    reasons: list[dict]
    flags: dict
    evidence: list[Evidence]
    evidence_hash: str
    category: str | None = None   # categoria do site quando as regras já sabem (senão: IA)


def _pop_text(rank: int) -> str:
    if rank <= 1000:
        return f"muito popular mundialmente (Tranco #{rank})"
    if rank <= 10000:
        return f"popular mundialmente (Tranco #{rank})"
    if rank <= 100000:
        return f"conhecido (Tranco #{rank})"
    return f"presente no top 1 milhão do Tranco (#{rank})"


def build_evidence(d: dict) -> list[Evidence]:
    """Transforma o dossiê em evidências numeradas (somente fatos observados/consultados)."""
    ev: list[Evidence] = []

    def add(kind, text, risk=False, **data):
        e = Evidence(f"E{len(ev)}", kind, text, risk, data)
        ev.append(e)
        return e

    name = d["name"]
    add("identity", f"nome do domínio: {name} (TLD .{d.get('tld') or '?'})", False, name=name)

    if d.get("kind") in ("internal", "reverse"):
        add("internal", "nome interno/local (AD, rede local ou DNS reverso) — não é domínio da internet")
        return ev

    if d.get("private_suffix"):
        add("platform", f"subdomínio da plataforma {d.get('platform')} (terceiros hospedam conteúdo nela; "
                        "IDs aleatórios são comuns)", False, platform=d.get("platform"))

    cat = d.get("catalog")
    if cat:
        add("catalog", f"{cat.get('label') or 'catálogo interno'}: {cat['topic']} ({cat['classification']})"
                       + ("; infraestrutura protegida" if cat.get("protected") else ""),
            False, suffix=cat["suffix"], protected=cat.get("protected", False))

    web = d.get("web") or {}
    wd = web.get("wikidata")
    if wd and wd.get("label"):
        add("wikidata", f"Wikidata (base curada): o site oficial de '{wd['label']}' é {name}"
                        + (f" — {wd['description']}" if wd.get("description") else ""), False, qid=wd.get("qid"))
    cert = web.get("cert") or {}
    if cert.get("verified") and (cert.get("org") or cert.get("san_domains")):
        partes = []
        if cert.get("org"):
            partes.append(f"emitido para a organização '{cert['org']}'")
        if cert.get("san_domains"):
            mais = cert.get("san_total", 0) - len(cert["san_domains"])
            partes.append("também cobre " + ", ".join(cert["san_domains"]) + (f" e +{mais}" if mais > 0 else "")
                          + " (mesmo dono)")
        add("cert", f"certificado TLS verificado ({cert.get('issuer') or 'CA'}): " + "; ".join(partes), False)
    site = web.get("site") or {}
    if site.get("title") or site.get("description") or site.get("site_name"):
        bits = [f"título '{site['title']}'" if site.get("title") else "",
                f"nome '{site['site_name']}'" if site.get("site_name") else "",
                f"descrição '{site['description']}'" if site.get("description") else ""]
        extra = f"; redireciona para {site['final_host']}" if site.get("final_host") not in (None, name, "www." + name) else ""
        add("site", "página inicial (texto DECLARADO pelo próprio site, não verificado): "
                    + "; ".join(b for b in bits if b) + extra, False)

    hits = d.get("ti_hits") or []
    for h in hits:
        where = "o próprio domínio" if h["matched"] == name else f"o host {h['matched']}"
        add("ti", f"{where} consta em {h['label']} (tipo: {h['threat']}, confiança da fonte: {h['confidence']})",
            True, source=h["source"], threat=h["threat"], confidence=h["confidence"],
            matched=h["matched"], weight=h["weight"])
    if not hits and d.get("kind") == "public":
        add("negative", "não encontrado nas listas de ameaça consultadas "
                        "(ausência em lista NÃO significa que é seguro)")

    if d.get("abused_tld"):
        add("tld", f"TLD .{d.get('tld')} está na lista de TLDs mais abusados", True)

    rank = d.get("popularity_rank")
    if rank:
        add("popularity", _pop_text(rank), False, rank=rank)
    elif d.get("platform_rank"):
        add("popularity", f"o domínio em si não está no Tranco; a plataforma {d.get('platform')} "
                          f"é #{d['platform_rank']}", False, platform_rank=d["platform_rank"])
    elif d.get("kind") == "public":
        add("popularity", "não está entre o 1 milhão de domínios mais acessados (Tranco)", False)

    age = d.get("age_days")
    if age is not None:
        risky = age < 180
        add("age", f"registrado há {age} dias ({d.get('registered_at')})", risky, age_days=age)

    f = d.get("features") or {}
    dga = f.get("sld_dga", 0) or 0
    if dga >= 0.45:
        add("lexical", f"nome com aparência aleatória (score DGA {dga:.2f}, entropia {f.get('sld_entropy')})",
            True, dga=dga)
    if f.get("punycode"):
        add("lexical", "nome internacionalizado (punycode) — pode imitar outro domínio", True)

    fs = d.get("fqdn_stats") or {}
    if fs.get("random_subs", 0) >= 20 and fs.get("count", 0) >= 30:
        add("tunnel", f"{fs['count']} subdomínios distintos, {fs['random_subs']} com aparência aleatória "
                      "(possível túnel DNS/DGA)", True)
    if fs.get("sample"):
        add("logs", "subdomínios observados (amostra): " + ", ".join(fs["sample"][:8]), False)

    lg = d.get("logs") or {}
    if lg:
        add("logs", f"{lg.get('total_queries', 0)} consultas de {lg.get('clients', 0)} computador(es) em "
                    f"{lg.get('tenants', 0)} cliente(s); visto pela primeira vez em {lg.get('first_seen_str', '?')}",
            False)
        nx = lg.get("nx_ratio") or 0
        if nx >= 0.5 and lg.get("total_queries", 0) >= 20:
            add("logs", f"{round(nx * 100)}% das consultas retornam NXDOMAIN (domínio inexistente)", True,
                nx_ratio=nx)
    return ev


def evaluate(d: dict) -> RuleResult:
    ev = build_evidence(d)
    by_kind = {}
    for e in ev:
        by_kind.setdefault(e.kind, []).append(e)
    kind = d.get("kind")
    name = d["name"]
    reasons: list[dict] = []
    flags = {"protected": False, "ti_high": False, "ti_medium": False, "ti_low": False, "popular": False}

    def reason(e: Evidence, text: str | None = None):
        reasons.append({"evidence_id": e.id, "text": text or e.text, "by": "regras"})

    # 1) nomes internos / inválidos: decisão final sem IA
    if kind in ("internal", "reverse"):
        e = by_kind["internal"][0]
        reason(e)
        return RuleResult("TRABALHO", 0, 100, "Interno (AD/rede local)" if kind == "internal" else "DNS reverso",
                          0.95, True, False, "NONE", reasons, flags, ev, _hash(d), category="interno")
    if kind in ("ip", "invalid"):
        reason(ev[0], "consulta a IP literal" if kind == "ip" else "nome DNS malformado")
        return RuleResult("DESCONHECIDO", 20, None, "Consulta a IP" if kind == "ip" else "Nome inválido",
                          0.5, True, False, "MONITOR", reasons, flags, ev, _hash(d), category="outros")

    rank = d.get("popularity_rank")
    popular = bool(rank and rank <= 10000)
    flags["popular"] = popular
    # no top 1M do Tranco: único caso em que faz sentido a IA "reconhecer" o serviço
    flags["ranked"] = bool(rank)
    cat = d.get("catalog")
    protected = bool(cat and cat.get("protected"))
    flags["protected"] = protected

    # 2) risco aditivo
    risk = 10
    platform = bool(d.get("private_suffix"))
    f = d.get("features") or {}
    dga = f.get("sld_dga", 0) or 0
    unpopular = not rank or rank > 100000
    for e in by_kind.get("lexical", []):
        if "DGA" in e.text and unpopular:
            pts = 25 if dga >= 0.6 else 12
            risk += pts // 2 if platform else pts
            reason(e)
        elif "punycode" in e.text:
            risk += 10
            reason(e)
    for e in by_kind.get("tld", []):
        risk += 15
        reason(e)
    for e in by_kind.get("age", []):
        a = e.data.get("age_days", 9999)
        if a < 7:
            risk += 30
        elif a < 30:
            risk += 20
        elif a < 180:
            risk += 8
        if a < 180:
            reason(e)
    for e in by_kind.get("tunnel", []):
        risk += 20
        reason(e)
    for e in by_kind.get("logs", []):
        if e.risk:
            risk += 10
            reason(e)
    if rank:
        risk -= 25 if rank <= 1000 else 20 if rank <= 10000 else 10 if rank <= 100000 else 5

    # 3) threat intel (piso de risco)
    ti = by_kind.get("ti", [])
    best, ti_conf = 0, set()
    for e in ti:
        w = int(e.data.get("weight", 0))
        if e.data.get("matched") != name:
            w = int(w * 0.75)       # só um host listado, não o domínio todo
        best = max(best, w)
        ti_conf.add(e.data.get("confidence"))
        reason(e)
    if len(ti) > 1:
        best += min(5 * (len({e.data.get('source') for e in ti}) - 1), 15)
    flags["ti_high"] = "high" in ti_conf
    flags["ti_medium"] = "medium" in ti_conf
    flags["ti_low"] = "low" in ti_conf
    risk = max(risk, best)

    # 4) travas contra falso positivo
    if ti and popular:
        cap = 70 if flags["ti_high"] else 45
        if risk > cap:
            risk = cap
    elif ti and rank and rank <= 100000 and not (flags["ti_high"] or flags["ti_medium"]):
        risk = min(risk, 45)
    risk = max(0, min(100, risk))

    # 5) decisão
    if cat:
        ce = by_kind["catalog"][0]
        reason(ce)
        action = "NONE"
        if protected:
            risk = min(risk, 30)
            if ti:
                action = "REVIEW"
                reasons.append({"evidence_id": ce.id, "by": "regras",
                                "text": "infraestrutura protegida listada em feed: provável falso positivo — revisar"})
        if not (flags["ti_high"] and not protected):
            from .categories import catalog_category
            return RuleResult(cat["classification"], risk, cat.get("work"), cat.get("topic"), 0.9,
                              True, False, action, reasons, flags, ev, _hash(d), category=catalog_category(cat))

    if flags["ti_high"] and not protected and not popular:
        threats = [e.data.get("threat") for e in ti if e.data.get("confidence") == "high"]
        topic = THREAT_TOPIC.get(threats[0], "Ameaça") if threats else "Ameaça"
        return RuleResult("MALICIOSO", max(risk, 85), 2, topic, 0.9, True, False, "BLOCK_CANDIDATE",
                          reasons, flags, ev, _hash(d), category="ameaca")

    # dica de categoria quando a única lista que casou é a de VPN/proxy/DoH
    hint = "vpn_proxy" if ti and all(e.data.get("threat") == "bypass" for e in ti) else None
    if risk >= 50:
        return RuleResult("SUSPEITO", risk, None, None, 0.6, False, True, "REVIEW", reasons, flags, ev, _hash(d),
                          category=hint)

    if not reasons:
        reasons.append({"evidence_id": ev[0].id, "by": "regras",
                        "text": "sem indícios técnicos de risco nas fontes consultadas"})
    return RuleResult("DESCONHECIDO", risk, None, None, 0.3, False, True,
                      "MONITOR" if risk >= 30 else "NONE", reasons, flags, ev, _hash(d), category=hint)


def _bucket(v, cuts):
    if v is None:
        return "na"
    for c in cuts:
        if v <= c:
            return str(c)
    return "big"


def _hash(d: dict) -> str:
    """Hash das evidências RELEVANTES (sem contadores voláteis de log)."""
    f = d.get("features") or {}
    fs = d.get("fqdn_stats") or {}
    lg = d.get("logs") or {}
    parts = [
        d["name"], d.get("kind", ""),
        ",".join(sorted({h["source"] + ":" + h["matched"] for h in d.get("ti_hits") or []})),
        "tld" if d.get("abused_tld") else "",
        _bucket(d.get("popularity_rank"), [1000, 10000, 100000, 1000000]),
        _bucket(d.get("age_days"), [7, 30, 180, 365]),
        _bucket(f.get("sld_dga"), [0.3, 0.45, 0.6, 1.0]),
        "tunnel" if fs.get("random_subs", 0) >= 20 and fs.get("count", 0) >= 30 else "",
        "nx" if (lg.get("nx_ratio") or 0) >= 0.5 and lg.get("total_queries", 0) >= 20 else "",
        (d.get("catalog") or {}).get("suffix", ""),
        # identidade externa estável (o título do site muda muito: fica de fora)
        ((d.get("web") or {}).get("wikidata") or {}).get("qid", "") or "",
        ((d.get("web") or {}).get("cert") or {}).get("org", "") or "",
        ",".join(((d.get("web") or {}).get("cert") or {}).get("san_domains", [])[:5]),
    ]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def age_days(registered: date | None, today: date | None = None) -> int | None:
    if not registered:
        return None
    today = today or datetime.now(timezone.utc).date()
    return max((today - registered).days, 0)
