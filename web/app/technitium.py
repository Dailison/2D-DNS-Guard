"""Integração com o Technitium DNS (app 'Advanced Blocking') para ISENTAR IPs do
filtro DNS: mapeia o IP para o grupo 'Liberados' (enableBlocking:false) no
`networkGroupMap`. Revogar = tirar o mapeamento (o IP volta a filtrar pela rede).

O config do Advanced Blocking é CRÍTICO (todas as blocklists dos sites vivem
nele). Aqui lemos o config inteiro, mexemos SÓ no `networkGroupMap`, e gravamos
de volta — nunca tocamos nos `groups`.
"""
import ipaddress
import json
import re
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

from flask import current_app

APP_NAME = "Advanced Blocking"

# Valores aceitos pelo filtro `responseType` do app Query Logs (Sqlite) do
# Technitium (enum DnsServerResponseType) e os rcodes mais comuns. Usados nos
# dropdowns da tela de Logs DNS.
RESPONSE_TYPES = ["Authoritative", "Recursive", "Cached", "Blocked",
                  "UpstreamBlocked", "CacheBlocked"]
RCODES = ["NoError", "NxDomain", "ServerFailure", "Refused",
          "FormatError", "NotImplemented"]

# Fuso de exibição dos logs. O Technitium grava os timestamps em UTC; convertemos
# para São Paulo na entrada (filtros) e na saída (tabela). Usa a base de fusos do
# sistema quando existir (respeita eventual horário de verão futuro); se faltar
# tzdata na imagem, cai para -03:00 fixo (Brasil hoje não tem horário de verão).
try:
    from zoneinfo import ZoneInfo
    TZ_LOCAL = ZoneInfo("America/Sao_Paulo")
except Exception:  # noqa: BLE001
    TZ_LOCAL = timezone(timedelta(hours=-3))


def _parse_utc(ts):
    """ISO do Technitium (UTC, às vezes com 'Z'/frações) -> datetime aware UTC."""
    if not ts:
        return None
    s = str(ts).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.fromisoformat(s[:19])
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def utc_para_local(ts):
    """Timestamp UTC do log -> 'YYYY-MM-DD HH:MM:SS' no fuso de São Paulo."""
    dt = _parse_utc(ts)
    return dt.astimezone(TZ_LOCAL).strftime("%Y-%m-%d %H:%M:%S") if dt else (ts or "")


def local_para_utc_iso(local_str):
    """'YYYY-MM-DDTHH:MM' digitado no fuso de São Paulo -> ISO UTC pra API."""
    s = (local_str or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s if len(s) > 16 else s + ":00")
    except ValueError:
        return s
    dt = dt.replace(tzinfo=TZ_LOCAL) if dt.tzinfo is None else dt
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def agora_local():
    """datetime 'agora' no fuso de São Paulo (naive, p/ preencher os inputs)."""
    return datetime.now(TZ_LOCAL).replace(tzinfo=None)


def _base():
    return (current_app.config.get("TECHNITIUM_URL") or "").rstrip("/")


def _token():
    return current_app.config.get("TECHNITIUM_TOKEN") or ""


def _grupo():
    return current_app.config.get("TECHNITIUM_LIBERADOS_GROUP") or "Liberados"


def _api_get(path, timeout=15):
    sep = "&" if "?" in path else "?"
    url = f"{_base()}/api/{path}{sep}token={urllib.parse.quote(_token())}"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    if d.get("status") != "ok":
        raise RuntimeError(d.get("errorMessage") or f"Technitium status={d.get('status')}")
    return d.get("response", {})


def _api_post(path, data, timeout=25):
    data = {"token": _token(), **data}
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(f"{_base()}/api/{path}", data=body)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    if d.get("status") != "ok":
        raise RuntimeError(d.get("errorMessage") or f"Technitium status={d.get('status')}")
    return d.get("response", {})


def _get_config():
    r = _api_get(f"apps/config/get?name={urllib.parse.quote(APP_NAME)}")
    cfg = r.get("config")
    return json.loads(cfg) if isinstance(cfg, str) else (cfg or {})


def _set_config(cfg):
    _api_post("apps/config/set", {"name": APP_NAME, "config": json.dumps(cfg)})


def norm_ip(v):
    """Normaliza IP ou CIDR. IP único -> 'x.x.x.x/32'. Retorna str ou None."""
    v = (v or "").strip()
    if not v:
        return None
    try:
        if "/" in v:
            return str(ipaddress.ip_network(v, strict=False))
        return f"{ipaddress.ip_address(v)}/32"
    except ValueError:
        return None


def _sort_key(cidr):
    try:
        return int(ipaddress.ip_network(cidr, strict=False).network_address)
    except ValueError:
        return 0


def listar():
    """IPs/redes atualmente no grupo de isenção (Liberados)."""
    cfg = _get_config()
    grp = _grupo()
    out = [norm_ip(k) or k for k, v in cfg.get("networkGroupMap", {}).items() if v == grp]
    return sorted(out, key=_sort_key)


def liberar(ip_raw, por="admin"):
    """Mapeia o IP/CIDR para o grupo de isenção. Retorna (ip_norm, msg) ou (None, erro)."""
    ipn = norm_ip(ip_raw)
    if not ipn:
        return None, "IP ou CIDR inválido (ex.: 10.100.10.20 ou 10.100.10.0/24)."
    grp = _grupo()
    cfg = _get_config()
    ngmap = cfg.setdefault("networkGroupMap", {})
    anterior = None
    for k in list(ngmap):
        if norm_ip(k) == ipn:
            if ngmap[k] != grp:
                anterior = ngmap[k]
            del ngmap[k]
    ngmap[ipn] = grp
    _set_config(cfg)
    return ipn, (f"liberado (antes filtrava em '{anterior}')" if anterior else "liberado")


def revogar(ip_raw):
    """Remove o IP do grupo de isenção (volta a filtrar pela rede). Retorna ip_norm ou None."""
    ipn = norm_ip(ip_raw)
    if not ipn:
        return None
    grp = _grupo()
    cfg = _get_config()
    ngmap = cfg.get("networkGroupMap", {})
    removed = False
    for k in list(ngmap):
        if norm_ip(k) == ipn and ngmap[k] == grp:
            del ngmap[k]
            removed = True
    if removed:
        _set_config(cfg)
        return ipn
    return None


# ---- Bloqueios por grupo (domínios da lista `blocked` de cada grupo) ----

def ngm_de(cfg):
    """networkGroupMap (ip_network -> grupo) a partir de uma config já carregada."""
    out = {}
    for k, v in cfg.get("networkGroupMap", {}).items():
        try:
            out[ipaddress.ip_network(k, strict=False)] = v
        except ValueError:
            pass
    return out


def grupo_da_rede(cidr, ngm):
    """Grupo de bloqueio que vale para uma rede: a entrada mais específica do
    networkGroupMap que a contém."""
    net = ipaddress.ip_network(cidr, strict=False)
    best = None
    for k, g in ngm.items():
        if k.version == net.version and net.subnet_of(k) and (best is None or k.prefixlen > best[0].prefixlen):
            best = (k, g)
    return best[1] if best else None


# ------------------------------------------------ listas por categoria (assinadas pelos grupos)
# O analisador publica /listas/<categoria>.txt; cada grupo assina as que quiser (blockListUrls).
CATEGORIAS_LISTA = [("ameaca", "Ameaças"), ("vpn_proxy", "VPN / Proxy"), ("adulto", "Conteúdo adulto"),
                    ("apostas", "Apostas"), ("jogos", "Jogos"), ("redes_sociais", "Redes sociais"), ("mensageiros", "Mensageiros"),
                    ("streaming", "Vídeo e streaming"), ("publicidade", "Publicidade e rastreamento"),
                    ("compras", "Compras"), ("noticias", "Notícias"), ("infra_bloqueio", "Infraestrutura (DoH, DNS, CDN)"),
                    ("outros_bloqueios", "Outros bloqueios"),
                    ("para_revisar", "Para revisar")]
CATEGORIAS_RISCO = {"ameaca", "vpn_proxy", "adulto", "apostas", "jogos"}   # bloqueio automático

_LISTA_RE = re.compile(r"/listas/([a-z_]+)\.txt$")


def url_lista(cat):
    return (current_app.config.get("ANALYZER_URL") or "").rstrip("/") + f"/listas/{cat}.txt"


def listas_assinadas(g):
    """Categorias que o grupo assina (pelas URLs de listas do DNS Guard em blockListUrls)."""
    return sorted({m.group(1) for u in (g.get("blockListUrls") or []) if (m := _LISTA_RE.search(str(u)))})


def dominios_das_listas(cats):
    """{categoria: set(domínios)} (do analisador, 1 chamada; cache por requisição). Falha = vazio."""
    from flask import g as fg
    from app import analyzer_client as api
    cache = fg.setdefault("_listas_cat", {})
    falta = [c for c in cats if c not in cache]
    if falta:
        try:
            r = api.get("/listas-dominios", cats=falta)
        except Exception:  # noqa: BLE001
            r = {}
        for c in falta:
            cache[c] = set(r.get(c) or [])
    return {c: cache[c] for c in cats}


def dominios_liberacao(slug):
    """Domínios de uma lista de liberação (do analisador; cache por requisição). Falha = vazio."""
    from flask import g as fg
    from app import analyzer_client as api
    cache = fg.setdefault("_lib_cat", {})
    if slug not in cache:
        try:
            cache[slug] = {r["domain"] for r in api.get(f"/liberacao/{slug}", limit=20000)}
        except Exception:  # noqa: BLE001
            cache[slug] = set()
    return cache[slug]


def indice_bloqueio(cfg=None):
    """Índice p/ checar muitos domínios de uma vez (listas): {grupo: set(entradas)} dos
    grupos com bloqueio ligado + networkGroupMap. Montado uma vez por página. Inclui os
    domínios das listas por categoria que o grupo assina."""
    cfg = cfg if cfg is not None else _get_config()
    ativos = [g for g in cfg.get("groups", []) if g.get("name") and g.get("enableBlocking", True)]
    cats = sorted({c for g in ativos for c in listas_assinadas(g)})
    doms = dominios_das_listas(cats) if cats else {}
    grupos, permitidos = {}, {}
    for g in ativos:
        s = {x.lower() for x in g.get("blocked", [])}
        for c in listas_assinadas(g):
            s |= doms.get(c, set())
        for u in g.get("blockListUrls") or []:
            m = _LIB_RE.search(str(u))
            if m:
                s |= dominios_liberacao(m.group(1))
        grupos[g["name"]] = s
        permitidos[g["name"]] = {x.lower() for x in g.get("allowed") or []}
        for slug in listas_liberacao_do_grupo(g):
            permitidos[g["name"]] |= dominios_liberacao(slug)
    return {"grupos": grupos, "permitidos": permitidos, "ngm": ngm_de(cfg), "ativos": sorted(grupos)}


def bloqueado_em(indice, dominio, grupos=None):
    """Grupos (dentre `grupos`, ou todos) em que o domínio está bloqueado — por ele
    mesmo ou por um domínio pai. Subdomínios bloqueados isolados não contam aqui."""
    d = (dominio or "").lower().rstrip(".")
    parts = d.split(".")
    cands = {".".join(parts[i:]) for i in range(len(parts))}
    alvo = grupos if grupos is not None else indice["ativos"]
    perm = indice.get("permitidos") or {}
    # exceção liberada no grupo (allowed) vence qualquer bloqueio dele
    return [g for g in alvo if indice["grupos"].get(g, set()) & cands and not (perm.get(g, set()) & cands)]


def blocked_index():
    """(union, por_lista): todos os domínios das listas de bloqueio por categoria (do analisador) e
    {lista: set(domínios)}. Para diagnosticar qual entrada causa um bloqueio (inclusive por CNAME)."""
    doms = dominios_das_listas([c for c, _ in CATEGORIAS_LISTA])
    return set().union(*doms.values()) if doms else set(), doms


def parse_chain(answer):
    """Extrai os hostnames da cadeia CNAME de um `answer` de log
    (ex.: 'CNAME a.b.com., CNAME c.d.net., A 0.0.0.0')."""
    doms = []
    for part in (answer or "").split(","):
        part = part.strip()
        if part.upper().startswith("CNAME "):
            h = part[6:].strip().rstrip(".").lower()
            if h and h not in doms:
                doms.append(h)
    return doms


def culpados(qname, answer, union):
    """Dado o nome consultado + a cadeia CNAME, retorna as entradas da lista
    `union` que causam o bloqueio (o próprio nome ou um ancestral de qualquer
    elo da cadeia). Ordenado, sem repetição."""
    alvos = [qname] + parse_chain(answer)
    out = []
    for d in alvos:
        d = (d or "").strip().rstrip(".").lower()
        labels = d.split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            if cand in union:
                if cand not in out:
                    out.append(cand)
                break
    return out


def networkgroupmap():
    """{ip_network: grupo} do Advanced Blocking, para resolver a empresa do IP."""
    cfg = _get_config()
    out = {}
    for k, v in cfg.get("networkGroupMap", {}).items():
        try:
            out[ipaddress.ip_network(k, strict=False)] = v
        except ValueError:
            pass
    return out


def resolver_empresa(ip_str, mapa):
    """Empresa do IP por longest-prefix match, ou None."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    best, best_len = None, -1
    for net, grp in mapa.items():
        if ip in net and net.prefixlen > best_len:
            best, best_len = grp, net.prefixlen
    return best


def consultar_logs(mapa, redes=None, inicio=None, fim=None, dominio=None,
                   ip_exato=None, ip_like=None, resposta=None, rcode=None,
                   limite=300, scan_max=6000, por_pagina=500, orcamento_s=25):
    """Consulta os query logs do Technitium (período/IP/tipo-de-resposta/rcode
    empurrados para a API); resolve a empresa e filtra por `redes` (CIDR),
    `dominio` (substring, %dominio%) e `ip_like` (parte do IP, ex.: '10.100') no
    app, pois a API não faz range nem match parcial. Retorna (linhas, scaneados,
    atingiu_cap). Os timestamps voltam já convertidos para o fuso de São Paulo."""
    base = {"name": "Query Logs (Sqlite)", "classPath": "QueryLogsSqlite.App",
            "descendingOrder": "true"}
    if inicio:
        base["start"] = inicio
    if fim:
        base["end"] = fim
    if ip_exato:
        base["clientIpAddress"] = ip_exato.strip()
    if resposta:
        base["responseType"] = resposta.strip()
    if rcode:
        base["rcode"] = rcode.strip()
    dom_like = (dominio or "").strip().lower()
    ip_sub = (ip_like or "").strip()
    import time
    t0 = time.monotonic()
    linhas, scanned, page = [], 0, 1
    while len(linhas) < limite and scanned < scan_max:
        if page > 1 and time.monotonic() - t0 > orcamento_s:
            break                      # cada página custa segundos no Technitium: não estoura o timeout
        r = _api_get("logs/query?" + urllib.parse.urlencode(
            {**base, "pageNumber": page, "entriesPerPage": por_pagina}), timeout=60)
        ents = r.get("entries", [])
        if not ents:
            break
        for e in ents:
            scanned += 1
            cip = e.get("clientIpAddress", "")
            if dom_like and dom_like not in (e.get("qname") or "").lower():
                continue
            if ip_sub and ip_sub not in cip:
                continue
            if redes is not None:
                try:
                    ipo = ipaddress.ip_address(cip)
                except ValueError:
                    continue
                if not any(ipo in n for n in redes):
                    continue
            linhas.append({
                "timestamp": utc_para_local(e.get("timestamp")), "ip": cip,
                "empresa": resolver_empresa(cip, mapa) or "—",
                "dominio": e.get("qname"), "tipo": e.get("qtype"),
                "resposta": e.get("responseType"), "rcode": e.get("rcode"),
                "answer": e.get("answer"),
            })
            if len(linhas) >= limite:
                break
        if len(ents) < por_pagina:
            break
        page += 1
    return linhas, scanned, (len(linhas) >= limite or scanned >= scan_max)


# ------------------------------------------------ políticas por empresa -> grupos internos
# O usuário vincula LISTAS às empresas (e, se precisar, a uma unidade); o Technitium só aceita
# UM grupo por rede, então o console mantém sozinho um grupo por política: "Empresa: <nome>"
# (ou "Empresa: <nome> · <unidade>"). Ninguém edita esses grupos à mão.
PREFIXO_GRUPO = "Empresa: "


def nome_grupo(empresa: str, unidade: str | None = None) -> str:
    return PREFIXO_GRUPO + empresa + (f" · {unidade}" if unidade else "")


def plano_politicas(empresas, politicas):
    """-> (grupos {nome: {"lists", "services"}}, mapa {cidr: grupo}, default {"lists","services"}).
    Rede de empresa sem política (nem da unidade nem da empresa) fica sem mapeamento: vale o default."""
    pol = {p["scope"]: p for p in politicas}
    grupos, mapa = {}, {}
    for e in empresas:
        pe = pol.get(f"tenant:{e['id']}")
        for n in e.get("networks") or []:
            cidr = norm_ip(n.get("cidr"))
            if not cidr:
                continue
            unidade = n.get("unit") or ""
            pu = pol.get(f"unit:{e['id']}:{unidade}") if unidade else None
            p, nome = (pu, nome_grupo(e["name"], unidade)) if pu else (pe, nome_grupo(e["name"]))
            if not p:
                continue
            grupos[nome] = {"lists": sorted(p.get("lists") or []), "services": sorted(p.get("services") or []),
                            "blocked": sorted(p.get("services_blocked") or [])}
            mapa[cidr] = nome
    d = pol.get("default") or {}
    return grupos, mapa, {"lists": sorted(d.get("lists") or []), "services": sorted(d.get("services") or []),
                          "blocked": sorted(d.get("services_blocked") or [])}


_LIB_RE = re.compile(r"/(?:liberacao|servico)/([a-z0-9-]+)\.txt$")


def url_liberacao(slug):
    """URL de um serviço / lista de liberação (a mesma serve p/ bloquear ou liberar)."""
    return (current_app.config.get("ANALYZER_URL") or "").rstrip("/") + f"/servico/{slug}.txt"


def listas_liberacao_do_grupo(g):
    return sorted({m.group(1) for u in (g.get("allowListUrls") or []) if (m := _LIB_RE.search(str(u)))})


def _aplica_politica(g, lists, services, bloqueados=()):
    """Listas de bloqueio + serviços bloqueados -> blockListUrls; serviços/listas de liberação
    liberados -> allowListUrls (vencem o bloqueio). URLs de terceiros e liberações manuais ficam."""
    outras = [u for u in (g.get("blockListUrls") or []) if not _LISTA_RE.search(str(u)) and not _LIB_RE.search(str(u))]
    g["blockListUrls"] = (outras + [url_lista(c) for c, _ in CATEGORIAS_LISTA if c in set(lists)]
                          + [url_liberacao(s) for s in sorted(set(bloqueados) - set(services))])
    outras = [u for u in (g.get("allowListUrls") or []) if not _LIB_RE.search(str(u))]
    g["allowListUrls"] = outras + [url_liberacao(s) for s in sorted(set(services))]


def sincronizar_politicas(empresas, politicas, aplicar=True):
    """Deixa o Technitium igual às políticas: cria/atualiza/apaga os grupos "Empresa: …", aponta
    as redes das empresas para eles e aplica a política default no grupo default. Não mexe no
    grupo Liberados nem em redes/IPs mapeados para ele. Retorna um resumo do que mudou."""
    cfg = _get_config()
    grupos, mapa, default = plano_politicas(empresas, politicas)
    lib = current_app.config.get("TECHNITIUM_LIBERADOS_GROUP", "Liberados")
    existentes = {g.get("name"): g for g in cfg.get("groups", [])}
    criados, atualizados, apagados = [], [], []
    for nome, p in grupos.items():
        g = existentes.get(nome)
        if g is None:
            g = {"name": nome, "enableBlocking": True, "allowTxtBlockingReport": True, "blockAsNxDomain": False,
                 "blockingAddresses": (existentes.get("default") or {}).get("blockingAddresses", ["0.0.0.0", "::"]),
                 "allowed": [], "blocked": [], "allowListUrls": [], "blockListUrls": [],
                 "allowedRegex": [], "blockedRegex": [], "regexAllowListUrls": [], "regexBlockListUrls": [],
                 "adblockListUrls": []}
            cfg.setdefault("groups", []).append(g)
            criados.append(nome)
        else:
            atualizados.append(nome)
        g["enableBlocking"] = True
        _aplica_politica(g, p["lists"], p["services"], p["blocked"])
    if "default" in existentes:
        _aplica_politica(existentes["default"], default["lists"], default["services"], default["blocked"])
    ngm = cfg.setdefault("networkGroupMap", {})
    for k in list(ngm):
        v = ngm[k]
        if v == lib:
            continue                      # isenções (Liberados) ficam como estão
        if norm_ip(k) in mapa or (str(v).startswith(PREFIXO_GRUPO) and v not in grupos):
            del ngm[k]                    # será reapontado (ou o grupo da empresa deixou de existir)
    for cidr, nome in mapa.items():
        if ngm.get(cidr) != lib:
            ngm[cidr] = nome
    for g in list(cfg.get("groups", [])):
        n = g.get("name") or ""
        if n.startswith(PREFIXO_GRUPO) and n not in grupos:
            cfg["groups"].remove(g)
            apagados.append(n)
    if aplicar:
        _set_config(cfg)
    return {"criados": criados, "atualizados": atualizados, "apagados": apagados, "redes": len(mapa),
            "default": default, "cfg": cfg}
