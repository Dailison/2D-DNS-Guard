"""Integração com o Technitium DNS (app 'Advanced Blocking') para ISENTAR IPs do
filtro DNS: mapeia o IP para o grupo 'Liberados' (enableBlocking:false) no
`networkGroupMap`. Revogar = tirar o mapeamento (o IP volta a filtrar pela rede).

O config do Advanced Blocking é CRÍTICO (todas as blocklists dos sites vivem
nele). Aqui lemos o config inteiro, mexemos SÓ no `networkGroupMap`, e gravamos
de volta — nunca tocamos nos `groups`.
"""
import copy
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

def _grupo_obj(cfg, nome):
    for g in cfg.get("groups", []):
        if g.get("name") == nome:
            return g
    return None


def grupos_bloqueio():
    """Nomes dos grupos (seletor das telas Grupos e Domínios)."""
    cfg = _get_config()
    return sorted(g.get("name") for g in cfg.get("groups", []) if g.get("name"))


# ---- Bloquear/liberar UM domínio (ações da tela Análise DNS -> domínio) ----

_NOME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


def _norm_nome(dominio):
    d = (dominio or "").strip().rstrip(".").lower()
    if not d or not _NOME_RE.match(d):
        raise ValueError(f"domínio inválido: {dominio!r}")
    return d


def tipo_entrada(entrada, dominio):
    """Como uma entrada de `blocked` afeta o domínio: exata | pai | sub."""
    if entrada == dominio:
        return "exata"
    return "pai" if dominio.endswith("." + entrada) else "sub"


def grupos_ativos(cfg):
    """Grupos com bloqueio ligado (exclui os de isenção, como Liberados)."""
    return sorted(g["name"] for g in cfg.get("groups", []) if g.get("name") and g.get("enableBlocking", True))


def estado_bloqueio(dominio, cfg=None):
    """{grupo: [(entrada, tipo)]}: entradas de `blocked` que afetam o domínio — o
    próprio nome (exata), um domínio pai (bloqueia tudo abaixo) ou subdomínios (parcial)."""
    d = _norm_nome(dominio)
    cfg = cfg if cfg is not None else _get_config()
    out = {}
    for g in cfg.get("groups", []):
        if not g.get("enableBlocking", True):
            continue
        hits = []
        for e in g.get("blocked", []):
            el = e.lower()
            if el == d or d.endswith("." + el) or el.endswith("." + d):
                hits.append((el, tipo_entrada(el, d)))
        if hits:
            out[g["name"]] = sorted(hits, key=lambda x: ({"exata": 0, "pai": 1, "sub": 2}[x[1]], x[0]))
    return out


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


def indice_bloqueio(cfg=None):
    """Índice p/ checar muitos domínios de uma vez (listas): {grupo: set(entradas)} dos
    grupos com bloqueio ligado + networkGroupMap. Montado uma vez por página."""
    cfg = cfg if cfg is not None else _get_config()
    grupos = {g["name"]: {x.lower() for x in g.get("blocked", [])}
              for g in cfg.get("groups", []) if g.get("name") and g.get("enableBlocking", True)}
    return {"grupos": grupos, "ngm": ngm_de(cfg), "ativos": sorted(grupos)}


def bloqueado_em(indice, dominio, grupos=None):
    """Grupos (dentre `grupos`, ou todos) em que o domínio está bloqueado — por ele
    mesmo ou por um domínio pai. Subdomínios bloqueados isolados não contam aqui."""
    d = (dominio or "").lower().rstrip(".")
    parts = d.split(".")
    cands = {".".join(parts[i:]) for i in range(len(parts))}
    alvo = grupos if grupos is not None else indice["ativos"]
    return [g for g in alvo if indice["grupos"].get(g, set()) & cands]


def bloquear_em(grupos, dominio):
    """Adiciona o domínio (e, com isso, seus subdomínios) ao `blocked` dos grupos,
    numa única gravação. Retorna {grupo: 'adicionado' | 'já bloqueado' | 'grupo inexistente'}."""
    d = _norm_nome(dominio)
    cfg = _get_config()
    res, mudou = {}, False
    for nome in grupos:
        g = _grupo_obj(cfg, nome)
        if g is None:
            res[nome] = "grupo inexistente"
            continue
        atual = {x.lower() for x in g.get("blocked", [])}
        if d in atual or any(d.endswith("." + p) for p in atual):
            res[nome] = "já bloqueado"
            continue
        g["blocked"] = sorted(atual | {d})
        res[nome] = "adicionado"
        mudou = True
    if mudou:
        _set_config(cfg)
        limpar_cache(d)
    return res


def bloquear_varios_em(grupos, dominios):
    """Vários domínios em vários grupos, numa única gravação.
    Retorna {grupo: {'adicionados': [...], 'ja': [...]}} (grupo inexistente fica de fora)."""
    ds = list(dict.fromkeys(_norm_nome(x) for x in dominios if x))
    cfg = _get_config()
    res, novos = {}, set()
    for nome in grupos:
        g = _grupo_obj(cfg, nome)
        if g is None:
            continue
        atual = {x.lower() for x in g.get("blocked", [])}
        r = res[nome] = {"adicionados": [], "ja": []}
        for d in ds:
            if d in atual or any(d.endswith("." + p) for p in atual):
                r["ja"].append(d)
            else:
                atual.add(d)
                r["adicionados"].append(d)
                novos.add(d)
        g["blocked"] = sorted(atual)
    if novos:
        _set_config(cfg)
        for d in novos:
            limpar_cache(d)
    return res


def liberar_em(grupos, dominio):
    """Remove do `blocked` dos grupos as entradas EXATAS e de SUBDOMÍNIOS do domínio
    (numa única gravação). Entradas de domínio PAI não são removidas (liberariam
    tudo abaixo delas): voltam em `restam` para o operador decidir em Domínios."""
    d = _norm_nome(dominio)
    cfg = _get_config()
    removidas, restam, mudou = {}, {}, False
    for nome in grupos:
        g = _grupo_obj(cfg, nome)
        if g is None:
            continue
        manter, tirar = [], []
        for e in g.get("blocked", []):
            el = e.lower()
            if el == d or el.endswith("." + d):
                tirar.append(el)
            else:
                manter.append(e)
                if d.endswith("." + el):
                    restam.setdefault(nome, []).append(el)
        if tirar:
            g["blocked"] = manter
            removidas[nome] = sorted(tirar)
            mudou = True
    if mudou:
        _set_config(cfg)
        limpar_cache(d)
    return removidas, restam


def limpar_cache(dominio):
    """Tira o domínio do cache do Technitium (a mudança vale na próxima consulta)."""
    try:
        _api_get(f"cache/delete?domain={urllib.parse.quote(dominio)}")
    except Exception:  # noqa: BLE001 — cache é otimização; a regra já foi gravada
        pass


# Listas por-grupo que definem o que o grupo bloqueia/permite (zeradas num grupo vazio)
_LISTAS_GRUPO = ("blocked", "allowed", "blockedRegex", "allowedRegex",
                 "blockListUrls", "allowListUrls", "regexBlockListUrls",
                 "regexAllowListUrls", "adblockListUrls")


def _grupos_protegidos():
    """Grupos do sistema que não podem ser renomeados/removidos: o `default`
    (exigido pelo Technitium) e o de isenção usado pela tela Liberados."""
    return {"default", _grupo()}


def renomear_grupo(velho, novo):
    """Renomeia um grupo e atualiza as redes que apontam para ele no
    networkGroupMap. Retorna (novo_nome, msg) ou (None, erro)."""
    velho = (velho or "").strip()
    novo = (novo or "").strip()[:150]
    if not novo:
        return None, "Informe o novo nome."
    if velho in _grupos_protegidos():
        return None, f"O grupo '{velho}' é do sistema e não pode ser renomeado."
    cfg = _get_config()
    g = _grupo_obj(cfg, velho)
    if g is None:
        return None, f"Grupo '{velho}' não existe."
    if novo == velho:
        return None, "O novo nome é igual ao atual."
    if _grupo_obj(cfg, novo) is not None:
        return None, f"Já existe um grupo chamado '{novo}'."
    g["name"] = novo
    for k, v in cfg.get("networkGroupMap", {}).items():
        if v == velho:
            cfg["networkGroupMap"][k] = novo
    _set_config(cfg)
    return novo, "renomeado"


def deletar_grupo(grupo):
    """Remove um grupo e desatribui as redes que apontavam para ele. Retorna
    (grupo, nº_redes_desatribuídas) ou (None, erro)."""
    grupo = (grupo or "").strip()
    if grupo in _grupos_protegidos():
        return None, f"O grupo '{grupo}' é do sistema e não pode ser removido."
    cfg = _get_config()
    if _grupo_obj(cfg, grupo) is None:
        return None, f"Grupo '{grupo}' não existe."
    cfg["groups"] = [x for x in cfg.get("groups", []) if x.get("name") != grupo]
    ngm = cfg.get("networkGroupMap", {})
    redes = [k for k, v in ngm.items() if v == grupo]
    for k in redes:
        del ngm[k]
    _set_config(cfg)
    return grupo, len(redes)


def criar_grupo(nome, clonar_de=None):
    """Cria um novo grupo no Advanced Blocking. Se `clonar_de`, copia a estrutura
    inteira do grupo de origem (incl. domínios bloqueados); senão cria vazio.
    Preserva todos os campos exigidos pelo Technitium via deep-copy de um modelo.
    Retorna (nome, msg) em sucesso ou (None, erro)."""
    nome = (nome or "").strip()[:150]
    if not nome:
        return None, "Informe o nome do grupo."
    cfg = _get_config()
    grupos = cfg.get("groups")
    if not grupos:
        return None, "Nenhum grupo modelo disponível no Technitium."
    if _grupo_obj(cfg, nome) is not None:
        return None, f"Já existe um grupo chamado '{nome}'."
    if clonar_de:
        src = _grupo_obj(cfg, clonar_de)
        if src is None:
            return None, f"Grupo de origem '{clonar_de}' não encontrado."
        novo = copy.deepcopy(src)
        novo["name"] = nome
        msg = f"criado (clonado de '{clonar_de}': {len(novo.get('blocked', []))} bloqueios)"
    else:
        novo = copy.deepcopy(grupos[0])   # modelo p/ manter todos os campos exigidos
        novo["name"] = nome
        for k in _LISTAS_GRUPO:
            if k in novo:
                novo[k] = []
        msg = "criado (vazio)"
    grupos.append(novo)
    _set_config(cfg)
    return nome, msg


def redes_do_grupo(grupo):
    """CIDRs/IPs atribuídos a um grupo no networkGroupMap (redes que usam esse grupo)."""
    cfg = _get_config()
    out = [norm_ip(k) or k for k, v in cfg.get("networkGroupMap", {}).items() if v == grupo]
    return sorted(out, key=_sort_key)


def atribuir_rede(ip_raw, grupo):
    """Atribui uma rede/IP (CIDR) a um grupo de bloqueio no networkGroupMap.
    Retorna (cidr, anterior_ou_None) ou (None, mensagem_erro)."""
    ipn = norm_ip(ip_raw)
    if not ipn:
        return None, "IP ou faixa inválidos (ex.: 10.23.0.0/16 ou 10.23.5.10)."
    cfg = _get_config()
    if _grupo_obj(cfg, grupo) is None:
        return None, f"Grupo '{grupo}' não existe."
    ngmap = cfg.setdefault("networkGroupMap", {})
    anterior = None
    for k in list(ngmap):
        if norm_ip(k) == ipn:
            if ngmap[k] != grupo:
                anterior = ngmap[k]
            del ngmap[k]
    ngmap[ipn] = grupo
    _set_config(cfg)
    return ipn, anterior


def atribuir_redes(ips, grupo):
    """Várias redes de uma vez (1 leitura/gravação do config). Retorna
    ([(cidr, anterior_ou_None)], [inválidos]) ou levanta ValueError se o grupo não existe."""
    cfg = _get_config()
    if _grupo_obj(cfg, grupo) is None:
        raise ValueError(f"Grupo '{grupo}' não existe.")
    ngmap = cfg.setdefault("networkGroupMap", {})
    feitos, invalidos = [], []
    for ip_raw in ips:
        ipn = norm_ip(ip_raw)
        if not ipn:
            invalidos.append(ip_raw)
            continue
        anterior = None
        for k in list(ngmap):
            if norm_ip(k) == ipn:
                if ngmap[k] != grupo:
                    anterior = ngmap[k]
                del ngmap[k]
        ngmap[ipn] = grupo
        feitos.append((ipn, anterior))
    if feitos:
        _set_config(cfg)
    return feitos, invalidos


def remover_rede(ip_raw, grupo):
    """Remove a atribuição de uma rede/IP de um grupo (só se estiver nesse grupo)."""
    ipn = norm_ip(ip_raw)
    if not ipn:
        return None
    cfg = _get_config()
    ngmap = cfg.get("networkGroupMap", {})
    removed = False
    for k in list(ngmap):
        if norm_ip(k) == ipn and ngmap[k] == grupo:
            del ngmap[k]
            removed = True
    if removed:
        _set_config(cfg)
        return ipn
    return None


def _clean_dom(line):
    s = (line or "").strip()
    if not s or s[0] in "#!;[":
        return None
    parts = s.split()
    if len(parts) >= 2 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[0]):
        s = parts[1]          # formato hosts: "0.0.0.0 dominio"
    else:
        s = parts[0]
    s = s.lstrip("|").rstrip("^").replace("*.", "")
    s = re.sub(r"^https?://", "", s).split("/")[0].strip(".").lower()
    if re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", s):
        return s
    return None


def parse_dominios(texto):
    """Extrai domínios de um texto (um por linha; aceita hosts/adblock/comentários)."""
    seen, res = set(), []
    for line in (texto or "").splitlines():
        d = _clean_dom(line)
        if d and d not in seen:
            seen.add(d)
            res.append(d)
    return res


def _norm_busca(s):
    """Normaliza o termo de busca para casar mesmo quando se cola uma URL ou
    formato de blocklist: tira esquema (http/https), caminho após '/', prefixos
    '||'/'*.'/'www.' e '^'/'.' das pontas. Assim 'https://openai.com/',
    'www.openai.com' e '||openai.com^' casam com 'openai.com' e seus subdomínios."""
    s = (s or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0].split("?")[0]
    s = s.lstrip("|").replace("*.", "").strip(".^")
    if s.startswith("www."):
        s = s[4:]
    return s


def bloqueados(grupo, busca=None):
    cfg = _get_config()
    g = _grupo_obj(cfg, grupo)
    if g is None:
        return None
    doms = sorted(g.get("blocked", []))
    if busca:
        b = _norm_busca(busca)
        if b:
            doms = [d for d in doms if b in d.lower()]
    return doms


def add_bloqueio(grupo, dominios):
    """Adiciona 1+ domínios à lista `blocked` do grupo (dedupe). Retorna
    (adicionados, ja_existiam, total) ou (None, 0, 0) se grupo inexistente."""
    novos = parse_dominios(dominios) if isinstance(dominios, str) else \
        [d for d in (_clean_dom(x) for x in dominios) if d]
    cfg = _get_config()
    g = _grupo_obj(cfg, grupo)
    if g is None:
        return None, 0, 0
    atual = set(g.get("blocked", []))
    add = [d for d in dict.fromkeys(novos) if d not in atual]
    if add:
        g["blocked"] = sorted(atual | set(add))
        _set_config(cfg)
    return len(add), len(novos) - len(add), len(g.get("blocked", []))


def limpar_bloqueios(grupo):
    """Esvazia a lista `blocked` do grupo. Retorna nº removidos, ou None se o grupo
    não existe. Não toca em allowed/URLs/regex nem em outros grupos."""
    cfg = _get_config()
    g = _grupo_obj(cfg, grupo)
    if g is None:
        return None
    n = len(g.get("blocked", []))
    if n:
        g["blocked"] = []
        _set_config(cfg)
    return n


def rem_bloqueio(grupo, dominio):
    dom = (dominio or "").strip().lower()
    cfg = _get_config()
    g = _grupo_obj(cfg, grupo)
    if g is None or dom not in set(g.get("blocked", [])):
        return None
    g["blocked"] = [d for d in g.get("blocked", []) if d != dom]
    _set_config(cfg)
    return dom


def rem_bloqueios(grupo, dominios):
    """Remove vários domínios da lista `blocked` do grupo numa única gravação.
    Retorna (removidos, total_restante) ou (None, 0) se o grupo não existe."""
    alvo = {(d or "").strip().lower() for d in (dominios or []) if (d or "").strip()}
    cfg = _get_config()
    g = _grupo_obj(cfg, grupo)
    if g is None:
        return None, 0
    atual = g.get("blocked", [])
    restante = [d for d in atual if d.lower() not in alvo]
    rem = len(atual) - len(restante)
    if rem:
        g["blocked"] = restante
        _set_config(cfg)
    return rem, len(restante)


def buscar_em_todos(termo, limite=500):
    """Procura `termo` (substring) na lista `blocked` de TODOS os grupos.
    Retorna (itens, total, cap) onde itens = [(dominio, [grupos])] ordenado."""
    t = (termo or "").strip().lower()
    if not t:
        return [], 0, False
    cfg = _get_config()
    mapa = {}
    for g in cfg.get("groups", []):
        gn = g.get("name")
        for d in g.get("blocked", []):
            if t in d.lower():
                mapa.setdefault(d, []).append(gn)
    itens = sorted(mapa.items())
    total = len(itens)
    return [(d, grs) for d, grs in itens[:limite]], total, total > limite


def blocked_index():
    """Retorna (union, bygroup): conjunto de todos os domínios bloqueados (união
    de todos os grupos) e o mapa {grupo: set(domínios)}. Para diagnosticar qual
    entrada da lista causa um bloqueio (inclusive por cadeia CNAME)."""
    cfg = _get_config()
    union, bygroup = set(), {}
    for g in cfg.get("groups", []):
        s = {x.lower() for x in g.get("blocked", [])}
        bygroup[g.get("name")] = s
        union |= s
    return union, bygroup


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


def rem_dominios_todos(dominios):
    """Remove os domínios (exatos) da lista `blocked` de TODOS os grupos numa
    única gravação. Retorna (remocoes, grupos_afetados)."""
    alvo = {(d or "").strip().lower() for d in (dominios or []) if (d or "").strip()}
    if not alvo:
        return 0, 0
    cfg = _get_config()
    rem, gruposaf = 0, 0
    for g in cfg.get("groups", []):
        atual = g.get("blocked", [])
        restante = [d for d in atual if d.lower() not in alvo]
        n = len(atual) - len(restante)
        if n:
            g["blocked"] = restante
            rem += n
            gruposaf += 1
    if rem:
        _set_config(cfg)
    return rem, gruposaf


# ---- Logs DNS: resolve empresa (grupo do Advanced Blocking) + consulta ----

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


def empresas(mapa=None):
    """Nomes de empresa/grupo que têm redes atribuídas (para o dropdown)."""
    mapa = mapa if mapa is not None else networkgroupmap()
    return sorted(set(mapa.values()))


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


def empresa_redes(empresa, mapa):
    """Redes (ip_network) atribuídas a uma empresa/grupo."""
    return [n for n, g in mapa.items() if g == empresa]


def consultar_logs(mapa, redes=None, inicio=None, fim=None, dominio=None,
                   ip_exato=None, ip_like=None, resposta=None, rcode=None,
                   limite=300, scan_max=6000, por_pagina=500):
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
    linhas, scanned, page = [], 0, 1
    while len(linhas) < limite and scanned < scan_max:
        r = _api_get("logs/query?" + urllib.parse.urlencode(
            {**base, "pageNumber": page, "entriesPerPage": por_pagina}), timeout=30)
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
