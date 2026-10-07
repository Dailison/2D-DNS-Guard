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


def _canon(cfg) -> str:
    return json.dumps(cfg, sort_keys=True)


def _set_config(cfg, por="console", motivo="", anterior=None):
    """Grava o config do Advanced Blocking. ANTES guarda no analisador o config anterior (o lido; sem
    `anterior`, lê agora) — sem backup, não grava (é a gravação de maior raio de estrago do sistema)."""
    from app import analyzer_client as api
    anterior = anterior if anterior is not None else _get_config()
    try:
        api.post("/console/technitium-backups", {"config": anterior, "por": por or "console", "motivo": motivo or ""})
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"não foi possível guardar o backup do Technitium ({e}); nada foi gravado") from e
    _api_post("apps/config/set", {"name": APP_NAME, "config": json.dumps(cfg)})


def _read_modify_write(fn, por="console", motivo=""):
    """Lê o config, aplica fn(cfg) -> (resultado, gravar) e grava — relendo antes: se outra pessoa mudou o
    config nesse meio tempo, refaz a operação a partir do config novo (até 3 vezes; na 4ª, erro)."""
    for tentativa in range(4):
        cfg = _get_config()
        base = _canon(cfg)
        resultado, gravar = fn(cfg)
        if not gravar:
            return resultado
        if _canon(_get_config()) != base:
            if tentativa == 3:
                raise RuntimeError("o config do Technitium foi alterado por outra pessoa durante a gravação; tente de novo")
            continue
        _set_config(cfg, por, motivo, anterior=json.loads(base))
        return resultado


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

    def muda(cfg):
        ngmap = cfg.setdefault("networkGroupMap", {})
        anterior = None
        for k in list(ngmap):
            if norm_ip(k) == ipn:
                if ngmap[k] != grp:
                    anterior = ngmap[k]
                del ngmap[k]
        ngmap[ipn] = grp
        return anterior, True
    anterior = _read_modify_write(muda, por, f"liberar {ipn}")
    return ipn, (f"liberado (antes filtrava em '{anterior}')" if anterior else "liberado")


def revogar(ip_raw, por="admin"):
    """Remove o IP do grupo de isenção (volta a filtrar pela rede). Retorna ip_norm ou None."""
    ipn = norm_ip(ip_raw)
    if not ipn:
        return None
    grp = _grupo()

    def muda(cfg):
        ngmap = cfg.get("networkGroupMap", {})
        removed = False
        for k in list(ngmap):
            if norm_ip(k) == ipn and ngmap[k] == grp:
                del ngmap[k]
                removed = True
        return removed, removed
    return ipn if _read_modify_write(muda, por, f"revogar {ipn}") else None


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
# organização das listas (pedido do usuário 2026-09-26): seções só p/ a tela; ⚡ = risco (só destaque)
SECOES_LISTA = [
    ("🔒 Segurança", [("ameaca", "Ameaças"), ("blacklist", "Blacklist"), ("vpn_proxy", "VPN / Proxy"), ("doh_dns", "DoH / DNS"),
                     ("adware", "Adware / Apps indesejados"), ("nao_identificado", "Não identificados"),
                     ("dns_inativo", "DNS Inativo")]),
    ("🚫 Conteúdo", [("adulto", "Adulto"), ("apostas", "Apostas"), ("jogos", "Jogos"), ("redes_sociais", "Redes sociais"),
                    ("streaming", "Streaming"), ("mensageiros", "Mensageiros"), ("cripto_trading", "Cripto / Trading")]),
    ("🌐 Web", [("publicidade", "Publicidade / Rastreamento"), ("noticias", "Notícias"), ("pirataria", "Pirataria / Downloads")]),
    ("🏢 Trabalho", [("compras", "Compras"), ("ia_chatbots", "IA / Chatbots"), ("nuvem_remoto", "Nuvem / Acesso remoto")]),
    ("🔧 Sistema", [("infra_bloqueio", "Infraestrutura"), ("outros_bloqueios", "Outros")]),   # (Para revisar/fase 5: removida em 27/09)
]
CATEGORIAS_LISTA = [x for _, itens in SECOES_LISTA for x in itens]
# whitelists por categoria (analisador: whitelist.py) — assinadas por TODOS os grupos (vencem qualquer bloqueio)
CATEGORIAS_WHITELIST = [("essenciais", "Essenciais (catálogo)"), ("produtividade", "Produtividade e escritório"),
                        ("comunicacao", "Comunicação corporativa"), ("erp_gestao", "ERP, gestão e fiscal"),
                        ("financas", "Bancos, pagamentos e maquininhas"), ("governo", "Governo e órgãos públicos"),
                        ("juridico", "Jurídico, cartórios e conselhos"), ("rh_beneficios", "RH, folha e benefícios"),
                        ("vendas_crm", "Vendas, CRM e atendimento"), ("logistica", "Logística, transporte e entregas"),
                        ("fornecedores", "Fornecedores, indústria e B2B"), ("institucional", "Sites institucionais de empresas"),
                        ("telecom", "Telecom e internet"), ("infraestrutura", "Infraestrutura e sistemas"),
                        ("cdn", "CDN e entrega de conteúdo"), ("seguranca", "Segurança"),
                        ("desenvolvimento", "TI e desenvolvimento"), ("educacao", "Educação e cursos"), ("saude", "Saúde"),
                        ("utilidades", "Utilidades (conversores, PDF, tradutores)"),
                        ("servicos", "Serviços do dia a dia (mapas, clima, viagens)"), ("outros_trabalho", "Outros de trabalho"),
                        ("religiao", "Religião e espiritualidade"), ("infantil_hobby", "Infantil, hobby e arte"),
                        ("bem_estar", "Fitness, saúde pessoal e família"),
                        ("outros_liberados", "Outros liberados (não é trabalho, sem lista de bloqueio)"),
                        ("sem_resposta", "Sem resposta (não resolve no DNS)")]
# as que vão p/ o DNS (allowListUrls): "Sem resposta" só organiza (nunca é publicada)
CATEGORIAS_WHITELIST_DNS = [x for x in CATEGORIAS_WHITELIST if x[0] != "sem_resposta"]
_WL_RE = re.compile(r"/whitelist/([a-z_]+)\.txt$")
CATEGORIAS_RISCO = {"ameaca", "blacklist", "vpn_proxy", "doh_dns", "adware", "adulto", "apostas", "nao_identificado"}   # ⚡ (só destaque visual)
CATEGORIAS_MANUAIS = {"infra_bloqueio", "outros_bloqueios", "para_revisar"}   # a IA não põe sozinha
# Blacklist (30/09): posta só pela verificação do analisador (infraestrutura de terceiros em lista de ameaça, no
# VirusTotal ou com veredito malicioso no URLScan) — a IA não escolhe essa lista

_LISTA_RE = re.compile(r"/listas/([a-z_]+)\.txt$")


def url_whitelist(cat):
    return f"{current_app.config['ANALYZER_URL'].rstrip('/')}/whitelist/{cat}.txt"


def dominios_whitelist() -> set[str]:
    from app import analyzer_client as api
    try:
        return {d.lower() for d in api.get("/whitelist-dominios")}
    except Exception:  # noqa: BLE001 — sem o analisador, o índice segue sem a whitelist
        return set()


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
    wl = dominios_whitelist()   # whitelists: assinadas por todos os grupos, vencem as listas
    for g in ativos:
        s = {x.lower() for x in g.get("blocked", [])}
        for c in listas_assinadas(g):
            s |= doms.get(c, set())
        for u in g.get("blockListUrls") or []:
            m = _LIB_RE.search(str(u))
            if m:
                s |= dominios_liberacao(m.group(1))
        esc = escopo_do_grupo(g)   # ajustes das listas do escopo (empresa/unidade) que o grupo assina
        aj = ajustes_do_escopo(esc) if esc else {"liberar": set(), "bloquear": set()}
        grupos[g["name"]] = s | aj["bloquear"]
        permitidos[g["name"]] = {x.lower() for x in g.get("allowed") or []} | aj["liberar"]
        for slug in listas_liberacao_do_grupo(g):
            permitidos[g["name"]] |= dominios_liberacao(slug)
        if any(_WL_RE.search(str(u)) for u in g.get("allowListUrls") or []):
            permitidos[g["name"]] |= wl
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


def cadeia_cname(nome: str) -> list[str]:
    """Nomes para onde `nome` aponta por CNAME, na ordem, resolvidos pelo próprio Technitium (o bloqueio também vale
    para eles: um destino numa lista bloqueia o nome consultado). Sem CNAME ou sem resposta = []."""
    try:
        r = _api_get("dnsClient/resolve?" + urllib.parse.urlencode(
            {"server": "this-server", "domain": nome, "type": "A", "protocol": "Udp"}), timeout=6)
    except Exception:  # noqa: BLE001 — é só um complemento da busca
        return []
    out = []
    for x in (r.get("result") or {}).get("Answer") or []:
        if str(x.get("Type") or "").upper() == "CNAME":
            d = str((x.get("RDATA") or {}).get("Domain") or "").strip().rstrip(".").lower()
            if d and d not in out:
                out.append(d)
    return out


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
                   limite=300, scan_max=6000, por_pagina=500, orcamento_s=20, sem_locais=False):
    """Consulta os query logs do Technitium (período/IP/tipo-de-resposta/rcode
    empurrados para a API); resolve a empresa e filtra por `redes` (CIDR),
    `dominio` (substring, %dominio%) e `ip_like` (parte do IP, ex.: '10.100') no
    app, pois a API não faz range nem match parcial. Retorna (linhas, scaneados,
    atingiu_cap, coberto_desde). Os timestamps voltam já convertidos para o fuso de São Paulo.

    (07/10) Anda PARA TRÁS em janelas curtas de tempo, do fim do período até juntar `limite` linhas, varrer
    `scan_max`, chegar ao início ou gastar `orcamento_s`: no Technitium cada chamada custa a CONTAGEM do período
    pedido (SQLite com milhões de linhas — o dia inteiro, 2,5 M de registros, levava 28 s por chamada e a tela dava
    timeout); uma janela de minutos responde em décimos de segundo. `coberto_desde` = até onde a busca chegou
    (horário local) quando parou antes do início — a tela oferece "mais antigos" a partir dali; None = período todo."""
    import time
    from datetime import timedelta
    base = {"name": "Query Logs (Sqlite)", "classPath": "QueryLogsSqlite.App",
            "descendingOrder": "true"}
    if ip_exato:
        base["clientIpAddress"] = ip_exato.strip()
    if resposta:
        base["responseType"] = resposta.strip()
    if rcode:
        base["rcode"] = rcode.strip()
    dom_like = (dominio or "").strip().lower()
    ip_sub = (ip_like or "").strip()
    zonas = zonas_locais() if sem_locais else []
    fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S")   # noqa: E731
    agora = datetime.now(timezone.utc)
    ini_dt = _parse_utc(inicio) if inicio else None
    fim_dt = min(_parse_utc(fim) or agora, agora + timedelta(minutes=1)) if fim else agora + timedelta(minutes=1)
    t0 = time.monotonic()
    linhas, scanned, vistos, chamadas = [], 0, set(), 0
    cursor, janela = fim_dt, timedelta(seconds=120)
    JANELA_MAX = timedelta(hours=6)
    parou = False   # parou antes de cobrir o período (limite, varredura ou tempo)
    while not ini_dt or cursor > ini_dt:
        if len(linhas) >= limite or scanned >= scan_max or (chamadas and time.monotonic() - t0 > orcamento_s):
            parou = True
            break
        a = max(ini_dt, cursor - janela) if ini_dt else cursor - janela
        page, total, ult, meio = 1, 0, None, False
        while True:
            chamadas += 1
            r = _api_get("logs/query?" + urllib.parse.urlencode(
                {**base, "start": fmt(a), "end": fmt(cursor), "pageNumber": page, "entriesPerPage": por_pagina}),
                timeout=max(8, orcamento_s - (time.monotonic() - t0) + 10))
            ents = r.get("entries", [])
            total = r.get("totalEntries") or len(ents)
            for e in ents:
                cip = e.get("clientIpAddress", "")
                chave = (e.get("timestamp"), cip, e.get("qname"), e.get("qtype"))
                if chave in vistos:   # (a borda de duas janelas pode trazer o mesmo registro)
                    continue
                vistos.add(chave)
                scanned += 1
                ult = e.get("timestamp")
                if dom_like and dom_like not in (e.get("qname") or "").lower():
                    continue
                if sem_locais and nome_local(e.get("qname"), zonas):
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
                    meio = e is not ents[-1]   # parou no meio da página
                    break
            if len(ents) < por_pagina and not meio:   # a janela foi lida até o fim
                break
            if meio or len(linhas) >= limite or scanned >= scan_max or time.monotonic() - t0 > orcamento_s:
                parou = True   # a janela NÃO foi lida até o fim: a busca vai até o último registro lido
                break
            page += 1
        if parou:
            cursor = _parse_utc(ult) or a
            break
        # próxima janela: do tamanho que traz ~1 página (o custo da chamada é o nº de registros da janela)
        seg = max(janela.total_seconds(), 1)
        janela = min(JANELA_MAX, timedelta(seconds=max(30, seg * 0.8 * por_pagina / total)) if total else janela * 4)
        cursor = a
        if not ini_dt and fim_dt - cursor > timedelta(days=31):   # sem início: não volta além de um mês
            break
    cap = len(linhas) >= limite or scanned >= scan_max
    # (ao segundo, +1 s: "mais antigos" continua daqui — repetir um registro da borda é melhor que pular até 1 min)
    desde = ((cursor + timedelta(seconds=1)).astimezone(TZ_LOCAL).strftime("%Y-%m-%dT%H:%M:%S")
             if parou and (not ini_dt or cursor > ini_dt) else None)
    return linhas, scanned, cap, desde


# ------------------------------------------------ nomes locais (fora dos Logs por padrão)
_ZONAS = {"at": 0.0, "zonas": []}


def zonas_locais() -> list[str]:
    """Zonas hospedadas no Technitium (ex.: 2d.local, barretos.local — forwarders p/ os DCs), guardadas
    por 10 min. Falha = lista vazia (os Logs seguem, só sem esse filtro)."""
    import time
    if time.monotonic() - _ZONAS["at"] > 600:
        try:
            r = _api_get("zones/list")
            _ZONAS["zonas"] = sorted({(z.get("name") or "").lower().strip(".") for z in r.get("zones", []) if z.get("name")})
        except Exception:  # noqa: BLE001
            _ZONAS["zonas"] = _ZONAS["zonas"] or []
        _ZONAS["at"] = time.monotonic()
    return _ZONAS["zonas"]


def nome_local(qname: str, zonas) -> bool:
    """Nome local: sem ponto (nome de máquina/wpad), reverso (PTR), .local ou de uma zona local do Technitium."""
    n = (qname or "").lower().rstrip(".")
    if not n or "." not in n or n.endswith((".arpa", ".local")):
        return True
    return any(n == z or n.endswith("." + z) for z in zonas)


# ------------------------------------------------ políticas por empresa -> grupos internos
# O usuário vincula LISTAS às empresas (e, se precisar, a uma unidade); o Technitium só aceita
# UM grupo por rede, então o console mantém sozinho um grupo por política: "Empresa: <nome>"
# (ou "Empresa: <nome> · <unidade>"). Ninguém edita esses grupos à mão.
PREFIXO_GRUPO = "Empresa: "


def nome_grupo(empresa: str, unidade: str | None = None) -> str:
    return PREFIXO_GRUPO + empresa + (f" · {unidade}" if unidade else "")


def nome_grupo_ip(empresa: str | None, ip: str) -> str:
    """Grupo de um IP (ou faixa) com serviço liberado só para ele: "Empresa: <nome> · IP 10.1.2.3"."""
    return nome_grupo(empresa or "(sem cadastro)") + " · IP " + (ip[:-3] if ip.endswith("/32") else ip)


def nome_grupo_sem(base: str, sem) -> str:
    """Grupo dos IPs liberados só de algumas listas: o grupo da rede deles + " · sem <listas>" (um por combinação)."""
    return base + " · sem " + "+".join(sorted(sem))


def plano_politicas(empresas, politicas, ajustes=(), ips=(), parciais=()):
    """-> (grupos {nome: {"lists", "services", "blocked", "escopo"}}, mapa {cidr: grupo}, default {...}).
    Rede de empresa sem política (nem da unidade nem da empresa) e sem ajuste fica sem mapeamento: vale o default.
    `ajustes` = escopos com ajuste próprio das listas (01/10: listas por empresa/unidade): a unidade com ajuste ganha
    grupo próprio (com as listas da empresa) e cada grupo assina as listas de ajuste do escopo dele ("escopo").
    `ips` = [{"ip", "slug"}] serviços liberados só para um IP/faixa (03/10): o IP ganha grupo próprio com a política
    da rede mais específica que o contém (sem rede no cadastro: a padrão) mais esses serviços.
    `parciais` = [{"ip", "listas"}] IPs liberados só de algumas listas de bloqueio (07/10): em vez do grupo de isenção
    (que não bloqueia nada), o IP vai p/ um grupo com a política da rede dele MENOS essas listas — compartilhado por
    quem tem a mesma rede e a mesma escolha ("Empresa: X · sem redes_sociais"); com serviço só dele, o grupo do IP."""
    pol = {p["scope"]: p for p in politicas}
    ajustes = set(ajustes or ())
    grupos, mapa = {}, {}
    redes = []   # (rede, empresa, política que vale nela ou None, escopo dos ajustes) p/ achar a rede de cada IP
    for e in empresas:
        te = f"tenant:{e['id']}"
        pe = pol.get(te)
        for n in e.get("networks") or []:
            cidr = norm_ip(n.get("cidr"))
            if not cidr:
                continue
            unidade = n.get("unit") or ""
            tu = f"unit:{e['id']}:{unidade}" if unidade else None
            pu = pol.get(tu) if tu else None
            proprio = bool(tu) and (bool(pu) or tu in ajustes)       # unidade com política ou ajuste: grupo dela
            escopo = tu if tu in ajustes else te if te in ajustes else None
            p = pu or pe or (pol.get("default") if escopo else None)   # só ajuste, sem política: listas do padrão
            nome = nome_grupo(e["name"], unidade) if proprio else nome_grupo(e["name"])
            try:
                redes.append((ipaddress.ip_network(cidr), e["name"], p, escopo, nome if p else nome_grupo(e["name"])))
            except ValueError:
                pass
            if not p:
                continue
            grupos[nome] = {"lists": sorted(p.get("lists") or []), "services": sorted(p.get("services") or []),
                            "blocked": sorted(p.get("services_blocked") or []), "escopo": escopo}
            mapa[cidr] = nome
    d = pol.get("default") or {}
    por_ip: dict[str, set] = {}
    for x in ips or ():
        ipn = norm_ip(x.get("ip"))
        if ipn and x.get("slug"):
            por_ip.setdefault(ipn, set()).add(x["slug"])
    sem_ip: dict[str, set] = {}
    for x in parciais or ():
        ipn = norm_ip(x.get("ip"))
        if ipn and x.get("listas"):
            sem_ip[ipn] = set(x["listas"])
    for ipn in sorted(set(por_ip) | set(sem_ip)):
        slugs, sem = por_ip.get(ipn, set()), sem_ip.get(ipn, set())
        alvo = ipaddress.ip_network(ipn)
        dona = max((r for r in redes if r[0].version == alvo.version and alvo.subnet_of(r[0])),
                   key=lambda r: r[0].prefixlen, default=None)
        p = (dona[2] if dona else None) or d
        if slugs:
            nome = nome_grupo_ip(dona[1] if dona else None, ipn)
        else:
            nome = nome_grupo_sem(dona[4] if dona else nome_grupo("(sem cadastro)"), sem)
        grupos[nome] = {"lists": sorted(set(p.get("lists") or []) - sem), "services": sorted(set(p.get("services") or []) | slugs),
                        "blocked": sorted(p.get("services_blocked") or []), "escopo": dona[3] if dona else None}
        mapa[ipn] = nome
    return grupos, mapa, {"lists": sorted(d.get("lists") or []), "services": sorted(d.get("services") or []),
                          "blocked": sorted(d.get("services_blocked") or [])}


_LIB_RE = re.compile(r"/(?:liberacao|servico)/([a-z0-9-]+)\.txt$")


def url_liberacao(slug):
    """URL de um serviço / lista de liberação (a mesma serve p/ bloquear ou liberar)."""
    return (current_app.config.get("ANALYZER_URL") or "").rstrip("/") + f"/servico/{slug}.txt"


_AJ_RE = re.compile(r"/ajustes/(liberar|bloquear)/([A-Za-z0-9_-]+)\.txt$")


def url_ajuste(escopo: str, acao: str) -> str:
    """Lista de ajustes do escopo (empresa/unidade) publicada pelo analisador (ver analyzer: ajustes.py)."""
    import base64
    tok = base64.urlsafe_b64encode(escopo.encode()).decode().rstrip("=")
    return (current_app.config.get("ANALYZER_URL") or "").rstrip("/") + f"/ajustes/{acao}/{tok}.txt"


def escopo_do_grupo(g) -> str | None:
    """Escopo cujos ajustes o grupo assina (pela URL)."""
    import base64
    for u in (g.get("allowListUrls") or []) + (g.get("blockListUrls") or []):
        m = _AJ_RE.search(str(u))
        if m:
            try:
                return base64.urlsafe_b64decode(m.group(2) + "=" * (-len(m.group(2)) % 4)).decode()
            except (ValueError, UnicodeDecodeError):
                return None
    return None


def ajustes_do_escopo(escopo: str) -> dict:
    """{"liberar": set, "bloquear": set} que valem no escopo (do analisador; cache por requisição). Falha = vazio."""
    from flask import g as fg
    from app import analyzer_client as api
    cache = fg.setdefault("_ajustes_escopo", {})
    if escopo not in cache:
        try:
            ef = api.get("/ajustes", scope=escopo).get("efetivo") or {}
            cache[escopo] = {k: set(ef.get(k) or []) for k in ("liberar", "bloquear")}
        except Exception:  # noqa: BLE001
            cache[escopo] = {"liberar": set(), "bloquear": set()}
    return cache[escopo]


def listas_liberacao_do_grupo(g):
    return sorted({m.group(1) for u in (g.get("allowListUrls") or []) if (m := _LIB_RE.search(str(u)))})


def _aplica_politica(g, lists, services, bloqueados=(), escopo=None):
    """Listas de bloqueio + serviços bloqueados -> blockListUrls; serviços/listas de liberação
    liberados -> allowListUrls (vencem o bloqueio). URLs de terceiros e liberações manuais ficam.
    `escopo` (empresa/unidade com ajuste das listas): o grupo assina também "bloquear aqui" e "liberar aqui"."""
    nossa = lambda u: _LISTA_RE.search(str(u)) or _LIB_RE.search(str(u)) or _AJ_RE.search(str(u))   # noqa: E731
    outras = [u for u in (g.get("blockListUrls") or []) if not nossa(u)]
    g["blockListUrls"] = (outras + [url_lista(c) for c, _ in CATEGORIAS_LISTA if c in set(lists)]
                          + [url_liberacao(s) for s in sorted(set(bloqueados) - set(services))]
                          + ([url_ajuste(escopo, "bloquear")] if escopo else []))
    outras = [u for u in (g.get("allowListUrls") or []) if not _LIB_RE.search(str(u)) and not _WL_RE.search(str(u))
              and not _AJ_RE.search(str(u))]
    g["allowListUrls"] = (outras + [url_whitelist(c) for c, _ in CATEGORIAS_WHITELIST_DNS]
                          + [url_liberacao(s) for s in sorted(set(services))]
                          + ([url_ajuste(escopo, "liberar")] if escopo else []))


def _valida_sincronizacao(antes: dict, depois: dict, lib: str, saem=()) -> None:
    """Recusa gravar (RuntimeError) um resultado que apagaria o que não é da sincronização."""
    ga = {g.get("name") for g in antes.get("groups", [])}
    gd = {g.get("name") for g in depois.get("groups", [])}
    if lib in ga and lib not in gd:
        raise RuntimeError(f"a sincronização apagaria o grupo de isenção '{lib}'; nada foi gravado")
    sumiram = sorted(n for n in ga - gd if n and not n.startswith(PREFIXO_GRUPO))
    if sumiram:
        raise RuntimeError(f"a sincronização apagaria grupos que não são de empresa ({', '.join(sumiram)}); nada foi gravado")
    na, nd = antes.get("networkGroupMap") or {}, depois.get("networkGroupMap") or {}
    if len(na) >= 5 and len(nd) < 0.8 * len(na):
        raise RuntimeError(f"a sincronização deixaria o mapa de redes com {len(nd)} de {len(na)} entradas; nada foi gravado")
    saem = set(saem)   # IPs que passaram a ser liberados só de algumas listas: saem da isenção de propósito
    mudou = sorted(k for k, v in na.items() if v == lib and nd.get(k) != lib and norm_ip(k) not in saem)
    if mudou:
        raise RuntimeError(f"a sincronização mexeria em redes isentas ({', '.join(mudou[:5])}); nada foi gravado")


def sincronizar_politicas(empresas, politicas, aplicar=True, por="console", motivo="sincronizar políticas", ajustes=(),
                          ips=(), parciais=()):
    """Deixa o Technitium igual às políticas: cria/atualiza/apaga os grupos "Empresa: …", aponta
    as redes das empresas para eles e aplica a política default no grupo default. Não mexe no
    grupo Liberados nem em redes/IPs mapeados para ele — a não ser os `parciais` (IPs liberados só de algumas listas:
    saem da isenção e vão p/ o grupo "… · sem <listas>"). Valida o resultado antes de gravar (ver
    _valida_sincronizacao), guarda backup e não sobrescreve alteração de outra pessoa
    (_read_modify_write). Retorna um resumo do que mudou."""
    lib = current_app.config.get("TECHNITIUM_LIBERADOS_GROUP", "Liberados")

    def muda(cfg):
        antes = json.loads(_canon(cfg))
        r = _sincroniza(cfg, empresas, politicas, lib, ajustes, ips, parciais)
        _valida_sincronizacao(antes, cfg, lib, [norm_ip(x.get("ip")) for x in parciais or () if x.get("listas")])
        return r, aplicar
    return _read_modify_write(muda, por, motivo)


def _sincroniza(cfg, empresas, politicas, lib, ajustes=(), ips=(), parciais=()):
    """Aplica as políticas no config (em memória)."""
    grupos, mapa, default = plano_politicas(empresas, politicas, ajustes, ips, parciais)
    saem = {norm_ip(x.get("ip")) for x in parciais or () if x.get("listas")}
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
        _aplica_politica(g, p["lists"], p["services"], p["blocked"], p.get("escopo"))
    if "default" in existentes:
        _aplica_politica(existentes["default"], default["lists"], default["services"], default["blocked"])
    ngm = cfg.setdefault("networkGroupMap", {})
    for k in list(ngm):
        v = ngm[k]
        if v == lib and norm_ip(k) not in saem:
            continue                      # isenções (Liberados) ficam como estão
        if norm_ip(k) in mapa or (str(v).startswith(PREFIXO_GRUPO) and v not in grupos):
            del ngm[k]                    # será reapontado (ou o grupo da empresa deixou de existir)
    for cidr, nome in mapa.items():
        if ngm.get(cidr) != lib or cidr in saem:
            ngm[cidr] = nome
    for g in list(cfg.get("groups", [])):
        n = g.get("name") or ""
        if n.startswith(PREFIXO_GRUPO) and n not in grupos:
            cfg["groups"].remove(g)
            apagados.append(n)
    return {"criados": criados, "atualizados": atualizados, "apagados": apagados, "redes": len(mapa),
            "default": default, "cfg": cfg}


# ---- Exceção imediata ("manter liberado" vale na hora; plano de confiabilidade, fase 3.3) ----
def grupos_bloqueando(dominios) -> dict[str, list[str]]:
    """{domínio: [grupos em que está bloqueado agora pelas listas]} (um índice só p/ todos)."""
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return {}
    idx = indice_bloqueio()
    return {d: bloqueado_em(idx, d) for d in dominios}


def rotulo_grupo(g: str) -> str:
    return g[len(PREFIXO_GRUPO):] if g.startswith(PREFIXO_GRUPO) else ("redes sem cadastro" if g == "default" else g)


def liberar_agora(dominios, antes: dict[str, list[str]], por: str = "console") -> list[str]:
    """Depois de tirar domínios das listas: põe no `allowed` dos grupos em que a mudança os libera (bloqueados
    `antes`, livres pelas listas agora) — vale na hora, sem esperar o Technitium baixar a lista. Só nesses
    grupos: se outra lista ainda bloqueia o domínio numa empresa, lá fica bloqueado. Registra no analisador
    (p/ tirar depois só as exceções do console). Retorna os grupos liberados."""
    if not antes:
        return []
    depois = grupos_bloqueando(dominios)
    mapa = {d: [g for g in antes.get(d, []) if g not in depois.get(d, [])] for d in dominios}
    mapa = {d: gs for d, gs in mapa.items() if gs}
    return excecao_direta(mapa, por, "manter liberado agora")


def excecao_direta(mapa: dict[str, list[str]], por: str = "console", motivo: str = "exceção") -> list[str]:
    """Põe cada domínio no `allowed` dos grupos indicados ({domínio: [grupos]}) e registra no analisador."""
    if not mapa:
        return []
    from app import analyzer_client as api

    def muda(cfg):
        mudou = False
        for g in cfg.get("groups", []):
            al = g.setdefault("allowed", [])
            for d, gs in mapa.items():
                if g.get("name") in gs and d not in al:
                    al.append(d)
                    mudou = True
        return None, mudou
    _read_modify_write(muda, por, f"{motivo}: " + ", ".join(sorted(mapa))[:200])
    api.post("/console/excecoes", {"excecoes": mapa, "por": por})
    return sorted({g for gs in mapa.values() for g in gs})


def remover_excecao(dominios, por: str = "console") -> list[str]:
    """Domínio voltou para uma lista: tira do `allowed` SÓ as exceções que o console pôs (as manuais ficam)."""
    if not current_app.config.get("TECHNITIUM_ENABLED") or not dominios:
        return []
    from app import analyzer_client as api
    nossos = api.get("/console/excecoes", domains=list(dominios)) or {}
    if not nossos:
        return []

    def muda(cfg):
        mudou = False
        for g in cfg.get("groups", []):
            al = g.get("allowed") or []
            for d, gs in nossos.items():
                if g.get("name") in gs and d in al:
                    al.remove(d)
                    mudou = True
        return None, mudou
    _read_modify_write(muda, por, "fim da exceção: " + ", ".join(sorted(nossos))[:200])
    api.post("/console/excecoes/remover", {"domains": sorted(nossos)})
    return sorted({g for gs in nossos.values() for g in gs})


def grupos_da_empresa(nome_empresa: str) -> list[str]:
    """Grupos internos da empresa no Technitium ("Empresa: X" e "Empresa: X · unidade")."""
    base = nome_grupo(nome_empresa)
    return [g.get("name") for g in _get_config().get("groups", []) if g.get("name") == base or (g.get("name") or "").startswith(base + " · ")]


def msg_liberado(grupos: list[str]) -> str:
    return (f" Liberado agora em {', '.join(rotulo_grupo(g) for g in grupos)}; a lista atualiza em até 2 min." if grupos
            else " O DNS atualiza em até 2 min.")
