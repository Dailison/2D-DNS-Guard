"""Etapa "lista": a IA diz a qual LISTA de bloqueio cada site pertence (o que o site É, separado de
"é trabalho?": o ChatGPT é TRABALHO e é da lista IA / Chatbots; cada empresa decide se aplica a lista).

Roda depois da classificação principal (etapa 1-3), com a capacidade livre da IA, e reaproveita o que
já se sabe do domínio (serviço, motivo, página, busca na web, WHOIS) — sem nova busca. Resultado em
domains.lista_* ; `aplicar` põe o site na lista quando há certeza e manda para "Para revisar" (com a
sugestão) quando não há — de lá vai para a etapa 4 (IA online) ou para a aprovação manual.
"""

from __future__ import annotations

import json
import logging
import re
import time

import httpx
from pydantic import BaseModel, Field, ValidationError

from . import catalog, corporate, db, eventos, listas, whitelist
from .config import settings
from .llm import LLMBadOutput, LLMUnavailable, OllamaClient

log = logging.getLogger(__name__)

# listas que a IA preenche (as de "Sistema" — Infraestrutura, Outros, Para revisar — são manuais)
LISTAS_IA = {
    "ameaca": "phishing, golpe, malware, comando e controle, site malicioso confirmado, e site com CAMUFLAGEM (a página "
              "imita erro do navegador ou prende o botão Voltar — SINAL na evidência da página): não é site honesto",
    "vpn_proxy": "VPN de uso pessoal, proxy, anonimizador, Tor, qualquer coisa para contornar o filtro "
                 "(VPN CORPORATIVA — Fortinet, GlobalProtect, Cisco AnyConnect, Zscaler — é nenhuma)",
    "doh_dns": "resolvedor DNS público e DNS sobre HTTPS/TLS (dns.google, cloudflare-dns, quad9, nextdns, adguard-dns, opendns)",
    "adware": "adware e software indesejado (PUP): sequestradores de navegador, extensões e 'utilitários' que empurram "
              "propaganda (leitor de PDF, calendário, clima, conversor grátis), falso antivírus/otimizador, mineração de "
              "cripto no navegador (sem ser golpe confirmado — golpe/malware é ameaca). Ferramenta online legítima e conhecida "
              "(Convertio, iLovePDF, Smallpdf, Google Tradutor, calculadoras) NÃO é adware: é nenhuma",
    "adulto": "pornografia, conteúdo sexual, encontros adultos, acompanhantes",
    "apostas": "bets, cassino online, apostas esportivas, loterias e jogos de azar online",
    "jogos": "jogos online, lojas e launchers de games, servidores e fóruns de jogos, cheats",
    "redes_sociais": "redes sociais (Facebook, Instagram, TikTok, X, Kwai, Pinterest, Reddit, Threads, Snapchat)",
    "streaming": "vídeo, música e lives sob demanda (YouTube, Netflix, Spotify, Deezer, Twitch, Globoplay, Prime Video)",
    "mensageiros": "mensageiros e chat pessoal (WhatsApp, Telegram, Discord, Signal, Messenger, WeChat)",
    "cripto_trading": "criptomoedas e trading especulativo: corretoras de cripto (Binance, OKX), carteiras, opções binárias, "
                      "forex/day trade, sinais de trading, pirâmides (bancos e corretoras tradicionais são nenhuma)",
    "publicidade": "redes de anúncio, rastreamento, analytics, pixels, atribuição de apps",
    "compras": "LOJAS ONLINE de varejo: e-commerce, marketplaces, supermercado online, delivery, cupons (conta como trabalho: "
               "compras da empresa). NÃO é compras: fabricante, indústria ou distribuidor, mesmo com loja virtual própria, "
               "catálogo de produtos e loja física (esses vão para wl:fornecedores)",
    "noticias": "portais de notícias, revistas e fofoca de celebridades (site de hobby, desenhos para colorir, receitas, "
                "artesanato, conteúdo infantil ou educativo NÃO é notícia: sem lista de bloqueio, vai para a whitelist)",
    "pirataria": "torrents, downloads piratas, cracks, IPTV pirata, filmes e séries piratas, sites que baixam vídeo/música "
                 "de YouTube e streamings (conversor de ARQUIVOS/PDF legítimo não é pirataria: é nenhuma)",
    "ia_chatbots": "assistentes de IA, chatbots e geradores de texto ou imagem (ChatGPT, Claude, Gemini, Copilot, Perplexity)",
    "nuvem_remoto": "SÓ armazenamento/compartilhamento de ARQUIVOS pessoal (Dropbox, Google Drive, Mega, WeTransfer) e "
                    "acesso remoto a computadores (AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop). Nuvem PARA SISTEMAS "
                    "(AWS, Azure, Google Cloud, APIs, login/autenticação, hospedagem), Microsoft 365, SharePoint, OneDrive "
                    "da empresa e Google Workspace são nenhuma",
    "nao_identificado": "NÃO IDENTIFICADO: depois de todas as evidências não dá para saber o que o site é (nome aleatório "
                        "ou gerado, sem presença na web, registro recente ou titular oculto, nenhum serviço reconhecido). "
                        "O que não foi identificado NÃO vai para whitelist (espelho de cassino, golpe e rastreador têm esse perfil); "
                        "se o site foi identificado, use a lista ou a whitelist dele",
}
NAO_IDENT = "nao_identificado"
NENHUMA = "nenhuma"
FONTE_LOCAL = "local"
FONTE_CATALOGO = "catalogo"   # lista fixa do catálogo (`lista:` em data/catalog.yaml): sem IA
# fase 6 (investigacao.py): só grava com alta certeza e, como a IA online, é resposta final — mas a classificação e a
# categoria dela ficam no próprio domínio (não em online_resp)
FONTE_INVESTIGACAO = "investigacao"


def _final(r: dict) -> bool:
    """Resposta final (IA online ou investigação profunda): vale com as travas, sem voltar às fases 2-4."""
    f = r.get("lista_fonte") or ""
    return f.startswith("online") or f == FONTE_INVESTIGACAO
# destino de quem é liberado: uma whitelist por categoria ("wl:financas"); todo site vai p/ alguma fila
WL = {f"wl:{k}": v for k, v in whitelist.DESCRICOES.items()}


def e_wl(lista: str | None) -> bool:
    return bool(lista) and lista.startswith("wl:") and lista[3:] in whitelist.CATEGORIAS
# o site precisa ser coerente com a classificação principal p/ entrar sozinho (senão: Para revisar)
_EXIGE_NAO_TRABALHO = {"vpn_proxy", "adulto", "apostas", "jogos", "redes_sociais", "streaming", "publicidade", "pirataria",
                       "noticias", "adware", "cripto_trading"}   # site TRABALHO nessas = contradição -> revisão (Compras conta como trabalho)

SYSTEM = """Você organiza sites em LISTAS de filtro de DNS para empresas brasileiras. Todo site vai para UMA lista:
uma LISTA DE BLOQUEIO (o que o site é — cada empresa escolhe depois quais bloqueia) ou, se não é de nenhuma delas, uma
WHITELIST (sites liberados), na categoria que melhor o descreve.
Domínios técnicos de um serviço (CDN, API, imagens, apps) vão para a lista do serviço (ex.: fbcdn.net = redes_sociais, ytimg.com = streaming, whatsapp.net = mensageiros); CDN genérica sem serviço identificado (CloudFront, Akamai, Fastly, subdomínio aleatório de CDN) = "wl:cdn".

Listas de bloqueio:
{listas}

Whitelists (sites liberados):
{whitelists}

Atenção a estes erros comuns:
- Domínio que IMITA uma marca famosa com letras trocadas, dobradas ou erro de digitação (ffacebook, feceboock, g00gle, paypa1) e que NÃO é o domínio oficial dela é golpe: "ameaca" — nunca a lista da marca imitada. Pista: marca famosa fora do top 1M de popularidade.
- Quem BLOQUEIA anúncios, rastreadores ou ameaças (AdGuard, uBlock, Adblock Plus, antivírus, VPN corporativa) é ferramenta de segurança: "wl:seguranca" — não é publicidade nem adware (só o DNS público da AdGuard é doh_dns).
- SDK e plataforma técnica: analytics de marketing, atribuição e anúncios de apps (app-measurement, branch.io, AppsFlyer, SDK de anúncios) = "publicidade"; logs/telemetria técnica e APIs = "wl:infraestrutura"; voz e vídeo em tempo real, login, pagamentos, notificações para apps = "wl:desenvolvimento", mesmo que o site fale em IA ou chat. "ia_chatbots" é só o assistente de IA que a pessoa usa.
- Placar, resultados e estatísticas esportivas = "noticias"; "apostas" só quando o site oferece apostar.

"confianca": 1.0 SÓ para o site oficial de um serviço que você conhece pelo nome e que se encaixa claramente na lista; se você deduz pelo nome do domínio, pelo WHOIS ou por resultados de busca, no máximo 0.7; 0.4 ou menos se está chutando.
Responda só o JSON, em português, numa linha."""


class ListaResult(BaseModel):
    servico: str = Field(default="", max_length=200)
    lista: str
    confianca: float = Field(ge=0, le=1)
    motivo: str = Field(default="", max_length=300)


def _schema() -> dict:
    return {"type": "object",
            "properties": {"servico": {"type": "string", "maxLength": 60},
                           "lista": {"type": "string", "enum": [*LISTAS_IA, *WL]},
                           "confianca": {"type": "number", "minimum": 0, "maximum": 1},
                           "motivo": {"type": "string", "maxLength": 160}},
            "required": ["servico", "lista", "confianca", "motivo"]}


def _contexto(d: dict) -> str:
    """O que já se sabe do domínio, curto (a geração é o gargalo; o prompt nem tanto)."""
    linhas = [f"Domínio: {d['name']}"]
    if d.get("topic"):
        linhas.append(f"Serviço (análise anterior): {d['topic']}")
    linhas.append(f"Classificação anterior: {d.get('classification')} · categoria {d.get('category') or '—'}")
    if d.get("corp_reason"):
        linhas.append(f"Motivo: {d['corp_reason']}")
    ia = [r.get("text", "") for r in (d.get("reasons") or []) if r.get("by") == "ia"][:3]
    if ia:
        linhas.append("Razões da IA: " + " | ".join(ia))
    for e in d.get("evidence") or []:
        if e.get("kind") in ("catalog", "site", "websearch", "whois", "wikidata", "cert", "platform", "ti"):
            linhas.append(f"- {e.get('text', '')[:260]}")
    r = d.get("popularity_rank")
    return "\n".join(linhas[:14] + ["Popularidade: " + (f"top {r} no ranking Tranco" if r else "fora do top 1M (pouco acessado no mundo)")])


def perguntar(client: OllamaClient, d: dict) -> tuple[ListaResult, dict]:
    listas = "\n".join(f"- {k}: {v}" for k, v in LISTAS_IA.items())
    wls = "\n".join(f"- {k}: {v}" for k, v in WL.items())
    options = {"temperature": 0, "seed": 42, "num_ctx": client.num_ctx, "num_predict": 160}
    if client.num_thread:
        options["num_thread"] = client.num_thread
    payload = {"model": client.model, "stream": False, "think": False, "keep_alive": client.keep_alive,
               "format": _schema(), "options": options,
               "messages": [{"role": "system", "content": SYSTEM.format(listas=listas, whitelists=wls)},
                            {"role": "user", "content": _contexto(d) + "\n\nA qual lista este site pertence? /no_think"}]}
    t0 = time.monotonic()
    try:
        r = httpx.post(f"{client.url}/api/chat", json=payload, timeout=client.timeout)
    except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
        raise LLMUnavailable(str(e)) from e
    if r.status_code >= 500 or r.status_code == 404:
        raise LLMUnavailable(f"HTTP {r.status_code}: {r.text[:300]}")
    r.raise_for_status()
    content = (r.json().get("message") or {}).get("content", "")
    try:
        res = ListaResult.model_validate(json.loads(content))
    except (json.JSONDecodeError, ValidationError) as e:
        raise LLMBadOutput(f"{e}: {content[:300]}") from e
    if res.lista not in LISTAS_IA and res.lista != NENHUMA and not e_wl(res.lista):
        raise LLMBadOutput(f"lista inválida: {res.lista}")
    return res, {"model": client.model, "seconds": round(time.monotonic() - t0, 1), "extra": client.extra}


# fila: analisados (menos os desconhecidos) sem lista ainda ou reanalisados depois dela
_FILA = ("kind = 'public' AND classification IS NOT NULL AND classification <> 'DESCONHECIDO' AND NOT llm_pending "
         "AND (lista_at IS NULL OR lista_at < analyzed_at)")


def _reservar(c) -> dict | None:
    return c.execute(
        "UPDATE domains SET lista_claimed_at = now() WHERE id = (SELECT id FROM domains WHERE " + _FILA +
        " AND (lista_claimed_at IS NULL OR lista_claimed_at < now() - interval '10 minutes') "
        "ORDER BY (analyzed_at > now() - interval '1 day') DESC, total_queries DESC LIMIT 1 FOR UPDATE SKIP LOCKED) "
        "RETURNING " + _COLUNAS).fetchone()


_COLUNAS = "id, name, topic, classification, category, corp_reason, reasons, evidence, whois_at, web_search_at, popularity_rank"
_FASE_TXT = {1: "fase 1 · IA local", 2: "fase 2 · WHOIS + IA local", 3: "fase 3 · busca na web + IA local"}


def incerta_sql(t: str = "") -> str:
    """Sugestão da IA local (fases 1-3) sem confiança alta — ou com confiança alta e trava (lista_segue): segue p/ a
    próxima fase (pedido do usuário 2026-09-26/27: "se a confiança não for alta, passa para a próxima fase"; nenhum
    domínio vai da fase 1 direto p/ a 4)."""
    p = t + "." if t else ""
    return (f"({p}lista_fonte = '{FONTE_LOCAL}' AND (coalesce({p}lista_conf, 0) < "
            f"{float(settings().lista_confianca_min)} OR {p}lista_segue) AND {p}lista_at >= {p}analyzed_at "
            f"AND NOT {p}lista_duvida)")


def proxima_fase(d: dict) -> int:
    """Próxima fase de quem não teve confiança alta: 2 (WHOIS), 3 (busca na web) ou 4 (IA online)."""
    cfg = settings()
    if cfg.whois_enabled and not d.get("whois_at"):
        return 2
    if cfg.web_search_url and not d.get("web_search_at"):
        return 3
    return 4


def fase(client: OllamaClient) -> str:
    """Lista de UM domínio classificado sem a IA local (catálogo/regras) — os que passam pela IA local recebem a
    lista na própria fase 1 (`sugerir`). 'idle' = fila vazia."""
    if not settings().lista_ia_enabled:
        return "idle"
    with db.conn() as c:
        d = _reservar(c)
    if not d:
        return "idle"
    return "done" if lista_do_catalogo(d) else _sugerir(client, d)


def lista_do_catalogo(d: dict, fase_n: int = 1) -> bool:
    """Catálogo com lista fixa (amazonaws.com, cloudfront.net -> wl:infraestrutura): grava e aplica sem perguntar à IA.
    Segue o fluxo normal: ameaça (SUSPEITO/MALICIOSO) e quem já está numa lista de bloqueio (bucket/distribuição que a
    IA ou uma pessoa identificou como apostas, adulto, ameaça… — não desbloqueia)."""
    e = catalog.match(d["name"])
    if not e or not e.get("lista") or d.get("classification") in ("SUSPEITO", "MALICIOSO"):
        return False
    with db.conn() as c:
        if c.execute("SELECT 1 FROM category_lists WHERE domain = %s AND category NOT IN (%s, %s)",   # (Não identificados
                     (d["name"], PARA_REVISAR, NAO_IDENT)).fetchone():                                  #  não é identificação)
            return False
        salvar(c, d["id"], e["lista"], 1.0, f"catálogo: {e.get('topic')}", e.get("topic") or "", FONTE_CATALOGO, fase_n)
        aplicar(c, ids=[d["id"]])
    eventos.registrar("lista_local", d["name"], d["id"], d.get("classification"), None,
                      detail=f"{fase_n}|lista {e['lista']} 100% · {e.get('topic')} — catálogo (sem IA)")
    return True


def sugerir(client: OllamaClient, domain_id: int, fase_n: int = 1) -> str:
    """2ª pergunta à IA local nas fases 1-3: em qual lista o site entra (logo depois da classificação)."""
    if not settings().lista_ia_enabled:
        return "idle"
    with db.conn() as c:
        d = c.execute("UPDATE domains SET lista_claimed_at = now() WHERE id = %s AND kind = 'public' "
                      "RETURNING " + _COLUNAS, (domain_id,)).fetchone()
    if d and lista_do_catalogo(d, fase_n):
        return "done"
    return _sugerir(client, d, fase_n) if d else "idle"


def _sugerir(client: OllamaClient, d: dict, fase_n: int = 1) -> str:
    try:
        res, meta = perguntar(client, d)
    except LLMUnavailable:
        with db.conn() as c:
            c.execute("UPDATE domains SET lista_claimed_at = NULL WHERE id = %s", (d["id"],))
        return "unavailable"
    except LLMBadOutput as e:
        log.warning("lista da IA para %s: resposta inválida: %s", d["name"], e)
        with db.conn() as c:   # não trava a fila: tenta de novo só se o domínio for reanalisado
            c.execute("UPDATE domains SET lista_ia = NULL, lista_conf = NULL, lista_motivo = %s, lista_fonte = 'falhou', "
                      "lista_at = now(), lista_claimed_at = NULL WHERE id = %s", (str(e)[:200], d["id"]))
        return "done"
    gravar_local(d, res.lista, res.confianca, res.motivo, res.servico, fase_n, getattr(client, "model", None), meta.get("seconds"))
    return "done"


def gravar_local(d: dict, lista: str, conf: float, motivo: str, servico: str, fase_n: int, modelo: str | None,
                 segundos: float | None) -> None:
    """Resposta de lista da IA local (pergunta própria ou etapa única): grava, aplica na hora e registra o evento."""
    with db.conn() as c:
        salvar(c, d["id"], lista, conf, motivo, servico, FONTE_LOCAL, fase_n, modelo)
        fim = aplicar(c, ids=[d["id"]])["local"].get(d["id"])   # na hora (o ciclo de 5 min é a rede de segurança)
        from . import online
        vai_online = (fim or ("",))[0] not in ("online", "segue") and online.na_fila(c, d["id"])
    log.debug("lista %s -> %s (%.2f)", d["name"], lista, conf or 0)
    alta = (conf or 0) >= settings().lista_confianca_min
    eventos.registrar("lista_local", d["name"], d["id"], d.get("classification"), segundos,
                      detail=f"{fase_n}|lista {lista} {float(conf or 0) * 100:.0f}%"
                      + (f" · {servico}" if servico else "") + (f" — {motivo}" if motivo else "")
                      + _proximo(fim, alta)
                      + (" · desconhecido: vai p/ a fase 4 (IA online)" if vai_online else ""))


def lista_valida(lista: str | None) -> bool:
    return bool(lista) and (lista in LISTAS_IA or lista == NENHUMA or (e_wl(lista) and lista[3:] in whitelist.CATEGORIAS
                                                                      and lista[3:] != whitelist.SEM_RESPOSTA))


def codigos_lista() -> list[str]:
    return list(LISTAS_IA) + [f"wl:{k}" for k in whitelist.DESCRICOES]


def regras_lista() -> str:
    """Parte fixa da etapa local única: como escolher a lista + as listas e whitelists (mesmas regras da fase 4)."""
    from . import online
    s = online.SYSTEM
    regra = s[s.index('- "lista":'):s.index('- "confianca":')].replace("{{", "{").replace("}}", "}")
    return ("ALÉM da classificação, diga para onde o site vai (campos lista, lista_confianca, lista_motivo). "
            "lista_confianca 1.0 só com certeza; 0.7 provável; 0.4 ou menos se está chutando.\n" + regra
            + "\nListas de bloqueio:\n" + "\n".join(f"- {k}: {v}" for k, v in LISTAS_IA.items())
            + "\n\nWhitelists (sites liberados):\n" + "\n".join(f"- {k}: {v}" for k, v in WL.items()))


def _proximo(fim: tuple | None, alta: bool) -> str:
    """O que aconteceu com a resposta (aplicar): decide / segue p/ a fase N / IA online, com o motivo da trava."""
    if not fim:   # IA online desligada: a certeza da IA local basta
        return " · confiança alta: a IA local decide" if alta else ""
    if fim[0] == "decide":
        return " · confiança alta: a IA local decide"   # (o IA ao vivo mostra esta como decisão)
    if fim[0] == "mantida":
        return " · lista atual mantida"
    if fim[0] == "humano":
        return " · decisão humana mantida (liberado)"
    conf = "confiança alta" + (f", trava: {fim[-1]}" if fim[-1] else "") if alta else "confiança baixa"
    return f" · {conf}: segue p/ a fase {fim[1]}" if fim[0] == "segue" else f" · {conf}: vai p/ a fase 4 (IA online)"


def salvar(c, domain_id: int, lista: str, conf: float, motivo: str, servico: str, fonte: str, fase: int | None = None,
           modelo: str | None = None) -> None:
    wl = lista[3:] if e_wl(lista) else None
    c.execute("UPDATE domains SET lista_ia = %s, lista_wl = %s, lista_conf = %s, lista_motivo = %s, lista_servico = %s, "
              "lista_fonte = %s, lista_fase = %s, lista_modelo = %s, lista_segue = false, lista_at = now(), "
              "lista_claimed_at = NULL WHERE id = %s",
              (None if lista == NENHUMA or wl else lista, wl, conf, (motivo or "")[:500], (servico or "")[:200], fonte, fase,
               modelo, domain_id))


def decide_sozinho(modelo: str | None) -> bool:
    """O modelo local passou na prova (critério do usuário) e decide sozinho quando tem confiança alta."""
    return bool(modelo) and modelo in settings().local_decide_models


def origem(r: dict) -> str:
    """Quem deu a resposta de lista em uso (p/ a coluna "Decisão" do IA ao vivo)."""
    if (r.get("lista_fonte") or "").startswith("online"):
        return "f4:online"
    if r.get("lista_fonte") == FONTE_INVESTIGACAO:
        return "f6:investigacao"
    return f"f{r['lista_fase']}:local" if r.get("lista_fase") else "local"


def status(c) -> dict:
    return c.execute("SELECT count(*) FILTER (WHERE " + _FILA + ") AS fila, "
                     "count(*) FILTER (WHERE lista_at IS NOT NULL AND lista_fonte <> 'falhou') AS feitos, "
                     "count(*) FILTER (WHERE lista_ia IS NOT NULL) AS com_lista FROM domains").fetchone()


# ------------------------------------------------------------------ aplicar nas listas
AUTO_BY = "IA automática"          # entrou sozinha na lista (certeza)
OUTROS = "outros_bloqueios"        # como Para revisar: com certeza, o site sai daqui p/ a lista certa
# Infraestrutura: só as entradas da MIGRAÇÃO (antigo grupo "CDN", nunca revisado) — com certeza vão p/ a lista
# certa; "nenhuma" tira só com a resposta do modelo maior da IA online (ou dois modelos de acordo) e sem
# suspeita (liberaria o site p/ todas as empresas que aplicam a lista); o resto vai p/ Decisões
INFRA = "infra_bloqueio"
DUVIDA_BY = "IA com dúvida"        # foi para Para revisar com a sugestão
REVER_BY = "IA recomenda"          # com confiança alta, contraria uma decisão humana: Para revisar com o parecer
PARA_REVISAR = "para_revisar"


# listas de serviços de uso misto por definição (a empresa escolhe aplicar): a categoria da IA para eles é
# "de trabalho" e são populares (WhatsApp = comunicação, ChatGPT = produtividade, Dropbox = TI) — as travas
# de categoria e de popularidade as deixariam vazias. Só a do catálogo (protegidos) vale.
_USO_MISTO = {"mensageiros", "ia_chatbots", "nuvem_remoto"}
# DoH/DNS (incidente 2026-09-26): nomes de DNS de CDN/plataforma (impervadns.net, apple-dns.net,
# herokudns.com…) parecem "resolvedor" p/ as IAs e são destino de CNAME de milhares de sites — um erro
# derruba tudo o que está atrás deles. Só entra sozinha com DOIS modelos online de acordo (volume + segunda
# opinião), ambos ≥ 0,95 (os acertos vieram com 1,0; os erros da IA online, bibledns/dnzdns, com 0,8-0,85).
_DOIS_MODELOS = {"doh_dns"}
_DOIS_MODELOS_CONF = 0.95


def guardado(r: dict, cat: str | None = None) -> str | None:
    """Motivo pelo qual o domínio NÃO pode entrar sozinho numa lista (vai p/ Decisões), ou None.
    Travas: infraestrutura protegida do catálogo; categoria de trabalho (corporate.NEVER_BLOCK) — com
    resposta da IA online, só quando AS DUAS IAs dão categoria de trabalho (a local erra justamente aí:
    CMP de cookies = "produtividade"); site de trabalho popular (Tranco ≤ 10.000; classificação da IA
    online quando é ela quem responde). Listas de uso misto (Mensageiros, IA/Chatbots, Nuvem/Acesso
    remoto) só têm a trava do catálogo (ver _USO_MISTO); DoH/DNS exige dois modelos online de acordo
    (ver _DOIS_MODELOS)."""
    e = catalog.match(r["name"])
    if e and e.get("protected"):
        return "trava: infraestrutura protegida (catálogo)"
    if cat in _DOIS_MODELOS:
        antes = r.get("antes") or {}
        try:
            ok = ((r.get("lista_fonte") or "").startswith("online") and (r.get("lista_conf") or 0) >= _DOIS_MODELOS_CONF
                  and antes.get("lista") == cat and float(antes.get("confianca") or 0) >= _DOIS_MODELOS_CONF)
        except (TypeError, ValueError):
            ok = False
        return None if ok else "trava: DoH/DNS exige dois modelos online de acordo (≥ 95%)"
    if cat in _USO_MISTO:
        return None
    online = (r.get("lista_fonte") or "").startswith("online")
    cls = (r.get("cls_online") or r.get("classification")) if online else r.get("classification")
    trabalho = [x for x in (r.get("category"), r.get("cat_online") if online else None) if x]
    if trabalho and all(x in corporate.NEVER_BLOCK for x in trabalho):
        return f"trava: categoria de trabalho ({trabalho[-1]})"
    rank = r.get("popularity_rank")
    if rank and rank <= 10000 and cls == "TRABALHO":
        return f"trava: site de trabalho popular (Tranco {rank})"
    return None


def _dois_nenhuma(r: dict) -> bool:
    """Dois modelos online disseram "nenhuma lista" com ≥ 0,9."""
    a = r.get("antes") or {}
    try:
        return (a.get("lista") in (None, NENHUMA) and float(a.get("confianca") or 0) >= 0.9
                and float(r.get("lista_conf") or 0) >= 0.9)
    except (TypeError, ValueError):
        return False


def _fonte(r: dict) -> str:
    f = r.get("lista_fonte") or ""
    conf = f" {r['lista_conf'] * 100:.0f}%" if r.get("lista_conf") is not None else ""
    return ("IA online" + conf if f.startswith("online") else "IA local" + conf if f == FONTE_LOCAL
            else "investigação profunda" + conf if f == FONTE_INVESTIGACAO else f)


def _suspeito(r: dict) -> str | None:
    """Liberar (whitelist) um site classificado SUSPEITO/MALICIOSO não vale: whitelist.aplicar o tiraria."""
    return f"recomenda liberar, mas o site está classificado {r['classification']}" \
        if r.get("classification") in ("SUSPEITO", "MALICIOSO") else None


# endereço de máquina de nuvem (nome reverso do IP: ec2-18-1-2-3.eu-west-3.compute.amazonaws.com): quem está por
# trás é um cliente qualquer do provedor — nunca "não identificado" (bloquearia em todas as empresas); só ameaça (TI)
_MAQUINA_NUVEM = re.compile(r"^ec2-\d{1,3}(-\d{1,3}){3}\.([a-z0-9-]+\.)?compute(-1)?\.amazonaws\.com(\.cn)?$")


def _dominio_proprio(nome: str) -> bool:
    """O nome é um domínio registrado por alguém (r5k9x2.com), não um endereço dentro de um provedor/plataforma
    (d1abc.cloudfront.net, x.azureedge.net: sufixo privado da PSL) nem subdomínio."""
    from .features import analyze_name
    info = analyze_name(nome, settings().internal_suffixes)
    return not info.private_suffix and info.registrable == nome


def _coerente(cat: str, cls: str | None, categoria: str | None) -> bool:
    return _incoerencia(cat, cls, categoria) is None


def _incoerencia(cat: str, cls: str | None, categoria: str | None) -> str | None:
    if cat == "ameaca" and cls != "MALICIOSO":
        return f"ameaça sem classificação maliciosa ({cls or '—'})"
    if cat in _EXIGE_NAO_TRABALHO and cls == "TRABALHO":
        return f"{cat} num site de trabalho"
    if categoria == "infraestrutura" and cat != "doh_dns":
        return "infraestrutura de sistemas: só com revisão"
    return None


def aplicar(c, limite: int = 3000, ids: list[int] | None = None) -> dict:
    """Resultados novos da etapa "lista" e da IA online -> listas.

    Sem fase 5 (pedido do usuário 27/09: "deixar que a IA tome todas as decisões na fase 4, 100% automatizado; os
    erros eu trato manualmente"). A IA local (gemma4) decide sozinha com confiança alta; senão, fases 2/3 e a IA online.
    A resposta da IA online é a ÚLTIMA: com ou sem certeza, vale — lista de bloqueio ou whitelist. Travas (protegido do
    catálogo, site de trabalho, DoH sem dois modelos, incoerência): a IA não bloqueia, o site vai p/ a whitelist (só na
    lista: nada muda no DNS). Decisão de pessoa vale sempre ("manter liberado" ou lista posta por ela): a IA não desfaz
    a correção humana. Sem IA online: a resposta da IA local é a última."""
    cfg = settings()
    rows = c.execute(
        "SELECT d.id, d.name, d.classification, d.category, d.locked, d.lista_ia, d.lista_conf, d.lista_fonte, d.lista_at, "
        " d.popularity_rank, d.corp_action, d.whois_at, d.web_search_at, d.lista_fase, d.lista_wl, d.lista_modelo, d.online_resp->>'classificacao' AS cls_online, d.online_resp->>'categoria' AS cat_online, "
        " d.online_resp->'_meta'->'antes' AS antes, coalesce((d.online_resp->'_meta'->>'nivel_reforco')::boolean, false) AS reforco, "
        " EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed' "
        "         AND g.reviewed_by NOT LIKE 'IA%%' AND g.reviewed_by NOT LIKE 'bloqueio automático%%') AS g_allowed, "
        " EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id AND (td.review_status = 'allowed' "
        "         OR td.override_classification = 'TRABALHO')) AS t_allowed, "
        " ARRAY(SELECT l.category || '|' || coalesce(l.added_by, '') FROM category_lists l WHERE l.domain = d.name) AS em "
        "FROM domains d WHERE d.lista_at IS NOT NULL AND d.lista_fonte <> 'falhou' "
        " AND d.lista_aplicada_at IS DISTINCT FROM d.lista_at" + (" AND d.id = ANY(%s)" if ids else "")
        + " ORDER BY d.lista_at LIMIT %s", (ids, limite) if ids else (limite,)).fetchall()
    aplicadas = {x for r in c.execute("SELECT lists FROM policies") for x in (r["lists"] or [])}
    out = {"direto": [], "travados": [], "resolvidos": [], "online": [], "local": {}}   # local: {id: destino da resposta}
    from . import online as _online
    online_ok = _online.habilitado()

    def sai_revisao(r, em):
        """Para revisar (antiga fila da fase 5) não recebe mais nada: quem estava lá sai quando a IA decide."""
        if PARA_REVISAR in em:
            c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (PARA_REVISAR, r["name"]))

    def liberar(r, cls, humano=False, trava=None):
        """Decisão final de liberar: o site entra numa whitelist (Domínios liberados), na categoria escolhida pela IA.
        Não é publicado no DNS (fora de listas de bloqueio já está liberado; a whitelist vence qualquer bloqueio em
        todas as empresas) — whitelist.aplicar publica o que tiver pessoa, catálogo ou dois modelos online.
        humano: decisão de pessoa ("manter liberado") com resposta de bloqueio da IA; trava: a IA recomendou bloquear."""
        on = (r["lista_fonte"] or "").startswith("online")
        wl = r["lista_wl"] or whitelist._categoria(r["cat_online"] if on else r["category"], cls)
        if wl == whitelist.SEM_RESPOSTA or wl not in whitelist.CATEGORIAS:
            wl = "outros_liberados"
        if humano:
            c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) SELECT %s, %s, %s, false "
                      "WHERE NOT EXISTS (SELECT 1 FROM whitelist_domains WHERE domain = %s)", (wl, r["name"], listas.SEM_DESTINO_BY, r["name"]))
            return
        por = ("IA online" if on else "Investigação profunda (fase 6)" if r["lista_fonte"] == FONTE_INVESTIGACAO
               else f"IA local (fase {r['lista_fase']})" if r["lista_fase"] else "IA local")
        ja = c.execute("SELECT category, added_by FROM whitelist_domains WHERE domain = %s", (r["name"],)).fetchone()
        if ja and trava:
            return
        if ja:
            if not ((ja["added_by"] or "").startswith("IA local") and ja["category"] != wl):
                # já estava (pessoa, catálogo, IA online ou a mesma categoria): a decisão confirma — aparece na coluna Decisão
                eventos.lista("aprovado", r["name"], f"wl:{ja['category']}", f"confirmou (já estava na whitelist) · {_fonte(r)}",
                              r["id"], origem(r), cls)
                return
            # posta antes pela IA local (provisória): a categoria da resposta nova (IA online ou IA local que decide) vale
            c.execute("DELETE FROM whitelist_domains WHERE domain = %s AND added_by LIKE 'IA local%%'", (r["name"],))
        listas.contexto(c, por, f"liberado: {whitelist.CATEGORIAS[wl]} · {_fonte(r)}" + (f" · {trava}" if trava else ""))
        c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES (%s, %s, %s, false) "
                  "ON CONFLICT DO NOTHING", (wl, r["name"], por))
        eventos.lista("aprovado", r["name"], f"wl:{wl}", f"{whitelist.CATEGORIAS[wl]} · {_fonte(r)}" + (f" · {trava}" if trava else ""),
                      r["id"], origem(r), cls)

    # reanálise pedida termina aqui também quando a decisão humana/migração segura a lista (28/09: ~1.100 decididos
    # reanalisados ficavam com reanalise_pedida = true p/ sempre e pareciam "na fila")
    fim_pedida = "UPDATE domains SET revisado_at = now(), reanalise_pedida = false WHERE id = %s AND reanalise_pedida"
    for r in rows:
        c.execute("UPDATE domains SET lista_aplicada_at = lista_at WHERE id = %s", (r["id"],))
        cat = r["lista_ia"]
        em = dict(x.split("|", 1) for x in (r["em"] or []))                    # {lista: quem pôs}
        da_ia = {k for k, v in em.items() if v.startswith((AUTO_BY, "bloqueio automático"))}   # postas pela IA
        moveis = {PARA_REVISAR, OUTROS} | da_ia | ({INFRA} if em.get(INFRA, "").startswith("migração") else set())
        fixas = set(em) - moveis                                                 # pessoa/migração/Sistema
        online = _final(r)   # IA online ou investigação profunda (fase 6): resposta final
        certo = (r["lista_conf"] or 0) >= (cfg.online_confianca_min if online else cfg.lista_confianca_min)
        cls = (r["cls_online"] if (r["lista_fonte"] or "").startswith("online") and r["cls_online"]
               else r["classification"])
        humano_contra = bool(cat) and cat in aplicadas and (r["g_allowed"] or r["t_allowed"] or r["locked"])

        if humano_contra:   # uma pessoa decidiu "manter liberado": vale a pessoa (a IA não desfaz a correção humana)
            out["local"][r["id"]] = ("humano",)
            c.execute(fim_pedida, (r["id"],))
            sai_revisao(r, em)
            if not (set(em) - {PARA_REVISAR}):   # sem lista de bloqueio: whitelist (só na lista), como decisão humana
                liberar(r, cls, humano=True)
            continue
        local_decide = False
        if not online and online_ok:   # IA local (fases 1-3)
            # resposta nova da IA local: a ida p/ a IA online de uma rodada anterior não vale mais
            sem_online = "UPDATE domains SET lista_duvida = false WHERE id = %s AND lista_duvida"
            if fixas or (cat and cat in em):
                c.execute(sem_online, (r["id"],))
                if cat and cat in em and certo and decide_sozinho(r["lista_modelo"]):   # já estava na lista: confirmou
                    out["local"][r["id"]] = ("decide",)
                    eventos.lista("lista_add", r["name"], cat, f"confirmou (já estava na lista) · {_fonte(r)}", r["id"], origem(r), cls)
                    sai_revisao(r, em)
                else:   # pessoa/migração pôs noutra lista: vale a decisão dela
                    out["local"][r["id"]] = ("mantida",)
                c.execute(fim_pedida, (r["id"],))
                continue
            # confiança alta de um modelo que passou na prova (LOCAL_DECIDE_MODELS: gemma4) = a IA local decide sozinha
            # (lista de bloqueio ou whitelist), com as travas: coerência, guardado (DoH 2 modelos online, protegido,
            # trabalho) e tirar da Infraestrutura (libera o site nas empresas) seguem p/ a IA online. Modelo fraco
            # (qwen3:8b: liberou mensageiro, rede social e CDN de apostas com 100%) sempre passa pela IA online.
            tira_infra = not cat and INFRA in moveis and INFRA in em
            trava = None
            if certo:
                trava = ("tirar da Infraestrutura" if tira_infra else
                         (_incoerencia(cat, cls, r["category"]) or guardado(r, cat)) if cat else _suspeito(r))
                if not decide_sozinho(r["lista_modelo"]) and r["lista_fonte"] != FONTE_CATALOGO:
                    trava = trava or f"modelo {r['lista_modelo'] or 'antigo'} não decide sozinho"
                if cat == NAO_IDENT:
                    trava = trava or "não identificado: só depois das fases 2 a 4"
            prox = proxima_fase(r)
            if certo and not trava:
                local_decide = True
                out["local"][r["id"]] = ("decide",)
            elif prox < 4:   # sem confiança alta ou com trava: fase 2 (WHOIS) / 3 (busca na web) antes da IA online
                c.execute("UPDATE domains SET lista_duvida = false, lista_segue = true WHERE id = %s", (r["id"],))
                out["local"][r["id"]] = ("segue", prox, trava)
                continue
            else:   # depois da fase 3, ainda sem confiança ou com trava: IA online
                c.execute("UPDATE domains SET lista_duvida = true WHERE id = %s", (r["id"],))
                out["online"].append((r["name"], cat))
                out["local"][r["id"]] = ("online", trava)
                continue
        if local_decide:   # avaliado pela IA local (sem reanálise) e fim da revisão pedida
            c.execute("UPDATE domains SET revisado_at = now(), reanalise_pedida = false, lista_duvida = false WHERE id = %s",
                      (r["id"],))

        # daqui p/ baixo a resposta é a ÚLTIMA (IA online, IA local que decide, ou sem IA online): sempre há destino
        if fixas and (not cat or cat not in em):   # pessoa/migração pôs noutra lista: vale a decisão dela
            c.execute(fim_pedida, (r["id"],))
            sai_revisao(r, em)
            continue
        if cat == NAO_IDENT and _MAQUINA_NUVEM.match(r["name"]) and cls not in ("SUSPEITO", "MALICIOSO"):
            cat, r["lista_wl"] = None, "infraestrutura"   # (28/09: o Gemini respondia "nao_identificado" p/ EC2)
        if not cat and cls == "DESCONHECIDO" and r["lista_wl"] != "sem_resposta" and (
                r["lista_wl"] not in ("cdn", "infraestrutura") or _dominio_proprio(r["name"])):
            # não identificado depois das 4 fases não é liberado em whitelist nenhuma (27/09: espelhos de cassino como
            # cs8sp.com iam p/ "Outros liberados", nomes aleatórios como r5k9x2.com viravam "CDN"; 28/09: 4-u-h-f.com
            # e appshield-sec.workers.dev iam p/ "Outros (trabalho)"); CDN/infraestrutura só segue liberada quando é
            # endereço DENTRO de um provedor (ex.: d1abc.cloudfront.net, bucket.s3.amazonaws.com)
            cat = NAO_IDENT
        elif local_decide and not cat and cls == "DESCONHECIDO" and r["lista_wl"] in ("cdn", "infraestrutura"):
            # endereço DENTRO de um provedor (ec2-1-2-3-4.compute.amazonaws.com, d1abc.cloudfront.net) liberado com
            # certeza pela IA local: "desconhecido" é o cliente do provedor, que a IA online também não tem como
            # saber — dispensa a fase 4 (28/09: ~110 endereços EC2/dia iam p/ o Gemini com 100% de confiança)
            c.execute("UPDATE domains SET online_at = now() WHERE id = %s", (r["id"],))
        if not cat:   # liberar: sai das listas que a IA pôs e vai p/ a whitelist
            # da Infraestrutura (migração) só com certeza, a resposta do modelo maior (ou dois modelos) e sem suspeita:
            # senão fica lá (bloqueado como estava)
            sai_infra = certo and cls not in ("SUSPEITO", "MALICIOSO") and (r["reforco"] or _dois_nenhuma(r))
            tirar = [x for x in moveis if x in em and x != OUTROS and (x != INFRA or sai_infra)]
            if tirar:
                listas.contexto(c, _fonte(r), ("IA online" if online else "IA local") + ": não é de lista nenhuma")
                c.execute("DELETE FROM category_lists WHERE category = ANY(%s) AND domain = %s", (tirar, r["name"]))
                out["resolvidos"].append(r["name"])
                if set(tirar) - {PARA_REVISAR}:
                    eventos.lista("lista_rem", r["name"], ",".join(sorted(set(tirar) - {PARA_REVISAR})),
                                  f"não é de lista nenhuma · {_fonte(r)}", r["id"], origem(r), cls)
            if not (set(em) - set(tirar)):   # não sobrou lista de bloqueio: vai p/ a whitelist
                liberar(r, cls)
            continue
        # lista de bloqueio. A lista diz O QUE O SITE É; p/ a IA online, "ameaça" só com classificação suspeita/maliciosa
        coerente = (cat != "ameaca" or cls in ("MALICIOSO", "SUSPEITO")) if online else _coerente(cat, cls, r["category"])
        trava = None if cat in em else (guardado(r, cat) if coerente else f"{cat} com classificação {cls}")
        if trava:   # a IA não bloqueia sozinha: fica como está; sem lista de bloqueio, vai p/ a whitelist (nada muda no DNS)
            out["travados"].append((r["name"], cat, trava))
            sai_revisao(r, em)
            if not (set(em) - {PARA_REVISAR}):
                liberar(r, cls, trava=f"trava: {trava} (a IA recomendou {cat})")
            continue
        # com ou sem certeza: a fase 4 é a última (sem Decisão Humana)
        por = f"{AUTO_BY} ({cat})"
        listas.contexto(c, por, _fonte(r) + ("" if certo else " · sem certeza"))
        if cat not in em:
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                      (cat, r["name"], por))
            if cat in aplicadas:   # passou a bloquear alguém: conta como decidido
                c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', %s) "
                          "ON CONFLICT (domain_id) DO NOTHING", (r["id"], por))
            out["direto"].append((r["name"], cat))
            eventos.lista("lista_add", r["name"], cat, _fonte(r) + ("" if certo else " · sem certeza")
                          + (f" · saiu de {', '.join(sorted(x for x in moveis if x in em))}" if any(x in em for x in moveis) else ""),
                          r["id"], origem(r), cls)
        elif online:   # já estava na lista: a IA online confirmou (a decisão aparece na coluna "Decisão")
            eventos.lista("lista_add", r["name"], cat, f"confirmou (já estava na lista) · {_fonte(r)}", r["id"], origem(r), cls)
        tirar = [x for x in moveis if x in em and x != cat]
        if tirar:
            c.execute("DELETE FROM category_lists WHERE category = ANY(%s) AND domain = %s", (tirar, r["name"]))
    if out["direto"] or out["travados"] or out["online"] or out["resolvidos"]:
        log.info("listas pela IA: %d direto, %d p/ a IA online, %d travados (whitelist), %d resolvidos", len(out["direto"]),
                 len(out["online"]), len(out["travados"]), len(out["resolvidos"]))
    return out
