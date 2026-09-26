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
import time

import httpx
from pydantic import BaseModel, Field, ValidationError

from . import catalog, corporate, db, eventos, listas
from .config import settings
from .llm import LLMBadOutput, LLMUnavailable, OllamaClient

log = logging.getLogger(__name__)

# listas que a IA preenche (as de "Sistema" — Infraestrutura, Outros, Para revisar — são manuais)
LISTAS_IA = {
    "ameaca": "phishing, golpe, malware, comando e controle, site malicioso confirmado",
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
    "compras": "lojas online, marketplaces, varejo, atacado, supermercado, delivery, cupons (conta como trabalho: compras da empresa)",
    "noticias": "portais de notícias, revistas, fofoca e entretenimento",
    "pirataria": "torrents, downloads piratas, cracks, IPTV pirata, filmes e séries piratas, sites que baixam vídeo/música "
                 "de YouTube e streamings (conversor de ARQUIVOS/PDF legítimo não é pirataria: é nenhuma)",
    "ia_chatbots": "assistentes de IA, chatbots e geradores de texto ou imagem (ChatGPT, Claude, Gemini, Copilot, Perplexity)",
    "nuvem_remoto": "SÓ armazenamento/compartilhamento de ARQUIVOS pessoal (Dropbox, Google Drive, Mega, WeTransfer) e "
                    "acesso remoto a computadores (AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop). Nuvem PARA SISTEMAS "
                    "(AWS, Azure, Google Cloud, APIs, login/autenticação, hospedagem), Microsoft 365, SharePoint, OneDrive "
                    "da empresa e Google Workspace são nenhuma",
}
NENHUMA = "nenhuma"
FONTE_LOCAL = "local"
# o site precisa ser coerente com a classificação principal p/ entrar sozinho (senão: Para revisar)
_EXIGE_NAO_TRABALHO = {"vpn_proxy", "adulto", "apostas", "jogos", "redes_sociais", "streaming", "publicidade", "pirataria",
                       "noticias", "adware", "cripto_trading"}   # site TRABALHO nessas = contradição -> revisão (Compras conta como trabalho)

SYSTEM = """Você organiza sites em LISTAS de filtro de DNS para empresas brasileiras.
A lista diz O QUE O SITE É — não se ele é de trabalho (cada empresa escolhe depois quais listas bloqueia).
Domínios técnicos de um serviço (CDN, API, imagens, apps) vão para a lista do serviço (ex.: fbcdn.net = redes_sociais, ytimg.com = streaming, whatsapp.net = mensageiros).
Se o site não é nenhuma destas coisas (ferramenta de trabalho, banco, governo, ERP, fornecedor, fabricante, sistema, infraestrutura técnica, educação, saúde), a lista é "nenhuma".

Listas:
{listas}

"confianca": 1.0 só quando você sabe exatamente que serviço é e ele se encaixa claramente na lista; 0.7 se é provável; 0.4 ou menos se está chutando. Não invente: se as informações não bastam, confiança baixa.
Responda só o JSON, em português, numa linha."""


class ListaResult(BaseModel):
    servico: str = Field(default="", max_length=200)
    lista: str
    confianca: float = Field(ge=0, le=1)
    motivo: str = Field(default="", max_length=300)


def _schema() -> dict:
    return {"type": "object",
            "properties": {"servico": {"type": "string", "maxLength": 60},
                           "lista": {"type": "string", "enum": [*LISTAS_IA, NENHUMA]},
                           "confianca": {"type": "number", "minimum": 0, "maximum": 1},
                           "motivo": {"type": "string", "maxLength": 80}},
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
    return "\n".join(linhas[:14])


def perguntar(client: OllamaClient, d: dict) -> tuple[ListaResult, dict]:
    listas = "\n".join(f"- {k}: {v}" for k, v in LISTAS_IA.items()) + f"\n- {NENHUMA}: não é nenhuma das anteriores"
    options = {"temperature": 0, "seed": 42, "num_ctx": client.num_ctx, "num_predict": 160}
    if client.num_thread:
        options["num_thread"] = client.num_thread
    payload = {"model": client.model, "stream": False, "think": False, "keep_alive": client.keep_alive,
               "format": _schema(), "options": options,
               "messages": [{"role": "system", "content": SYSTEM.format(listas=listas)},
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
    if res.lista not in LISTAS_IA and res.lista != NENHUMA:
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
        "RETURNING id, name, topic, classification, category, corp_reason, reasons, evidence").fetchone()


def fase(client: OllamaClient) -> str:
    """Classifica UM domínio na lista. 'idle' = fila vazia."""
    if not settings().lista_ia_enabled:
        return "idle"
    with db.conn() as c:
        d = _reservar(c)
    if not d:
        return "idle"
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
    with db.conn() as c:
        salvar(c, d["id"], res.lista, res.confianca, res.motivo, res.servico, FONTE_LOCAL)
    log.debug("lista %s -> %s (%.2f, %.1fs)", d["name"], res.lista, res.confianca, meta["seconds"])
    return "done"


def salvar(c, domain_id: int, lista: str, conf: float, motivo: str, servico: str, fonte: str) -> None:
    c.execute("UPDATE domains SET lista_ia = %s, lista_conf = %s, lista_motivo = %s, lista_servico = %s, "
              "lista_fonte = %s, lista_at = now(), lista_claimed_at = NULL WHERE id = %s",
              (None if lista == NENHUMA else lista, conf, (motivo or "")[:300], (servico or "")[:200], fonte, domain_id))


def status(c) -> dict:
    return c.execute("SELECT count(*) FILTER (WHERE " + _FILA + ") AS fila, "
                     "count(*) FILTER (WHERE lista_at IS NOT NULL AND lista_fonte <> 'falhou') AS feitos, "
                     "count(*) FILTER (WHERE lista_ia IS NOT NULL) AS com_lista FROM domains").fetchone()


# ------------------------------------------------------------------ aplicar nas listas
AUTO_BY = "IA automática"          # entrou sozinha na lista (certeza)
OUTROS = "outros_bloqueios"        # como Para revisar: com certeza, o site sai daqui p/ a lista certa
DUVIDA_BY = "IA com dúvida"        # foi para Para revisar com a sugestão
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


def _fonte(r: dict) -> str:
    f = r.get("lista_fonte") or ""
    conf = f" {r['lista_conf'] * 100:.0f}%" if r.get("lista_conf") is not None else ""
    return ("IA online" + conf if f.startswith("online") else "IA local" + conf if f == FONTE_LOCAL else f)


def _coerente(cat: str, cls: str | None, categoria: str | None) -> bool:
    return not (cat == "ameaca" and cls != "MALICIOSO") and \
        not (cat in _EXIGE_NAO_TRABALHO and cls == "TRABALHO") and \
        not (categoria == "infraestrutura" and cat != "doh_dns")   # infra de sistemas: só com revisão


def aplicar(c, limite: int = 3000) -> dict:
    """Resultados novos da etapa "lista" e da IA online -> listas.

    Com a IA online ligada, ela é a VALIDADORA: a sugestão da IA local (com ou sem certeza) espera a
    fase 4 (lista_duvida); a resposta da IA online com certeza e coerente (pela classificação DELA) põe o
    site na lista — e corrige o que a IA local tinha posto sozinha; sem certeza -> Decisões (fase 5),
    a menos que o site já esteja numa lista. Sem IA online: a certeza da IA local basta (como antes).
    Site posto numa lista por pessoa/migração fica onde está; com decisão humana "manter liberado" (numa
    lista que bloqueia alguém), a IA não mexe: decidido uma vez não volta."""
    cfg = settings()
    rows = c.execute(
        "SELECT d.id, d.name, d.classification, d.category, d.locked, d.lista_ia, d.lista_conf, d.lista_fonte, d.lista_at, "
        " d.popularity_rank, d.corp_action, d.online_resp->>'classificacao' AS cls_online, d.online_resp->>'categoria' AS cat_online, "
        " d.online_resp->'_meta'->'antes' AS antes, "
        " EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed' "
        "         AND g.reviewed_by NOT LIKE 'IA%%' AND g.reviewed_by NOT LIKE 'bloqueio automático%%') AS g_allowed, "
        " EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id AND (td.review_status = 'allowed' "
        "         OR td.override_classification = 'TRABALHO')) AS t_allowed, "
        " ARRAY(SELECT l.category || '|' || coalesce(l.added_by, '') FROM category_lists l WHERE l.domain = d.name) AS em "
        "FROM domains d WHERE d.lista_at IS NOT NULL AND d.lista_fonte <> 'falhou' "
        " AND d.lista_aplicada_at IS DISTINCT FROM d.lista_at ORDER BY d.lista_at LIMIT %s", (limite,)).fetchall()
    aplicadas = {x for r in c.execute("SELECT lists FROM policies") for x in (r["lists"] or [])}
    out = {"direto": [], "revisar": [], "resolvidos": [], "online": []}
    from . import online as _online
    online_ok = _online.habilitado()

    def para_decisoes(r, cat, motivo=None):
        listas.contexto(c, DUVIDA_BY, motivo or "nenhuma fase teve certeza")
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                  (PARA_REVISAR, r["name"], f"{DUVIDA_BY} ({cat or 'nenhuma'})" + (f" · {motivo}" if motivo else "")))
        out["revisar"].append((r["name"], cat))
        eventos.lista("fase5", r["name"], cat, (motivo or "nenhuma fase teve certeza")
                      + (f" · {_fonte(r)}" if r["lista_fonte"] else ""), r["id"])

    for r in rows:
        c.execute("UPDATE domains SET lista_aplicada_at = lista_at WHERE id = %s", (r["id"],))
        cat = r["lista_ia"]
        em = dict(x.split("|", 1) for x in (r["em"] or []))                    # {lista: quem pôs}
        da_ia = {k for k, v in em.items() if v.startswith((AUTO_BY, "bloqueio automático"))}   # postas pela IA
        moveis = {PARA_REVISAR, OUTROS} | da_ia
        fixas = set(em) - moveis                                                 # pessoa/migração/Sistema
        online = (r["lista_fonte"] or "").startswith("online")
        certo = (r["lista_conf"] or 0) >= (cfg.online_confianca_min if online else cfg.lista_confianca_min)
        cls = r["cls_online"] if online and r["cls_online"] else r["classification"]
        humano_contra = bool(cat) and cat in aplicadas and (r["g_allowed"] or r["t_allowed"] or r["locked"])

        if humano_contra:
            continue   # alguém decidiu "manter liberado": decidido uma vez não volta (nem lista, nem Decisões)
        if not online and online_ok:   # IA local: espera a validação da IA online
            if not cat or cat in em or fixas:
                continue
            c.execute("UPDATE domains SET lista_duvida = true WHERE id = %s", (r["id"],))
            out["online"].append((r["name"], cat))
            continue

        if fixas and (not cat or cat not in em):
            continue   # alguém pôs noutra lista: fica
        if certo and not cat and online:
            # a IA online resolveu: não é de lista nenhuma (sai de Decisões e das listas que a IA pôs)
            tirar = [x for x in moveis if x in em and x != OUTROS]
            if tirar:
                listas.contexto(c, _fonte(r), "IA online: não é de lista nenhuma")
                c.execute("DELETE FROM category_lists WHERE category = ANY(%s) AND domain = %s", (tirar, r["name"]))
                out["resolvidos"].append(r["name"])
                eventos.lista("lista_rem", r["name"], ",".join(tirar), f"não é de lista nenhuma · {_fonte(r)}", r["id"])
            continue
        if online and not certo and not cat and not em and (cls == "NAO_TRABALHO" or r["corp_action"] == "BLOQUEAR"):
            para_decisoes(r, None, "IA online sem certeza: talvez não seja de lista")
            continue
        if not cat:
            continue
        # a lista diz O QUE O SITE É (não se é de trabalho): p/ a IA online só Ameaças segue manual (sem lista
        # de ameaça confirmando); as travas de coerência completas valem p/ a IA local (modelo pequeno)
        coerente = (cat != "ameaca" or cls == "MALICIOSO") if online else _coerente(cat, cls, r["category"])
        motivo = guardado(r, cat) if certo and coerente and cat not in em else None
        if motivo:   # trava: não entra sozinho, vai p/ Decisões (a menos que já esteja numa lista da IA)
            if not da_ia and PARA_REVISAR not in em:
                para_decisoes(r, cat, motivo)
        elif certo and coerente:
            listas.contexto(c, f"{AUTO_BY} ({cat})", _fonte(r))
            if cat not in em:
                por = f"{AUTO_BY} ({cat})"
                c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                          (cat, r["name"], por))
                if cat in aplicadas:   # passou a bloquear alguém: conta como decidido
                    c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', %s) "
                              "ON CONFLICT (domain_id) DO NOTHING", (r["id"], por))
                out["direto"].append((r["name"], cat))
                eventos.lista("lista_add", r["name"], cat, _fonte(r)
                              + (f" · saiu de {', '.join(x for x in moveis if x in em)}" if any(x in em for x in moveis) else ""), r["id"])
            tirar = [x for x in moveis if x in em and x != cat]
            if tirar:
                c.execute("DELETE FROM category_lists WHERE category = ANY(%s) AND domain = %s", (tirar, r["name"]))
        elif not da_ia and PARA_REVISAR not in em and OUTROS not in em:
            para_decisoes(r, cat)   # sem certeza em nenhuma fase: fase 5 (Outros fica lá, bloqueado, com a sugestão)
    if out["direto"] or out["revisar"] or out["online"] or out["resolvidos"]:
        log.info("listas pela IA: %d direto, %d p/ a IA online, %d p/ Decisões, %d resolvidos", len(out["direto"]),
                 len(out["online"]), len(out["revisar"]), len(out["resolvidos"]))
    return out
