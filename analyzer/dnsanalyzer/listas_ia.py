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

from . import db
from .config import settings
from .llm import LLMBadOutput, LLMUnavailable, OllamaClient

log = logging.getLogger(__name__)

# listas que a IA preenche (as de "Sistema" — Infraestrutura, Outros, Para revisar — são manuais)
LISTAS_IA = {
    "ameaca": "phishing, golpe, malware, comando e controle, site malicioso confirmado",
    "vpn_proxy": "VPN de uso pessoal, proxy, anonimizador, Tor, qualquer coisa para contornar o filtro "
                 "(VPN CORPORATIVA — Fortinet, GlobalProtect, Cisco AnyConnect, Zscaler — é nenhuma)",
    "doh_dns": "resolvedor DNS público e DNS sobre HTTPS/TLS (dns.google, cloudflare-dns, quad9, nextdns, adguard-dns, opendns)",
    "adulto": "pornografia, conteúdo sexual, encontros adultos, acompanhantes",
    "apostas": "bets, cassino online, apostas esportivas, loterias e jogos de azar online",
    "jogos": "jogos online, lojas e launchers de games, servidores e fóruns de jogos, cheats",
    "redes_sociais": "redes sociais (Facebook, Instagram, TikTok, X, Kwai, Pinterest, Reddit, Threads, Snapchat)",
    "streaming": "vídeo, música e lives sob demanda (YouTube, Netflix, Spotify, Deezer, Twitch, Globoplay, Prime Video)",
    "mensageiros": "mensageiros e chat pessoal (WhatsApp, Telegram, Discord, Signal, Messenger, WeChat)",
    "publicidade": "redes de anúncio, rastreamento, analytics, pixels, atribuição de apps",
    "compras": "lojas online e marketplaces de consumo, varejo, supermercado, delivery, cupons",
    "noticias": "portais de notícias, revistas, fofoca e entretenimento",
    "pirataria": "torrents, downloads piratas, cracks, IPTV pirata, filmes e séries piratas, conversores de vídeo",
    "ia_chatbots": "assistentes de IA, chatbots e geradores de texto ou imagem (ChatGPT, Claude, Gemini, Copilot, Perplexity)",
    "nuvem_remoto": "armazenamento e compartilhamento de arquivos pessoal (Dropbox, Google Drive, Mega, WeTransfer) e "
                    "acesso remoto (AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop). Microsoft 365, SharePoint "
                    "e OneDrive da empresa e Google Workspace são nenhuma",
}
NENHUMA = "nenhuma"
FONTE_LOCAL = "local"
# o site precisa ser coerente com a classificação principal p/ entrar sozinho (senão: Para revisar)
_EXIGE_NAO_TRABALHO = {"vpn_proxy", "adulto", "apostas", "jogos", "redes_sociais", "streaming", "publicidade", "pirataria"}

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
DUVIDA_BY = "IA com dúvida"        # foi para Para revisar com a sugestão
PARA_REVISAR = "para_revisar"


def aplicar(c, limite: int = 3000) -> dict:
    """Resultados novos da etapa "lista" -> listas. Certeza = confiança >= LISTA_CONFIANCA_MIN, coerente
    com a classificação principal e sem decisão humana contra (quando a lista bloqueia alguma empresa).
    Sem certeza -> Para revisar (com a sugestão). Site já numa lista (pessoa/migração) fica onde está."""
    cfg = settings()
    rows = c.execute(
        "SELECT d.id, d.name, d.classification, d.locked, d.lista_ia, d.lista_conf, d.lista_fonte, d.lista_at, "
        " EXISTS (SELECT 1 FROM global_reviews g WHERE g.domain_id = d.id AND g.status = 'allowed') AS g_allowed, "
        " EXISTS (SELECT 1 FROM tenant_domains td WHERE td.domain_id = d.id AND (td.review_status = 'allowed' "
        "         OR td.override_classification = 'TRABALHO')) AS t_allowed, "
        " ARRAY(SELECT l.category FROM category_lists l WHERE l.domain = d.name) AS em "
        "FROM domains d WHERE d.lista_at IS NOT NULL AND d.lista_fonte <> 'falhou' "
        " AND d.lista_aplicada_at IS DISTINCT FROM d.lista_at ORDER BY d.lista_at LIMIT %s", (limite,)).fetchall()
    aplicadas = {x for r in c.execute("SELECT lists FROM policies") for x in (r["lists"] or [])}
    out = {"direto": [], "revisar": [], "resolvidos": []}
    for r in rows:
        c.execute("UPDATE domains SET lista_aplicada_at = lista_at WHERE id = %s", (r["id"],))
        cat, em = r["lista_ia"], set(r["em"] or [])
        certo = (r["lista_conf"] or 0) >= cfg.lista_confianca_min
        if not cat and em == {PARA_REVISAR} and certo and (r["lista_fonte"] or "").startswith("etapa4"):
            # a IA online resolveu a dúvida: não é de lista nenhuma
            c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (PARA_REVISAR, r["name"]))
            out["resolvidos"].append(r["name"])
            continue
        if not cat or cat in em or (em - {PARA_REVISAR}):
            continue
        coerente = not (cat == "ameaca" and r["classification"] != "MALICIOSO") and \
            not (cat in _EXIGE_NAO_TRABALHO and r["classification"] == "TRABALHO")
        humano_contra = cat in aplicadas and (r["g_allowed"] or r["t_allowed"] or r["locked"])
        if certo and coerente and not humano_contra:
            por = f"{AUTO_BY} ({cat})"
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                      (cat, r["name"], por))
            c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (PARA_REVISAR, r["name"]))
            if cat in aplicadas:   # passou a bloquear alguém: conta como decidido (sai da fila de Decisões)
                c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) VALUES (%s, 'blocked', %s) "
                          "ON CONFLICT (domain_id) DO NOTHING", (r["id"], por))
            out["direto"].append((r["name"], cat))
        elif PARA_REVISAR not in em:
            c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                      (PARA_REVISAR, r["name"], f"{DUVIDA_BY} ({cat})"))
            out["revisar"].append((r["name"], cat))
    if out["direto"] or out["revisar"]:
        log.info("listas pela IA: %d direto, %d p/ Para revisar", len(out["direto"]), len(out["revisar"]))
    return out
