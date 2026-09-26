"""Fase 4: IA online (Gemini, plano gratuito) para o que as fases 1-3 (IA local; WHOIS + IA local;
busca na web + IA local) não resolveram com confiança:

- desconhecidos que já passaram pela busca na web (ou que estão em Para revisar / Outros);
- dúvidas da etapa "lista" (a IA local sugeriu uma lista sem certeza).

Recebe o mesmo contexto curto da etapa "lista" (nome, serviço, página, busca, WHOIS) e, para os
desconhecidos, pode pesquisar no Google (grounding: 5.000 buscas/mês grátis nos modelos 3.x). A resposta
vira a sugestão de lista (lista_fonte 'online:gemini'); com certeza, `listas_ia.aplicar` põe na lista;
sem certeza, vai para Para revisar = fase 5 (Decisões: manual, equipe de TI). Desconhecido reconhecido
com certeza ganha a classificação (classified_by 'online'); não reconhecido também vai para a fase 5.

Plano gratuito: o Google pode usar o conteúdo enviado (só nomes de domínio públicos e o que já se sabe
deles). Limites por minuto/dia variam por conta (painel do AI Studio): GEMINI_RPM / GEMINI_RPD, e o
HTTP 429 pausa até a janela seguinte (cota diária zera à meia-noite do Pacífico).
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
from psycopg.types.json import Jsonb

from . import db, webintel
from .config import settings
from . import listas_ia
from .listas_ia import LISTAS_IA, NENHUMA, _contexto, salvar

log = logging.getLogger(__name__)
CLASSES = ["TRABALHO", "NAO_TRABALHO", "SUSPEITO", "MALICIOSO", "DESCONHECIDO"]
FONTE = "online:gemini"
URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

SYSTEM = """Você classifica sites para o filtro de DNS de EMPRESAS brasileiras (computadores de funcionários).
Para o domínio, diga:
- "servico": o que é o site, numa frase curta;
- "reconhecido": true só se você sabe com segurança que empresa/serviço é;
- "classificacao": TRABALHO (ferramentas, fornecedores, compras da empresa, bancos, governo, sistemas e infraestrutura técnica),
  NAO_TRABALHO (lazer: redes sociais, streaming, jogos, apostas, adulto, pirataria, publicidade), SUSPEITO, MALICIOSO
  (só com indício forte de golpe/malware) ou DESCONHECIDO;
- "categoria": uma das categorias de site abaixo;
- "lista": a lista de filtro a que o site pertence — O QUE ELE É, não se é de trabalho (uma loja é "compras" mesmo que
  empresas comprem nela; um CMP de cookies é "publicidade" mesmo sendo compliance). DOMÍNIOS TÉCNICOS (CDN, arquivos
  estáticos, imagens, API, app) DE UM SERVIÇO vão para a lista DO SERVIÇO: primeiro descubra de quem é o domínio
  (ex.: slatic.net = arquivos da Lazada = compras; alicdn.com = Alibaba/AliExpress = compras; mlstatic.com = Mercado Livre =
  compras; fbcdn.net = Facebook = redes_sociais; ytimg.com = YouTube = streaming; akamaihd.net de um jogo = jogos).
  "nenhuma" só para ferramentas de trabalho, bancos, governo, fornecedores e infraestrutura GENÉRICA (Cloudflare, Akamai,
  AWS, Azure, Google Cloud, certificados, atualizações de sistema);
- "confianca": 1.0 só se tem certeza; 0.7 provável; 0.4 ou menos se está chutando;
- "motivo": uma frase.

Listas:
{listas}
- nenhuma: não é nenhuma das anteriores

Categorias de site: {categorias}

Responda SOMENTE o JSON: {{"servico": "...", "reconhecido": true, "classificacao": "...", "categoria": "...", "lista": "...", "confianca": 0.9, "motivo": "..."}}"""


class OnlineIndisponivel(Exception):
    """Sem chave, fora do ar ou cota esgotada: tentar mais tarde (não conta tentativa)."""


class _Cota:
    """Cota de UM modelo (RPM/RPD do plano gratuito); 429 pausa até o próximo minuto/dia (meia-noite do Pacífico)."""

    def __init__(self, modelo: str, rpm: int, rpd: int):
        self.modelo, self.rpm, self.rpd = modelo, max(rpm, 1), max(rpd, 1)
        self.lock, self.ultimo, self.dia, self.n, self.pausa_ate = threading.Lock(), 0.0, None, 0, 0.0

    @staticmethod
    def _hoje():
        return datetime.now(ZoneInfo("America/Los_Angeles")).date()

    def esperar(self) -> bool:
        with self.lock:
            if time.time() < self.pausa_ate:
                return False
            if self.dia != self._hoje():
                self.dia, self.n = self._hoje(), 0
            if self.n >= self.rpd:
                self.pausar_dia()
                return False
            falta = 60.0 / self.rpm - (time.monotonic() - self.ultimo)
            if falta > 0:
                time.sleep(falta)
            self.ultimo, self.n = time.monotonic(), self.n + 1
            return True

    def pausar_dia(self):
        agora = datetime.now(ZoneInfo("America/Los_Angeles"))
        amanha = (agora + timedelta(days=1)).replace(hour=0, minute=5, second=0, microsecond=0)
        self.pausa_ate = time.time() + (amanha - agora).total_seconds()
        log.info("IA online: cota do dia do %s esgotada; volta às %s (Pacífico)", self.modelo, amanha.strftime("%H:%M"))

    def pausar(self, segundos: float):
        self.pausa_ate = max(self.pausa_ate, time.time() + segundos)


_COTAS: dict[str, _Cota] = {}


def niveis() -> list[list[tuple[str, int, int]]]:
    """[volume, reforço, busca]: cada nível = [(modelo, rpm, rpd)] na ordem de uso (ver config)."""
    cfg = settings()
    return [cfg.gemini_modelos, cfg.gemini_reforco, cfg.gemini_busca]


def cota(modelo: str) -> _Cota:
    if modelo not in _COTAS:
        rpm, rpd = next(((r, d) for nivel in niveis() for m, r, d in nivel if m == modelo), (5, 20))
        _COTAS[modelo] = _Cota(modelo, rpm, rpd)
    return _COTAS[modelo]


def _com_busca(modelo: str) -> bool:
    """Busca no Google (grounding) no plano grátis desta conta: só nos modelos 2.x/2.5 (3.x = 0/dia)."""
    return modelo.startswith("gemini-2")


def _evento(d: dict, cls: str, lista: str, conf: float, servico: str, meta: dict) -> None:
    """Feed "IA ao vivo" (mesma tabela do classificador; conexão própria, nunca derruba a fase)."""
    antes = d.get("lista_ia")
    val = ("" if not antes else " · confirmou a IA local" if antes == lista else f" · corrigiu a IA local ({antes})")
    try:
        with db.conn() as c:
            c.execute("INSERT INTO ai_events (kind, domain_id, name, classification, seconds, detail) VALUES "
                      "('online_done', %s, %s, %s, %s, %s)",
                      (d["id"], d["name"], cls, meta.get("seconds"),
                       f"fase 4 · {meta.get('model')} · lista {lista} ({conf * 100:.0f}%){val}"
                       + (f" · {servico}" if servico else "")))
    except Exception as e:  # noqa: BLE001
        log.debug("falha ao gravar evento: %s", e)


_KIND = {"catalog": "catálogo interno", "site": "página do site", "websearch": "busca na web (fase 3)",
         "whois": "WHOIS/RDAP (fase 2)", "wikidata": "Wikidata", "cert": "certificado TLS", "popularity": "popularidade (Tranco)",
         "platform": "plataforma/hospedagem", "ti": "listas de ameaça", "age": "idade do domínio", "tld": "TLD",
         "lexical": "análise do nome", "logs": "comportamento nos logs DNS", "tunnel": "túnel DNS", "internal": "interno"}
_FASE = {"llm": "fase 1 (IA local)", "web": "fase 3 (busca na web + IA local)", "online": "fase 4 (IA online)",
         "catalog": "catálogo", "rules": "regras", "internal": "interno", "manual": "manual"}


def contexto_completo(d: dict, limite: int = 8000) -> str:
    """Tudo o que as fases 1-3 juntaram do domínio (p/ a IA online decidir melhor): resultado atual da IA
    local, razões, TODAS as evidências (WHOIS, busca na web, página, catálogo, popularidade…) e o histórico."""
    with db.conn() as c:
        r = c.execute("SELECT name, classification, category, topic, confidence, corp_action, corp_reason, classified_by, "
                      "reasons, evidence, popularity_rank, whois_at, web_search_at FROM domains WHERE id = %s", (d["id"],)).fetchone()
        hist = c.execute("SELECT source, classification, topic, confidence, created_at FROM classification_history "
                         "WHERE domain_id = %s ORDER BY created_at DESC LIMIT 6", (d["id"],)).fetchall()
    if not r:
        return _contexto(d)
    L = [f"Domínio: {r['name']}",
         f"Resultado atual da IA local ({_FASE.get(r['classified_by'], r['classified_by'] or '—')}): "
         f"{r['classification'] or '—'} · categoria {r['category'] or '—'} · serviço: {r['topic'] or '—'}"
         + (f" · confiança {r['confidence']:.2f}" if r["confidence"] is not None else ""),
         f"Recomendação p/ empresas: {r['corp_action'] or '—'}" + (f" — {r['corp_reason']}" if r["corp_reason"] else ""),
         "Fases já feitas: 1 (IA local)" + (" · 2 (WHOIS)" if r["whois_at"] else "") + (" · 3 (busca na web)" if r["web_search_at"] else "")]
    razoes = [f"- [{x.get('by') or '?'}] {x.get('text', '')}" for x in (r["reasons"] or []) if x.get("text")]
    if razoes:
        L += ["Razões:"] + razoes[:10]
    ev = [e for e in (r["evidence"] or []) if e.get("kind") not in ("identity", "negative") and e.get("text")]
    if ev:
        L.append("Evidências coletadas (fases 1 a 3):")
        L += [f"- {_KIND.get(e['kind'], e['kind'])}: {e['text'][:900]}" for e in ev]
    busca = d.get("_busca") or []
    if busca and not any(e.get("kind") == "websearch" for e in ev):
        L.append("Busca na web feita agora (texto de terceiros, pista — não prova):")
        L += [f"- {x.get('title') or ''} — {x.get('snippet') or ''} ({x.get('host') or ''})" for x in busca[:6]]
    if hist:
        L.append("Histórico de classificações (mais recente primeiro):")
        L += [f"- {h['created_at']:%d/%m %H:%M} {_FASE.get(h['source'], h['source'] or '?')}: {h['classification'] or '—'}"
              + (f" · {h['topic']}" if h["topic"] else "") for h in hist]
    texto = "\n".join(L)
    return texto if len(texto) <= limite else texto[:limite] + "\n[…]"


def habilitado() -> bool:
    cfg = settings()
    return bool(cfg.gemini_api_key) and cfg.online_enabled and bool(cfg.gemini_modelos)


def _json_da_resposta(texto: str) -> dict:
    m = re.search(r"\{.*\}", texto or "", re.S)
    if not m:
        raise ValueError(f"sem JSON: {texto[:200]}")
    return json.loads(m.group(0))


def perguntar(d: dict, categorias: list[str], buscar: bool, modelo: str | None = None) -> tuple[dict, dict]:
    cfg = settings()
    modelo = modelo or cfg.gemini_modelos[0][0]
    listas = "\n".join(f"- {k}: {v}" for k, v in LISTAS_IA.items())
    sistema = SYSTEM.format(listas=listas, categorias=", ".join(categorias))
    sug = ""
    if d.get("lista_ia"):   # validação: a IA online confirma ou corrige a sugestão da IA local
        sug = (f"\nSugestão da IA local (modelo pequeno, pode errar): lista '{d['lista_ia']}'"
               + (f" (confiança {d['lista_conf']:.2f})" if d.get("lista_conf") is not None else "")
               + (f" — {d['lista_motivo']}" if d.get("lista_motivo") else "") + ". Confirme ou corrija.")
    pergunta = contexto_completo(d) + sug + "\n\nClassifique este domínio."
    corpo: dict = {"generationConfig": {"temperature": 0}}
    if modelo.startswith("gemma"):   # Gemma pela API: sem instrução de sistema nem modo JSON (JSON extraído do texto)
        corpo["contents"] = [{"role": "user", "parts": [{"text": sistema + "\n\n" + pergunta}]}]
        buscar = False
    else:
        corpo["systemInstruction"] = {"parts": [{"text": sistema}]}
        corpo["contents"] = [{"role": "user", "parts": [{"text": pergunta}]}]
        buscar = buscar and _com_busca(modelo)
        if buscar:   # desconhecido: pesquisa no Google (resposta em texto; o JSON é extraído)
            corpo["tools"] = [{"google_search": {}}]
        else:
            corpo["generationConfig"]["responseMimeType"] = "application/json"
    t0 = time.monotonic()
    ct = cota(modelo)
    try:
        r = httpx.post(URL.format(model=modelo), json=corpo, timeout=150 if modelo.startswith("gemma") else 60,
                       headers={"x-goog-api-key": cfg.gemini_api_key})
    except httpx.HTTPError as e:
        raise OnlineIndisponivel(f"Gemini {modelo}: {e.__class__.__name__}") from e
    if r.status_code == 429:
        dia = "day" in r.text.lower() or "perday" in r.text.lower().replace("_", "")
        ct.pausar_dia() if dia else ct.pausar(65)
        raise OnlineIndisponivel(f"Gemini {modelo}: cota esgotada (429)")
    if r.status_code >= 500:   # sobrecarga do modelo
        ct.pausar(90)
        raise OnlineIndisponivel(f"Gemini {modelo}: HTTP {r.status_code}")
    if r.status_code != 200:
        ct.pausar(600)   # chave inválida/modelo inexistente: não martela
        raise OnlineIndisponivel(f"Gemini: HTTP {r.status_code}: {r.text[:200]}")
    j = r.json()
    partes = ((j.get("candidates") or [{}])[0].get("content") or {}).get("parts") or []
    texto = "".join(p.get("text", "") for p in partes if not p.get("thought"))
    obj = _json_da_resposta(texto)
    fontes = [c.get("web", {}).get("uri") for c in
              ((j.get("candidates") or [{}])[0].get("groundingMetadata") or {}).get("groundingChunks") or []][:5]
    return obj, {"model": modelo, "seconds": round(time.monotonic() - t0, 1), "busca": buscar,
                 "fontes": [f for f in fontes if f]}


# fila da fase 3: dúvidas da etapa "lista" + desconhecidos que já passaram pela fase 2
_NAS_LISTAS_REVISAO = "d.name IN (SELECT domain FROM category_lists WHERE category IN ('para_revisar', 'outros_bloqueios'))"
_EM_DECISOES = "EXISTS (SELECT 1 FROM category_lists l WHERE l.category = 'para_revisar' AND l.domain = d.name)"
_FILA = ("d.kind = 'public' AND NOT d.llm_pending AND (d.online_claimed_at IS NULL OR d.online_claimed_at < now() - interval '10 minutes') "
         "AND ((d.lista_duvida AND (d.online_at IS NULL OR d.online_at < d.lista_at)) "
         " OR (d.classification = 'DESCONHECIDO' AND (d.online_at IS NULL OR d.online_at < d.analyzed_at) "
         "     AND ((d.web_search_at IS NOT NULL AND NOT dominio_decidido(d.id)) OR " + _NAS_LISTAS_REVISAO + ")))")


def _reservar(c) -> dict | None:
    return c.execute(
        "UPDATE domains SET online_claimed_at = now() WHERE id = (SELECT d.id FROM domains d WHERE " + _FILA +
        " ORDER BY " + _EM_DECISOES + " DESC, d.lista_duvida DESC, d.total_queries DESC LIMIT 1 FOR UPDATE SKIP LOCKED) "
        "RETURNING id, name, topic, classification, category, corp_reason, reasons, evidence, lista_ia, lista_conf, lista_motivo, "
        "online_resp").fetchone()


def _certo(obj: dict) -> bool:
    try:
        conf = float(obj.get("confianca") or 0)
    except (TypeError, ValueError):
        return False
    return conf >= settings().online_confianca_min and (obj.get("lista") in LISTAS_IA or bool(obj.get("reconhecido")))


def _candidato_whitelist(obj: dict) -> bool:
    """Trabalho, reconhecido, sem lista: pode ir p/ a whitelist (vence qualquer bloqueio) — só com 2 modelos de acordo."""
    return obj.get("lista") in (None, NENHUMA) and obj.get("classificacao") == "TRABALHO" and bool(obj.get("reconhecido"))


def _buscas_no_mes(c) -> int:
    """Buscas no Google (grounding) já feitas no mês: o plano grátis dá 5.000/mês p/ os modelos 3.x."""
    return c.execute("SELECT count(*) AS n FROM domains WHERE online_at >= date_trunc('month', now()) "
                     "AND online_resp->'_meta'->>'busca' = 'true'").fetchone()["n"]


def _consultar(nivel, d, categorias, buscar) -> tuple[dict, dict] | None:
    """Primeiro modelo do nível com cota que responder."""
    for modelo, _, _ in nivel:
        if not cota(modelo).esperar():
            continue
        try:
            return perguntar(d, categorias, buscar, modelo)
        except OnlineIndisponivel as e:
            log.info("%s", e)
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            log.warning("IA online (%s) para %s: resposta inválida: %s", modelo, d["name"], e)
    return None


def fase(categorias: list[str]) -> str:
    """Uma consulta à IA online, por níveis (cada modelo com a sua cota do plano grátis):
    1 volume (flash-lite 3.5 -> 3.1); 2 segunda opinião, quando o volume não tem certeza ou discorda da IA
    local (Gemma 4 31B -> 3.8 flash; vale a resposta do modelo maior); 3 busca no Google (desligada nesta
    conta). Sem busca das fases anteriores, faz uma busca na web (SearXNG) antes, p/ dar contexto.
    'idle' = nada na fila; 'unavailable' = sem chave/cota/fora."""
    if not habilitado():
        return "idle"
    cfg = settings()
    with db.conn() as c:
        d = _reservar(c)
        pode_buscar = (d is not None and d["classification"] == "DESCONHECIDO" and cfg.gemini_grounding
                       and _buscas_no_mes(c) < cfg.gemini_grounding_month)
    if not d:
        return "idle"
    if cfg.web_search_url:   # sem busca das fases anteriores: busca agora (SearXNG; cache) p/ dar contexto
        try:
            with db.conn() as c:
                d["_busca"] = webintel.search(c, d["name"], fetch=True, wait=True)
        except Exception as e:  # noqa: BLE001 — sem busca a IA online segue com o que tem
            log.info("busca da fase 4 indisponível p/ %s: %s", d["name"], e)
    # já respondida antes (pergunta de novo): a sugestão original da IA local foi sobrescrita, então não dá
    # p/ ver discordância — a segunda opinião (modelo maior) é obrigatória
    revalidar = bool(d.get("online_resp")) and not (d.get("online_resp") or {}).get("erro")
    vol, reforco, busca = niveis()
    obj = meta = None
    for nivel, buscar in ((vol, False), (reforco, False), (busca if pode_buscar else [], True)):
        # próximo nível (modelo maior) se não há resposta, se ela não tem certeza ou se DISCORDA da IA local
        if obj is not None and _certo(obj) and not (d.get("lista_ia") and obj.get("lista") != d.get("lista_ia")) \
                and not (revalidar and not meta.get("nivel_reforco")) \
                and not (obj.get("lista") in listas_ia._DOIS_MODELOS and not meta.get("nivel_reforco")) \
                and not (_candidato_whitelist(obj) and not meta.get("nivel_reforco")):
            break
        if obj is not None and meta.get("nivel_reforco") and nivel is not busca:
            break
        r = _consultar(nivel, d, categorias, buscar)
        if r and nivel is reforco:
            r[1]["nivel_reforco"] = True
        if r:
            if obj is not None:
                r[1]["antes"] = {"modelo": meta.get("model"), "lista": obj.get("lista"), "confianca": obj.get("confianca"),
                                 "classificacao": obj.get("classificacao")}
            obj, meta = r
    with db.conn() as c:
        if obj is None:   # nenhum modelo respondeu (cota/sobrecarga): tenta de novo depois
            c.execute("UPDATE domains SET online_claimed_at = NULL WHERE id = %s", (d["id"],))
            return "unavailable"
        gravar(c, d, obj, meta, categorias)
    return "done"


def gravar(c, d: dict, obj: dict, meta: dict, categorias: list[str], fonte: str = FONTE) -> None:
    lista = obj.get("lista") if obj.get("lista") in LISTAS_IA else NENHUMA
    try:
        conf = max(0.0, min(1.0, float(obj.get("confianca") or 0)))
    except (TypeError, ValueError):
        conf = 0.0
    cls = obj.get("classificacao") if obj.get("classificacao") in CLASSES else "DESCONHECIDO"
    # MALICIOSO com certeza da IA online, depois das fases 1-3, vale (pedido do usuário 2026-09-26: "não tem mais o
    # que decidir"): com lista ameaca entra direto em Ameaças; sem certeza, Decisões.
    cat = obj.get("categoria") if obj.get("categoria") in categorias else None
    servico, motivo = str(obj.get("servico") or "")[:200], str(obj.get("motivo") or "")[:300]
    salvar(c, d["id"], lista, conf, motivo, servico, fonte)
    c.execute("UPDATE domains SET online_at = now(), online_claimed_at = NULL, lista_duvida = false, online_resp = %s, "
              "revisado_at = now() WHERE id = %s", (Jsonb({**obj, "_meta": meta}), d["id"]))
    reconhecido = bool(obj.get("reconhecido")) and cls != "DESCONHECIDO" and conf >= settings().online_confianca_min
    if d["classification"] == "DESCONHECIDO" and reconhecido:
        razoes = [{"evidence_id": "E0", "text": f"IA online ({meta.get('model')}): {servico} — {motivo}"[:400], "by": "online"}]
        c.execute("UPDATE domains SET classification = %s, category = COALESCE(%s, category), topic = %s, confidence = %s, "
                  "classified_by = 'online', corp_reason = %s, reasons = %s || reasons WHERE id = %s",
                  (cls, cat, servico[:80], conf, motivo[:300], Jsonb(razoes), d["id"]))
        c.execute("INSERT INTO classification_history (domain_id, classification, confidence, topic, reasons, source, model, note) "
                  "VALUES (%s, %s, %s, %s, %s, 'online', %s, %s)",
                  (d["id"], cls, conf, servico[:80], Jsonb(razoes), meta.get("model"),
                   ("fontes: " + ", ".join(meta.get("fontes") or []))[:500] or None))
    elif d["classification"] == "DESCONHECIDO" and lista == NENHUMA:
        from . import listas as _listas
        _listas.contexto(c, "IA sem certeza", "nem a IA online identificou o site")
        # nem a IA online identificou: fase 5 (Decisões). Com lista sugerida, `aplicar` decide.
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', %s, %s) "
                  "ON CONFLICT DO NOTHING", (d["name"], "IA sem certeza (desconhecido)"))
    log.info("IA online: %s -> %s / %s (%.2f)%s", d["name"], cls, lista, conf, " [busca]" if meta.get("busca") else "")
    _evento(d, cls, lista, conf, servico, meta)


def _fase5_se_duvida(c, domain_id: int) -> None:
    """Resposta inválida da IA online numa dúvida de lista: segue para a fase 4 (manual)."""
    r = c.execute("SELECT name, lista_ia FROM domains WHERE id = %s", (domain_id,)).fetchone()
    if r and r["lista_ia"]:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', %s, %s) "
                  "ON CONFLICT DO NOTHING", (r["name"], f"IA com dúvida ({r['lista_ia']})"))


def status(c) -> dict:
    r = c.execute("SELECT count(*) FILTER (WHERE " + _FILA.replace("(d.online_claimed_at IS NULL OR d.online_claimed_at < now() - interval '10 minutes') AND ", "") +
                  ") AS fila, count(*) FILTER (WHERE d.online_at > now() - interval '24 hours') AS ult_24h "
                  "FROM domains d").fetchone()
    cfg = settings()
    modelos = {}
    for m in dict.fromkeys(x for nivel in niveis() for x, _, _ in nivel):
        if m:
            ct = cota(m)
            modelos[m] = {"hoje": ct.n if ct.dia == ct._hoje() else 0, "limite_dia": ct.rpd,
                          "pausado_ate": datetime.fromtimestamp(ct.pausa_ate, timezone.utc).isoformat() if ct.pausa_ate > time.time() else None}
    with db.conn() as c2:
        buscas = _buscas_no_mes(c2)
    return {**r, "habilitado": habilitado(), "modelos": modelos, "buscas_google_mes": buscas,
            "limite_buscas_mes": cfg.gemini_grounding_month}
