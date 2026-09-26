"""Fase 3: IA online (Gemini, plano gratuito) para o que as fases 1 e 2 (IA local; busca na web +
WHOIS + IA local) não resolveram com confiança:

- desconhecidos que já passaram pela busca na web (ou que estão em Para revisar / Outros);
- dúvidas da etapa "lista" (a IA local sugeriu uma lista sem certeza).

Recebe o mesmo contexto curto da etapa "lista" (nome, serviço, página, busca, WHOIS) e, para os
desconhecidos, pode pesquisar no Google (grounding: 5.000 buscas/mês grátis nos modelos 3.x). A resposta
vira a sugestão de lista (lista_fonte 'online:gemini'); com certeza, `listas_ia.aplicar` põe na lista;
sem certeza, vai para Para revisar = fase 4 (manual, equipe de TI). Desconhecido reconhecido com
certeza ganha a classificação (classified_by 'online').

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

from . import db
from .config import settings
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
- "lista": a lista de filtro a que o site pertence (O QUE ELE É, não se é de trabalho; domínios técnicos de um serviço vão
  para a lista do serviço) ou "nenhuma";
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
    """Respeita GEMINI_RPM e GEMINI_RPD; 429 pausa até o próximo minuto/dia (meia-noite do Pacífico)."""

    def __init__(self):
        self.lock, self.ultimo, self.dia, self.n, self.pausa_ate = threading.Lock(), 0.0, None, 0, 0.0

    @staticmethod
    def _hoje():
        return datetime.now(ZoneInfo("America/Los_Angeles")).date()

    def esperar(self) -> bool:
        cfg = settings()
        with self.lock:
            if time.time() < self.pausa_ate:
                return False
            if self.dia != self._hoje():
                self.dia, self.n = self._hoje(), 0
            if self.n >= cfg.gemini_rpd:
                self.pausar_dia()
                return False
            falta = 60.0 / max(cfg.gemini_rpm, 1) - (time.monotonic() - self.ultimo)
            if falta > 0:
                time.sleep(falta)
            self.ultimo, self.n = time.monotonic(), self.n + 1
            return True

    def pausar_dia(self):
        agora = datetime.now(ZoneInfo("America/Los_Angeles"))
        amanha = (agora + timedelta(days=1)).replace(hour=0, minute=5, second=0, microsecond=0)
        self.pausa_ate = time.time() + (amanha - agora).total_seconds()
        log.info("IA online: cota do dia esgotada; volta às %s (Pacífico)", amanha.strftime("%H:%M"))

    def pausar(self, segundos: float):
        self.pausa_ate = max(self.pausa_ate, time.time() + segundos)


COTA = _Cota()


def habilitado() -> bool:
    cfg = settings()
    return bool(cfg.gemini_api_key) and cfg.online_enabled


def _json_da_resposta(texto: str) -> dict:
    m = re.search(r"\{.*\}", texto or "", re.S)
    if not m:
        raise ValueError(f"sem JSON: {texto[:200]}")
    return json.loads(m.group(0))


def perguntar(d: dict, categorias: list[str], buscar: bool) -> tuple[dict, dict]:
    cfg = settings()
    listas = "\n".join(f"- {k}: {v}" for k, v in LISTAS_IA.items())
    corpo: dict = {
        "systemInstruction": {"parts": [{"text": SYSTEM.format(listas=listas, categorias=", ".join(categorias))}]},
        "contents": [{"role": "user", "parts": [{"text": _contexto(d) + "\n\nClassifique este domínio."}]}],
        "generationConfig": {"temperature": 0},
    }
    if buscar:   # desconhecido: deixa o Gemini pesquisar no Google (resposta em texto; o JSON é extraído)
        corpo["tools"] = [{"google_search": {}}]
    else:
        corpo["generationConfig"]["responseMimeType"] = "application/json"
    t0 = time.monotonic()
    modelo = cfg.gemini_model
    for tentativa in (cfg.gemini_model, cfg.gemini_fallback_model):
        if not tentativa:
            continue
        modelo = tentativa
        try:
            r = httpx.post(URL.format(model=modelo), json=corpo, timeout=90, headers={"x-goog-api-key": cfg.gemini_api_key})
        except httpx.HTTPError as e:
            raise OnlineIndisponivel(f"Gemini: {e.__class__.__name__}") from e
        if r.status_code not in (500, 503):   # sobrecarga do modelo: tenta o reserva (flash-lite)
            break
    if r.status_code == 429:
        dia = "day" in r.text.lower() or "perday" in r.text.lower().replace("_", "")
        COTA.pausar_dia() if dia else COTA.pausar(65)
        raise OnlineIndisponivel("Gemini: cota esgotada (429)")
    if r.status_code >= 500:
        COTA.pausar(120)
        raise OnlineIndisponivel(f"Gemini: HTTP {r.status_code}")
    if r.status_code != 200:
        COTA.pausar(600)   # chave inválida/modelo inexistente: não martela
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
_FILA = ("d.kind = 'public' AND NOT d.llm_pending AND (d.online_claimed_at IS NULL OR d.online_claimed_at < now() - interval '10 minutes') "
         "AND ((d.lista_duvida AND (d.online_at IS NULL OR d.online_at < d.lista_at)) "
         " OR (d.classification = 'DESCONHECIDO' AND (d.online_at IS NULL OR d.online_at < d.analyzed_at) "
         "     AND ((d.web_search_at IS NOT NULL AND NOT dominio_decidido(d.id)) OR " + _NAS_LISTAS_REVISAO + ")))")


def _reservar(c) -> dict | None:
    return c.execute(
        "UPDATE domains SET online_claimed_at = now() WHERE id = (SELECT d.id FROM domains d WHERE " + _FILA +
        " ORDER BY d.lista_duvida DESC, d.total_queries DESC LIMIT 1 FOR UPDATE SKIP LOCKED) "
        "RETURNING id, name, topic, classification, category, corp_reason, reasons, evidence").fetchone()


def fase(categorias: list[str]) -> str:
    """Uma consulta à IA online. 'idle' = nada na fila; 'unavailable' = sem chave/cota/fora."""
    if not habilitado():
        return "idle"
    with db.conn() as c:
        d = _reservar(c)
    if not d:
        return "idle"
    if not COTA.esperar():
        with db.conn() as c:
            c.execute("UPDATE domains SET online_claimed_at = NULL WHERE id = %s", (d["id"],))
        return "unavailable"
    try:
        obj, meta = perguntar(d, categorias, buscar=d["classification"] == "DESCONHECIDO" and settings().gemini_grounding)
    except OnlineIndisponivel as e:
        log.info("%s", e)
        with db.conn() as c:
            c.execute("UPDATE domains SET online_claimed_at = NULL WHERE id = %s", (d["id"],))
        return "unavailable"
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        log.warning("IA online para %s: resposta inválida: %s", d["name"], e)
        with db.conn() as c:
            c.execute("UPDATE domains SET online_at = now(), online_claimed_at = NULL, lista_duvida = false, "
                      "online_resp = %s WHERE id = %s", (Jsonb({"erro": str(e)[:300]}), d["id"]))
            _fase4_se_duvida(c, d["id"])
        return "done"
    with db.conn() as c:
        gravar(c, d, obj, meta, categorias)
    return "done"


def gravar(c, d: dict, obj: dict, meta: dict, categorias: list[str], fonte: str = FONTE) -> None:
    lista = obj.get("lista") if obj.get("lista") in LISTAS_IA else NENHUMA
    try:
        conf = max(0.0, min(1.0, float(obj.get("confianca") or 0)))
    except (TypeError, ValueError):
        conf = 0.0
    cls = obj.get("classificacao") if obj.get("classificacao") in CLASSES else "DESCONHECIDO"
    cat = obj.get("categoria") if obj.get("categoria") in categorias else None
    servico, motivo = str(obj.get("servico") or "")[:200], str(obj.get("motivo") or "")[:300]
    salvar(c, d["id"], lista, conf, motivo, servico, fonte)
    c.execute("UPDATE domains SET online_at = now(), online_claimed_at = NULL, lista_duvida = false, online_resp = %s "
              "WHERE id = %s", (Jsonb({**obj, "_meta": meta}), d["id"]))
    reconhecido = bool(obj.get("reconhecido")) and cls != "DESCONHECIDO" and conf >= settings().lista_confianca_min
    if d["classification"] == "DESCONHECIDO" and reconhecido:
        razoes = [{"evidence_id": "E0", "text": f"IA online ({meta.get('model')}): {servico} — {motivo}"[:400], "by": "online"}]
        c.execute("UPDATE domains SET classification = %s, category = COALESCE(%s, category), topic = %s, confidence = %s, "
                  "classified_by = 'online', corp_reason = %s, reasons = %s || reasons WHERE id = %s",
                  (cls, cat, servico[:80], conf, motivo[:300], Jsonb(razoes), d["id"]))
        c.execute("INSERT INTO classification_history (domain_id, classification, confidence, topic, reasons, source, model, note) "
                  "VALUES (%s, %s, %s, %s, %s, 'online', %s, %s)",
                  (d["id"], cls, conf, servico[:80], Jsonb(razoes), meta.get("model"),
                   ("fontes: " + ", ".join(meta.get("fontes") or []))[:500] or None))
    log.info("IA online: %s -> %s / %s (%.2f)%s", d["name"], cls, lista, conf, " [busca]" if meta.get("busca") else "")


def _fase4_se_duvida(c, domain_id: int) -> None:
    """Resposta inválida da IA online numa dúvida de lista: segue para a fase 4 (manual)."""
    r = c.execute("SELECT name, lista_ia FROM domains WHERE id = %s", (domain_id,)).fetchone()
    if r and r["lista_ia"]:
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', %s, %s) "
                  "ON CONFLICT DO NOTHING", (r["name"], f"IA com dúvida ({r['lista_ia']})"))


def status(c) -> dict:
    r = c.execute("SELECT count(*) FILTER (WHERE " + _FILA.replace("(d.online_claimed_at IS NULL OR d.online_claimed_at < now() - interval '10 minutes') AND ", "") +
                  ") AS fila, count(*) FILTER (WHERE d.online_at > now() - interval '24 hours') AS ult_24h "
                  "FROM domains d").fetchone()
    return {**r, "habilitado": habilitado(), "modelo": settings().gemini_model,
            "pausado_ate": datetime.fromtimestamp(COTA.pausa_ate, timezone.utc).isoformat() if COTA.pausa_ate > time.time() else None}
