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
    pergunta = _contexto(d) + "\n\nClassifique este domínio."
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
_FILA = ("d.kind = 'public' AND NOT d.llm_pending AND (d.online_claimed_at IS NULL OR d.online_claimed_at < now() - interval '10 minutes') "
         "AND ((d.lista_duvida AND (d.online_at IS NULL OR d.online_at < d.lista_at)) "
         " OR (d.classification = 'DESCONHECIDO' AND (d.online_at IS NULL OR d.online_at < d.analyzed_at) "
         "     AND ((d.web_search_at IS NOT NULL AND NOT dominio_decidido(d.id)) OR " + _NAS_LISTAS_REVISAO + ")))")


def _reservar(c) -> dict | None:
    return c.execute(
        "UPDATE domains SET online_claimed_at = now() WHERE id = (SELECT d.id FROM domains d WHERE " + _FILA +
        " ORDER BY d.lista_duvida DESC, d.total_queries DESC LIMIT 1 FOR UPDATE SKIP LOCKED) "
        "RETURNING id, name, topic, classification, category, corp_reason, reasons, evidence").fetchone()


def _certo(obj: dict) -> bool:
    try:
        conf = float(obj.get("confianca") or 0)
    except (TypeError, ValueError):
        return False
    return conf >= settings().lista_confianca_min and (obj.get("lista") in LISTAS_IA or bool(obj.get("reconhecido")))


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
    1 volume (flash-lite 3.5 -> 3.1 -> Gemma 4 31B); 2 reforço sem certeza (3.8 flash); 3 busca no Google
    para desconhecido que seguiu desconhecido (2.5 flash / flash-lite: únicos com busca no plano grátis).
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
    vol, reforco, busca = niveis()
    obj = meta = None
    for nivel, buscar in ((vol, False), (reforco, False), (busca if pode_buscar else [], True)):
        if obj is not None and _certo(obj):
            break
        r = _consultar(nivel, d, categorias, buscar)
        if r:
            if obj is not None:
                r[1]["antes"] = {"modelo": meta.get("model"), "lista": obj.get("lista"), "confianca": obj.get("confianca")}
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
    if cls == "MALICIOSO":   # regra do sistema: MALICIOSO só com lista de ameaça; palpite da IA = SUSPEITO (fase 5)
        cls = "SUSPEITO"
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
    elif d["classification"] == "DESCONHECIDO" and lista == NENHUMA:
        # nem a IA online identificou: fase 5 (Decisões). Com lista sugerida, `aplicar` decide.
        c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES ('para_revisar', %s, %s) "
                  "ON CONFLICT DO NOTHING", (d["name"], "IA sem certeza (desconhecido)"))
    log.info("IA online: %s -> %s / %s (%.2f)%s", d["name"], cls, lista, conf, " [busca]" if meta.get("busca") else "")


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
