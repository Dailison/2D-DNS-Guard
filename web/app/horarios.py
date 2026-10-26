"""Horários livres (26/10, pedido do usuário): por empresa e por unidade, em certos dias e horas, as listas escolhidas
deixam de bloquear (ex.: redes sociais no almoço).

O Technitium não tem horário nos grupos: toda sincronização (politicas.sincronizar) aplica a política VIGENTE agora —
sem as listas liberadas por um horário em vigor —, e o agendador (uma thread por processo do console) reaplica no começo
e no fim de cada horário. A virada é atômica no analisador (/horarios/virada): só o primeiro processo que vê a mudança
sincroniza. Unidade com horários próprios usa os dela; sem, segue os da empresa. Ameaças, Blacklist e VPN/Proxy nunca
são liberadas por horário.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime

from flask import current_app

from app import analyzer_client as api

TRAVADAS = ("ameaca", "blacklist", "vpn_proxy")
DIAS = [(1, "seg"), (2, "ter"), (3, "qua"), (4, "qui"), (5, "sex"), (6, "sáb"), (0, "dom")]   # 0 = domingo


def lista() -> list[dict]:
    try:
        return api.get("/horarios")
    except api.AnalyzerError as e:
        if str(e).startswith("404"):   # analisador antigo
            return []
        raise


def _min(hhmm: str) -> int:
    h, m = hhmm.split(":")[:2]
    return int(h) * 60 + int(m)


def em_vigor(h: dict, agora: datetime) -> bool:
    """agora = hora local (São Paulo). fim < início = passa da meia-noite (começa no dia marcado, termina no seguinte)."""
    dia, m = (agora.weekday() + 1) % 7, agora.hour * 60 + agora.minute   # weekday(): segunda = 0
    ini, fim = _min(h["inicio"]), _min(h["fim"])
    if ini < fim:
        return dia in h["dias"] and ini <= m < fim
    return (dia in h["dias"] and m >= ini) or ((dia - 1) % 7 in h["dias"] and m < fim)


def ativos(horarios: list[dict], agora: datetime) -> dict[str, set[str]]:
    """{escopo: listas liberadas agora}."""
    out: dict[str, set[str]] = {}
    for h in horarios:
        if em_vigor(h, agora):
            out.setdefault(h["scope"], set()).update(x for x in h["listas"] if x not in TRAVADAS)
    return {k: v for k, v in out.items() if v}


def chave(atv: dict[str, set[str]]) -> str:
    return ";".join(f"{s}={','.join(sorted(v))}" for s, v in sorted(atv.items()))


def vigentes(empresas: list[dict], politicas: list[dict], horarios: list[dict], agora: datetime) -> list[dict]:
    """As políticas com os horários livres em vigor agora: as listas liberadas saem do escopo. Empresa sem política
    própria parte da padrão; unidade sem horários próprios segue os da empresa; unidade sem política própria que precisa
    de liberação diferente da empresa ganha a dela (cópia da empresa) enquanto durar o horário."""
    atv = ativos(horarios, agora)
    if not atv:
        return politicas
    orig = {p["scope"]: p for p in politicas}
    pol = dict(orig)
    proprios = {h["scope"] for h in horarios}

    def menos(p: dict, escopo: str, livres: set[str]) -> dict:
        return {**p, "scope": escopo, "lists": [x for x in (p.get("lists") or []) if x not in livres]}

    for e in empresas:
        te = f"tenant:{e['id']}"
        base = orig.get(te) or orig.get("default")
        if not base:
            continue
        lt = atv.get(te, set())
        if lt:
            pol[te] = menos(base, te, lt)
        for u in sorted({n.get("unit") for n in e.get("networks") or [] if n.get("unit")}):
            tu = f"unit:{e['id']}:{u}"
            lu = atv.get(tu, set()) if tu in proprios else lt
            if tu in orig:
                if lu:
                    pol[tu] = menos(orig[tu], tu, lu)
            elif lu != lt:   # segue a empresa, mas libera outra coisa (ou nada) agora: grupo próprio enquanto durar
                pol[tu] = menos(base, tu, lu)
    return list(pol.values())


def tick() -> bool:
    """Um minuto do agendador: se o conjunto de horários em vigor mudou, reaplica as políticas no Technitium."""
    from app import politicas as pol
    from app import technitium as dnslib
    ch = chave(ativos(lista(), dnslib.agora_local()))
    if not api.post("/horarios/virada", {"chave": ch}).get("mudou"):
        return False
    try:
        pol.sincronizar()
    except Exception:
        api.delete("/horarios/virada")   # o próximo minuto tenta de novo
        raise
    current_app.logger.info("horários livres: virada aplicada no Technitium (%s)", ch or "nenhum em vigor")
    return True


_INICIADO = [False]


def iniciar_agendador(app) -> None:
    """Thread do agendador (uma por processo do gunicorn; a virada no analisador evita sincronizar em dobro)."""
    if (_INICIADO[0] or app.config.get("TESTING") or not app.config.get("TECHNITIUM_ENABLED")
            or os.environ.get("HORARIOS_AGENDADOR", "true").lower() == "false"):
        return
    _INICIADO[0] = True

    def laco():
        while True:
            time.sleep(62 - datetime.now().second)   # logo depois da virada de cada minuto
            try:
                with app.app_context():
                    tick()
            except Exception:  # noqa: BLE001 — o agendador nunca morre
                app.logger.exception("horários livres: falha no agendador")
    threading.Thread(target=laco, daemon=True, name="horarios-livres").start()
