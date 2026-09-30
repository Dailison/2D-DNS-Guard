"""Pausas do classificador pelo botão Pausar do IA ao vivo (30/09, pedido do usuário).

local   = IA local: fase 1, WHOIS/busca (fases 2-3), pergunta de lista e investigação (as regras seguem rodando);
online  = IA online (fase 4);
reforco = reforços com GPU: os workers deles param e a IA local volta a usar só a VM.
O que já está em análise termina; os workers conferem a pausa antes de pegar o próximo domínio (cache de 10 s).
"""

from __future__ import annotations

import logging
import threading
import time

from . import db

log = logging.getLogger(__name__)
CHAVES = ("local", "online", "reforco")
ESPERA_S = 10
_cache: tuple[float, dict] = (0.0, {})
_lock = threading.Lock()


def estado(fresco: bool = False) -> dict[str, dict]:
    """{chave: {"pausado", "por", "em"}}. Sem banco: nada pausado (nunca trava o classificador por isso)."""
    global _cache
    with _lock:
        if not fresco and time.monotonic() - _cache[0] < ESPERA_S:
            return _cache[1]
        try:
            with db.conn() as c:
                rows = {r["chave"]: {"pausado": r["pausado"], "por": r["por"], "em": r["em"].isoformat() if r["em"] else None}
                        for r in c.execute("SELECT chave, pausado, por, em FROM controle")}
        except Exception as e:  # noqa: BLE001
            log.debug("controle indisponível: %s", e)
            rows = _cache[1]
        out = {k: rows.get(k) or {"pausado": False, "por": None, "em": None} for k in CHAVES}
        _cache = (time.monotonic(), out)
        return out


def pausado(chave: str) -> bool:
    return bool(estado()[chave]["pausado"])


def definir(chave: str, pausar: bool, por: str | None) -> dict[str, dict]:
    if chave not in CHAVES:
        raise ValueError(chave)
    with db.conn() as c:
        c.execute("INSERT INTO controle (chave, pausado, por, em) VALUES (%s, %s, %s, now()) ON CONFLICT (chave) "
                  "DO UPDATE SET pausado = EXCLUDED.pausado, por = EXCLUDED.por, em = now()", (chave, pausar, por))
        c.execute("INSERT INTO ai_events (kind, detail) VALUES ('controle', %s)",
                  (f"{'pausou' if pausar else 'retomou'} {dict(local='a fila local', online='a fila online', reforco='o reforço')[chave]}"
                   + (f" · {por}" if por else ""),))
    log.info("controle: %s %s por %s", chave, "pausado" if pausar else "retomado", por or "?")
    return estado(fresco=True)
