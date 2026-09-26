"""Feed "IA ao vivo" (tabela ai_events). Duas colunas no console: CLASSIFICAÇÃO (fases 1-4) e DECISÃO
(o que entrou/saiu das listas, o que foi para Decisões e as decisões manuais). Conexão própria:
visível na hora e nunca derruba quem registra."""

from __future__ import annotations

import logging

from . import db

log = logging.getLogger(__name__)
# eventos da coluna "Decisão"; detail = "<lista>|<texto>" nos de lista
DECISAO = ("lista_add", "lista_rem", "fase5", "decisao", "auto_block", "lista_ia")


def registrar(kind: str, name: str | None = None, domain_id: int | None = None, classification: str | None = None,
              seconds: float | None = None, detail: str | None = None) -> None:
    try:
        with db.conn() as c:
            c.execute("INSERT INTO ai_events (kind, domain_id, name, classification, seconds, detail) "
                      "VALUES (%s, %s, %s, %s, %s, %s)", (kind, domain_id, name, classification, seconds, (detail or "")[:500] or None))
    except Exception as e:  # noqa: BLE001
        log.debug("falha ao gravar evento: %s", e)


def lista(kind: str, dominio: str, cat: str | None, texto: str, domain_id: int | None = None) -> None:
    registrar(kind, dominio, domain_id, detail=f"{cat or ''}|{texto}")
