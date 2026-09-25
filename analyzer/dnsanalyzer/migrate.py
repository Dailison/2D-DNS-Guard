"""Migrações SQL simples: aplica migrations/NNN_*.sql em ordem, uma vez cada."""

from __future__ import annotations

import logging
from pathlib import Path

import psycopg

from .config import settings

log = logging.getLogger(__name__)
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def migrate(database_url: str | None = None, directory: Path = MIGRATIONS_DIR) -> list[str]:
    url = database_url or settings().database_url
    applied_now: list[str] = []
    with psycopg.connect(url, autocommit=False) as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        c.commit()
        done = {r[0] for r in c.execute("SELECT version FROM schema_migrations").fetchall()}
        for f in sorted(directory.glob("*.sql")):
            version = f.stem
            if version in done:
                continue
            log.info("aplicando migração %s", version)
            with c.transaction():
                c.execute(f.read_text(encoding="utf-8"))
                c.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
            applied_now.append(version)
    if not applied_now:
        log.info("banco já está na versão mais recente")
    return applied_now
