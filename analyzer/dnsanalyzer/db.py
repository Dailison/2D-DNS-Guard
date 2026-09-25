"""Acesso ao PostgreSQL (psycopg 3 + pool)."""

from __future__ import annotations

import contextlib
import logging
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings

log = logging.getLogger(__name__)
_pool: ConnectionPool | None = None


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            settings().database_url, min_size=1, max_size=8, open=True,
            kwargs={"row_factory": dict_row, "autocommit": False},
        )
    return _pool


@contextlib.contextmanager
def conn() -> Iterator[psycopg.Connection]:
    """Conexão do pool com commit no sucesso e rollback em erro."""
    with pool().connection() as c:
        yield c


def close() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


def begin_run(kind: str) -> int:
    with conn() as c:
        return c.execute("INSERT INTO analysis_runs (kind) VALUES (%s) RETURNING id", (kind,)).fetchone()["id"]


def end_run(run_id: int, ok: bool, stats: dict | None = None, error: str | None = None) -> None:
    from psycopg.types.json import Jsonb
    with conn() as c:
        c.execute(
            "UPDATE analysis_runs SET finished_at=now(), ok=%s, stats=%s, error=%s WHERE id=%s",
            (ok, Jsonb(stats or {}), (error or "")[:2000] or None, run_id),
        )


def get_state(key: str) -> str | None:
    with conn() as c:
        r = c.execute("SELECT value FROM ingest_state WHERE key=%s", (key,)).fetchone()
        return r["value"] if r else None


def set_state(key: str, value: str) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO ingest_state (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()",
            (key, value),
        )
