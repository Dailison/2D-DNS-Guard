"""Cliente da API de Query Logs do Technitium (somente leitura)."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Iterator

import httpx

from .config import settings

log = logging.getLogger(__name__)
_FRAC_RE = re.compile(r"(\.\d{1,6})\d*")


def parse_ts(ts: str) -> datetime | None:
    """'2026-09-23T02:24:48.9617347Z' -> datetime UTC (frações > 6 dígitos truncadas)."""
    if not ts:
        return None
    s = _FRAC_RE.sub(r"\1", ts.strip()).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class TechnitiumClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 120):
        cfg = settings()
        self.base_url = (base_url or cfg.technitium_url).rstrip("/")
        self.token = token if token is not None else cfg.technitium_token
        self.app = cfg.technitium_logs_app
        self.cls = cfg.technitium_logs_class
        self.http = httpx.Client(timeout=timeout)

    def _get(self, path: str, params: dict) -> dict:
        params = {"token": self.token, **params}
        r = self.http.get(f"{self.base_url}/api/{path}", params=params)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "ok":
            raise RuntimeError(f"Technitium {path}: {data.get('errorMessage') or data.get('status')}")
        return data.get("response", {})

    def iter_logs(self, start: datetime, end: datetime, page_size: int = 5000) -> Iterator[dict]:
        """Entradas com start <= ts <= end, em ordem crescente, paginando."""
        page = 1
        while True:
            resp = self._get("logs/query", {
                "name": self.app, "classPath": self.cls,
                "start": fmt_ts(start), "end": fmt_ts(end),
                "pageNumber": page, "entriesPerPage": page_size, "descendingOrder": "false",
            })
            entries = resp.get("entries", []) or []
            yield from entries
            total_pages = resp.get("totalPages") or 0
            if not entries or page >= total_pages:
                break
            page += 1

    def ping(self) -> bool:
        try:
            self._get("user/session/get", {})
            return True
        except Exception:  # noqa: BLE001
            return False

    def close(self) -> None:
        self.http.close()
