"""Catálogo de domínios conhecidos (data/catalog.yaml)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

CATALOG_PATH = Path(__file__).resolve().parent / "data" / "catalog.yaml"


@lru_cache(maxsize=1)
def load_catalog(path: str = str(CATALOG_PATH)) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = []
    for e in data.get("entries", []):
        e = dict(e)
        e["suffix"] = e["suffix"].strip().lower().strip(".")
        e.setdefault("protected", False)
        e.setdefault("exact", False)
        entries.append(e)
    # mais específico primeiro (office365.com antes de com...)
    entries.sort(key=lambda x: len(x["suffix"]), reverse=True)
    return entries


def match(registrable: str, entries: list[dict] | None = None) -> dict | None:
    name = (registrable or "").lower()
    for e in entries if entries is not None else load_catalog():
        s = e["suffix"]
        if name == s or (not e["exact"] and name.endswith("." + s)):
            return e
    return None
