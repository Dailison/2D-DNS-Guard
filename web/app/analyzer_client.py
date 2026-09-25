"""Cliente da API interna do analisador de DNS (VM 10.100.10.4)."""

from __future__ import annotations

import requests
from flask import current_app


class AnalyzerError(Exception):
    pass


def _req(method: str, path: str, timeout: int = 30, **kw):
    cfg = current_app.config
    url = cfg["ANALYZER_URL"].rstrip("/") + path
    try:
        r = requests.request(method, url, timeout=timeout,
                             headers={"Authorization": f"Bearer {cfg['ANALYZER_TOKEN']}"}, **kw)
    except requests.RequestException as e:
        raise AnalyzerError(f"analisador indisponível ({e.__class__.__name__})") from e
    if r.status_code >= 400:
        try:
            msg = r.json().get("detail")
        except ValueError:
            msg = r.text[:200]
        raise AnalyzerError(f"{r.status_code}: {msg}")
    return r.json()


def get(path: str, **params):
    return _req("GET", path, params={k: v for k, v in params.items() if v not in (None, "")})


def post(path: str, json: dict | None = None):
    return _req("POST", path, json=json or {})


def put(path: str, json: dict | None = None):
    return _req("PUT", path, json=json or {})


def patch(path: str, json: dict | None = None):
    return _req("PATCH", path, json=json or {})


def delete(path: str):
    return _req("DELETE", path)
