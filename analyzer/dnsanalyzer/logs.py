"""Logs próprios: stdout (journald) + arquivo rotativo por serviço."""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path


def setup_logging(service: str, level: str = "INFO", log_dir: str = "") -> logging.Logger:
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if log_dir:
        try:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, f"{service}.log"), maxBytes=20 * 1024 * 1024,
                backupCount=5, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as e:  # sem permissão no diretório: segue só com stdout
            root.warning("não foi possível abrir log em %s: %s", log_dir, e)

    for noisy in ("httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logging.getLogger(service)
