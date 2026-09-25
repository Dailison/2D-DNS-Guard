"""Configuração via variáveis de ambiente (arquivo .env em dev, EnvironmentFile no systemd)."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Carrega KEY=VALUE de um .env sem sobrescrever o ambiente (dev)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "sim")


def _int(name: str, default: int) -> int:
    v = os.environ.get(name, "")
    return int(v) if v.strip() else default


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    database_url: str
    technitium_url: str
    technitium_token: str
    technitium_logs_app: str
    technitium_logs_class: str

    ingest_interval: int
    ingest_lag: int
    ingest_backfill_hours: int
    ingest_page_size: int
    ingest_max_window_minutes: int
    exclude_clients: list[ipaddress._BaseNetwork]
    internal_suffixes: list[str]
    mesh_cidr: ipaddress._BaseNetwork | None

    llm_enabled: bool
    ollama_url: str
    ollama_model: str
    llm_timeout: int
    llm_num_ctx: int
    llm_num_thread: int
    llm_keep_alive: str
    llm_workers: int
    llm_max_attempts: int
    llm_skip_hosting_subdomains: bool

    rdap_enabled: bool
    rdap_cache_days: int
    rdap_skip_top_rank: int

    webhook_urls: list[str]
    webhook_kinds: list[str]
    push_api_url: str
    push_api_token: str
    push_app_name: str
    portal_url: str

    web_intel_enabled: bool
    web_fetch_site: bool
    web_cache_days: int
    web_search_url: str
    web_search_results: int
    web_search_min_interval: int

    reanalyze_days: int
    retention_days: int
    classify_batch: int
    behavior_interval: int

    api_host: str
    api_port: int
    api_token: str

    log_dir: str
    log_level: str
    data_dir: str

    extra: dict = field(default_factory=dict)


def load_settings() -> Settings:
    _load_dotenv(Path(os.environ.get("DNSANALYZER_ENV", ".env")))
    mesh = os.environ.get("MESH_CIDR", "10.100.100.0/24").strip()
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "postgresql://dnsanalyzer@localhost/dnsanalyzer"),
        technitium_url=os.environ.get("TECHNITIUM_URL", "http://10.100.10.15:5380").rstrip("/"),
        technitium_token=os.environ.get("TECHNITIUM_TOKEN", ""),
        technitium_logs_app=os.environ.get("TECHNITIUM_LOGS_APP", "Query Logs (Sqlite)"),
        technitium_logs_class=os.environ.get("TECHNITIUM_LOGS_CLASS", "QueryLogsSqlite.App"),
        ingest_interval=_int("INGEST_INTERVAL_SECONDS", 300),
        ingest_lag=_int("INGEST_LAG_SECONDS", 120),
        ingest_backfill_hours=_int("INGEST_BACKFILL_HOURS", 168),
        ingest_page_size=_int("INGEST_PAGE_SIZE", 5000),
        ingest_max_window_minutes=_int("INGEST_MAX_WINDOW_MINUTES", 60),
        exclude_clients=[ipaddress.ip_network(c, strict=False) for c in _list("EXCLUDE_CLIENTS")],
        internal_suffixes=[s.lower().lstrip(".") for s in _list(
            "INTERNAL_SUFFIXES", "local,lan,internal,home.arpa,in-addr.arpa,ip6.arpa,resolver.arpa")],
        mesh_cidr=ipaddress.ip_network(mesh, strict=False) if mesh else None,
        llm_enabled=_bool(os.environ.get("LLM_ENABLED"), True),
        ollama_url=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen3:8b"),
        llm_timeout=_int("LLM_TIMEOUT_SECONDS", 600),
        llm_num_ctx=_int("LLM_NUM_CTX", 4096),
        llm_num_thread=_int("LLM_NUM_THREAD", 0),
        llm_keep_alive=os.environ.get("LLM_KEEP_ALIVE", "60m"),
        # análises simultâneas (combine com OLLAMA_NUM_PARALLEL). Em CPU sem GPU não ganhou nada
        # (medido 2026-09-24: banda de memória é o gargalo) — padrão 1
        llm_workers=max(_int("LLM_WORKERS", 1), 1),
        llm_max_attempts=_int("LLM_MAX_ATTEMPTS", 3),
        llm_skip_hosting_subdomains=_bool(os.environ.get("LLM_SKIP_HOSTING_SUBDOMAINS"), False),
        rdap_enabled=_bool(os.environ.get("RDAP_ENABLED"), True),
        rdap_cache_days=_int("RDAP_CACHE_DAYS", 30),
        rdap_skip_top_rank=_int("RDAP_SKIP_TOP_RANK", 100000),
        webhook_urls=_list("WEBHOOK_URLS"),
        webhook_kinds=_list("WEBHOOK_KINDS", "malicious_access,suspicious_access,dga_burst"),
        push_api_url=os.environ.get("PUSH_API_URL", ""),
        push_api_token=os.environ.get("PUSH_API_TOKEN", ""),
        push_app_name=os.environ.get("PUSH_APP_NAME", "2D-Monitoramento"),
        portal_url=os.environ.get("PORTAL_URL", "https://dns-guard.2dtecnologia.com"),
        web_intel_enabled=_bool(os.environ.get("WEB_INTEL_ENABLED"), True),
        web_fetch_site=_bool(os.environ.get("WEB_FETCH_SITE"), True),
        web_cache_days=_int("WEB_CACHE_DAYS", 30),
        web_search_url=os.environ.get("WEB_SEARCH_URL", ""),   # SearXNG local (etapa 2); vazio = desligada
        web_search_results=_int("WEB_SEARCH_RESULTS", 6),
        # buscadores gratuitos bloqueiam rajadas (~10-15 buscas seguidas): intervalo mínimo (s)
        web_search_min_interval=_int("WEB_SEARCH_MIN_INTERVAL", 20),
        reanalyze_days=_int("REANALYZE_DAYS", 30),
        retention_days=_int("RETENTION_DAYS", 180),
        classify_batch=_int("CLASSIFY_BATCH", 10),
        behavior_interval=_int("BEHAVIOR_INTERVAL_SECONDS", 300),
        api_host=os.environ.get("API_HOST", "127.0.0.1"),
        api_port=_int("API_PORT", 8088),
        api_token=os.environ.get("API_TOKEN", ""),
        log_dir=os.environ.get("LOG_DIR", ""),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        data_dir=os.environ.get("DATA_DIR", "/var/lib/2d-dnsanalyzer"),
    )


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings
