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


def _modelos(nome: str, padrao: str) -> list[tuple[str, int, int]]:
    """"modelo:rpm:rpd,..." -> [(modelo, rpm, rpd)] (sem rpm/rpd: 5/min e 20/dia)."""
    out = []
    for item in (os.environ.get(nome) or padrao).split(","):
        p = [x.strip() for x in item.split(":")]
        if p[0]:
            out.append((p[0], int(p[1]) if len(p) > 1 and p[1].isdigit() else 5, int(p[2]) if len(p) > 2 and p[2].isdigit() else 20))
    return out


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
    ollama_extra_model: str   # modelo dos Ollamas de reforço (GPU); vazio = o mesmo da VM
    local_decide_models: list  # modelos locais que decidem sozinhos com confiança alta (os outros passam pela IA online)
    llm_vm_reserva: bool       # IA da VM só trabalha com o reforço (GPU) fora do ar
    llm_timeout: int
    llm_num_ctx: int
    llm_num_thread: int
    llm_keep_alive: str
    llm_workers: int
    ollama_extra_urls: list[str]
    ollama_extra_modelos: dict   # url -> modelo daquele reforço ("url=modelo" em OLLAMA_EXTRA_URLS)
    llm_extra_workers: int
    llm_extra_workers_url: dict   # url -> análises simultâneas daquele reforço (senão LLM_EXTRA_WORKERS)
    ollama_etapas_urls: list      # reforços das fases 2/3 e da pergunta de lista (vazio = todos, em rodízio)
    llm_extra_timeout: int
    llm_max_attempts: int
    llm_skip_hosting_subdomains: bool
    llm_min_queries: int       # triagem por acesso: menos consultas que isto (e menos computadores que
    llm_min_clients: int       # llm_min_clients) fica só com as regras até recorrer; 0 = desligado

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
    web_search_before_llm: bool
    web_search_before_llm_todos: bool   # "todos": todo domínio da fase 1, não só os que a IA não reconheceria
    whois_enabled: bool
    whois_workers: int
    auto_block_categories: list[str]
    lista_ia_enabled: bool
    lista_confianca_min: float
    online_confianca_min: float
    online_enabled: bool
    online_workers: int
    gemini_api_key: str
    gemini_api_keys_extra: list
    gemini_modelos: list
    gemini_reforco: list
    gemini_busca: list
    gemini_grounding_month: int
    gemini_grounding: bool
    lists_allowed_ips: list[str]

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
        # o reforço com GPU (PC 10.100.50.201) roda um modelo maior que a VM (só CPU)
        ollama_extra_model=os.environ.get("OLLAMA_EXTRA_MODEL") or os.environ.get("OLLAMA_MODEL", "qwen3:8b"),
        # prova de 27/09 (10 domínios difíceis, fases 1-3 x IA online): gemma4:31b 9/9, gemma4:26b 7/8 (usuário escolheu o
        # 26b, MoE ~4B ativos, rápido também na CPU); qwen3:8b 5/9, qwen3:14b 6/10 — esses não decidem sozinhos
        local_decide_models=_list("LOCAL_DECIDE_MODELS", "gemma4:26b,gemma4:31b"),
        llm_vm_reserva=_bool(os.environ.get("LLM_VM_RESERVA"), True),
        llm_timeout=_int("LLM_TIMEOUT_SECONDS", 600),
        llm_num_ctx=_int("LLM_NUM_CTX", 4096),
        llm_num_thread=_int("LLM_NUM_THREAD", 0),
        llm_keep_alive=os.environ.get("LLM_KEEP_ALIVE", "60m"),
        # análises simultâneas (combine com OLLAMA_NUM_PARALLEL). Em CPU sem GPU não ganhou nada
        # (medido 2026-09-24: banda de memória é o gargalo) — padrão 1
        llm_workers=max(_int("LLM_WORKERS", 1), 1),
        # reforço opcional (ex.: PC com GPU): outros Ollama que aceleram a fila quando estão no ar.
        # A IA da VM segue sozinha quando eles estão desligados.
        # "http://pc1:11434,http://pc2:11434=gemma4:26b-iq3s": cada reforço pode ter o seu modelo (sem "=": OLLAMA_EXTRA_MODEL)
        ollama_extra_urls=[u.split("=", 1)[0].rstrip("/") for u in _list("OLLAMA_EXTRA_URLS")],
        ollama_extra_modelos={u.split("=", 1)[0].rstrip("/"): u.split("=", 1)[1].strip()
                              for u in _list("OLLAMA_EXTRA_URLS") if "=" in u and u.split("=", 1)[1].strip()},
        llm_extra_workers=max(_int("LLM_EXTRA_WORKERS", 2), 1),
        # "http://pc1:11434=2,http://pc2:11434=4": GPU mais lenta recebe menos análises ao mesmo tempo (27/09: o PC
        # enfileirava ~30 s por pedido e as fases 2/3 presas nele pararam)
        llm_extra_workers_url={u.rsplit("=", 1)[0].rstrip("/"): max(int(u.rsplit("=", 1)[1]), 0)
                               for u in _list("LLM_EXTRA_WORKERS_URL") if "=" in u and u.rsplit("=", 1)[1].strip().isdigit()},
        ollama_etapas_urls=[u.rstrip("/") for u in _list("OLLAMA_ETAPAS_URLS")],
        # GPU responde em segundos: pedido que some (queda do PC/VPN) não pode segurar o domínio 10 min
        llm_extra_timeout=_int("LLM_EXTRA_TIMEOUT_SECONDS", 90),
        llm_max_attempts=_int("LLM_MAX_ATTEMPTS", 3),
        llm_skip_hosting_subdomains=_bool(os.environ.get("LLM_SKIP_HOSTING_SUBDOMAINS"), False),
        # triagem por acesso (27/09: 83% da fila da IA eram domínios com <= 2 consultas de 1 computador): domínio
        # com pouco acesso vai para o fim da fila (analisado quando ela esvazia ou quando recorrer). Risco (feed de
        # ameaça, SUSPEITO/MALICIOSO) e análise pedida por pessoa nunca esperam. 0 desliga.
        llm_min_queries=_int("LLM_MIN_QUERIES", 3),
        llm_min_clients=_int("LLM_MIN_CLIENTS", 2),
        rdap_enabled=_bool(os.environ.get("RDAP_ENABLED"), True),
        rdap_cache_days=_int("RDAP_CACHE_DAYS", 30),
        rdap_skip_top_rank=_int("RDAP_SKIP_TOP_RANK", 100000),
        webhook_urls=_list("WEBHOOK_URLS"),
        # (blocked_work/block_spike ficam só na tela Alertas até o volume ser avaliado — ligar aqui quando quiser)
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
        # busca ANTES da IA na etapa 1 (desligada a pedido do usuário em 2026-09-26: a IA analisa
        # primeiro; o que ela não reconhecer vai p/ Decisões e a etapa 2 busca quando a fila zerar)
        # (27/09: WEB_SEARCH_BEFORE_LLM=todos a pedido do usuário — busca em todo domínio novo, IA local na VM)
        web_search_before_llm=(os.environ.get("WEB_SEARCH_BEFORE_LLM") or "").strip().lower() == "todos"
                              or _bool(os.environ.get("WEB_SEARCH_BEFORE_LLM"), False),
        web_search_before_llm_todos=(os.environ.get("WEB_SEARCH_BEFORE_LLM") or "").strip().lower() == "todos",
        whois_enabled=_bool(os.environ.get("WHOIS_ENABLED"), True),   # etapa 3 (RDAP + CNPJ/BrasilAPI)
        # em paralelo com a etapa 2; cada serviço tem intervalo mínimo próprio (registro.br 2 s,
        # rdap.org 1,5 s, BrasilAPI 1 s), então 2 workers já ocupam os três
        whois_workers=max(_int("WHOIS_WORKERS", 2), 1),
        # bloqueio automático (pedido do usuário 2026-09-26): categorias de baixo risco de impacto,
        # recomendação BLOQUEAR, sem decisão -> lista da categoria (vazio = desligado)
        auto_block_categories=_list("AUTO_BLOCK_CATEGORIES", "jogos,apostas,adulto,vpn_proxy,ameaca"),
        lista_ia_enabled=_bool(os.environ.get("LISTA_IA_ENABLED"), True),   # etapa "lista" (qual lista de bloqueio)
        lista_confianca_min=float(os.environ.get("LISTA_CONFIANCA_MIN") or 0.9),
        # a IA online responde 0,9 quando sabe e 0,8 p/ "provável" (bem calibrada p/ lista); a local exige 0,9
        online_confianca_min=float(os.environ.get("ONLINE_CONFIANCA_MIN") or 0.8),
        online_enabled=_bool(os.environ.get("ONLINE_ENABLED"), True),   # fase 4 (só com GEMINI_API_KEY)
        online_workers=max(_int("ONLINE_WORKERS", 6), 1),   # consultas simultâneas (Gemma é lento; a cota é por modelo)
        gemini_api_key=os.environ.get("GEMINI_API_KEY", "").strip(),
        # chaves de outros projetos (cada uma com a própria cota por modelo), usadas depois da principal
        gemini_api_keys_extra=[k for k in (os.environ.get(f"GEMINI_API_KEY_{i}", "").strip() for i in (2, 3, 4)) if k],
        # plano grátis desta conta (AI Studio, 2026-09-26) — "modelo:rpm:rpd", na ordem de uso:
        # volume: 3.5/3.1 Flash-Lite 15/min 500/dia, Gemma 4 31B 30/min 14.400/dia (lento: ~40-75 s);
        # reforço: 3.8/3.7/3.5/3.6 Flash 5/min 20/dia cada (27/09: 2.5 Flash/Flash-Lite fechados p/ contas novas, 3 Flash 404)
        gemini_modelos=_modelos("GEMINI_MODELS", "gemini-3.5-flash-lite:14:490,gemini-3.1-flash-lite:14:490"),
        # segunda opinião (sem certeza/discorda da IA local; também quando o volume esgota a cota do dia)
        gemini_reforco=_modelos("GEMINI_ESCALATE_MODELS", "gemma-4-31b-it:28:14000,gemini-3.8-flash:5:19,gemini-3.7-flash:5:19,"
                                "gemini-3.5-flash:5:19,gemini-3.6-flash:5:19"),
        # busca no Google (grounding): indisponível nesta conta (2.5 fechado p/ contas novas; 3.x = 0/dia) —
        # a IA online avalia o que a fase 3 (busca na web) já achou. Ex.: GEMINI_SEARCH_MODELS=gemini-2.5-flash:5:18
        gemini_busca=_modelos("GEMINI_SEARCH_MODELS", ""),
        gemini_grounding_month=_int("GEMINI_GROUNDING_MONTH", 4500),   # buscas no Google/mês (grátis: 5.000)
        gemini_grounding=_bool(os.environ.get("GEMINI_GROUNDING"), True),   # busca no Google p/ desconhecidos
        # quem pode baixar /listas/<categoria>.txt sem token (o Technitium)
        lists_allowed_ips=_list("LISTS_ALLOWED_IPS", "10.100.10.15,127.0.0.1"),
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
