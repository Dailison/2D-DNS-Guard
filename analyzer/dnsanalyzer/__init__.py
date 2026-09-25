"""2D DNS Analyzer — análise contínua dos logs do Technitium com IA local.

Fluxo: Technitium → coleta → agregação → PostgreSQL → reputação (feeds locais)
→ regras determinísticas → IA local (Ollama/Qwen3) → classificação → API/dashboard.
"""

__version__ = "0.1.0"
