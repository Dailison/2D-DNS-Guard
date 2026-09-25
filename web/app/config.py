"""Configuração via variáveis de ambiente."""

import os


def _bool(v: str, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "sim")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-inseguro-trocar")

    # Technitium DNS (app Advanced Blocking): bloqueios por grupo, liberados e logs.
    TECHNITIUM_URL = os.environ.get("TECHNITIUM_URL", "")  # ex: http://10.100.10.15:5380
    TECHNITIUM_TOKEN = os.environ.get("TECHNITIUM_TOKEN", "")
    TECHNITIUM_LIBERADOS_GROUP = os.environ.get("TECHNITIUM_LIBERADOS_GROUP", "Liberados")
    TECHNITIUM_ENABLED = bool(TECHNITIUM_URL and TECHNITIUM_TOKEN)

    # Analisador (IA local na VM 10.100.10.4, pasta analyzer/ deste repo). Também guarda
    # os operadores do console e os metadados dos liberados.
    ANALYZER_URL = os.environ.get("ANALYZER_URL", "")  # ex: http://10.100.10.4:8088
    ANALYZER_TOKEN = os.environ.get("ANALYZER_TOKEN", "")
    ANALYZER_ENABLED = bool(ANALYZER_URL and ANALYZER_TOKEN)

    # Operador inicial (criado no 1º acesso se ainda não houver nenhum super-admin).
    SUPERADMIN_EMAIL = os.environ.get("SUPERADMIN_EMAIL", "")
    SUPERADMIN_PASSWORD = os.environ.get("SUPERADMIN_PASSWORD", "")

    # 2D Hub: launcher de apps no topo e login único (ERP como emissor). Vazios = desligados.
    PORTAL_KIT_URL = os.environ.get("PORTAL_KIT_URL", "")  # ex: https://portal.2dtecnologia.com/kit/launcher.js
    SSO_LOGIN_URL = os.environ.get("SSO_LOGIN_URL", "")    # ex: https://portal.2dtecnologia.com/2dtecnologia/sso/login
    SSO_COOKIE = os.environ.get("SSO_COOKIE", "twod_sso_2dtecnologia")
    ERP_API_BASE_URL = os.environ.get("ERP_API_BASE_URL", "https://api.2dtecnologia.com/2dtecnologia/v1")

    SESSION_COOKIE_NAME = "dnsguard_session"
    SESSION_COOKIE_SECURE = _bool(os.environ.get("SESSION_COOKIE_SECURE"), True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
