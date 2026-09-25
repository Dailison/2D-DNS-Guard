"""Cliente do login único (SSO) do 2D Hub para módulos Python/Flask.

Arquivo único, sem dependências além de ``requests``: copie para o módulo
(ex.: ``app/twod_sso.py``). Fonte: github.com/Dailison/2D-Portal/kit/python.

Fluxo (ver README do 2D-Portal):
  * o login central grava o cookie ``twod_sso_<cliente>`` em ``.2dtecnologia.com``;
  * o módulo lê o cookie no servidor e troca no ERP (``POST <ERP>/v1/sso/exchange``),
    que devolve o MESMO formato do ``/v1/auth/login`` ({access_token, usuario});
  * permissões continuam no módulo; a sessão local acompanha o login central
    comparando o ``sub`` do cookie (saiu/trocou de usuário no portal → encerra).

Configuração típica (variáveis de ambiente):
  SSO_LOGIN_URL   ex.: https://portal.2dtecnologia.com/2dtecnologia/sso/login (vazio = desligado)
  SSO_COOKIE      ex.: twod_sso_2dtecnologia
  ERP_API_BASE_URL ex.: https://api.2dtecnologia.com/2dtecnologia/v1
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote

import requests

TIMEOUT = 10


class SSOError(Exception):
    """ERP indisponível ou resposta inesperada (não é "credencial inválida")."""


class SSORecusado(Exception):
    """Token inválido/expirado ou usuário inativo no ERP (401)."""


def sub(token: str | None) -> str:
    """``sub`` do JWT central SEM validar a assinatura. Só para perceber mudança de
    usuário/saída; quem valida de verdade é o ERP no ``exchange``."""
    try:
        seg = (token or "").split(".")[1]
        return str(json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("sub", ""))
    except (IndexError, ValueError):
        return ""


def exchange(erp_base_url: str, token: str, timeout: int = TIMEOUT) -> dict:
    """Troca o token central no ERP. Retorna {access_token, usuario{id,nome,email,ativo,...}}."""
    url = erp_base_url.rstrip("/") + "/sso/exchange"
    try:
        r = requests.post(url, json={"token": token}, timeout=timeout)
    except requests.RequestException as e:
        raise SSOError(f"ERP indisponível: {e}") from e
    if r.status_code == 401:
        raise SSORecusado("login central inválido/expirado ou usuário inativo")
    if r.status_code >= 400:
        raise SSOError(f"ERP respondeu {r.status_code} no login central")
    try:
        return r.json()
    except ValueError as e:
        raise SSOError("resposta inválida do ERP no login central") from e


def login_redirect_url(sso_login_url: str, volta: str) -> str:
    """URL do login central que, depois de entrar, volta para ``volta`` (URL absoluta https)."""
    return f"{sso_login_url}?next={quote(volta, safe='')}"


def logout_url(sso_login_url: str, volta: str) -> str:
    """Sair de todos os sistemas (apaga o cookie central) e voltar para ``volta``."""
    return f"{sso_login_url.rsplit('/login', 1)[0]}/logout?next={quote(volta, safe='')}"
