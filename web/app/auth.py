"""Autenticação dos operadores do console (guardados no banco do analisador).

Login único do 2D Hub (cookie central -> troca no ERP) ou, como alternativa,
e-mail/senha local (``/login?local=1``). Quem entra pelo login único pela 1ª vez
fica INATIVO até um super-admin liberar em Operadores.
"""

import logging
import secrets
from functools import wraps
from types import SimpleNamespace

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import analyzer_client as api
from app import twod_sso
from app.analyzer_client import AnalyzerError

log = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)


def _op(d: dict | None):
    return SimpleNamespace(**d) if d else None


def operador_por_email(email: str):
    rows = api.get("/console/operators", email=email)
    return _op(rows[0]) if rows else None


def admin_atual():
    if "admin_id" not in session:
        return None
    if getattr(g, "_admin", None) is None:
        try:
            g._admin = _op(api.get(f"/console/operators/{int(session['admin_id'])}"))
        except AnalyzerError:
            g._admin = None
        if g._admin is None or not g._admin.ativo:
            session.pop("admin_id", None)
            g._admin = None
    return g._admin


def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not admin_atual():
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return f(*a, **kw)
    return wrap


def super_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        adm = admin_atual()
        if not adm or not adm.is_super:
            flash("Acesso restrito ao super-admin.", "erro")
            return redirect(url_for("admin.dashboard"))
        return f(*a, **kw)
    return wrap


@auth_bp.app_context_processor
def _adm():
    return {"adm": admin_atual()}


def _bootstrap_superadmin() -> None:
    """Cria o super-admin inicial (env) se ainda não houver nenhum."""
    cfg = current_app.config
    if current_app.extensions.get("dnsguard_boot") or not (cfg["SUPERADMIN_EMAIL"] and cfg["SUPERADMIN_PASSWORD"]):
        return
    try:
        if not any(o["is_super"] for o in api.get("/console/operators")):
            api.post("/console/operators", {"email": cfg["SUPERADMIN_EMAIL"], "nome": "Super Admin",
                                            "senha_hash": generate_password_hash(cfg["SUPERADMIN_PASSWORD"]),
                                            "is_super": True, "ativo": True})
            log.info("super-admin inicial criado: %s", cfg["SUPERADMIN_EMAIL"])
        current_app.extensions["dnsguard_boot"] = True
    except AnalyzerError as e:
        log.warning("bootstrap do super-admin adiado: %s", e)


def _entrar(adm, sso_sub: str | None = None):
    session.clear()
    session.permanent = True
    session["admin_id"] = adm.id
    if sso_sub is not None:
        session["sso_sub"] = sso_sub
    try:
        api.patch(f"/console/operators/{adm.id}", {"last_login": True})
    except AnalyzerError:
        pass


# --------------------------------------------------------------- login único (2D Hub)
def _sso_url() -> str:
    return current_app.config.get("SSO_LOGIN_URL", "")


def _sso_token() -> str:
    return request.cookies.get(current_app.config.get("SSO_COOKIE", ""), "")


def next_local(v: str | None) -> str:
    v = (v or "").strip()
    return v if v.startswith("/") and not v.startswith("//") else ""


@auth_bp.before_app_request
def _seguir_login_central():
    """Saiu (ou trocou de usuário) no login central -> encerra a sessão do operador."""
    s = session.get("sso_sub")
    if s is not None and _sso_url() and twod_sso.sub(_sso_token()) != s:
        session.clear()


def _admin_do_erp(usuario: dict):
    """Casa o usuário do ERP com o operador pelo e-mail. Novo = criado INATIVO:
    o super-admin libera em Operadores."""
    email = (usuario.get("email") or "").strip().lower()
    if not email:
        return None
    adm = operador_por_email(email)
    if adm is None:
        adm = _op(api.post("/console/operators", {"email": email, "nome": usuario.get("nome") or email,
                                                  "is_super": False, "ativo": False}))
        log.info("SSO: operador %s criado aguardando liberação", email)
    return adm


@auth_bp.get("/login")
def login():
    _bootstrap_superadmin()
    if admin_atual():
        return redirect(url_for("admin.dashboard"))
    nxt = next_local(request.args.get("next"))
    # Login único: cookie do login central -> troca no ERP. ?local=1 = formulário local.
    if _sso_url() and not request.args.get("local"):
        token = _sso_token()
        if not token:
            volta = url_for("auth.login", next=nxt or None, _external=True)
            return redirect(twod_sso.login_redirect_url(_sso_url(), volta))
        try:
            dados = twod_sso.exchange(current_app.config["ERP_API_BASE_URL"], token)
            adm = _admin_do_erp(dados.get("usuario") or {})
            if adm and adm.ativo:
                _entrar(adm, twod_sso.sub(token))
                return redirect(nxt or url_for("admin.dashboard"))
            # sem acesso: mostra a tela (NÃO volta ao portal — seria loop)
            flash("Seu acesso ao DNS Guard ainda não foi liberado. "
                  "Peça a um super-admin para ativá-lo em Operadores.", "erro")
        except twod_sso.SSORecusado:
            flash("Seu usuário não tem acesso (inativo no ERP).", "erro")
        except twod_sso.SSOError as e:
            log.warning("SSO indisponível: %s", e)
            flash("Login central indisponível no momento. Use o acesso local.", "erro")
        except AnalyzerError as e:
            flash(f"Analisador indisponível: {e}", "erro")
    return render_template("login.html")


@auth_bp.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    senha = request.form.get("senha") or ""
    try:
        adm = operador_por_email(email)
    except AnalyzerError as e:
        flash(f"Analisador indisponível: {e}", "erro")
        return redirect(url_for("auth.login", local=1))
    if not adm or not adm.ativo or not adm.senha_hash or not check_password_hash(adm.senha_hash, senha):
        flash("E-mail ou senha inválidos.", "erro")
        return redirect(url_for("auth.login", local=1))
    _entrar(adm)
    return redirect(next_local(request.args.get("next")) or url_for("admin.dashboard"))


@auth_bp.get("/logout")
def logout():
    central = session.get("sso_sub") is not None
    session.clear()
    if central and _sso_url():
        return redirect(twod_sso.logout_url(_sso_url(), url_for("admin.dashboard", _external=True)))
    return redirect(url_for("auth.login", local=1))


def senha_hash(senha: str) -> str:
    return generate_password_hash(senha)


def senha_aleatoria() -> str:
    return secrets.token_urlsafe(12)
