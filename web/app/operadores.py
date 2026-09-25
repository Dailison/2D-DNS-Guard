"""Operadores do console (super-admin): criar, liberar quem veio do login único,
promover a super, trocar senha e desativar."""

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app import analyzer_client as api
from app.analyzer_client import AnalyzerError
from app.auth import admin_atual, login_required, senha_hash, super_required

operadores_bp = Blueprint("operadores", __name__, url_prefix="/operadores")


@operadores_bp.get("")
@login_required
@super_required
def lista():
    ops = []
    try:
        ops = api.get("/console/operators")
    except AnalyzerError as e:
        flash(f"Não foi possível listar os operadores: {e}", "erro")
    return render_template("admin/operadores.html", lista=ops)


@operadores_bp.post("")
@login_required
@super_required
def criar():
    email = (request.form.get("email") or "").strip().lower()
    senha = request.form.get("senha") or ""
    try:
        api.post("/console/operators", {"email": email, "nome": (request.form.get("nome") or "").strip() or email,
                                        "senha_hash": senha_hash(senha) if senha else None,
                                        "is_super": bool(request.form.get("is_super")), "ativo": True})
        flash(f"Operador {email} criado.", "ok")
    except AnalyzerError as e:
        flash(f"Falha ao criar: {e}", "erro")
    return redirect(url_for("operadores.lista"))


def _patch(oid: int, dados: dict, ok: str):
    try:
        api.patch(f"/console/operators/{oid}", dados)
        flash(ok, "ok")
    except AnalyzerError as e:
        flash(f"Falha ao salvar: {e}", "erro")
    return redirect(url_for("operadores.lista"))


@operadores_bp.post("/<int:oid>/acesso")
@login_required
@super_required
def acesso(oid):
    if oid == admin_atual().id and not request.form.get("is_super"):
        flash("Você não pode tirar o seu próprio acesso de super-admin.", "erro")
        return redirect(url_for("operadores.lista"))
    dados = {"is_super": bool(request.form.get("is_super"))}
    if request.form.get("ativar"):
        dados["ativo"] = True
    return _patch(oid, dados, "Acesso atualizado.")


@operadores_bp.post("/<int:oid>/senha")
@login_required
@super_required
def senha(oid):
    s = request.form.get("senha") or ""
    if len(s) < 8:
        flash("A senha precisa ter pelo menos 8 caracteres.", "erro")
        return redirect(url_for("operadores.lista"))
    return _patch(oid, {"senha_hash": senha_hash(s)}, "Senha alterada.")


@operadores_bp.post("/<int:oid>/ativo")
@login_required
@super_required
def ativo(oid):
    if oid == admin_atual().id:
        flash("Você não pode desativar a si mesmo.", "erro")
        return redirect(url_for("operadores.lista"))
    return _patch(oid, {"ativo": request.form.get("ativo") == "1"}, "Operador atualizado.")
