"""Telas de DNS do console: Bloqueios (listas por grupo), Liberados (IPs isentos do
filtro) e Logs DNS — tudo direto no Technitium (app Advanced Blocking)."""

from urllib.parse import quote

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from app import analyzer_client as api
from app import technitium as dnslib
from app.analyzer_client import AnalyzerError
from app.auth import admin_atual, login_required, next_local

admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/")
@login_required
def dashboard():
    if current_app.config.get("ANALYZER_ENABLED"):
        return redirect(url_for("analise.painel"))
    return redirect(url_for("admin.bloqueios"))




# ------------------------------------------------- Liberados DNS (Technitium)
@admin_bp.get("/liberados")
@login_required
def liberados():
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        flash("Technitium não configurado (defina TECHNITIUM_URL/TOKEN).", "erro")
        return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")
    q = (request.args.get("q") or "").strip().lower()
    rows = []
    try:
        ips = dnslib.listar()
        try:
            metas = {m["ip"]: m for m in api.get("/console/liberados-meta")}
        except AnalyzerError as e:
            metas = {}
            flash(f"Descrições indisponíveis (analisador): {e}", "erro")
        for ip in ips:
            m = metas.get(ip) or {}
            rows.append({k: m.get(k) or "" for k in ("empresa", "departamento", "usuario", "tipo")} | {"ip": ip})
        if q:
            rows = [r for r in rows if q in r["ip"].lower() or q in r["empresa"].lower()
                    or q in r["departamento"].lower() or q in r["usuario"].lower()]
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar o Technitium: {e}", "erro")
    return render_template("admin/liberados.html", rows=rows, q=q,
                           grupo=current_app.config.get("TECHNITIUM_LIBERADOS_GROUP"))


def _liberado_meta_upsert(ip):
    """Grava empresa/descrição/nota (do form) para o IP normalizado."""
    api.put("/console/liberados-meta", {"ip": ip, "by": admin_atual().email,
                                        **{k: request.form.get(k) or "" for k in
                                           ("empresa", "departamento", "usuario", "tipo")}})


@admin_bp.post("/liberados/liberar")
@login_required
def liberados_liberar():
    try:
        ip, msg = dnslib.liberar(request.form.get("ip"), por=admin_atual().email)
        if ip:
            _liberado_meta_upsert(ip)
        flash((f"{ip} {msg}." if ip else msg), "ok" if ip else "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao liberar: {e}", "erro")
    return redirect(url_for("admin.liberados"))


@admin_bp.post("/liberados/editar")
@login_required
def liberados_editar():
    ip = dnslib.norm_ip(request.form.get("ip"))
    try:
        if ip:
            _liberado_meta_upsert(ip)
            flash(f"{ip} atualizado.", "ok")
        else:
            flash("IP inválido.", "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao salvar: {e}", "erro")
    return redirect(url_for("admin.liberados"))


@admin_bp.post("/liberados/revogar")
@login_required
def liberados_revogar():
    try:
        ip = dnslib.revogar(request.form.get("ip"))
        if ip:
            api.delete(f"/console/liberados-meta?ip={quote(ip, safe='')}")
            flash(f"{ip} removido (volta a filtrar).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao revogar: {e}", "erro")
    return redirect(url_for("admin.liberados"))


@admin_bp.get("/bloqueios")
@login_required
def bloqueios():
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        flash("Technitium não configurado (defina TECHNITIUM_URL/TOKEN).", "erro")
        return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")
    grupos, doms = [], []
    try:
        grupos = dnslib.grupos_bloqueio()
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar o Technitium: {e}", "erro")
    grupo = (request.args.get("grupo") or (grupos[0] if grupos else "")).strip()
    q = (request.args.get("q") or "").strip()
    qg = (request.args.get("qg") or "").strip()
    redes = []
    total = 0
    limite = 1000
    if grupo:
        try:
            doms = dnslib.bloqueados(grupo, q or None) or []
            total = len(doms)
            doms = doms[:limite]  # cap p/ não travar a tela (listas com dezenas de milhares)
            redes = dnslib.redes_do_grupo(grupo)
        except Exception as e:  # noqa: BLE001
            flash(f"Falha ao listar bloqueios: {e}", "erro")
    # Busca global (em todas as listas)
    globais, globais_total, globais_cap = [], 0, False
    if qg:
        try:
            globais, globais_total, globais_cap = dnslib.buscar_em_todos(qg)
        except Exception as e:  # noqa: BLE001
            flash(f"Falha na busca global: {e}", "erro")
    # empresa dona de cada rede do grupo (cadastro de empresas) — vários clientes podem
    # compartilhar o mesmo grupo de bloqueio
    from app import empresas as emp
    redes_emp = emp.rotulos_de_redes(redes) if redes else {}
    empresas_grupo = sorted({v.split(" · ")[0] for v in redes_emp.values()})
    return render_template("admin/bloqueios.html", grupos=grupos, grupo=grupo, q=q,
                           doms=doms, redes=redes, total=total, limite=limite, qg=qg,
                           globais=globais, globais_total=globais_total, globais_cap=globais_cap,
                           redes_emp=redes_emp, empresas_grupo=empresas_grupo)


@admin_bp.post("/bloqueios/add")
@login_required
def bloqueios_add():
    grupo = (request.form.get("grupo") or "").strip()
    texto = request.form.get("dominios") or ""
    f = request.files.get("arquivo")
    if f and f.filename:
        try:
            texto += "\n" + f.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            flash("Não consegui ler o arquivo enviado.", "erro")
    de = (request.form.get("de_grupo") or "").strip()
    if de and de != grupo:
        try:
            texto += "\n" + "\n".join(dnslib.bloqueados(de) or [])
        except Exception as e:  # noqa: BLE001
            flash(f"Não consegui ler o grupo de origem: {e}", "erro")
    try:
        add, ja, total = dnslib.add_bloqueio(grupo, texto)
        if add is None:
            flash("Grupo inválido.", "erro")
        elif add == 0 and ja == 0:
            flash("Nenhum domínio válido no que você enviou.", "erro")
        else:
            flash(f"{add} adicionado(s), {ja} já existia(m). Total do grupo: {total}.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao adicionar: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=grupo))


@admin_bp.post("/bloqueios/limpar")
@login_required
def bloqueios_limpar():
    grupo = (request.form.get("grupo") or "").strip()
    try:
        n = dnslib.limpar_bloqueios(grupo)
        if n is None:
            flash("Grupo inválido.", "erro")
        else:
            flash(f"Lista de {grupo} limpa ({n} domínio(s) removido(s)).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao limpar: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=grupo))


@admin_bp.post("/bloqueios/renomear")
@login_required
def bloqueios_renomear():
    velho = (request.form.get("grupo") or "").strip()
    novo = (request.form.get("novo_nome") or "").strip()
    try:
        n, msg = dnslib.renomear_grupo(velho, novo)
        if n:
            flash(f"Grupo '{velho}' {msg} para '{n}'.", "ok")
            return redirect(url_for("admin.bloqueios", grupo=n))
        flash(msg, "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao renomear: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=velho))


@admin_bp.post("/bloqueios/deletar")
@login_required
def bloqueios_deletar():
    grupo = (request.form.get("grupo") or "").strip()
    try:
        n, info = dnslib.deletar_grupo(grupo)
        if n:
            extra = f" ({info} rede(s) desatribuída(s))" if info else ""
            flash(f"Grupo '{n}' removido{extra}.", "ok")
            return redirect(url_for("admin.bloqueios"))
        flash(info, "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover grupo: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=grupo))


@admin_bp.post("/bloqueios/grupo")
@login_required
def bloqueios_grupo():
    nome = (request.form.get("nome") or "").strip()
    clonar = (request.form.get("clonar_de") or "").strip() or None
    try:
        n, msg = dnslib.criar_grupo(nome, clonar)
        if n:
            flash(f"Grupo '{n}' {msg}.", "ok")
            return redirect(url_for("admin.bloqueios", grupo=n))
        flash(msg, "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao criar grupo: {e}", "erro")
    return redirect(url_for("admin.bloqueios"))


@admin_bp.post("/bloqueios/rede")
@login_required
def bloqueios_rede_add():
    grupo = (request.form.get("grupo") or "").strip()
    try:
        cidr, ant = dnslib.atribuir_rede(request.form.get("rede"), grupo)
        if cidr:
            flash(f"Rede {cidr} atribuída a {grupo}"
                  + (f" (antes: {ant})." if ant else "."), "ok")
        else:
            flash(ant, "erro")   # ant carrega a mensagem de erro quando cidr é None
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao atribuir rede: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=grupo))


@admin_bp.post("/bloqueios/rede/rem")
@login_required
def bloqueios_rede_rem():
    grupo = (request.form.get("grupo") or "").strip()
    try:
        r = dnslib.remover_rede(request.form.get("rede"), grupo)
        if r:
            flash(f"Rede {r} removida de {grupo} (volta a filtrar pela rede pai).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover rede: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=grupo))


@admin_bp.post("/bloqueios/rem")
@login_required
def bloqueios_rem():
    grupo = (request.form.get("grupo") or "").strip()
    qg = (request.form.get("qg") or "").strip()
    try:
        d = dnslib.rem_bloqueio(grupo, request.form.get("dominio"))
        if d:
            flash(f"{d} removido de {grupo}.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover: {e}", "erro")
    if qg:  # veio da busca global: volta pra ela
        return redirect(url_for("admin.bloqueios", qg=qg))
    return redirect(url_for("admin.bloqueios", grupo=grupo, q=(request.form.get("q") or "")))


@admin_bp.post("/bloqueios/rem-todos")
@login_required
def bloqueios_rem_todos():
    doms = request.form.getlist("dominios")
    qg = (request.form.get("qg") or "").strip()
    voltar = (request.form.get("voltar") or "").strip()
    try:
        rem, gruposaf = dnslib.rem_dominios_todos(doms)
        if rem == 0:
            flash("Nenhum domínio removido.", "erro")
        else:
            alvo = ", ".join(doms) if len(doms) <= 3 else f"{len(doms)} domínios"
            flash(f"{alvo}: {rem} remoção(ões) em {gruposaf} lista(s).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover de todas as listas: {e}", "erro")
    if next_local(voltar):  # veio da tela de logs: volta pra ela
        return redirect(voltar)
    return redirect(url_for("admin.bloqueios", qg=qg))


@admin_bp.post("/bloqueios/rem-varios")
@login_required
def bloqueios_rem_varios():
    grupo = (request.form.get("grupo") or "").strip()
    doms = request.form.getlist("dominios")
    try:
        rem, total = dnslib.rem_bloqueios(grupo, doms)
        if rem is None:
            flash("Grupo inválido.", "erro")
        elif rem == 0:
            flash("Nenhum domínio selecionado para remover.", "erro")
        else:
            flash(f"{rem} domínio(s) removido(s) de {grupo}. Total restante: {total}.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover em massa: {e}", "erro")
    return redirect(url_for("admin.bloqueios", grupo=grupo, q=(request.form.get("q") or "")))


@admin_bp.get("/logs-dns")
@login_required
def logs_dns():
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        flash("Technitium não configurado (defina TECHNITIUM_URL/TOKEN).", "erro")
        return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")
    from app import empresas as emp
    empresa = (request.args.get("empresa") or "").strip()   # id do cadastro de empresas
    grupo = (request.args.get("grupo") or "").strip()       # grupo de bloqueio (política) do Technitium
    if empresa and not empresa.isdigit():                   # links antigos: empresa=<grupo>
        grupo, empresa = empresa, ""
    cidr = (request.args.get("cidr") or "").strip()
    ip = (request.args.get("ip") or "").strip()
    dominio = (request.args.get("dominio") or "").strip()
    resposta = (request.args.get("resposta") or "").strip()
    rcode = (request.args.get("rcode") or "").strip()
    inicio = (request.args.get("inicio") or "").strip()
    fim = (request.args.get("fim") or "").strip()
    vista = (request.args.get("vista") or "agrupado").strip()  # padrão: agrupado por domínio
    agrupar = vista != "detalhado"
    if not request.args:  # primeira carga (sem filtros): dia atual, início ao fim (São Paulo)
        hoje = dnslib.agora_local().date()
        inicio = f"{hoje}T00:00"
        fim = f"{hoje}T23:59"

    linhas, agrupado, grupos, scanned, cap = [], [], [], 0, False
    lista_empresas = emp.lista()
    try:
        mapa = dnslib.networkgroupmap()
        grupos = sorted(set(mapa.values()))
        redes = None
        ip_like = None
        if empresa:
            redes = emp.redes_da_empresa(int(empresa))
        elif grupo:
            redes = dnslib.empresa_redes(grupo, mapa)
        elif cidr:
            import ipaddress
            try:
                redes = [ipaddress.ip_network(cidr, strict=False)]
            except ValueError:
                ip_like = cidr  # não é CIDR válido: trata como parte do IP (ex.: '10.100')
        # agrupado varre mais entradas p/ a contagem fazer sentido
        lim, smax = (4000, 20000) if agrupar else (300, 6000)
        linhas, scanned, cap = dnslib.consultar_logs(
            mapa, redes=redes, ip_like=ip_like,
            inicio=dnslib.local_para_utc_iso(inicio), fim=dnslib.local_para_utc_iso(fim),
            dominio=dominio or None, ip_exato=ip or None,
            resposta=resposta or None, rcode=rcode or None, limite=lim, scan_max=smax)
        # empresa/unidade pelo cadastro (o "empresa" do Technitium é o grupo de bloqueio)
        info = emp.resolver(l.get("ip") for l in linhas)
        for l in linhas:
            l["grupo"] = l.get("empresa")
            l["empresa"] = emp.rotulo(info.get(l.get("ip"))) or "—"
        union = None
        if any(l.get("resposta") == "Blocked" for l in linhas):
            union, _ = dnslib.blocked_index()

        if agrupar:
            # agrega por domínio: nº de entradas, clientes distintos, último acesso
            agg = {}
            for l in linhas:
                k = l.get("dominio") or ""
                a = agg.get(k)
                if not a:
                    a = {"dominio": k, "n": 0, "clientes": set(), "ultima": l["timestamp"],
                         "tipo": l.get("tipo"), "empresa": l.get("empresa"), "empresas": set(),
                         "blocked": False, "answer": None}
                    agg[k] = a
                a["n"] += 1
                if l.get("ip"):
                    a["clientes"].add(l["ip"])
                if l.get("empresa") and l["empresa"] != "—":
                    a["empresas"].add(l["empresa"])
                if l["timestamp"] > a["ultima"]:
                    a["ultima"] = l["timestamp"]
                    a["empresa"] = l.get("empresa")
                if l.get("resposta") == "Blocked":
                    a["blocked"] = True
                    if not a["answer"]:
                        a["answer"] = l.get("answer")
            for a in agg.values():
                a["nclientes"] = len(a["clientes"])
                a["empresas"] = sorted(a["empresas"])
                if a["blocked"] and union is not None:
                    a["culpados"] = dnslib.culpados(a["dominio"], a["answer"], union)
            agrupado = sorted(agg.values(), key=lambda x: x["ultima"], reverse=True)
        else:
            for l in linhas:
                if l.get("resposta") == "Blocked" and union is not None:
                    l["culpados"] = dnslib.culpados(l.get("dominio"), l.get("answer"), union)
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar os logs: {e}", "erro")
    return render_template(
        "admin/logs_dns.html", linhas=linhas, agrupado=agrupado, agrupar=agrupar, vista=vista,
        grupos=grupos, grupo=grupo, lista_empresas=lista_empresas, empresa=empresa,
        cidr=cidr, ip=ip, dominio=dominio, resposta=resposta, rcode=rcode,
        respostas=dnslib.RESPONSE_TYPES, rcodes=dnslib.RCODES,
        inicio=inicio, fim=fim, scanned=scanned, cap=cap, voltar=request.full_path)
