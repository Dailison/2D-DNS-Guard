"""Seção "Análise DNS" do admin: exibe os resultados do analisador (IA local na VM).

O portal NÃO analisa nada — só consome a API interna do analisador e mostra os
resultados. Cada tela é por cliente (empresa do cadastro) ou na visão "Todos os
clientes" (t=0), que consolida para a 2D mas sempre identifica a empresa de cada
linha. Ajustes manuais (override) valem por empresa.
"""

from __future__ import annotations

from urllib.parse import quote

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from app import analyzer_client as api
from app import technitium as dnslib
from app.analyzer_client import AnalyzerError
from app.auth import admin_atual, login_required, next_local

analise_bp = Blueprint("analise", __name__, url_prefix="/analise")

CLASSES = [
    ("TRABALHO", "Trabalho"), ("NAO_TRABALHO", "Não trabalho"), ("SUSPEITO", "Suspeito"),
    ("MALICIOSO", "Malicioso"), ("DESCONHECIDO", "Desconhecido"),
]
CLASS_LABEL = dict(CLASSES)


@analise_bp.app_template_filter("dt_sp")
def _dt_sp(v, fmt="%d/%m/%Y %H:%M"):
    """ISO UTC (vindo da API) -> horário de São Paulo."""
    if not v:
        return "—"
    s = dnslib.utc_para_local(v)  # 'YYYY-MM-DD HH:MM:SS'
    try:
        from datetime import datetime
        return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").strftime(fmt)
    except ValueError:
        return s


@analise_bp.app_template_filter("urlq")
def _urlq(v):
    return quote(str(v or ""), safe="")


@analise_bp.before_request
@login_required
def _guard():
    if not current_app.config.get("ANALYZER_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Analisador (ANALYZER_URL/ANALYZER_TOKEN)")
    return None


def _quem() -> str:
    adm = admin_atual()
    return (getattr(adm, "email", None) or getattr(adm, "nome", None) or "admin") if adm else "admin"


def _tenants() -> list[dict]:
    try:
        return api.get("/tenants")
    except AnalyzerError as e:
        flash(f"Não foi possível consultar o analisador: {e}", "erro")
        return []


TODOS = 0   # "Todos os clientes": visão geral (cada linha diz de qual empresa é)


def _tid(tenants: list[dict]) -> int | None:
    """Cliente selecionado: ?t= > sessão > Todos os clientes. 0 = todos."""
    if not tenants:
        return None
    ids = {t["id"] for t in tenants} | {TODOS}
    t = request.args.get("t", type=int)
    if t in ids:
        session["an_tid"] = t
        return t
    if session.get("an_tid") in ids:
        return session["an_tid"]
    session["an_tid"] = TODOS
    return TODOS


def _days() -> int:
    d = request.args.get("dias", type=int) or session.get("an_periodo") or 1
    d = d if d in (1, 7, 30, 90) else 1
    session["an_periodo"] = d
    return d


def _ctx(**kw):
    tenants = kw.pop("tenants", None) or _tenants()
    tid = _tid(tenants)
    tenant = ({"id": TODOS, "name": "Todos os clientes", "networks": []} if tid == TODOS
              else next((t for t in tenants if t["id"] == tid), None))
    return {"tenants": tenants, "tid": tid, "tenant": tenant, "todos": tid == TODOS, "dias": _days(),
            "CLASSES": CLASSES, "CLASS_LABEL": CLASS_LABEL, **kw}


# ------------------------------------------------------------------ status bloqueado/liberado
def _indice_status(tenant: dict | None):
    """(índice de bloqueio, grupos do escopo). Escopo = grupos da empresa; na visão
    'todos' (ou empresa sem grupo), todos os grupos de bloqueio."""
    from flask import g
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return None, None
    if "_idx_bloq" not in g:
        try:
            g._idx_bloq = dnslib.indice_bloqueio()
        except Exception as e:  # noqa: BLE001
            flash(f"Não foi possível consultar os bloqueios do Technitium: {e}", "erro")
            g._idx_bloq = None
    idx = g._idx_bloq
    if idx is None:
        return None, None
    grupos = sorted(_grupos_empresa(tenant, idx["ngm"])) if tenant and tenant.get("id") else []
    return idx, (grupos or None)


def _status(nomes, tenant: dict | None) -> dict[str, list[str]]:
    """{domínio: [grupos onde está bloqueado]} ([] = liberado) no escopo da empresa."""
    idx, grupos = _indice_status(tenant)
    if idx is None:
        return {}
    return {n: dnslib.bloqueado_em(idx, n, grupos) for n in dict.fromkeys(nomes) if n}


def _fila_pendente(fila: list[dict], tenants: list[dict]) -> tuple[list[dict], int]:
    """Tira da fila o que já está bloqueado para a empresa da linha (não há o que decidir).
    Retorna (fila, quantos ocultos)."""
    idx, _ = _indice_status(None)
    if idx is None:
        return fila, 0
    por_id = {t["id"]: t for t in tenants}
    escopo: dict[int, list[str] | None] = {}
    out = []
    for f in fila:
        tid = f["tenant_id"]
        if tid not in escopo:
            escopo[tid] = sorted(_grupos_empresa(por_id.get(tid), idx["ngm"])) or None
        if not dnslib.bloqueado_em(idx, f["name"], escopo[tid]):
            out.append(f)
    return out, len(fila) - len(out)


def _agrupar_fila(fila: list[dict]) -> list[dict]:
    """Uma linha por site: junta as empresas que acessaram (soma consultas/PCs, 1º acesso mais antigo).
    A ordem da API (risco > recomendação > consultas) é mantida pela 1ª ocorrência."""
    out: dict[str, dict] = {}
    for f in fila:
        g = out.get(f["name"])
        if g is None:
            g = out[f["name"]] = {**f, "empresas": [], "total_queries": 0, "clients_count": 0}
        g["empresas"].append({"id": f["tenant_id"], "name": f["tenant_name"]})
        g["total_queries"] += int(f.get("total_queries") or 0)
        g["clients_count"] += int(f.get("clients_count") or 0)
        if f.get("first_seen") and (not g.get("first_seen") or f["first_seen"] < g["first_seen"]):
            g["first_seen"] = f["first_seen"]
    for g in out.values():
        g["empresas"].sort(key=lambda e: e["name"] or "")
        g["itens"] = [f"{e['id']}|{g['name']}" for e in g["empresas"]]
    return list(out.values())


def _grp_ctx(tenants: list[dict]) -> dict | None:
    """Dados do diálogo "Bloquear em quais listas?": grupos ativos (com as empresas
    que usam cada um) e os grupos de cada empresa (pré-seleção)."""
    idx, _ = _indice_status(None)
    if idx is None:
        return None
    ngm = idx["ngm"]
    comp = _compartilham(idx["ativos"], ngm, None)
    return {"grupos": [{"nome": g, "empresas": comp.get(g, [])} for g in idx["ativos"]],
            "por_tenant": {t["id"]: sorted(_grupos_empresa(t, ngm)) for t in tenants}}


def _site_cats() -> dict[str, dict]:
    from flask import g
    if "_scats" not in g:
        try:
            g._scats = {c["code"]: c for c in api.get("/site-categories")}
        except AnalyzerError:
            g._scats = {}
    return g._scats


def _por_categoria(tid: int, dias: int, tenant: dict | None) -> list[dict]:
    """Resumo por categoria (domínios, consultas, bloqueados/liberados) — top 1000 do período."""
    try:
        itens = api.get(f"/tenants/{tid}/domains", days=dias, limit=1000, sort="queries")["items"]
    except AnalyzerError:
        return []
    st = _status([i["name"] for i in itens], tenant)
    cats = _site_cats()
    agg: dict[str, dict] = {}
    for i in itens:
        code = i.get("category") or "_pendente"
        a = agg.setdefault(code, {"code": code, "label": cats.get(code, {}).get("label", "Aguardando IA"),
                                  "nonwork": cats.get(code, {}).get("nonwork", False),
                                  "dominios": 0, "consultas": 0, "bloqueados": 0})
        a["dominios"] += 1
        a["consultas"] += int(i.get("total_queries") or 0)
        a["bloqueados"] += 1 if st.get(i["name"]) else 0
    return sorted(agg.values(), key=lambda x: x["consultas"], reverse=True)


# ------------------------------------------------------------------ painel
@analise_bp.get("")
def painel():
    ctx = _ctx()
    s, fila, porcat, st = None, [], [], {}
    if ctx["tid"] is not None:
        try:
            s = api.get(f"/tenants/{ctx['tid']}/summary", days=ctx["dias"])
            fila = api.get(f"/tenants/{ctx['tid']}/review", days=ctx["dias"], limit=200)
        except AnalyzerError as e:
            flash(f"Falha ao carregar o painel: {e}", "erro")
        fila = _agrupar_fila(_fila_pendente(fila, ctx["tenants"])[0])[:12]
        if s:
            porcat = _por_categoria(ctx["tid"], ctx["dias"], ctx["tenant"])
            nomes = [d["name"] for k in ("top_nonwork", "top_risk", "top_domains") for d in s.get(k, [])]
            st = _status(nomes, ctx["tenant"])
    return render_template("admin/analise/painel.html", s=s, fila=fila, porcat=porcat, st=st,
                           scats=_site_cats(), grp=_grp_ctx(ctx["tenants"]), aba="painel", **ctx)


# ------------------------------------------------------------------ fila de decisão
@analise_bp.get("/decisoes")
def decisoes():
    ctx = _ctx()
    fila, ocultos = [], 0
    if ctx["tid"] is not None:
        try:
            fila = api.get(f"/tenants/{ctx['tid']}/review", days=ctx["dias"], limit=1000)
        except AnalyzerError as e:
            flash(f"Falha ao carregar a fila: {e}", "erro")
        fila, ocultos = _fila_pendente(fila, ctx["tenants"])
    ff = {"categoria": request.args.get("categoria", ""), "empresa": request.args.get("empresa", type=int),
          "classe": request.args.get("classe", ""), "rec": request.args.get("rec", ""),
          "q": request.args.get("q", "").strip().lower()}
    opc = _opcoes_fila(fila)
    fila = _agrupar_fila([f for f in fila if _passa(f, ff)])
    return render_template("admin/analise/decisoes.html", fila=fila[:500], ocultos=ocultos, ff=ff, opc=opc,
                           scats=_site_cats(), grp=_grp_ctx(ctx["tenants"]), aba="decisoes", **ctx)


def _passa(f: dict, ff: dict) -> bool:
    """Filtros da fila (aplicados por empresa ANTES de agrupar: filtrando uma empresa,
    as ações valem só para ela)."""
    if ff["categoria"] and (f.get("category") or "_pendente") != ff["categoria"]:
        return False
    if ff["empresa"] and f["tenant_id"] != ff["empresa"]:
        return False
    if ff["classe"] and f.get("classification") != ff["classe"]:
        return False
    if ff["rec"] and (f.get("corp_action") or "_sem") != ff["rec"]:
        return False
    return not ff["q"] or ff["q"] in f["name"]


def _opcoes_fila(fila: list[dict]) -> dict:
    """Opções dos filtros com contagem de sites (distintos) na fila atual."""
    def conta(chave):
        c: dict = {}
        for f in fila:
            c.setdefault(chave(f), set()).add(f["name"])
        return {k: len(v) for k, v in c.items()}
    emp = {}
    for f in fila:
        emp.setdefault(f["tenant_id"], [f["tenant_name"], set()])[1].add(f["name"])
    return {"categoria": conta(lambda f: f.get("category") or "_pendente"),
            "classe": conta(lambda f: f.get("classification")),
            "rec": conta(lambda f: f.get("corp_action") or "_sem"),
            "empresa": sorted(((k, v[0], len(v[1])) for k, v in emp.items()), key=lambda x: x[1] or "")}


@analise_bp.post("/decisoes/lote")
def decisoes_lote():
    """Bloquear (nas listas escolhidas) ou manter liberado — um ou vários domínios."""
    acao = request.form.get("acao")
    voltar = request.form.get("voltar") or ""
    voltar = voltar if next_local(voltar) else url_for("analise.decisoes")
    itens = []
    for it in request.form.getlist("itens"):
        t, _, n = it.partition("|")
        if n.strip():
            itens.append((int(t) if t.isdigit() else 0, n.strip()))
    if not itens:
        flash("Nenhum domínio selecionado.", "erro")
        return redirect(voltar)
    todos = request.form.get("visao") == "todos"   # decidido na visão "Todos os clientes"
    try:
        if acao == "bloquear":
            ativos = set(dnslib.grupos_ativos(dnslib._get_config()))
            grupos = [g for g in request.form.getlist("grupos") if g in ativos]
            if not grupos:
                flash("Escolha pelo menos uma lista de bloqueio.", "erro")
                return redirect(voltar)
            res = dnslib.bloquear_varios_em(grupos, [n for _, n in itens])
            for t, n in itens:
                _registrar_decisao(t, n, "blocked")
            if todos:
                for n in dict.fromkeys(n for _, n in itens):
                    _registrar_global(n, "blocked")
            novos = sum(len(r["adicionados"]) for r in res.values())
            current_app.logger.info("DNS: %s BLOQUEOU %s em %s (decisão em lote)", _quem(),
                                    [n for _, n in itens], grupos)
            flash(f"{len(itens)} domínio(s) bloqueado(s) em: {', '.join(grupos)} ({novos} entrada(s) nova(s)"
                  + (", o resto já estava bloqueado" if novos < len(itens) * len(grupos) else "") + ").", "ok")
        elif acao == "liberar":
            for t, n in itens:
                _registrar_decisao(t, n, "allowed")
            if todos:
                for n in dict.fromkeys(n for _, n in itens):
                    _registrar_global(n, "allowed")
            flash(f"{len(itens)} domínio(s) mantido(s) liberado(s) (decisão registrada"
                  + (", vale também para empresas que acessarem depois" if todos else "") + ").", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha: {e}", "erro")
    return redirect(voltar)


@analise_bp.post("/decisoes/<int:tid>/<path:nome>")
def decisao(tid, nome):
    """Bloquear (nos grupos da empresa) ou manter liberado — e registra a decisão."""
    acao = request.form.get("acao")
    voltar = request.form.get("voltar") or url_for("analise.decisoes", t=tid)
    try:
        if acao == "bloquear":
            tenant = next((t for t in _tenants() if t["id"] == tid), None)
            idx = dnslib.indice_bloqueio()
            grupos = sorted(_grupos_empresa(tenant, idx["ngm"]))
            if not grupos:
                flash(f"{nome}: a empresa não tem grupo de bloqueio no Technitium — bloqueie pela página do domínio.",
                      "erro")
                return redirect(voltar)
            dnslib.bloquear_em(grupos, nome)
            api.post(f"/tenants/{tid}/review/{quote(nome, safe='')}", {"status": "blocked", "by": _quem()})
            current_app.logger.info("DNS: %s BLOQUEOU %s em %s (decisão)", _quem(), nome, grupos)
            flash(f"{nome} bloqueado em {', '.join(grupos)}.", "ok")
        elif acao == "liberar":
            api.post(f"/tenants/{tid}/review/{quote(nome, safe='')}", {"status": "allowed", "by": _quem()})
            flash(f"{nome}: mantido liberado (decisão registrada).", "ok")
        elif acao == "manter_bloqueado":
            api.post(f"/tenants/{tid}/review/{quote(nome, safe='')}", {"status": "blocked", "by": _quem()})
            flash(f"{nome}: mantido bloqueado (decisão registrada).", "ok")
        elif acao == "reabrir":
            api.post(f"/tenants/{tid}/review/{quote(nome, safe='')}", {"status": None, "by": _quem()})
            flash(f"{nome} voltou para a fila de decisão.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha: {e}", "erro")
    return redirect(voltar if next_local(voltar) else url_for("analise.decisoes", t=tid))


# ------------------------------------------------------------------ domínios
@analise_bp.get("/dominios")
def dominios():
    ctx = _ctx()
    f = {"classification": request.args.get("classe", ""), "q": request.args.get("q", "").strip(),
         "sort": request.args.get("ordem", "queries"), "offset": request.args.get("offset", 0, type=int),
         "category": request.args.get("categoria", ""), "corp": request.args.get("rec", "")}
    res, st = {"total": 0, "items": []}, {}
    if ctx["tid"] is not None:
        try:
            res = api.get(f"/tenants/{ctx['tid']}/domains", days=ctx["dias"], limit=100, **f)
        except AnalyzerError as e:
            flash(f"Falha ao listar domínios: {e}", "erro")
        st = _status([d["name"] for d in res["items"]], ctx["tenant"])
    return render_template("admin/analise/dominios.html", res=res, f=f, st=st, scats=_site_cats(),
                           grp=_grp_ctx(ctx["tenants"]), aba="dominios", voltar=request.full_path, **ctx)


def _grupos_empresa(tenant: dict | None, ngm: dict) -> dict[str, list[str]]:
    """{grupo de bloqueio: [redes da empresa que usam esse grupo]}."""
    out: dict[str, list[str]] = {}
    for n in (tenant or {}).get("networks", []):
        g = dnslib.grupo_da_rede(n["cidr"], ngm)
        if g:
            out.setdefault(g, []).append(n["cidr"])
    return out


def _compartilham(grupos, ngm: dict, excluir: str | None) -> dict[str, list[str]]:
    """{grupo: [outras empresas que usam o mesmo grupo]} — via cadastro de empresas."""
    from app import empresas as emp
    out = {}
    for g in grupos:
        redes = [str(k) for k, v in ngm.items() if v == g and k.prefixlen < 32 and k.prefixlen > 0]
        nomes = {r.split(" · ")[0] for r in emp.rotulos_de_redes(redes).values()}
        out[g] = sorted(nomes - {excluir})
    return out


def _bloqueio_ctx(nome_reg: str, tenant: dict | None, evidencias: list) -> dict | None:
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return None
    try:
        cfg = dnslib._get_config()
        ngm = dnslib.ngm_de(cfg)
        estado = dnslib.estado_bloqueio(nome_reg, cfg)
        g_emp = _grupos_empresa(tenant, ngm)
        return {
            "nome": nome_reg, "estado": estado, "grupos_empresa": g_emp,
            "compartilham": _compartilham(g_emp.keys(), ngm, (tenant or {}).get("name")),
            "todos": dnslib.grupos_ativos(cfg),
            "bloqueado_empresa": sorted(set(estado) & set(g_emp)),
            "protegido": any(e.get("kind") == "catalog" and (e.get("data") or {}).get("protected")
                             for e in evidencias or []),
        }
    except ValueError:
        return None   # nome que não é domínio bloqueável (ex.: IP)
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar os bloqueios do Technitium: {e}", "erro")
        return None


@analise_bp.get("/dominio/<path:nome>")
def dominio(nome):
    ctx = _ctx()
    d, blq = None, None
    if ctx["tid"] is not None:
        try:
            d = api.get(f"/tenants/{ctx['tid']}/domains/{quote(nome, safe='')}")
        except AnalyzerError as e:
            flash(f"Domínio {nome}: {e}", "erro")
    if d:
        blq = _bloqueio_ctx(d["domain"]["name"], ctx["tenant"], d["domain"].get("evidence"))
    return render_template("admin/analise/dominio.html", d=d, nome=nome, blq=blq, scats=_site_cats(),
                           aba="dominios", **ctx)


def _escopo_grupos(escopo: str, tid: int, dominio: str, acao: str) -> list[str]:
    cfg = dnslib._get_config()
    ngm = dnslib.ngm_de(cfg)
    ativos = set(dnslib.grupos_ativos(cfg))
    tenant = next((t for t in _tenants() if t["id"] == tid), None)
    if escopo.startswith("g:"):
        return [escopo[2:]] if escopo[2:] in ativos else []
    if escopo == "empresa":
        return sorted(set(_grupos_empresa(tenant, ngm)) & ativos)
    if escopo == "todos":
        return sorted(ativos) if acao == "bloquear" else sorted(dnslib.estado_bloqueio(dominio, cfg))
    return []


def _voltar(nome: str, tid):
    v = request.form.get("voltar") or ""
    return redirect(v if v.startswith("/admin/") else url_for("analise.dominio", nome=nome, t=tid))


def _registrar_global(dominio: str, status: str | None) -> None:
    """Decisão da visão "Todos os clientes": vale também p/ empresas que acessarem depois."""
    try:
        api.post(f"/domains/{quote(dominio, safe='')}/review", {"status": status, "by": _quem()})
    except AnalyzerError:
        pass


def _registrar_decisao(tid, dominio: str, status: str) -> None:
    """Bloquear/liberar pela tela também conta como decisão da empresa (sai da fila).
    Sem empresa (visão "Todos os clientes") = decisão global do site."""
    if not tid:
        _registrar_global(dominio, status)
        return
    try:
        api.post(f"/tenants/{tid}/review/{quote(dominio, safe='')}", {"status": status, "by": _quem()})
    except AnalyzerError:
        pass   # domínio nunca visto nesta empresa: nada a registrar


@analise_bp.post("/dominio/<path:nome>/bloquear")
def dominio_bloquear(nome):
    tid = request.form.get("tid", type=int)
    dominio_reg = request.form.get("dominio", "")
    try:
        grupos = _escopo_grupos(request.form.get("escopo", ""), tid, dominio_reg, "bloquear")
        if not grupos:
            flash("Nenhum grupo de bloqueio no escopo escolhido.", "erro")
        else:
            res = dnslib.bloquear_em(grupos, dominio_reg)
            add = [g for g, s in res.items() if s == "adicionado"]
            ja = [g for g, s in res.items() if s == "já bloqueado"]
            current_app.logger.info("DNS: %s BLOQUEOU %s em %s", _quem(), dominio_reg, add)
            flash(f"{dominio_reg} bloqueado em: {', '.join(add) or '—'}."
                  + (f" Já estava bloqueado em: {', '.join(ja)}." if ja else ""), "ok")
        _registrar_decisao(tid, dominio_reg, "blocked")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao bloquear: {e}", "erro")
    return _voltar(nome, tid)


@analise_bp.post("/dominio/<path:nome>/liberar")
def dominio_liberar(nome):
    tid = request.form.get("tid", type=int)
    dominio_reg = request.form.get("dominio", "")
    try:
        grupos = _escopo_grupos(request.form.get("escopo", ""), tid, dominio_reg, "liberar")
        removidas, restam = dnslib.liberar_em(grupos, dominio_reg)
        current_app.logger.info("DNS: %s LIBEROU %s em %s", _quem(), dominio_reg, removidas)
        if removidas:
            flash(f"{dominio_reg} liberado. Entradas removidas: "
                  + "; ".join(f"{g}: {', '.join(v)}" for g, v in removidas.items()) + ".", "ok")
        else:
            flash("Nenhuma entrada do domínio encontrada no escopo escolhido.", "erro")
        if restam:
            flash("Atenção: continua bloqueado por domínio PAI em "
                  + "; ".join(f"{g} ({', '.join(v)})" for g, v in restam.items())
                  + ". Remover o pai liberaria tudo abaixo dele — faça isso em Domínios se for o caso.", "erro")
        _registrar_decisao(tid, dominio_reg, "allowed")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao liberar: {e}", "erro")
    return _voltar(nome, tid)


@analise_bp.post("/dominio/<path:nome>/decisao-global")
def dominio_decisao_global(nome):
    """Desfaz a decisão global: empresas sem decisão própria voltam para a fila."""
    tid = request.form.get("tid", type=int) or 0
    _registrar_global(nome, None)
    flash(f"{nome}: decisão global removida (empresas sem decisão própria voltam para a fila).", "ok")
    return redirect(url_for("analise.dominio", nome=nome, t=tid))


@analise_bp.post("/dominio/<path:nome>/override")
def dominio_override(nome):
    tid = request.form.get("tid", type=int)
    cls = None if request.form.get("remover") else (request.form.get("classe") or None)
    ws = request.form.get("work_score", type=int)
    try:
        api.put(f"/tenants/{tid}/domains/{quote(nome, safe='')}/override",
                {"classification": cls, "work_score": ws, "note": request.form.get("nota", "").strip(),
                 "by": _quem()})
        flash(f"{nome}: classificação ajustada para {CLASS_LABEL.get(cls, cls)} neste cliente." if cls
              else f"{nome}: ajuste manual removido (volta à classificação automática).", "ok")
    except AnalyzerError as e:
        flash(f"Falha ao ajustar: {e}", "erro")
    return redirect(url_for("analise.dominio", nome=nome, t=tid))


@analise_bp.post("/dominio/<path:nome>/falso-positivo")
def dominio_fp(nome):
    tid = request.form.get("tid", type=int)
    try:
        api.post(f"/domains/{quote(nome, safe='')}/false-positive",
                 {"source": request.form.get("fonte") or None, "note": request.form.get("nota", "").strip(),
                  "by": _quem()})
        flash(f"{nome}: marcado como falso positivo; será reanalisado em instantes.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.dominio", nome=nome, t=tid))


@analise_bp.post("/dominio/<path:nome>/reanalisar")
def dominio_reanalisar(nome):
    tid = request.form.get("tid", type=int)
    try:
        api.post(f"/domains/{quote(nome, safe='')}/reanalyze")
        flash(f"{nome}: enviado para nova análise (regras agora; IA na fila).", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.dominio", nome=nome, t=tid))


# ------------------------------------------------------------------ computadores
@analise_bp.get("/computadores")
def computadores():
    ctx = _ctx()
    lista = []
    if ctx["tid"] is not None:
        try:
            lista = api.get(f"/tenants/{ctx['tid']}/clients", days=ctx["dias"], limit=500)
        except AnalyzerError as e:
            flash(f"Falha ao listar computadores: {e}", "erro")
    return render_template("admin/analise/computadores.html", lista=lista, aba="computadores", **ctx)


@analise_bp.get("/computador/<ip>")
def computador(ip):
    ctx = _ctx()
    c = None
    if ctx["tid"] is not None:
        try:
            c = api.get(f"/tenants/{ctx['tid']}/clients/{ip}", days=ctx["dias"])
        except AnalyzerError as e:
            flash(f"Computador {ip}: {e}", "erro")
    return render_template("admin/analise/computador.html", c=c, ip=ip, aba="computadores", **ctx)


# ------------------------------------------------------------------ alertas
@analise_bp.get("/alertas")
def alertas():
    ctx = _ctx()
    st = request.args.get("status", "open")
    lista = []
    if ctx["tid"] is not None:
        try:
            lista = api.get(f"/tenants/{ctx['tid']}/alerts", status=st, limit=300)
        except AnalyzerError as e:
            flash(f"Falha ao listar alertas: {e}", "erro")
    return render_template("admin/analise/alertas.html", lista=lista, st=st, aba="alertas", **ctx)


@analise_bp.post("/alertas/<int:aid>/status")
def alerta_status(aid):
    tid = request.form.get("tid", type=int)
    try:
        api.post(f"/tenants/{tid}/alerts/{aid}/status", {"status": request.form.get("status"), "by": _quem()})
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(request.referrer or url_for("analise.alertas", t=tid))


# ------------------------------------------------------------------ cadastro de empresas (CIDR)
def _realocou(res: dict | None) -> str:
    r = (res or {}).get("realocacao") or res or {}
    n = r.get("moved_clients") or 0
    return f" {n} computador(es) e seus dados foram realocados." if n else ""


def parse_planilha(texto: str) -> tuple[list[dict], list[str]]:
    """Linhas coladas da planilha -> [{empresa, unidade, cidr}].

    Aceita (colunas separadas por TAB, ';' ou '|'):
      Empresa<TAB>CIDR               ex.: Semetra	10.7.0.0/16
      Empresa<TAB>Unidade<TAB>CIDR   ex.: Moral Auto Peças	PBS	10.57.0.0/16
    """
    import ipaddress
    import re
    rows, erros = [], []
    for n, linha in enumerate((texto or "").splitlines(), 1):
        if not linha.strip() or linha.strip().startswith("#"):
            continue
        cols = [c.strip() for c in re.split(r"\t|;|\|", linha) if c.strip()]
        if len(cols) == 1:  # "Nome 10.7.0.0/16" separado só por espaço
            m = re.match(r"^(.*\S)\s+(\S+/\d+)$", cols[0])
            cols = [m.group(1), m.group(2)] if m else cols
        if len(cols) < 2:
            erros.append(f"linha {n}: esperado Empresa e CIDR")
            continue
        try:
            cidr = str(ipaddress.ip_network(cols[-1], strict=False))
        except ValueError:
            erros.append(f"linha {n}: CIDR inválido '{cols[-1]}'")
            continue
        rows.append({"empresa": cols[0], "unidade": cols[1] if len(cols) >= 3 else "", "cidr": cidr})
    return rows, erros


@analise_bp.get("/clientes")
def clientes():  # nome antigo
    return redirect(url_for("analise.empresas"))


@analise_bp.get("/empresas")
def empresas():
    return render_template("admin/analise/empresas.html", aba="empresas", **_ctx())


@analise_bp.post("/empresas")
def empresa_criar():
    import re
    nome = request.form.get("nome", "").strip()
    redes, erros = [], []
    for linha in request.form.get("redes", "").splitlines():   # "10.23.0.0/16" ou "Matriz 10.23.0.0/16"
        m = re.match(r"^\s*(.*?)\s*([0-9a-fA-F:.]+/\d+)\s*$", linha)
        if m:
            redes.append({"cidr": m.group(2), "unit": m.group(1).strip(" -\t")})
        elif linha.strip():
            erros.append(f"linha ignorada (sem CIDR): {linha.strip()}")
    try:
        res = api.post("/tenants", {"name": nome, "networks": redes})
        flash(f"Empresa {nome} criada.{_realocou(res)}", "ok")
    except AnalyzerError as e:
        flash(f"Falha ao criar: {e}", "erro")
    for er in erros:
        flash(er, "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/importar")
def empresas_importar():
    rows, erros = parse_planilha(request.form.get("planilha", ""))
    if erros:
        for er in erros[:10]:
            flash(er, "erro")
        return redirect(url_for("analise.empresas"))
    if not rows:
        flash("Nada para importar.", "erro")
        return redirect(url_for("analise.empresas"))
    try:
        res = api.post("/tenants/import", {"rows": rows, "replace": request.form.get("substituir") == "1"})
        rem = res.get("tenants_removed") or []
        flash(f"Importação concluída: {res.get('networks_created', 0)} rede(s) nova(s), "
              f"{res.get('networks_updated', 0)} atualizada(s)"
              + (f", {len(res.get('networks_removed') or [])} removida(s)" if res.get("networks_removed") else "")
              + f".{_realocou(res)}" + (f" Empresas vazias removidas: {', '.join(rem)}." if rem else ""), "ok")
    except AnalyzerError as e:
        flash(f"Falha na importação: {e}", "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/<int:tid>")
def empresa_editar(tid):
    body = {}
    if request.form.get("nome"):
        body["name"] = request.form["nome"].strip()
    if "ativo" in request.form:
        body["active"] = request.form.get("ativo") == "1"
    try:
        api.patch(f"/tenants/{tid}", body)
        flash("Empresa atualizada.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/<int:tid>/unidades")
def unidade_add(tid):
    try:
        r = api.post(f"/tenants/{tid}/networks", {"cidr": request.form.get("cidr", ""),
                                                  "unit": request.form.get("unidade", "")})
        flash(f"Unidade {r['cidr']} cadastrada.{_realocou(r)}", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/rede/<int:nid>")
def unidade_editar(nid):
    body = {}
    if "unidade" in request.form:
        body["unit"] = request.form.get("unidade", "")
    if request.form.get("mover_para"):
        body["tenant_id"] = request.form.get("mover_para", type=int)
    try:
        r = api.patch(f"/networks/{nid}", body)
        flash(("Rede atribuída à empresa escolhida." if body.get("tenant_id") else "Unidade atualizada.")
              + _realocou(r), "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/<int:tid>/unidades/<int:nid>/remover")
def unidade_rem(tid, nid):
    try:
        r = api.delete(f"/tenants/{tid}/networks/{nid}")
        flash("Rede removida do cadastro (os IPs dela passam a aparecer como 'sem cadastro')." + _realocou(r), "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/<int:tid>/mesclar")
def empresa_mesclar(tid):
    destino = request.form.get("destino", type=int)
    try:
        r = api.post(f"/tenants/{tid}/merge", {"into": destino})
        flash(f"Empresa mesclada.{_realocou(r)}", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.empresas"))


@analise_bp.post("/empresas/<int:tid>/excluir")
def empresa_excluir(tid):
    try:
        api.delete(f"/tenants/{tid}")
        flash("Empresa excluída.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.empresas"))


# ------------------------------------------------------------------ IA ao vivo
@analise_bp.get("/ia")
def ia_ao_vivo():
    return render_template("admin/analise/ia.html", aba="ia", **_ctx())


@analise_bp.get("/ia/eventos")
def ia_eventos():
    from flask import jsonify
    try:
        return jsonify(api.get("/ai/events", after_id=request.args.get("after", 0, type=int), limit=60))
    except AnalyzerError as e:
        return jsonify({"error": str(e)}), 502


# ------------------------------------------------------------------ fontes / status da IA
@analise_bp.get("/fontes")
def fontes():
    ctx = _ctx()
    fontes_, stats, health = [], {}, {}
    try:
        fontes_ = api.get("/sources")
        stats = api.get("/stats")
        health = api.get("/health")
    except AnalyzerError as e:
        flash(f"Falha ao consultar o analisador: {e}", "erro")
    return render_template("admin/analise/fontes.html", fontes=fontes_, stats=stats, health=health,
                           aba="fontes", **ctx)


@analise_bp.post("/fontes/<int:sid>")
def fonte_editar(sid):
    body = {}
    if "ativo" in request.form:
        body["enabled"] = request.form.get("ativo") == "1"
    if request.form.get("peso"):
        body["weight"] = request.form.get("peso", type=int)
    try:
        api.patch(f"/sources/{sid}", body)
        flash("Fonte atualizada; domínios afetados serão reanalisados.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.fontes"))
