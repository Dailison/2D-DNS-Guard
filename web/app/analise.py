"""Seção "Análise DNS" do admin: exibe os resultados do analisador (IA local na VM).

O portal NÃO analisa nada — só consome a API interna do analisador e mostra os
resultados. Cada tela é por cliente (empresa do cadastro) ou na visão "Todos os
clientes" (t=0), que consolida para a 2D mas sempre identifica a empresa de cada
linha. Ajustes manuais (override) valem por empresa.
"""

from __future__ import annotations

from urllib.parse import quote

from flask import (Blueprint, current_app, flash, get_flashed_messages, jsonify, redirect, render_template,
                   request, session, url_for)
from markupsafe import escape

from app import analyzer_client as api
from app import technitium as dnslib
from app.analyzer_client import AnalyzerError
from app.auth import admin_atual, login_required, next_local, super_required

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


ULTIMA_HORA = 0   # dias=0 = "Última hora" (29/09: só nas telas de computadores; o analisador recebe hours=1)


def _days(com_hora: bool = False) -> int:
    d = request.args.get("dias", type=int)
    if d is None:
        d = session.get("an_periodo")
    validos = (ULTIMA_HORA, 1, 7, 30, 90) if com_hora else (1, 7, 30, 90)
    if d not in validos:
        d = 1
    session["an_periodo"] = d
    return d


def _periodo_api(dias: int) -> dict:
    """Parâmetro de período para a API do analisador."""
    return {"hours": 1} if dias == ULTIMA_HORA else {"days": dias}


def _ctx(com_hora: bool = False, **kw):
    tenants = kw.pop("tenants", None) or _tenants()
    tid = _tid(tenants)
    tenant = ({"id": TODOS, "name": "Todos os clientes", "networks": []} if tid == TODOS
              else next((t for t in tenants if t["id"] == tid), None))
    return {"tenants": tenants, "tid": tid, "tenant": tenant, "todos": tid == TODOS, "dias": _days(com_hora),
            "com_hora": com_hora, "CLASSES": CLASSES, "CLASS_LABEL": CLASS_LABEL, **kw}


# ------------------------------------------------------------------ status bloqueado/liberado
def _indice_status(tenant: dict | None):
    """(índice de bloqueio, grupos do escopo). Escopo = grupos internos "Empresa: …" das redes da
    empresa (um por política); na visão 'todos', todos."""
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


def _grp_ctx(tenants: list[dict]) -> dict | None:
    """Dados do diálogo "Pôr em quais listas?": as listas de bloqueio por categoria."""
    return {"listas": dnslib.CATEGORIAS_LISTA, "risco": sorted(dnslib.CATEGORIAS_RISCO)}


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
    """Zero loading (29/09): responde na hora só com filtros, abas e o esqueleto; o conteúdo (resumo do analisador,
    por categoria e status no Technitium, que levava 25-50 s em "Todos os clientes") vem de painel_conteudo."""
    ctx = _ctx()
    return render_template("admin/analise/painel.html", grp=_grp_ctx(ctx["tenants"]), aba="painel", **ctx)


@analise_bp.get("/painel/conteudo")
def painel_conteudo():
    ctx = _ctx()
    s, porcat, st, erro = None, [], {}, None
    if ctx["tid"] is not None:
        try:
            s = api.get(f"/tenants/{ctx['tid']}/summary", days=ctx["dias"])
        except AnalyzerError as e:
            erro = str(e)
        if s:
            porcat = _por_categoria(ctx["tid"], ctx["dias"], ctx["tenant"])
            nomes = [d["name"] for k in ("top_nonwork", "top_risk", "top_domains") for d in s.get(k, [])]
            st = _status(nomes, ctx["tenant"])
    html = render_template("admin/analise/_painel_conteudo.html", s=s, porcat=porcat, st=st, erro=erro,
                           scats=_site_cats(), aba="painel", **ctx)
    # avisos do Technitium (flash) iriam para a próxima página: mostra junto do conteúdo
    avisos = "".join(f'<div class="flash {escape(c)}">{escape(m)}</div>'
                     for c, m in get_flashed_messages(with_categories=True))
    return avisos + html


# ------------------------------------------------------------------ fila de decisão
@analise_bp.get("/decisoes")
def decisoes():
    """A fase 5 (Decisão Humana) foi removida em 27/09: a IA decide tudo na fase 4 (os erros a TI corrige nas listas)."""
    return redirect(url_for("analise.ia_ao_vivo", **request.args))


@analise_bp.post("/decisoes/lote")
@super_required
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
    if not itens and acao == "sugerida":
        itens = [(0, "")]   # os itens vêm em "sug" (categoria|tid|domínio)
    if not itens:
        flash("Nenhum domínio selecionado.", "erro")
        return _fim(voltar)
    todos = request.form.get("visao") == "todos"   # decidido na visão "Todos os clientes"
    try:
        rot = dict(dnslib.CATEGORIAS_LISTA)
        if acao == "bloquear":
            listas = [c for c in request.form.getlist("listas") if c in rot]
            if not listas:
                flash("Escolha pelo menos uma lista de bloqueio.", "erro")
                return _fim(voltar)
            nomes = list(dict.fromkeys(n for _, n in itens))
            api.post("/listas-lote", {"cats": listas, "domains": nomes, "by": _quem()})
            from app.dns import _fim_excecao
            _fim_excecao(nomes)
            for t, n in itens:
                _registrar_decisao(t, n, "blocked")
            if todos:
                for n in nomes:
                    _registrar_global(n, "blocked")
            current_app.logger.info("DNS: %s pôs %s nas listas %s (decisão em lote)", _quem(), nomes, listas)
            flash(f"{len(nomes)} domínio(s) nas listas: {', '.join(rot[c] for c in listas)} (vale no DNS em até 2 min).", "ok")
        elif acao == "sugerida":
            por_cat: dict[str, list] = {}
            for s in request.form.getlist("sug"):
                cat, _, it = s.partition("|")
                t, _, n = it.partition("|")
                if cat in rot and n.strip():
                    por_cat.setdefault(cat, []).append((int(t) if t.isdigit() else 0, n.strip()))
            for cat, its in por_cat.items():
                nomes = list(dict.fromkeys(n for _, n in its))
                api.post("/listas-lote", {"cats": [cat], "domains": nomes, "by": _quem()})
                from app.dns import _fim_excecao
                _fim_excecao(nomes)
                for t, n in its:
                    _registrar_decisao(t, n, "blocked")
                if todos:
                    for n in nomes:
                        _registrar_global(n, "blocked")
            current_app.logger.info("DNS: %s pôs nas listas sugeridas: %s", _quem(), {c: [n for _, n in v] for c, v in por_cat.items()})
            flash("Nas listas sugeridas: " + "; ".join(f"{rot[c]} ({len(v)})" for c, v in por_cat.items()) + " — vale no DNS em até 2 min.", "ok")
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
    return _fim(voltar)


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
    return render_template("admin/analise/dominios.html", res=res, f=f, st=st,
                           scats=_site_cats(),
                           grp=_grp_ctx(ctx["tenants"]), aba="dominios", voltar=request.full_path, **ctx)


def _grupos_empresa(tenant: dict | None, ngm: dict) -> dict[str, list[str]]:
    """{grupo interno do Technitium ("Empresa: …"): [redes da empresa nesse grupo]}."""
    out: dict[str, list[str]] = {}
    for n in (tenant or {}).get("networks", []):
        g = dnslib.grupo_da_rede(n["cidr"], ngm)
        if g:
            out.setdefault(g, []).append(n["cidr"])
    return out


def _aplicam_listas() -> dict[str, list[str]]:
    """{lista: [empresas que a aplicam]} pelas políticas (redes sem cadastro = "padrão")."""
    from app import empresas as emp
    from app import politicas as pol
    por = pol.por_escopo()
    empresas = [e for e in emp.lista() if not e.get("auto_created")]
    out: dict[str, set] = {}
    for e in empresas:
        p = por.get(f"tenant:{e['id']}") or por.get("default") or {}
        for c in p.get("lists") or []:
            out.setdefault(c, set()).add(e["name"])
        for k, pu in por.items():
            if k.startswith(f"unit:{e['id']}:"):
                for c in pu.get("lists") or []:
                    out.setdefault(c, set()).add(f"{e['name']} · {k.split(':', 2)[2]}")
    for c in (por.get("default") or {}).get("lists") or []:
        out.setdefault(c, set()).add("padrão")
    return {c: sorted(v) for c, v in out.items()}


def _listas_da_empresa(tid: int | None) -> list[str]:
    """Listas que valem para a empresa (política dela + unidades; sem política = padrão)."""
    from app import politicas as pol
    por = pol.por_escopo()
    p = por.get(f"tenant:{tid}") or por.get("default") or {}
    cats = set(p.get("lists") or [])
    for k, pu in por.items():
        if k.startswith(f"unit:{tid}:"):
            cats |= set(pu.get("lists") or [])
    return sorted(cats)


def _bloqueio_ctx(nome_reg: str, tenant: dict | None, evidencias: list) -> dict | None:
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return None
    try:
        rot, listas = dict(dnslib.CATEGORIAS_LISTA), []
        aplicam = _aplicam_listas()
        da_empresa = set(_listas_da_empresa(tenant["id"])) if tenant and tenant.get("id") else set()
        try:
            listas = [{"cat": r["category"], "rot": rot.get(r["category"], r["category"]), "entrada": r["domain"],
                       "por": r.get("added_by"), "empresas": aplicam.get(r["category"], []),
                       "da_empresa": r["category"] in da_empresa}
                      for r in api.get(f"/listas-dominio/{quote(nome_reg, safe='')}")]
        except AnalyzerError:
            pass
        return {
            "nome": nome_reg, "listas": listas,
            "categorias": dnslib.CATEGORIAS_LISTA, "risco": sorted(dnslib.CATEGORIAS_RISCO),
            "protegido": any(e.get("kind") == "catalog" and (e.get("data") or {}).get("protected")
                             for e in evidencias or []),
        }
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar as listas de bloqueio: {e}", "erro")
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
    auditoria, irmaos = [], []
    if d:
        blq = _bloqueio_ctx(d["domain"]["name"], ctx["tenant"], d["domain"].get("evidence"))
        try:
            auditoria = api.get("/auditoria", domain=d["domain"]["name"], limit=50)
        except AnalyzerError:
            pass
        try:
            irmaos = api.get(f"/domains/{quote(d['domain']['name'], safe='')}/irmaos", limit=30)
        except AnalyzerError:
            irmaos = []
    wl_atual = _whitelist_do_dominio(d["domain"]["name"]) if d else []
    return render_template("admin/analise/dominio.html", d=d, nome=nome, blq=blq, scats=_site_cats(), auditoria=auditoria, irmaos=irmaos,
                           wl_atual=wl_atual, wls=dnslib.CATEGORIAS_WHITELIST_DNS, aba="dominios", **ctx)


def _whitelist_do_dominio(nome_reg: str) -> list[dict]:
    """Entradas de whitelist do domínio (a dele e as de pais publicadas no DNS), p/ o bloco "Whitelist" da página."""
    try:
        return api.get(f"/whitelist-dominio/{quote(nome_reg, safe='')}") or []
    except AnalyzerError:
        return []


def _voltar(nome: str, tid):
    v = request.form.get("voltar") or ""
    return _fim(v if next_local(v) else url_for("analise.dominio", nome=nome, t=tid))


def _fim(destino: str):
    """Fim das ações de bloquear/liberar/decidir: JSON quando vem do fetch da tela (sem
    recarregar a página — as mensagens vão no corpo), senão o redirect de sempre."""
    if request.headers.get("X-Requested-With") == "fetch":
        msgs = get_flashed_messages(with_categories=True)
        return jsonify(ok=not any(c == "erro" for c, _ in msgs), msgs=msgs)
    return redirect(destino)


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


@analise_bp.post("/dominio/<path:nome>/liberar")
@super_required
def dominio_liberar(nome):
    """Desbloquear: tira o domínio das listas de bloqueio (escopo "empresa" = só das listas que a
    empresa aplica; senão, de todas) e registra "manter liberado". Listas são compartilhadas: vale
    para todas as empresas que aplicam cada lista."""
    tid = request.form.get("tid", type=int)
    dominio_reg = request.form.get("dominio", "")
    try:
        cats = _listas_da_empresa(tid) if request.form.get("escopo") == "empresa" and tid else []
        from app.dns import _antes, _libera_agora
        antes = _antes([dominio_reg])
        n = api.post("/listas-remover", {"domains": [dominio_reg], "cats": cats}).get("removidos", 0)
        current_app.logger.info("DNS: %s LIBEROU %s (%d lista(s)%s)", _quem(), dominio_reg, n,
                                f" dentre {cats}" if cats else "")
        if n:
            flash(f"{dominio_reg} fora de {n} lista(s) de bloqueio." + _libera_agora([dominio_reg], antes), "ok")
        else:
            flash(f"{dominio_reg} não está em nenhuma lista de bloqueio"
                  + (" da empresa" if cats else "") + " (pode estar bloqueado por um domínio pai: abra o domínio pai em Domínios bloqueados).",
                  "erro")
        _registrar_decisao(tid, dominio_reg, "allowed")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao liberar: {e}", "erro")
    return _voltar(nome, tid)


@analise_bp.post("/dominio/<path:nome>/liberar-empresa")
@super_required
def dominio_liberar_empresa(nome):
    """Libera o domínio SÓ para uma empresa: lista de liberação "Exceções · <Empresa>" (criada na 1ª vez e
    ligada à política da empresa e das exceções de unidade) + exceção imediata nos grupos dela."""
    from app import politicas as pol
    tid = request.form.get("tid", type=int)
    dominio_reg = (request.form.get("dominio") or nome).strip().lower().rstrip(".")
    tenant = next((t for t in _tenants() if t["id"] == tid), None)
    if not tenant:
        flash("Escolha a empresa no topo da página para liberar só para ela.", "erro")
        return _voltar(nome, tid)
    try:
        nome_lista = f"Exceções · {tenant['name']}"
        existe = next((x for x in api.get("/liberacao") if x["name"] == nome_lista), None)
        slug = existe["slug"] if existe else api.post("/liberacao", {"name": nome_lista, "by": _quem(),
                                                                      "description": "liberações só desta empresa"})["slug"]
        api.post(f"/liberacao/{quote(slug, safe='')}/dominios", {"domains": [dominio_reg], "by": _quem()})
        por = pol.por_escopo()
        escopos = [f"tenant:{tid}"] + [k for k in por if k.startswith(f"unit:{tid}:")]
        for esc in escopos:
            p = por.get(esc) or (por.get("default") if esc == f"tenant:{tid}" else None) or {}
            if slug not in (p.get("services") or []):
                api.put(f"/policies/{quote(esc, safe='')}", {"lists": p.get("lists") or [], "services": sorted({*(p.get("services") or []), slug}),
                                                             "services_blocked": p.get("services_blocked") or [], "by": _quem()})
        pol.sincronizar()
        grupos = dnslib.excecao_direta({dominio_reg: dnslib.grupos_da_empresa(tenant["name"])}, _quem(), "exceção só da empresa")
        _registrar_decisao(tid, dominio_reg, "allowed")
        current_app.logger.info("DNS: %s liberou %s só para %s (lista %s)", _quem(), dominio_reg, tenant["name"], slug)
        flash(f"{dominio_reg} liberado só para {tenant['name']} (lista “{nome_lista}”)." + dnslib.msg_liberado(grupos), "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao liberar para a empresa: {e}", "erro")
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
        api.post(f"/domains/{quote(nome, safe='')}/reanalyze?by={quote(admin_atual().email, safe='@')}")
        flash(f"{nome}: enviado para nova análise (regras agora; IA na fila).", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("analise.dominio", nome=nome, t=tid))


# ------------------------------------------------------------------ computadores
@analise_bp.get("/computadores")
def computadores():
    ctx = _ctx(com_hora=True)
    lista = []
    if ctx["tid"] is not None:
        try:
            lista = api.get(f"/tenants/{ctx['tid']}/clients", limit=500, **_periodo_api(ctx["dias"]))
        except AnalyzerError as e:
            flash(f"Falha ao listar computadores: {e}", "erro")
    return render_template("admin/analise/computadores.html", lista=lista, aba="computadores", **ctx)


@analise_bp.get("/computador/<ip>")
def computador(ip):
    ctx = _ctx(com_hora=True)
    c = None
    if ctx["tid"] is not None:
        try:
            c = api.get(f"/tenants/{ctx['tid']}/clients/{ip}", **_periodo_api(ctx["dias"]))
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
    from app import politicas as pol
    ctx = _ctx()
    resumo, default = {}, {}
    try:
        por = pol.por_escopo()
        resumo = pol.resumo_empresas([t for t in ctx["tenants"] if not t.get("auto_created")], por)
        default = por.get("default") or {}
    except AnalyzerError as e:
        flash(f"Não foi possível carregar as políticas: {e}", "erro")
    return render_template("admin/analise/empresas.html", aba="empresas", pol=resumo, pol_default=default,
                           cats=dnslib.CATEGORIAS_LISTA, cats_risco=sorted(dnslib.CATEGORIAS_RISCO),
                           pacotes=_listas_liberacao(), **ctx)


def _listas_liberacao() -> list[dict]:
    """Serviços (com categoria = sublista de uma lista de bloqueio) e listas de liberação avulsas."""
    try:
        return api.get("/liberacao")
    except AnalyzerError:
        return []


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


# ------------------------------------------------------------------ fontes de ameaça (Threat Intelligence)
@analise_bp.get("/fontes")
def fontes():
    ctx = _ctx()
    fontes_ = []
    try:
        fontes_ = api.get("/sources")
    except AnalyzerError as e:
        flash(f"Falha ao consultar o analisador: {e}", "erro")
    return render_template("admin/analise/fontes.html", fontes=fontes_, aba="fontes", **ctx)


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
