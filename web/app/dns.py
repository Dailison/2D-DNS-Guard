"""Telas de DNS do console: Domínios bloqueados (listas por categoria) e liberados (listas de liberação), (em quais listas
cada domínio está), políticas por empresa (sincronizadas no Technitium), Liberados (IPs isentos), Logs DNS e Gráficos."""

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
    return redirect(url_for("admin.liberados"))


# ------------------------------------------------- Liberados DNS (Technitium)
TIPOS_LIBERADO = ["Computador", "Celular", "Roteador", "Faixa de IP"]


@admin_bp.get("/liberados")
@login_required
def liberados():
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")
    from app import empresas as emp
    q = (request.args.get("q") or "").strip().lower()
    f_emp = request.args.get("empresa", type=int)
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
            rows.append({k: m.get(k) or "" for k in ("tenant_name", "filial", "empresa", "departamento",
                                                      "usuario", "tipo")} | {"ip": ip, "tenant_id": m.get("tenant_id")})
        if f_emp:
            rows = [r for r in rows if r["tenant_id"] == f_emp]
        if q:
            rows = [r for r in rows if any(q in (r[k] or "").lower() for k in
                                           ("ip", "tenant_name", "filial", "empresa", "departamento", "usuario"))]
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar o Technitium: {e}", "erro")
    empresas = sorted(({"id": e["id"], "name": e["name"],
                        "filiais": sorted({n["unit"] for n in e.get("networks", []) if n.get("unit")}),
                        "redes": [{"cidr": n["cidr"], "unit": n.get("unit") or ""} for n in e.get("networks", [])]}
                       for e in emp.lista()), key=lambda e: e["name"].lower())
    return render_template("admin/liberados.html", rows=rows, q=q, f_emp=f_emp, empresas=empresas,
                           tipos=TIPOS_LIBERADO, grupo=current_app.config.get("TECHNITIUM_LIBERADOS_GROUP"))


def _liberado_meta_upsert(ip):
    """Grava empresa (cadastro) + filial e a descrição (do form) para o IP normalizado."""
    tid = request.form.get("tenant_id", type=int)
    api.put("/console/liberados-meta", {"ip": ip, "by": admin_atual().email, "tenant_id": tid,
                                        **{k: request.form.get(k) or "" for k in
                                           ("filial", "empresa", "departamento", "usuario", "tipo")}})


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


@admin_bp.get("/grupos")
@login_required
def grupos():
    """Tela antiga: os grupos agora são internos (um por empresa, mantidos pelas políticas)."""
    return redirect(url_for("analise.empresas"))


@admin_bp.get("/bloqueios")
@login_required
def bloqueios():
    return redirect(url_for("admin.listas_categoria"))


def _sem_technitium():
    return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")


@admin_bp.get("/dominios")
@login_required
def dominios():
    """Página antiga (removida a pedido do usuário): com ?q=<domínio> abre a página do domínio; senão,
    Domínios bloqueados."""
    q = (request.args.get("q") or request.args.get("qg") or "").strip().lower().rstrip(".")
    if q and "." in q and " " not in q:
        return redirect(url_for("analise.dominio", nome=q, t=0))
    return redirect(url_for("admin.listas_categoria"))


@admin_bp.post("/bloqueios/rem-todos")
@login_required
def bloqueios_rem_todos():
    doms = request.form.getlist("dominios")
    qg = (request.form.get("qg") or "").strip()
    voltar = (request.form.get("voltar") or "").strip()
    try:   # tira de todas as listas de bloqueio (+ decisão 'manter liberado': o automático não põe de volta)
        rem = api.post("/listas-remover", {"domains": doms}).get("removidos", 0)
        for d in doms:
            _decisao_global(d, "allowed")
        if rem == 0:
            flash("Nenhuma entrada encontrada nas listas de bloqueio.", "erro")
        else:
            alvo = ", ".join(doms) if len(doms) <= 3 else f"{len(doms)} domínios"
            flash(f"{alvo}: fora de {rem} lista(s) de bloqueio (vale no DNS em até 1 h).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover de todas as listas: {e}", "erro")
    if next_local(voltar):  # veio da tela de logs: volta pra ela
        return redirect(voltar)
    return redirect(url_for("analise.dominio", nome=qg, t=0) if qg else url_for("admin.listas_categoria"))


LOGS_LIMITE = 1000
# classificação da IA nos logs (filtro "Classificação IA"): AMEACAS = Malicioso + Suspeito
CLS_FILTROS = [("", "— Todas —"), ("AMEACAS", "Ameaças (Malicioso + Suspeito)"), ("MALICIOSO", "Malicioso"),
               ("SUSPEITO", "Suspeito"), ("NAO_TRABALHO", "Não trabalho"), ("DESCONHECIDO", "Desconhecido"),
               ("TRABALHO", "Trabalho"), ("PENDENTE", "Aguardando IA")]
CLS_LABEL = {"TRABALHO": "Trabalho", "NAO_TRABALHO": "Não trabalho", "SUSPEITO": "Suspeito",
             "MALICIOSO": "Malicioso", "DESCONHECIDO": "Desconhecido"}
CLS_ORDEM = ("TRABALHO", "DESCONHECIDO", "NAO_TRABALHO", "SUSPEITO", "MALICIOSO")   # pior por último


def _cls_lista(v: str) -> list[str]:
    return ["MALICIOSO", "SUSPEITO"] if v == "AMEACAS" else ([v] if v else [])


def _pior(a, b):
    return max((a, b), key=lambda c: CLS_ORDEM.index(c) + 1 if c in CLS_ORDEM else 0)


def _site_categorias() -> list[dict]:
    try:
        return api.get("/site-categories") if current_app.config.get("ANALYZER_ENABLED") else []
    except AnalyzerError:
        return []


def _classificar_linhas(linhas: list[dict], info: dict) -> bool:
    """Vista em tempo real (Technitium): classificação da IA de cada nome, em lote, com o ajuste
    manual da empresa do IP. False = analisador fora (sem classificação)."""
    nomes = sorted({l.get("dominio") for l in linhas if l.get("dominio")})
    if not nomes or not current_app.config.get("ANALYZER_ENABLED"):
        return False
    try:
        m = api.post("/logs/classificar", {"nomes": nomes})
    except AnalyzerError as e:
        flash(f"Classificação da IA indisponível: {e}", "erro")
        return False
    for l in linhas:
        c = m.get((l.get("dominio") or "").lower().rstrip(".")) or {}
        tid = str((info.get(l.get("ip")) or {}).get("tenant_id") or "")
        aj = (c.get("ajustes") or {}).get(tid)
        l["cls"], l["ajustada"], l["categoria"] = aj or c.get("classificacao"), bool(aj), c.get("categoria")
    return True


def _logs_agrupados_analisador(inicio, fim, empresa, grupo, cidr, ip, dominio, resposta, redes, ip_like,
                               mapa, grupos, lista_empresas, cls_f="", categoria="", vista="agrupado"):
    def utc(v):
        iso = dnslib.local_para_utc_iso(v)
        return iso + "+00:00" if iso and len(iso) == 19 else iso
    agrupado, cap, coletado, total = [], False, None, 0
    try:
        hoje = dnslib.agora_local().date()
        d = api.get("/logs/grouped", start=utc(inicio or f"{hoje}T00:00"), end=utc(fim or f"{hoje}T23:59"),
                    tid=int(empresa) if empresa else 0, ip=ip or None, ip_like=ip_like,
                    cidr=[str(n) for n in redes] if (redes is not None and not empresa) else None,
                    dominio=dominio or None, blocked="true" if resposta == "Blocked" else None,
                    cls=_cls_lista(cls_f) or None, categoria=categoria or None,
                    por_cliente="true" if vista == "cliente" else None, limit=LOGS_LIMITE)
        cap, coletado = d.get("cap"), d.get("coletado_ate")
        union = None
        if any(r["bloqueadas"] for r in d["rows"]):
            union, _ = dnslib.blocked_index()
        for r in d["rows"]:
            total += r["n"]
            a = {"dominio": r["dominio"], "n": r["n"], "nclientes": r.get("nclientes"),
                 "ultima": dnslib.utc_para_local(r["ultima"]), "empresas": r.get("empresas"),
                 "blocked": r["bloqueadas"] > 0, "bloqueadas": r["bloqueadas"], "tipo": "Resolvido", "answer": None,
                 "cls": r.get("classificacao"), "ajustada": r.get("ajustada"), "categoria": r.get("categoria"),
                 "ip": r.get("ip"), "computador": r.get("computador"), "empresa": r.get("empresa")}
            if a["blocked"] and union is not None:
                a["culpados"] = dnslib.culpados(a["dominio"], None, union)
            agrupado.append(a)
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar os logs no analisador: {e}", "erro")
    return render_template(
        "admin/logs_dns.html", linhas=[], agrupado=agrupado, agrupar=True, vista=vista,
        grupos=grupos, grupo=grupo, lista_empresas=lista_empresas, empresa=empresa,
        cidr=cidr, ip=ip, dominio=dominio, resposta=resposta, respostas=dnslib.RESPONSE_TYPES,
        inicio=inicio, fim=fim, scanned=None, cap=cap, voltar=request.full_path,
        fonte_analisador=True, total_acessos=total,
        coletado_ate=dnslib.utc_para_local(coletado) if coletado else None, **_ctx_cls(cls_f, categoria))


def _ctx_cls(cls_f: str, categoria: str) -> dict:
    cats = _site_categorias()
    return {"cls_f": cls_f, "categoria": categoria, "cls_filtros": CLS_FILTROS, "cls_label": CLS_LABEL,
            "site_categorias": cats, "cat_label": {c["code"]: c["label"] for c in cats}}


@admin_bp.get("/logs-dns")
@login_required
def logs_dns():
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        flash("Technitium não configurado (defina TECHNITIUM_URL/TOKEN).", "erro")
        return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")
    from app import empresas as emp
    empresa = (request.args.get("empresa") or "").strip()   # id do cadastro de empresas
    grupo = ""   # (filtro por grupo saiu: os grupos agora são internos, um por empresa)
    if empresa and not empresa.isdigit():                   # links antigos: empresa=<grupo>
        empresa = ""
    cidr = (request.args.get("cidr") or "").strip()
    ip = (request.args.get("ip") or "").strip()
    dominio = (request.args.get("dominio") or "").strip()
    resposta = (request.args.get("resposta") or "").strip()
    inicio = (request.args.get("inicio") or "").strip()
    fim = (request.args.get("fim") or "").strip()
    vista = (request.args.get("vista") or "agrupado").strip()  # padrão: agrupado por domínio
    if vista not in ("agrupado", "cliente", "detalhado"):
        vista = "agrupado"
    agrupar = vista == "agrupado"
    cls_f = (request.args.get("cls") or "").strip().upper()        # classificação da IA (AMEACAS = Mal.+Susp.)
    if cls_f not in dict(CLS_FILTROS):
        cls_f = ""
    categoria = (request.args.get("categoria") or "").strip()       # categoria do site (IA)
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
        elif cidr:
            import ipaddress
            try:
                redes = [ipaddress.ip_network(cidr, strict=False)]
            except ValueError:
                ip_like = cidr  # não é CIDR válido: trata como parte do IP (ex.: '10.100')
        if current_app.config.get("ANALYZER_ENABLED") and (
                vista == "cliente" or (agrupar and resposta in ("", "Blocked"))):
            # Vista agrupada / por computador pelo analisador (PostgreSQL, agregado por hora):
            # < 2 s para qualquer período/empresa, com a classificação da IA. O Technitium leva
            # 15-30 s por página e não filtra por empresa/faixa. Atraso = o da coleta (~5-7 min).
            if vista == "cliente" and resposta not in ("", "Blocked"):
                flash(f"Resposta \"{resposta}\" não se aplica à vista Por computador (só Todas ou Blocked).", "erro")
                resposta = ""
            return _logs_agrupados_analisador(
                inicio, fim, empresa, grupo, cidr, ip, dominio, resposta, redes, ip_like, mapa, grupos,
                lista_empresas, cls_f, categoria, vista)
        # Máx. 1000 logs por busca: cada página do Technitium custa segundos (SQLite com
        # milhões de linhas). Sem filtro feito aqui = 1 chamada; com filtro de domínio/
        # empresa/faixa (a API não faz) varre até 5000 p/ achar os 1000 resultados.
        filtro_local = bool(dominio or redes is not None or ip_like)
        # 1 chamada só: o custo de cada página é o COUNT do Technitium (~15-30 s), não o
        # tamanho — com filtro local pede 5000 de uma vez em vez de 5 páginas de 1000.
        lim, smax = LOGS_LIMITE, (LOGS_LIMITE * 5 if filtro_local else LOGS_LIMITE)
        linhas, scanned, cap = dnslib.consultar_logs(
            mapa, redes=redes, ip_like=ip_like,
            inicio=dnslib.local_para_utc_iso(inicio), fim=dnslib.local_para_utc_iso(fim),
            dominio=dominio or None, ip_exato=ip or None,
            resposta=resposta or None, limite=lim, scan_max=smax, por_pagina=smax)
        # empresa/unidade pelo cadastro (o "empresa" do Technitium é o grupo interno)
        info = emp.resolver(l.get("ip") for l in linhas)
        for l in linhas:
            l["grupo"] = l.get("empresa")
            l["empresa"] = emp.rotulo(info.get(l.get("ip"))) or "—"
        # classificação da IA (com o ajuste da empresa do IP) e filtros dela, aplicados aqui
        if _classificar_linhas(linhas, info) and (cls_f or categoria):
            quer = _cls_lista(cls_f)
            linhas = [l for l in linhas
                      if (not quer or (l.get("cls") or "PENDENTE") in quer)
                      and (not categoria or l.get("categoria") == categoria)]
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
                         "blocked": False, "answer": None, "cls": None, "ajustada": False,
                         "categoria": l.get("categoria")}
                    agg[k] = a
                a["n"] += 1
                a["cls"] = _pior(a["cls"], l.get("cls"))   # juntando empresas, vale a pior
                a["ajustada"] = a["ajustada"] or bool(l.get("ajustada"))
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
        cidr=cidr, ip=ip, dominio=dominio, resposta=resposta,
        respostas=dnslib.RESPONSE_TYPES,
        inicio=inicio, fim=fim, scanned=scanned, cap=cap, voltar=request.full_path, **_ctx_cls(cls_f, categoria))


# ------------------------------------------------- Gráficos (analisador: query_agg + classificação da IA)
RESPOSTAS_GRAF = [("", "Todas"), ("liberado", "Liberadas"), ("bloqueado", "Bloqueadas")]


@admin_bp.get("/graficos")
@login_required
def graficos():
    """Consultas liberadas × bloqueadas no tempo e por classificação da IA, categoria do site,
    empresa e site, com filtros de empresa, categoria, classificação e resposta."""
    if not current_app.config.get("ANALYZER_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Analisador (ANALYZER_URL/ANALYZER_TOKEN)")
    from datetime import timedelta
    from app import empresas as emp
    hoje = dnslib.agora_local().date()
    presets = {"hoje": (hoje, hoje), "ontem": (hoje - timedelta(days=1),) * 2,
               "7d": (hoje - timedelta(days=6), hoje), "30d": (hoje - timedelta(days=29), hoje)}
    periodo = (request.args.get("periodo") or ("" if request.args.get("inicio") else "hoje")).strip()
    if periodo in presets:
        a, b = presets[periodo]
        inicio, fim = f"{a}T00:00", f"{b}T23:59"
    else:
        periodo = ""
        inicio = (request.args.get("inicio") or f"{hoje}T00:00").strip()
        fim = (request.args.get("fim") or f"{hoje}T23:59").strip()
    empresa = (request.args.get("empresa") or "").strip()
    categoria = (request.args.get("categoria") or "").strip()
    cls_f = (request.args.get("cls") or "").strip().upper()
    cls_f = cls_f if cls_f in dict(CLS_FILTROS) else ""
    resposta = (request.args.get("resposta") or "").strip()
    resposta = resposta if resposta in dict(RESPOSTAS_GRAF) else ""

    def utc(v):
        iso = dnslib.local_para_utc_iso(v)
        return iso + "+00:00" if iso and len(iso) == 19 else iso
    dados = None
    try:
        dados = api.get("/charts", start=utc(inicio), end=utc(fim), tid=int(empresa) if empresa.isdigit() else 0,
                        cls=_cls_lista(cls_f) or None, categoria=categoria or None, resposta=resposta or None)
    except AnalyzerError as e:
        flash(f"Não foi possível carregar os gráficos: {e}", "erro")
    return render_template(
        "admin/graficos.html", dados=dados, periodo=periodo, inicio=inicio, fim=fim, empresa=empresa,
        resposta=resposta, respostas=RESPOSTAS_GRAF, lista_empresas=emp.lista(),
        coletado_ate=dnslib.utc_para_local(dados["coletado_ate"]) if dados and dados.get("coletado_ate") else None,
        **_ctx_cls(cls_f, categoria))


@admin_bp.get("/listas-categoria")
@login_required
def listas_categoria():
    """Listas de bloqueio por categoria: o que está em cada uma e quais empresas a aplicam."""
    if not current_app.config.get("ANALYZER_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Analisador (ANALYZER_URL/ANALYZER_TOKEN)")
    cat = (request.args.get("cat") or "apostas").strip()
    if cat == "para_revisar":   # Para revisar = fila da fase 5, na tela Decisões
        return redirect(url_for("analise.decisoes", **{k: v for k, v in request.args.items() if k != "cat"}))
    q = (request.args.get("q") or "").strip().lower()
    resumo, det = {"categorias": [], "auto": [], "auto_24h": 0}, _DET_VAZIO
    fd = _det_filtros("recentes")
    try:
        resumo = api.get("/listas")
        det = api.get(f"/listas/{quote(cat, safe='')}/detalhes", **_det_params(fd))
    except AnalyzerError as e:
        flash(f"Falha ao carregar as listas: {e}", "erro")
    from app import empresas as emp
    from app import politicas as pol
    sugestoes, empresas_pol, default_tem = [], [], False
    try:
        por = pol.por_escopo()
        default_tem = cat in ((por.get("default") or {}).get("lists") or [])
        for e in emp.lista():
            if e.get("auto_created"):
                continue
            p = por.get(f"tenant:{e['id']}") or {}
            unid = [s.split(":", 2)[2] for s, v in por.items()
                    if s.startswith(f"unit:{e['id']}:") and cat in (v.get("lists") or [])]
            empresas_pol.append({"id": e["id"], "nome": e["name"], "tem": cat in (p.get("lists") or []), "unidades": unid})
    except AnalyzerError as e:
        flash(f"Falha ao carregar políticas/sugestões: {e}", "erro")
    empresas_pol.sort(key=lambda x: x["nome"].lower())
    try:
        servicos = api.get("/liberacao")
    except AnalyzerError:
        servicos = []
    return render_template("admin/listas_categoria.html", cat=cat, q=q, resumo=resumo, det=det, fd=fd,
                           scats=_site_cats(), pag_url=_pag_url,
                           categorias=dnslib.CATEGORIAS_LISTA, sugestoes=sugestoes, empresas_pol=empresas_pol,
                           default_tem=default_tem, servicos=servicos)


# --------------------------------------------- tabela detalhada (listas e "Classificados por IA como Trabalho")
_DET_VAZIO = {"total": 0, "total_geral": 0, "items": [], "facetas": {"cat_ia": {}, "classificacao": {}, "revisao": {}}}


def _det_filtros(ordem_padrao: str, cls_padrao: str = "") -> dict:
    a = request.args
    pp = a.get("pp", 100, type=int)
    return {"q": (a.get("q") or "").strip().lower(), "cls": a.get("cls", cls_padrao), "cat_ia": a.get("cat_ia", ""),
            "revisao": a.get("revisao", ""), "sug": a.get("sug", ""), "rec": a.get("rec", ""), "ordem": a.get("ordem") or ordem_padrao,
            "pp": pp if pp in (100, 250, 500) else 100, "pag": max(1, a.get("pag", 1, type=int))}


def _det_params(fd: dict) -> dict:
    return {"q": fd["q"] or None, "cls": fd["cls"] or None, "cat_ia": fd["cat_ia"] or None,
            "revisao": fd["revisao"] or None, "sug": fd["sug"] or None, "rec": fd["rec"] or None, "ordem": fd["ordem"], "limit": fd["pp"], "offset": (fd["pag"] - 1) * fd["pp"]}


def _pag_url(n: int) -> str:
    args = request.args.to_dict()
    args["pag"] = n
    return url_for(request.endpoint, **args)


def _site_cats() -> dict[str, str]:
    try:
        return {c["code"]: c["label"] for c in api.get("/site-categories")}
    except AnalyzerError:
        return {}


@admin_bp.post("/listas-lote-dominios")
@login_required
def listas_lote_dominios():
    """Ações em lote da tabela detalhada: mover p/ outras listas, tirar da lista, pôr em listas,
    pedir nova análise da IA."""
    d = request.get_json(silent=True) or {}
    acao, cat = d.get("acao"), d.get("cat") or ""
    doms = list(dict.fromkeys(x.strip().lower().rstrip(".") for x in d.get("dominios") or [] if x and x.strip()))
    rot = dict(dnslib.CATEGORIAS_LISTA)
    para = [c for c in d.get("para") or [] if c in rot and c != cat]
    if not doms:
        return _json(False, "Selecione pelo menos um domínio.")
    quem = admin_atual().email
    try:
        if acao == "reanalisar":
            r = api.post("/domains-reanalyze", {"domains": doms})
            return _json(True, f"{r.get('enviados', 0)} domínio(s) enviados para nova análise (regras agora; IA, busca na web e WHOIS na fila)."
                         + (f" {r['ignorados']} ficaram de fora (classificação travada à mão ou nunca acessados)." if r.get("ignorados") else ""))
        if acao == "aprovar":
            if cat not in rot:
                return _json(False, "lista inválida")
            r = api.post("/listas-aprovar", {"domains": doms, "de": cat, "by": quem})
            for alvo, ds in (r.get("movidos") or {}).items():
                for x in ds:
                    _decisao_global(x, "blocked")
            for x in r.get("tirados") or []:
                _decisao_global(x, "allowed")
            current_app.logger.info("DNS: %s aprovou sugestões da IA em %s: %s", quem, cat, r)
            partes = [f"{len(ds)} → {rot.get(a, a)}" for a, ds in (r.get("movidos") or {}).items()]
            if r.get("tirados"):
                partes.append(f"{len(r['tirados'])} fora de {rot[cat]} (nenhuma lista)")
            if r.get("sem_sugestao"):
                partes.append(f"{len(r['sem_sugestao'])} sem sugestão ainda (ficaram)")
            return _json(True, "Sugestões aprovadas: " + "; ".join(partes or ["nada a fazer"]) + ". O DNS atualiza em até 1 h.")
        if acao in ("mover", "tirar"):
            if cat not in rot:
                return _json(False, "lista inválida")
            if acao == "mover" and not para:
                return _json(False, "Marque pelo menos uma lista de destino.")
            api.post("/listas-mover", {"domains": doms, "de": cat, "para": para if acao == "mover" else [], "by": quem})
            for x in doms:
                _decisao_global(x, "blocked" if acao == "mover" else "allowed")
            current_app.logger.info("DNS: %s: %s %s de %s -> %s", quem, acao, doms, cat, para)
            if acao == "tirar":
                return _json(True, f"{len(doms)} domínio(s) fora da lista {rot[cat]} (decisão: manter liberado). O DNS atualiza em até 1 h.")
            return _json(True, f"{len(doms)} domínio(s) movidos de {rot[cat]} para {', '.join(rot[c] for c in para)}. O DNS atualiza em até 1 h.")
        if acao == "por":
            if not para:
                return _json(False, "Marque pelo menos uma lista.")
            api.post("/listas-lote", {"domains": doms, "cats": para, "by": quem})
            for x in doms:
                _decisao_global(x, "blocked")
            current_app.logger.info("DNS: %s pôs %s nas listas %s", quem, doms, para)
            return _json(True, f"{len(doms)} domínio(s) nas listas {', '.join(rot[c] for c in para)}. O DNS atualiza em até 1 h.")
        return _json(False, "ação inválida")
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


def _tirar_da_lista(cat: str, dominio: str) -> None:
    """Tira da lista e grava a decisão global 'manter liberado' (senão o bloqueio automático
    colocaria de volta no próximo ciclo)."""
    api.delete(f"/listas/{quote(cat, safe='')}/{quote(dominio, safe='')}")
    _decisao_global(dominio, "allowed")


def _decisao_global(dominio: str, status: str) -> None:
    try:
        api.post(f"/domains/{quote(dominio, safe='')}/review", {"status": status, "by": admin_atual().email})
    except AnalyzerError:
        pass   # domínio nunca visto nos logs: não há decisão a gravar


@admin_bp.post("/listas-categoria/rem")
@login_required
def listas_categoria_rem():
    cat, dom = request.form.get("cat", ""), request.form.get("dominio", "")
    try:
        _tirar_da_lista(cat, dom)
        current_app.logger.info("DNS: %s tirou %s da lista %s", admin_atual().email, dom, cat)
        flash(f"{dom} saiu da lista {cat} (decisão: manter liberado). O Technitium atualiza em até 1 h.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    voltar = request.form.get("voltar") or ""
    return redirect(voltar if next_local(voltar) else url_for("admin.listas_categoria", cat=cat))


@admin_bp.post("/listas-categoria/add")
@login_required
def listas_categoria_add():
    cat, dom = request.form.get("cat", ""), (request.form.get("dominio") or "").strip().lower().rstrip(".")
    try:
        api.post(f"/listas/{quote(cat, safe='')}", {"domain": dom, "by": admin_atual().email})
        _decisao_global(dom, "blocked")
        current_app.logger.info("DNS: %s pôs %s na lista %s", admin_atual().email, dom, cat)
        flash(f"{dom} entrou na lista {cat}. O Technitium atualiza em até 1 h.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("admin.listas_categoria", cat=cat))


# ------------------------------------------------- Grupos: ações sem recarregar (JSON)
def _json(ok: bool, msg: str, **kw):
    from flask import jsonify
    return jsonify(ok=ok, msg=msg, **kw), (200 if ok else 400)


# ------------------------------------------------- Políticas: empresa <-> listas (modais)
@admin_bp.post("/empresas/<int:tid>/politica")
@login_required
def empresa_politica(tid):
    """Modal da empresa: listas + serviços liberados da empresa inteira ou de uma unidade
    (exceção). herdar=true numa unidade = volta a valer a da empresa."""
    from app import politicas as pol
    d = request.get_json(silent=True) or {}
    unidade = (d.get("unidade") or "").strip()
    scope = f"unit:{tid}:{unidade}" if unidade else f"tenant:{tid}"
    try:
        if unidade and d.get("herdar"):
            api.delete(f"/policies/{quote(scope, safe='')}")
        else:
            api.put(f"/policies/{quote(scope, safe='')}", {"lists": d.get("lists") or [], "services": d.get("services") or [],
                                                           "services_blocked": d.get("blocked") or [], "by": admin_atual().email})
        r = pol.sincronizar()
        current_app.logger.info("DNS: %s: política %s = %s / %s", admin_atual().email, scope, d.get("lists"), d.get("services"))
        return _json(True, "Salvo e aplicado no DNS (listas valem em até 1 h; exceções na hora).", redes=r["redes"])
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


@admin_bp.post("/listas-categoria/empresas")
@login_required
def lista_empresas():
    """Modal da lista: quais empresas (e o default) aplicam esta lista."""
    from app import empresas as emp
    from app import politicas as pol
    d = request.get_json(silent=True) or {}
    cat = (d.get("cat") or "").strip()
    if cat not in dict(dnslib.CATEGORIAS_LISTA):
        return _json(False, "lista inválida")
    quer = {int(x) for x in d.get("tenants") or []}
    try:
        atual = pol.por_escopo()
        mudou = 0
        alvos = [(f"tenant:{e['id']}", e["id"] in quer) for e in emp.lista() if not e.get("auto_created")]
        alvos.append(("default", bool(d.get("default"))))
        for scope, liga in alvos:
            p = atual.get(scope) or {}
            ls = set(p.get("lists") or [])
            novo = ls | {cat} if liga else ls - {cat}
            if novo != ls and (p or liga):
                api.put(f"/policies/{quote(scope, safe='')}", {"lists": sorted(novo), "services": p.get("services") or [],
                                                               "services_blocked": p.get("services_blocked") or [],
                                                               "by": admin_atual().email})
                mudou += 1
        if mudou:
            pol.sincronizar()
        current_app.logger.info("DNS: %s: lista %s -> empresas %s (default=%s)", admin_atual().email, cat, sorted(quer), d.get("default"))
        return _json(True, f"{mudou} política(s) alterada(s) e aplicadas no DNS." if mudou else "Nada mudou.")
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


@admin_bp.post("/dominios/listas")
@login_required
def dominio_listas():
    """Em quais listas o domínio fica (Domínios / Decisões / página do domínio). Nenhuma lista =
    decisão 'manter liberado'; alguma = decisão 'bloquear' (sai da fila)."""
    d = request.get_json(silent=True) or {}
    doms = [x.strip().lower().rstrip(".") for x in (d.get("dominios") or [d.get("dominio") or ""]) if x and x.strip()]
    quer = [c for c in d.get("lists") or [] if c in dict(dnslib.CATEGORIAS_LISTA)]
    if not doms:
        return _json(False, "informe o domínio")
    try:
        todas = [c for c, _ in dnslib.CATEGORIAS_LISTA]
        fora = [c for c in todas if c not in quer]
        if d.get("so_adicionar"):
            fora = []
        if fora:
            api.post("/listas-remover", {"domains": doms, "cats": fora})
        if quer:
            api.post("/listas-lote", {"domains": doms, "cats": quer, "by": admin_atual().email})
        for x in doms:
            _decisao_global(x, "blocked" if quer else "allowed")
        rot = dict(dnslib.CATEGORIAS_LISTA)
        current_app.logger.info("DNS: %s: %s -> listas %s", admin_atual().email, doms, quer)
        alvo = doms[0] if len(doms) == 1 else f"{len(doms)} domínios"
        return _json(True, f"{alvo}: " + (", ".join(rot[c] for c in quer) if quer else "fora de todas as listas (manter liberado)")
                     + ". O DNS atualiza em até 1 h.")
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


# ------------------------------------------------- Listas de liberação avulsas + serviços (sublistas)
def _servico_ctx(slug: str) -> dict:
    """Dados de um serviço/lista de liberação: domínios e quem bloqueia/libera."""
    from app import empresas as emp
    from app import politicas as pol
    todas = api.get("/liberacao")
    s = next((x for x in todas if x["slug"] == slug), None)
    if not s:
        return {"servico": None, "todas": todas}
    doms = api.get(f"/liberacao/{quote(slug, safe='')}", limit=20000)
    por = pol.por_escopo()
    nomes = {f"tenant:{e['id']}": e["name"] for e in emp.lista() if not e.get("auto_created")}
    nomes["default"] = "Redes sem cadastro (padrão)"
    libera = sorted(nomes.get(k, k) for k, v in por.items() if slug in (v.get("services") or []) and not k.startswith("unit:"))
    bloqueia = sorted(nomes.get(k, k) for k, v in por.items() if slug in (v.get("services_blocked") or []) and not k.startswith("unit:"))
    empresas_pol = sorted(({"id": e["id"], "nome": e["name"], "tem": slug in ((por.get(f"tenant:{e['id']}") or {}).get("services") or [])}
                           for e in emp.lista() if not e.get("auto_created")), key=lambda x: x["nome"].lower())
    return {"servico": s, "todas": todas, "doms": doms, "libera": libera, "bloqueia": bloqueia,
            "empresas_pol": empresas_pol, "default_tem": slug in ((por.get("default") or {}).get("services") or [])}


@admin_bp.get("/listas-liberacao")
@login_required
def listas_liberacao():
    """Listas de liberação avulsas (whitelist): vencem qualquer lista de bloqueio."""
    ctx = {"servico": None, "todas": []}
    slug = request.args.get("slug") or ""
    try:
        todas = api.get("/liberacao")
        avulsas = [x for x in todas if not x.get("category")]
        if slug == "_trabalho":   # só consulta: não é lista, não vai p/ o Technitium
            fd = _det_filtros("consultas", "TRABALHO")
            ctx = {"servico": None, "todas": todas, "trabalho": True, "fd": fd, "det": api.get("/sem-lista", **_det_params(fd)),
                   "scats": _site_cats(), "pag_url": _pag_url}
        else:
            slug = slug or (avulsas[0]["slug"] if avulsas else "")
            ctx = _servico_ctx(slug) if slug else {"servico": None, "todas": todas}
    except AnalyzerError as e:
        flash(f"Falha ao carregar as listas de liberação: {e}", "erro")
    return render_template("admin/servico.html", modo="liberacao", categorias=dnslib.CATEGORIAS_LISTA, **ctx)


@admin_bp.get("/servicos/<slug>")
@login_required
def servico(slug):
    try:
        ctx = _servico_ctx(slug)
    except AnalyzerError as e:
        flash(f"Falha ao carregar o serviço: {e}", "erro")
        ctx = {"servico": None, "todas": []}
    return render_template("admin/servico.html", modo="servico", categorias=dnslib.CATEGORIAS_LISTA, **ctx)


def _volta_servico(slug: str):
    v = request.form.get("voltar") or ""
    return redirect(v if next_local(v) else url_for("admin.servico", slug=slug))


@admin_bp.post("/servicos/criar")
@login_required
def servico_criar():
    nome, cat = (request.form.get("nome") or "").strip(), (request.form.get("categoria") or "").strip() or None
    try:
        r = api.post("/liberacao", {"name": nome, "category": cat, "by": admin_atual().email})
        flash(f"{nome} criado." + ("" if cat else " Vincule às empresas no botão Empresas…"), "ok")
        return redirect(url_for("admin.servico", slug=r["slug"]) if cat else url_for("admin.listas_liberacao", slug=r["slug"]))
    except AnalyzerError as e:
        flash(f"Falha ao criar: {e}", "erro")
        return redirect(request.referrer or url_for("admin.listas_liberacao"))


@admin_bp.post("/servicos/<slug>/editar")
@login_required
def servico_editar(slug):
    try:
        api.put(f"/liberacao/{quote(slug, safe='')}", {"name": request.form.get("nome") or slug,
                                                       "category": (request.form.get("categoria") or None)})
        from app import politicas as pol
        pol.sincronizar()
        flash("Salvo.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha: {e}", "erro")
    return _volta_servico(slug)


@admin_bp.post("/servicos/<slug>/apagar")
@login_required
def servico_apagar(slug):
    try:
        api.delete(f"/liberacao/{quote(slug, safe='')}")
        from app import politicas as pol
        pol.sincronizar()
        flash(f"{slug} apagado (e retirado das empresas que o usavam).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("admin.listas_liberacao"))


@admin_bp.post("/servicos/<slug>/dominios")
@login_required
def servico_dominios(slug):
    acao, dom = request.form.get("acao"), (request.form.get("dominio") or "").strip().lower().rstrip(".")
    try:
        if acao == "rem":
            api.delete(f"/liberacao/{quote(slug, safe='')}/dominios/{quote(dom, safe='')}")
            flash(f"{dom} saiu.", "ok")
        else:
            doms = [x.strip() for x in (request.form.get("dominio") or "").replace(",", "\n").splitlines() if x.strip()]
            r = api.post(f"/liberacao/{quote(slug, safe='')}/dominios", {"domains": doms, "by": admin_atual().email})
            flash(f"{r.get('dominios', 0)} domínio(s) adicionado(s). Vale no DNS em até 1 h.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return _volta_servico(slug)


@admin_bp.post("/listas-liberacao/empresas")
@login_required
def liberacao_empresas():
    """Modal: quais empresas (e o padrão) liberam esta lista/serviço."""
    from app import empresas as emp
    from app import politicas as pol
    d = request.get_json(silent=True) or {}
    slug = (d.get("slug") or "").strip()
    quer = {int(x) for x in d.get("tenants") or []}
    try:
        atual = pol.por_escopo()
        mudou = 0
        alvos = [(f"tenant:{e['id']}", e["id"] in quer) for e in emp.lista() if not e.get("auto_created")]
        alvos.append(("default", bool(d.get("default"))))
        for scope, liga in alvos:
            p = atual.get(scope) or {}
            sv = set(p.get("services") or [])
            novo = sv | {slug} if liga else sv - {slug}
            if novo != sv and (p or liga):
                api.put(f"/policies/{quote(scope, safe='')}", {"lists": p.get("lists") or [], "services": sorted(novo),
                                                               "services_blocked": p.get("services_blocked") or [],
                                                               "by": admin_atual().email})
                mudou += 1
        if mudou:
            pol.sincronizar()
        return _json(True, f"{mudou} política(s) alterada(s) e aplicadas no DNS." if mudou else "Nada mudou.")
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")
