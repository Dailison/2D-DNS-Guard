"""Telas de DNS do console: Domínios bloqueados (listas por categoria), Domínios liberados (whitelists por categoria,
listas de liberação/serviços, exceções por empresa e Sites revisados), políticas por empresa (sincronizadas no
Technitium), IPs liberados (isentos), Logs DNS e Gráficos."""

import re
from urllib.parse import quote

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from app import analyzer_client as api
from app import technitium as dnslib
from app.analyzer_client import AnalyzerError
from app.auth import admin_atual, login_required, next_local, super_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/")
@login_required
def dashboard():
    if current_app.config.get("ANALYZER_ENABLED"):
        return redirect(url_for("analise.painel"))
    return redirect(url_for("admin.liberados"))


# ------------------------------------------------- Liberados DNS (Technitium)
TIPOS_LIBERADO = ["Computador", "Celular", "Roteador", "Faixa de IP"]
LISTAS_LIBERADO_PADRAO = ["noticias", "compras", "redes_sociais"]   # já marcadas ao liberar um IP (pedido do usuário 07/10)


@admin_bp.get("/liberados")
@login_required
def liberados():
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")
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
        # isentos de tudo = quem está no grupo de isenção do Technitium; liberados só de algumas listas = quem o
        # analisador diz (o Technitium os tem num grupo "… · sem <listas>")
        parciais = [ip for ip, m in metas.items() if m.get("listas")]
        for ip in sorted(set(ips) | set(parciais), key=dnslib._sort_key):
            m = metas.get(ip) or {}
            rows.append({k: m.get(k) or "" for k in ("tenant_name", "filial", "empresa", "departamento", "usuario", "tipo",
                                                      "autorizado_por", "created_by", "created_at", "updated_by", "updated_at")}
                        | {"ip": ip, "tenant_id": m.get("tenant_id"), "listas": m.get("listas") or None})
        if f_emp:
            rows = [r for r in rows if r["tenant_id"] == f_emp]
        if q:
            rows = [r for r in rows if any(q in (r[k] or "").lower() for k in
                                           ("ip", "tenant_name", "filial", "empresa", "departamento", "usuario",
                                            "autorizado_por", "created_by"))]
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar o Technitium: {e}", "erro")
    try:   # histórico: quem do console liberou/editou/revogou e quem da empresa autorizou
        historico = api.get("/console/liberados-log", limit=50)
    except AnalyzerError:
        historico = []
    return render_template("admin/liberados.html", rows=rows, q=q, f_emp=f_emp, empresas=_empresas_liberado(),
                           historico=historico, secoes_lista=dnslib.SECOES_LISTA, nomes_lista=dict(dnslib.CATEGORIAS_LISTA),
                           listas_novo=LISTAS_LIBERADO_PADRAO,
                           tipos=TIPOS_LIBERADO, grupo=current_app.config.get("TECHNITIUM_LIBERADOS_GROUP"))


def _empresas_liberado() -> list[dict]:
    """Empresas (com filiais e redes) p/ os campos de um IP liberado: selects e sugestão pelo IP digitado."""
    from app import empresas as emp
    return sorted(({"id": e["id"], "name": e["name"],
                    "filiais": sorted({n["unit"] for n in e.get("networks", []) if n.get("unit")}),
                    "redes": [{"cidr": n["cidr"], "unit": n.get("unit") or ""} for n in e.get("networks", [])]}
                   for e in emp.lista()), key=lambda e: e["name"].lower())


def _liberado_meta_upsert(ip, acao, listas=None, definir_listas=False):
    """Grava empresa (cadastro) + filial, a descrição e quem da empresa autorizou (do form) para o IP normalizado;
    o analisador registra no histórico o usuário logado. `definir_listas`: grava também de quais listas de bloqueio
    o IP fica livre (None = todas)."""
    tid = request.form.get("tenant_id", type=int)
    api.put("/console/liberados-meta", {"ip": ip, "by": admin_atual().email, "tenant_id": tid, "acao": acao,
                                        "listas": listas, "definir_listas": definir_listas,
                                        **{k: request.form.get(k) or "" for k in
                                           ("filial", "empresa", "departamento", "usuario", "tipo", "autorizado_por")}})


def _listas_do_form():
    """De quais listas de bloqueio o IP fica livre: None = todas ("Tudo": isento do filtro); senão as marcadas."""
    if request.form.get("tudo"):
        return None
    validas = dict(dnslib.CATEGORIAS_LISTA)
    return sorted({x for x in request.form.getlist("listas") if x in validas})


def _aplica_liberacao(ip, listas, acao) -> str:
    """Grava a escolha e deixa o Technitium igual: todas as listas = grupo de isenção (não bloqueia nada); algumas =
    grupo com a política da rede do IP menos elas (montado pela sincronização das políticas)."""
    from app import politicas as pol
    por = admin_atual().email
    if listas is None:
        if ip not in dnslib.listar():
            dnslib.liberar(ip, por=por)
        _liberado_meta_upsert(ip, acao, None, True)
        return "liberado de todas as listas"
    _liberado_meta_upsert(ip, acao, listas, True)
    pol.sincronizar()
    nomes = dict(dnslib.CATEGORIAS_LISTA)
    return "liberado de " + ", ".join(nomes.get(x, x) for x in listas)


@admin_bp.post("/liberados/liberar")
@login_required
def liberados_liberar():
    if not (request.form.get("autorizado_por") or "").strip():
        flash("Informe quem da empresa autorizou a liberação.", "erro")
        return redirect(url_for("admin.liberados"))
    ip, listas = dnslib.norm_ip(request.form.get("ip")), _listas_do_form()
    if not ip:
        flash("IP ou CIDR inválido (ex.: 10.100.10.20 ou 10.100.10.0/24).", "erro")
    elif listas is not None and not listas:
        flash("Escolha ao menos uma lista para liberar (ou Tudo).", "erro")
    else:
        try:
            flash(f"{ip} {_aplica_liberacao(ip, listas, 'liberar')}.", "ok")
        except Exception as e:  # noqa: BLE001
            flash(f"Falha ao liberar: {e}", "erro")
    return redirect(url_for("admin.liberados"))


@admin_bp.post("/liberados/editar")
@login_required
def liberados_editar():
    ip, listas = dnslib.norm_ip(request.form.get("ip")), _listas_do_form()
    try:
        if not ip:
            flash("IP inválido.", "erro")
        elif listas is not None and not listas:
            flash("Escolha ao menos uma lista para liberar (ou Tudo).", "erro")
        else:
            antes = next((m.get("listas") or None for m in api.get("/console/liberados-meta") if m["ip"] == ip), None)
            if listas == antes and (listas is not None or ip in dnslib.listar()):
                _liberado_meta_upsert(ip, "editar")   # só a descrição mudou: o Technitium fica como está
                flash(f"{ip} atualizado.", "ok")
            else:
                flash(f"{ip} atualizado: {_aplica_liberacao(ip, listas, 'editar')}.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao salvar: {e}", "erro")
    return redirect(url_for("admin.liberados"))


@admin_bp.post("/liberados/revogar")
@login_required
def liberados_revogar():
    from app import politicas as pol
    try:
        ip = dnslib.norm_ip(request.form.get("ip"))
        if ip:
            isento = dnslib.revogar(ip, por=admin_atual().email)   # (só quem está no grupo de isenção)
            api.delete(f"/console/liberados-meta?ip={quote(ip, safe='')}&by={quote(admin_atual().email, safe='@')}")
            if not isento:   # liberado só de algumas listas: a sincronização devolve o IP ao grupo da rede dele
                pol.sincronizar()
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
@super_required
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
            flash(f"{alvo}: fora de {rem} lista(s) de bloqueio (vale no DNS em até 2 min).", "ok")
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


def _ip_exato_ou_faixa(ip: str, cidr: str) -> tuple[str, str]:
    """"IP exato" só vale com um IP completo. Pedaço de IP ou faixa digitado ali (07/10: "10.24." ia como IP exato e
    o analisador respondia 500) passa a valer como "Faixa / parte do IP"; se esse campo também veio, é ignorado com aviso."""
    import ipaddress
    ip = (ip or "").strip()
    if not ip:
        return ip, cidr
    try:
        return str(ipaddress.ip_address(ip)), cidr
    except ValueError:
        pass
    if cidr:
        flash(f"\"{ip}\" não é um IP completo: ignorado (vale a faixa {cidr}).", "erro")
        return "", cidr
    return "", ip


def _logs_agrupados_analisador(inicio, fim, empresa, grupo, cidr, ip, dominio, resposta, redes, ip_like,
                               mapa, grupos, lista_empresas, cls_f="", categoria="", vista="agrupado", locais=False):
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
                    por_cliente="true" if vista == "cliente" else None, limit=LOGS_LIMITE,
                    sem_locais=None if locais else "true", excluir=None if locais else dnslib.zonas_locais())
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
        fonte_analisador=True, total_acessos=total, locais=locais,
        coletado_ate=dnslib.utc_para_local(coletado) if coletado else None, **_ctx_cls(cls_f, categoria))


def _logs_detalhe_analisador(inicio, fim, empresa, grupo, cidr, ip, dominio, resposta, redes, ip_like,
                             mapa, grupos, lista_empresas, cls_f="", categoria="", locais=False):
    """Vista Detalhado pelo analisador (07/10): cada consulta está em query_log (cópia dos logs do Technitium feita
    pelo coletor a cada minuto, 7 dias) — filtro por empresa, IP, domínio e classificação no banco, em menos de 1 s.
    O Technitium (tempo real, lento) fica no link "ao vivo" (?fonte=technitium)."""
    from app import empresas as emp

    def utc(v):
        iso = dnslib.local_para_utc_iso(v)
        return iso + "+00:00" if iso and len(iso) == 19 else iso
    linhas, cap, coletado, mais_antigos, desde = [], False, None, None, None
    hoje = dnslib.agora_local().date()
    inicio, fim = inicio or f"{hoje}T00:00", fim or f"{hoje}T23:59"
    try:
        d = api.get("/logs/detalhe", start=utc(inicio), end=utc(fim),
                    tid=int(empresa) if empresa else 0, ip=ip or None, ip_like=ip_like,
                    cidr=[str(n) for n in redes] if (redes is not None and not empresa) else None,
                    dominio=dominio or None, resposta=resposta or None,
                    cls=_cls_lista(cls_f) or None, categoria=categoria or None, limit=LOGS_LIMITE,
                    sem_locais=None if locais else "true", excluir=None if locais else dnslib.zonas_locais())
        cap, coletado, mais_antigos, desde = d.get("cap"), d.get("coletado_ate"), d.get("mais_antigos"), d.get("disponivel_desde")
        info = emp.resolver(r["ip"] for r in d["rows"])
        union = None
        if any(r.get("resposta") == "Blocked" for r in d["rows"]):
            union, _ = dnslib.blocked_index()
        for r in d["rows"]:
            l = {"timestamp": dnslib.utc_para_local(r["ts"]), "ip": r["ip"], "dominio": r["dominio"], "tipo": r.get("tipo"),
                 "resposta": r.get("resposta"), "rcode": r.get("rcode"), "answer": r.get("answer"),
                 "grupo": dnslib.resolver_empresa(r["ip"], mapa) or "—", "empresa": emp.rotulo(info.get(r["ip"])) or "—",
                 "cls": r.get("classificacao"), "ajustada": r.get("ajustada"), "categoria": r.get("categoria")}
            if l["resposta"] == "Blocked" and union is not None:
                l["culpados"] = dnslib.culpados(l["dominio"], l["answer"], union)
            linhas.append(l)
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar os logs no analisador: {e}", "erro")
    args = request.args.to_dict()
    local = lambda ts, n=16: (dnslib.utc_para_local(ts) or "")[:n].replace(" ", "T") if ts else None   # noqa: E731
    guardado = local(desde)
    antigos = None
    if mais_antigos:   # ao segundo, +1 s: repetir um registro da borda é melhor que pular
        from datetime import timedelta
        dt = dnslib._parse_utc(mais_antigos)
        antigos = local((dt + timedelta(seconds=1)).isoformat(), 19) if dt else None
    return render_template(
        "admin/logs_dns.html", linhas=linhas, agrupado=[], agrupar=False, vista="detalhado", locais=locais,
        grupos=grupos, grupo=grupo, lista_empresas=lista_empresas, empresa=empresa,
        cidr=cidr, ip=ip, dominio=dominio, resposta=resposta, respostas=dnslib.RESPONSE_TYPES,
        inicio=inicio, fim=fim, scanned=None, cap=cap, voltar=request.full_path,
        fonte_detalhe=True, coletado_ate=dnslib.utc_para_local(coletado) if coletado else None,
        coberto_desde=antigos, url_antigos=url_for("admin.logs_dns", **{**args, "inicio": inicio, "fim": antigos}) if antigos else None,
        # período pedido começa antes do que está guardado: o que falta só existe no Technitium
        guardado_desde=guardado if guardado and guardado > inicio[:16] else None,
        url_aovivo=url_for("admin.logs_dns", **{**args, "vista": "detalhado", "fonte": "technitium"}),
        **_ctx_cls(cls_f, categoria))


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
    locais = bool(request.args.get("locais"))   # mostrar nomes locais (zonas .local, reversos, sem ponto)? padrão: não
    if not request.args:  # primeira carga (sem filtros): dia atual, início ao fim (São Paulo)
        hoje = dnslib.agora_local().date()
        inicio = f"{hoje}T00:00"
        fim = f"{hoje}T23:59"

    ip, cidr = _ip_exato_ou_faixa(ip, cidr)
    linhas, agrupado, grupos, scanned, cap, coberto_desde = [], [], [], 0, False, None
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
                lista_empresas, cls_f, categoria, vista, locais)
        # Máx. 1000 logs por busca: cada página do Technitium custa segundos (SQLite com
        # milhões de linhas). Sem filtro feito aqui = 1 chamada; com filtro de domínio/
        # empresa/faixa (a API não faz) varre até 5000 p/ achar os 1000 resultados.
        filtro_local = bool(dominio or redes is not None or ip_like)
        if current_app.config.get("ANALYZER_ENABLED") and vista == "detalhado" and request.args.get("fonte") != "technitium":
            return _logs_detalhe_analisador(
                inicio, fim, empresa, grupo, cidr, ip, dominio, resposta, redes, ip_like, mapa, grupos,
                lista_empresas, cls_f, categoria, locais)
        # (07/10) a busca anda p/ trás em janelas curtas (o custo no Technitium é a contagem do período pedido: o
        # dia inteiro levava 28 s por chamada e a tela dava timeout). Com filtro feito aqui (a API não filtra por
        # empresa/faixa/parte do domínio) varre até 60 mil registros dentro do tempo; sem filtro, só os 1000.
        lim, smax = LOGS_LIMITE, (LOGS_LIMITE * 60 if filtro_local else LOGS_LIMITE)
        linhas, scanned, cap, coberto_desde = dnslib.consultar_logs(
            mapa, redes=redes, ip_like=ip_like,
            inicio=dnslib.local_para_utc_iso(inicio), fim=dnslib.local_para_utc_iso(fim),
            dominio=dominio or None, ip_exato=ip or None,
            resposta=resposta or None, limite=lim, scan_max=smax, por_pagina=5000 if filtro_local else lim,
            sem_locais=not locais)
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
        "admin/logs_dns.html", linhas=linhas, agrupado=agrupado, agrupar=agrupar, vista=vista, locais=locais,
        grupos=grupos, grupo=grupo, lista_empresas=lista_empresas, empresa=empresa,
        cidr=cidr, ip=ip, dominio=dominio, resposta=resposta,
        respostas=dnslib.RESPONSE_TYPES,
        inicio=inicio, fim=fim, scanned=scanned, cap=cap, voltar=request.full_path, coberto_desde=coberto_desde,
        url_antigos=(url_for("admin.logs_dns", **{**request.args.to_dict(), "inicio": inicio, "fim": coberto_desde})
                     if coberto_desde else None),
        url_analisador=(url_for("admin.logs_dns", **{k: v for k, v in request.args.to_dict().items() if k != "fonte"})
                        if request.args.get("fonte") == "technitium" else None), **_ctx_cls(cls_f, categoria))


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
    # filiais da empresa escolhida (unidade das redes cadastradas); filial de outra empresa é ignorada
    unidades = sorted({(n.get("unit") or "").strip() for e in emp.lista() if str(e.get("id")) == empresa
                       for n in (e.get("networks") or []) if (n.get("unit") or "").strip()}, key=str.lower)
    unidade = (request.args.get("unidade") or "").strip()
    unidade = unidade if unidade in unidades else ""
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
                        cls=_cls_lista(cls_f) or None, categoria=categoria or None, resposta=resposta or None,
                        unidade=unidade or None)
    except AnalyzerError as e:
        flash(f"Não foi possível carregar os gráficos: {e}", "erro")
    return render_template(
        "admin/graficos.html", dados=dados, periodo=periodo, inicio=inicio, fim=fim, empresa=empresa,
        unidade=unidade, unidades=unidades,
        resposta=resposta, respostas=RESPOSTAS_GRAF, lista_empresas=emp.lista(),
        coletado_ate=dnslib.utc_para_local(dados["coletado_ate"]) if dados and dados.get("coletado_ate") else None,
        **_ctx_cls(cls_f, categoria))


@admin_bp.get("/listas-categoria")
@login_required
def listas_categoria_antiga():
    return redirect(url_for("admin.listas_categoria", **request.args), 301)


def _escopo_ajuste():
    """Escopo escolhido em Domínios bloqueados (?empresa=<id>&unidade=<nome>) e os ajustes dele (01/10: listas por
    empresa/unidade). -> dict p/ o template: empresas (com as unidades), escopo, nome, ajustes."""
    from app import empresas as emp
    try:
        empresas = sorted(({"id": e["id"], "nome": e["name"],
                            "unidades": sorted({(n.get("unit") or "").strip() for n in e.get("networks") or []} - {""})}
                           for e in emp.lista() if not e.get("auto_created")), key=lambda x: x["nome"].lower())
    except AnalyzerError:
        empresas = []
    tid = request.args.get("empresa", type=int)
    e = next((x for x in empresas if x["id"] == tid), None)
    unidade = (request.args.get("unidade") or "").strip()
    unidade = unidade if e and unidade in e["unidades"] else ""
    out = {"aj_empresas": empresas, "aj_tid": e["id"] if e else None, "aj_unidade": unidade, "aj_escopo": "",
           "aj_nome": "", "aj": {"proprios": [], "herdados": [], "efetivo": {"liberar": [], "bloquear": []}}, "aj_origem": {}}
    if not e:
        return out
    out["aj_escopo"] = f"unit:{e['id']}:{unidade}" if unidade else f"tenant:{e['id']}"
    out["aj_nome"] = e["nome"] + (f" · {unidade}" if unidade else "")
    try:
        out["aj"] = api.get("/ajustes", scope=out["aj_escopo"])
    except AnalyzerError as err:
        flash(f"Falha ao carregar os ajustes: {err}", "erro")
        return out
    # de onde vem o que vale aqui: o da unidade vence o da empresa
    origem = {x["domain"]: (x["acao"], "empresa") for x in out["aj"].get("herdados") or []}
    origem.update({x["domain"]: (x["acao"], "aqui") for x in out["aj"].get("proprios") or []})
    out["aj_origem"] = origem
    return out


@admin_bp.post("/dominios-bloqueados/ajuste")
@login_required
@super_required
def listas_ajuste():
    """Ajuste das listas só para uma empresa ou unidade: liberar aqui, bloquear aqui ou desfazer. Aplica no Technitium
    (a unidade com ajuste ganha grupo próprio); vale em até 2 min."""
    from app import politicas as pol
    j = request.get_json(silent=True)
    d = j if j is not None else {"escopo": request.form.get("escopo"), "acao": request.form.get("acao"),
                                 "nome": request.form.get("nome"), "dominios": request.form.getlist("dominios")}
    escopo, acao = d.get("escopo") or "", d.get("acao") or ""
    nome = d.get("nome") or escopo
    doms = [x for v in (d.get("dominios") or []) for x in str(v).replace(",", " ").split()]
    doms = list(dict.fromkeys(x.strip().lower().rstrip(".") for x in doms if x.strip()))

    def volta(ok, msg):
        if j is not None:
            return _json(ok, msg)
        flash(msg, "ok" if ok else "erro")
        return redirect(request.referrer or url_for("admin.listas_categoria"))
    if not doms:
        return volta(False, "Informe pelo menos um domínio.")
    if acao not in ("liberar", "bloquear", "desfazer"):
        return volta(False, "Ação inválida.")
    quem = admin_atual().email
    try:
        if acao == "desfazer":
            n = api.post("/ajustes/desfazer", {"scope": escopo, "domains": doms, "by": quem}).get("desfeitos", 0)
            msg = f"{n} ajuste(s) desfeito(s) em {nome}: volta a valer a lista." if n else f"Nenhum ajuste próprio de {nome} para desfazer."
        else:
            n = api.put("/ajustes", {"scope": escopo, "domains": doms, "acao": acao, "by": quem}).get("gravados", 0)
            msg = (f"{n} domínio(s) liberado(s) só em {nome}." if acao == "liberar" else f"{n} domínio(s) bloqueado(s) só em {nome}.")
        pol.sincronizar()
        current_app.logger.info("DNS: %s ajuste %s em %s: %s", quem, acao, escopo, ", ".join(doms[:20]))
        return volta(True, msg + " O DNS atualiza em até 2 min.")
    except Exception as e:  # noqa: BLE001
        return volta(False, f"Falha no ajuste: {e}")


@admin_bp.get("/dominios-bloqueados")
@login_required
def listas_categoria():
    """Listas de bloqueio por categoria: o que está em cada uma e quais empresas a aplicam."""
    if not current_app.config.get("ANALYZER_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Analisador (ANALYZER_URL/ANALYZER_TOKEN)")
    cat = (request.args.get("cat") or "apostas").strip()
    if cat == "para_revisar":   # Para revisar era a fila da fase 5 (removida em 27/09: a IA decide tudo na fase 4)
        return redirect(url_for("admin.listas_categoria"))
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
    empresas_pol, default_tem = [], False
    try:
        por = pol.por_escopo()
        default_tem = cat in ((por.get("default") or {}).get("lists") or [])
        for e in emp.lista():
            if e.get("auto_created"):
                continue
            p = por.get(f"tenant:{e['id']}") or {}
            tem = cat in (p.get("lists") or [])
            # filiais (unidades das redes): a que tem política própria vale a dela; as outras seguem a empresa
            unid = []
            for u in sorted({(n.get("unit") or "").strip() for n in e.get("networks") or []} - {""}, key=str.lower):
                pu = por.get(f"unit:{e['id']}:{u}")
                unid.append({"nome": u, "tem": cat in (pu.get("lists") or []) if pu else tem, "propria": bool(pu)})
            empresas_pol.append({"id": e["id"], "nome": e["name"], "tem": tem, "unidades": unid if len(unid) > 1 else []})
    except AnalyzerError as e:
        flash(f"Falha ao carregar políticas/sugestões: {e}", "erro")
    empresas_pol.sort(key=lambda x: x["nome"].lower())
    try:
        servicos = api.get("/liberacao")
    except AnalyzerError:
        servicos = []
    busca = (request.args.get("busca") or "").strip().lower().rstrip(".")
    achados, cadeia = None, []
    if len(busca) >= 3:   # procura em TODAS as listas de bloqueio (não só na aberta)
        try:
            achados, cadeia = _busca_listas(busca)
        except AnalyzerError as e:
            flash(f"Falha na busca: {e}", "erro")
            achados = []
    aj = _escopo_ajuste()
    if request.headers.get("X-Partial"):   # filtros/paginação/ações via Ajax: só a tabela
        return render_template("admin/_dominios_detalhe.html", so_tabela=True, modo="lista", cat=cat, det=det, fd=fd,
                               categorias=dnslib.CATEGORIAS_LISTA, scats=_site_cats(), pag_url=_pag_url, **aj)
    pulso = next((x.get("pulso") for x in resumo.get("categorias", []) if x["categoria"] == cat), None)
    return render_template("admin/listas_categoria.html", cat=cat, q=q, resumo=resumo, det=det, fd=fd, pulso=pulso,
                           total_bloqueados=_total_bloqueados(resumo),
                           scats=_site_cats(), pag_url=_pag_url,
                           categorias=dnslib.CATEGORIAS_LISTA, empresas_pol=empresas_pol,
                           default_tem=default_tem, servicos=servicos, busca=busca, achados=achados, cadeia=cadeia, **aj)


_NOME_COMPLETO = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")


def _na_whitelist(nome: str, wl: set[str]) -> str | None:
    """Entrada da whitelist publicada (o próprio nome ou um domínio-pai) que libera `nome`."""
    p = nome.split(".")
    return next((c for c in (".".join(p[i:]) for i in range(len(p) - 1)) if c in wl), None)


def _busca_listas(busca: str) -> tuple[list[dict], list[str]]:
    """Busca em todas as listas de bloqueio -> (achados, cadeia de CNAME do nome buscado).
    Um nome completo também é procurado pela cadeia de CNAME (06/10: estacio.saladeavaliacoes.com.br era bloqueado
    pelo destino dele, d102xe4mjihvqq.cloudfront.net, na lista Adulto, e a busca pelo nome não achava nada): a entrada
    que bloqueia um elo da cadeia vem primeiro, com `via` = o elo. `wl` = whitelist publicada que vence aquele
    bloqueio (a do nome buscado, para o que veio por CNAME, ou a da própria entrada)."""
    achados = api.get("/listas-busca", q=busca)
    cadeia = []
    if _NOME_COMPLETO.match(busca) and current_app.config.get("TECHNITIUM_ENABLED"):
        cadeia = [x for x in dnslib.cadeia_cname(busca) if x != busca]
    vistos = {a["domain"] for a in achados}
    por_cname = []
    for elo in cadeia:
        for a in api.get("/listas-busca", q=elo):
            if (a["domain"] == elo or elo.endswith("." + a["domain"])) and a["domain"] not in vistos:
                vistos.add(a["domain"])
                por_cname.append({**a, "via": elo, "pai": a["domain"] != elo})
    achados = por_cname + achados
    if achados:
        wl = dnslib.dominios_whitelist()
        do_nome = _na_whitelist(busca, wl) if cadeia else None
        for a in achados:
            a["wl"] = (do_nome if a.get("via") else None) or _na_whitelist(a["domain"], wl)
    return achados, cadeia


def _total_bloqueados(resumo: dict) -> int:
    """Domínios distintos nas listas de bloqueio da página (um domínio em mais de uma lista conta uma vez), como o
    contador das whitelists em Domínios liberados. Sem a relação dos domínios (analisador fora), soma as listas."""
    cats = [c for c, _ in dnslib.CATEGORIAS_LISTA]
    soma = sum(x.get("total") or 0 for x in resumo.get("categorias", []) if x.get("categoria") in cats)
    distintos = len(set().union(*dnslib.dominios_das_listas(cats).values())) if cats else 0
    return distintos or soma


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
@super_required
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
            r = api.post("/domains-reanalyze", {"domains": doms, "by": quem, "de": cat})
            nome_de = dict(dnslib.CATEGORIAS_LISTA).get(cat) or dict(dnslib.CATEGORIAS_WHITELIST).get(cat[3:] if cat.startswith("wl:") else "")
            return _json(True, f"{r.get('enviados', 0)} domínio(s) enviados para nova análise (voltam à fase 1)"
                         + (f" e fora da lista {nome_de}." if nome_de else ".")
                         + (f" {r['ignorados']} ficaram de fora (classificação travada à mão ou nunca acessados)." if r.get("ignorados") else ""))
        if acao == "tirar_wl":
            api.post("/whitelist-remover", {"domains": doms, "by": quem})
            current_app.logger.info("DNS: %s tirou %s da whitelist", quem, doms)
            return _json(True, f"{len(doms)} domínio(s) fora da whitelist (voltam a valer as listas de bloqueio; o DNS atualiza em até 2 min).")
        if acao == "aprovar":
            if cat not in rot:
                return _json(False, "lista inválida")
            antes = _antes(doms)
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
            movidos = [x for ds in (r.get("movidos") or {}).values() for x in ds]
            if movidos:
                _fim_excecao(movidos)
            fim = _libera_agora(r.get("tirados") or [], antes) if r.get("tirados") else " O DNS atualiza em até 2 min."
            return _json(True, "Sugestões aprovadas: " + "; ".join(partes or ["nada a fazer"]) + "." + fim)
        if acao in ("mover", "tirar"):
            if cat not in rot:
                return _json(False, "lista inválida")
            if acao == "mover" and not para:
                return _json(False, "Marque pelo menos uma lista de destino.")
            antes = _antes(doms) if acao == "tirar" else {}
            api.post("/listas-mover", {"domains": doms, "de": cat, "para": para if acao == "mover" else [], "by": quem})
            for x in doms:
                _decisao_global(x, "blocked" if acao == "mover" else "allowed")
            current_app.logger.info("DNS: %s: %s %s de %s -> %s", quem, acao, doms, cat, para)
            if acao == "tirar":
                return _json(True, f"{len(doms)} domínio(s) fora da lista {rot[cat]} (decisão: manter liberado)." + _libera_agora(doms, antes))
            _fim_excecao(doms)
            return _json(True, f"{len(doms)} domínio(s) movidos de {rot[cat]} para {', '.join(rot[c] for c in para)}. O DNS atualiza em até 2 min.")
        if acao == "wl":
            wl = (d.get("para") or [None])[0]
            rot_wl = dict(dnslib.CATEGORIAS_WHITELIST)
            if wl not in rot_wl:
                return _json(False, "Escolha a whitelist.")
            antes = _antes(doms)
            api.post(f"/whitelist/{quote(wl, safe='')}", {"domains": doms, "by": quem})
            current_app.logger.info("DNS: %s liberou %s na whitelist %s", quem, doms, wl)
            return _json(True, f"{len(doms)} domínio(s) na whitelist {rot_wl[wl]}." + _libera_agora(doms, antes))
        if acao == "por":
            if not para:
                return _json(False, "Marque pelo menos uma lista.")
            api.post("/listas-lote", {"domains": doms, "cats": para, "by": quem})
            _fim_excecao(doms)
            for x in doms:
                _decisao_global(x, "blocked")
            current_app.logger.info("DNS: %s pôs %s nas listas %s", quem, doms, para)
            return _json(True, f"{len(doms)} domínio(s) nas listas {', '.join(rot[c] for c in para)}. O DNS atualiza em até 2 min.")
        return _json(False, "ação inválida")
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


def _antes(doms) -> dict:
    """Grupos em que os domínios estão bloqueados ANTES de tirá-los das listas (p/ a exceção imediata)."""
    try:
        return dnslib.grupos_bloqueando(doms)
    except Exception as e:  # noqa: BLE001
        current_app.logger.warning("exceção imediata: não consegui ler os bloqueios: %s", e)
        return {}


def _libera_agora(doms, antes) -> str:
    """"Manter liberado" vale na hora (allowed nos grupos que a mudança libera). Retorna o fim da mensagem."""
    try:
        return dnslib.msg_liberado(dnslib.liberar_agora(doms, antes, admin_atual().email))
    except Exception as e:  # noqa: BLE001
        return f" O DNS atualiza em até 2 min (não consegui liberar na hora: {e})."


def _fim_excecao(doms) -> None:
    """O domínio voltou para uma lista: tira as exceções imediatas que o console pôs."""
    try:
        dnslib.remover_excecao(doms, admin_atual().email)
    except Exception as e:  # noqa: BLE001
        current_app.logger.warning("não consegui tirar a exceção imediata de %s: %s", doms, e)


@admin_bp.post("/listas-categoria/aceitar")
@login_required
@super_required
def lista_aceitar():
    """A lista encolheu de propósito (limpeza): aceita publicar a versão menor."""
    cat = request.form.get("cat", "")
    try:
        r = api.post(f"/listas/{quote(cat, safe='')}/aceitar?by={quote(admin_atual().email)}")
        flash(f"Lista aceita com {r.get('dominios')} domínios; o DNS baixa a versão nova em até 2 min.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("admin.listas_categoria", cat=cat))


def _tirar_da_lista(cat: str, dominio: str) -> None:
    """Tira da lista e grava a decisão global 'manter liberado' (senão o bloqueio automático
    colocaria de volta no próximo ciclo)."""
    api.delete(f"/listas/{quote(cat, safe='')}/{quote(dominio, safe='')}", by=admin_atual().email)
    _decisao_global(dominio, "allowed")


def _decisao_global(dominio: str, status: str) -> None:
    try:
        api.post(f"/domains/{quote(dominio, safe='')}/review", {"status": status, "by": admin_atual().email})
    except AnalyzerError:
        pass   # domínio nunca visto nos logs: não há decisão a gravar


@admin_bp.post("/listas-categoria/rem")
@login_required
@super_required
def listas_categoria_rem():
    cat, dom = request.form.get("cat", ""), request.form.get("dominio", "")
    try:
        antes = _antes([dom])
        _tirar_da_lista(cat, dom)
        current_app.logger.info("DNS: %s tirou %s da lista %s", admin_atual().email, dom, cat)
        flash(f"{dom} saiu da lista {cat} (decisão: manter liberado)." + _libera_agora([dom], antes), "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    voltar = request.form.get("voltar") or ""
    return redirect(voltar if next_local(voltar) else url_for("admin.listas_categoria", cat=cat))


@admin_bp.post("/listas-categoria/add")
@login_required
@super_required
def listas_categoria_add():
    cat, dom = request.form.get("cat", ""), (request.form.get("dominio") or "").strip().lower().rstrip(".")
    try:
        api.post(f"/listas/{quote(cat, safe='')}", {"domain": dom, "by": admin_atual().email})
        _fim_excecao([dom])
        _decisao_global(dom, "blocked")
        current_app.logger.info("DNS: %s pôs %s na lista %s", admin_atual().email, dom, cat)
        flash(f"{dom} entrou na lista {cat}. O Technitium atualiza em até 2 min.", "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("admin.listas_categoria", cat=cat))


# ------------------------------------------------- Grupos: ações sem recarregar (JSON)
def _json(ok: bool, msg: str, **kw):
    from flask import jsonify
    return jsonify(ok=ok, msg=msg, **kw), (200 if ok else 400)


# ------------------------------------------------- Histórico do domínio (painel lateral, Ajax)
@admin_bp.get("/dominios/historico")
@login_required
def dominio_historico():
    d = (request.args.get("d") or "").strip().lower().rstrip(".")
    try:
        return _json(True, "", historico=api.get(f"/domains/{quote(d, safe='')}/historico"))
    except AnalyzerError as e:
        return _json(False, f"{e}")


@admin_bp.get("/dominios/irmaos")
@login_required
def dominio_irmaos():
    d = (request.args.get("d") or "").strip().lower().rstrip(".")
    try:
        return _json(True, "", irmaos=api.get(f"/domains/{quote(d, safe='')}/irmaos"))
    except AnalyzerError as e:
        return _json(False, f"{e}")


# ------------------------------------------------- Prévia de impacto (plano de confiabilidade, fase 3.1)
@admin_bp.get("/politicas/impacto")
@login_required
def politica_impacto():
    """Se a empresa passar a aplicar estas listas: computadores, consultas e mais acessados (7 dias)."""
    try:
        return _json(True, "", impacto=api.get("/policies/impacto", tid=request.args.get("tid", 0, type=int),
                                                lists=request.args.get("lists", ""), days=7))
    except AnalyzerError as e:
        return _json(False, f"Falha: {e}")


@admin_bp.post("/dominios/impacto")
@login_required
def dominios_impacto():
    """Antes de pôr domínios numa lista: empresas e computadores que os consultaram (7 dias)."""
    d = request.get_json(silent=True) or {}
    try:
        return _json(True, "", impacto=api.post("/domains/impacto", {"domains": d.get("dominios") or [], "days": 7}))
    except AnalyzerError as e:
        return _json(False, f"Falha: {e}")


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
        return _json(True, "Salvo e aplicado no DNS (listas valem em até 2 min; exceções na hora).", redes=r["redes"])
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


@admin_bp.post("/listas-categoria/empresas")
@login_required
def lista_empresas():
    """Modal da lista: quais empresas (e o default) aplicam esta lista — e, na empresa com filiais, em quais delas
    (01/10, pedido do usuário). Filial marcada diferente da empresa = política própria da filial (cópia da empresa com
    esta lista ligada/desligada); igualou de novo = a política própria sai e a filial volta a seguir a empresa."""
    from app import empresas as emp
    from app import politicas as pol
    d = request.get_json(silent=True) or {}
    cat = (d.get("cat") or "").strip()
    if cat not in dict(dnslib.CATEGORIAS_LISTA):
        return _json(False, "lista inválida")
    quer = {int(x) for x in d.get("tenants") or []}
    quem = admin_atual().email
    campos = lambda p: (sorted(p.get("lists") or []), sorted(p.get("services") or []),   # noqa: E731
                        sorted(p.get("services_blocked") or []))
    try:
        atual = pol.por_escopo()
        mudou = 0
        novas = {}   # política da empresa depois desta gravação (as filiais se comparam com ela)
        alvos = [(f"tenant:{e['id']}", e["id"] in quer) for e in emp.lista() if not e.get("auto_created")]
        alvos.append(("default", bool(d.get("default"))))
        for scope, liga in alvos:
            p = atual.get(scope) or {}
            ls = set(p.get("lists") or [])
            novo = ls | {cat} if liga else ls - {cat}
            novas[scope] = {**p, "lists": sorted(novo)}
            if novo != ls and (p or liga):
                api.put(f"/policies/{quote(scope, safe='')}", {"lists": sorted(novo), "services": p.get("services") or [],
                                                               "services_blocked": p.get("services_blocked") or [],
                                                               "by": quem})
                mudou += 1
        for u in d.get("unidades") or []:
            tid, unidade, liga = int(u.get("tid") or 0), (u.get("unidade") or "").strip(), bool(u.get("liga"))
            if not unidade or f"tenant:{tid}" not in novas:
                continue
            scope = f"unit:{tid}:{unidade}"
            # o que vale p/ a empresa depois desta gravação: a política dela ou, sem política, a padrão
            emp_nova = novas[f"tenant:{tid}"] if (atual.get(f"tenant:{tid}") or tid in quer) else novas["default"]
            pu = atual.get(scope)
            base = pu or emp_nova   # sem política própria: parte da política da empresa
            ls = set(base.get("lists") or [])
            nova = {**base, "lists": sorted(ls | {cat} if liga else ls - {cat})}
            if campos(nova) == campos(emp_nova):   # igual à empresa: não precisa de política própria
                if pu:
                    api.delete(f"/policies/{quote(scope, safe='')}")
                    mudou += 1
            elif not pu or campos(nova) != campos(pu):
                api.put(f"/policies/{quote(scope, safe='')}", {"lists": nova["lists"], "services": nova.get("services") or [],
                                                               "services_blocked": nova.get("services_blocked") or [], "by": quem})
                mudou += 1
        if mudou:
            pol.sincronizar()
        current_app.logger.info("DNS: %s: lista %s -> empresas %s (default=%s)", admin_atual().email, cat, sorted(quer), d.get("default"))
        return _json(True, f"{mudou} política(s) alterada(s) e aplicadas no DNS." if mudou else "Nada mudou.")
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


@admin_bp.post("/dominios/listas")
@login_required
@super_required
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
        antes = _antes(doms) if fora else {}
        if fora:
            api.post("/listas-remover", {"domains": doms, "cats": fora})
        if quer:
            api.post("/listas-lote", {"domains": doms, "cats": quer, "by": admin_atual().email})
            _fim_excecao(doms)
        for x in doms:
            _decisao_global(x, "blocked" if quer else "allowed")
        rot = dict(dnslib.CATEGORIAS_LISTA)
        current_app.logger.info("DNS: %s: %s -> listas %s", admin_atual().email, doms, quer)
        alvo = doms[0] if len(doms) == 1 else f"{len(doms)} domínios"
        return _json(True, f"{alvo}: " + (", ".join(rot[c] for c in quer) if quer else "fora de todas as listas (manter liberado)")
                     + "." + (_libera_agora(doms, antes) if antes else " O DNS atualiza em até 2 min."))
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
            "empresas_pol": empresas_pol, "default_tem": slug in ((por.get("default") or {}).get("services") or []),
            **_ips_servico_ctx(slug)}


def _ips_servico_ctx(slug: str) -> dict:
    """"IPs que liberam": IPs/faixas com este serviço liberado só para eles (mesmos dados dos IPs liberados).
    `ips` None = analisador ainda sem a rota (botão desligado)."""
    try:
        ips = api.get("/console/ip-servicos", slug=slug)
    except AnalyzerError as e:
        if not str(e).startswith("404"):
            flash(f"IPs que liberam indisponíveis (analisador): {e}", "erro")
        return {"ips": None, "ips_historico": [], "empresas": [], "tipos": TIPOS_LIBERADO}
    try:
        historico = api.get("/console/liberados-log", servico=slug, limit=30)
    except AnalyzerError:
        historico = []
    return {"ips": ips, "ips_historico": historico, "empresas": _empresas_liberado(), "tipos": TIPOS_LIBERADO}


@admin_bp.get("/listas-liberacao")
@login_required
def listas_liberacao_antiga():
    return redirect(url_for("admin.listas_liberacao", **request.args), 301)


@admin_bp.get("/dominios-liberados")
@login_required
def listas_liberacao():
    """Listas de liberação avulsas (whitelist): vencem qualquer lista de bloqueio."""
    ctx = {"servico": None, "todas": []}
    slug = request.args.get("slug") or ""
    wl = request.args.get("wl") or ""
    try:
        todas = api.get("/liberacao")
        avulsas = [x for x in todas if not x.get("category")]
        try:
            ctx_wl = api.get("/whitelist")
        except AnalyzerError:
            ctx_wl = {"categorias": [], "revisados": 0}
        if wl in dict(dnslib.CATEGORIAS_WHITELIST):   # whitelist por categoria (vai p/ o Technitium, vence bloqueio)
            fd = _det_filtros("consultas")
            p = _det_params(fd)
            p.pop("offset"), p.pop("limit")
            ctx = {"servico": None, "todas": todas, "wl": wl, "fd": fd, "scats": _site_cats(), "pag_url": _pag_url,
                   "det": api.get(f"/whitelist/{quote(wl, safe='')}/detalhes", offset=(fd["pag"] - 1) * fd["pp"], limit=fd["pp"], **p)}
        else:   # ("Aprovados", slug=_trabalho, deixou de existir em 27/09: nada fica sem lista)
            slug = (slug if slug != "_trabalho" else "") or (avulsas[0]["slug"] if avulsas else "")
            ctx = _servico_ctx(slug) if slug else {"servico": None, "todas": todas}
    except AnalyzerError as e:
        flash(f"Falha ao carregar as listas de liberação: {e}", "erro")
    if request.headers.get("X-Partial") and ctx.get("det") is not None:
        return render_template("admin/_dominios_detalhe.html", so_tabela=True, modo="whitelist" if ctx.get("wl") else "sem_lista",
                               categorias=dnslib.CATEGORIAS_LISTA, cat="", **{k: v for k, v in ctx.items() if k in ("det", "fd", "wl", "scats", "pag_url")})
    busca = (request.args.get("busca") or "").strip().lower().rstrip(".")
    achados = None
    if len(busca) >= 3:   # procura em TODAS as whitelists e listas de liberação (não só na aberta), como em Domínios bloqueados
        try:
            achados = api.get("/whitelist-busca", q=busca)
        except AnalyzerError as e:
            flash(f"Falha na busca: {e}", "erro")
            achados = []
    return render_template("admin/servico.html", modo="liberacao", categorias=dnslib.CATEGORIAS_LISTA, whitelists=ctx_wl,
                           cats_wl=dnslib.CATEGORIAS_WHITELIST, busca=busca, achados=achados, **ctx)


@admin_bp.post("/whitelist/add")
@login_required
@super_required
def whitelist_add():
    wl = request.form.get("wl", "")
    doms = [x.strip().lower().rstrip(".") for x in re.split(r"[\s,;]+", request.form.get("dominio", "")) if x.strip()]
    try:
        antes = _antes(doms)
        api.post(f"/whitelist/{quote(wl, safe='')}", {"domains": doms, "by": admin_atual().email})
        for x in doms:
            _decisao_global(x, "allowed")
        flash(f"{len(doms)} domínio(s) na whitelist {dict(dnslib.CATEGORIAS_WHITELIST).get(wl, wl)} (e fora das listas de bloqueio)."
              + _libera_agora(doms, antes), "ok")
    except AnalyzerError as e:
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("admin.listas_liberacao", wl=wl))


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
@super_required
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
@super_required
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
@super_required
def servico_apagar(slug):
    try:
        api.delete(f"/liberacao/{quote(slug, safe='')}")
        from app import politicas as pol
        pol.sincronizar()
        flash(f"{slug} apagado (e retirado das empresas que o usavam).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha: {e}", "erro")
    return redirect(url_for("admin.listas_liberacao"))


@admin_bp.post("/servicos/<slug>/ips")
@login_required
def servico_ip_liberar(slug):
    """Libera o serviço só para um IP/faixa (ou atualiza os dados de um já liberado) e aplica no Technitium:
    o IP ganha um grupo próprio com a política da rede dele mais este serviço."""
    from app import politicas as pol
    ip = dnslib.norm_ip(request.form.get("ip"))
    if not ip:
        flash("IP ou CIDR inválido (ex.: 10.100.10.20 ou 10.100.10.0/24).", "erro")
        return _volta_servico(slug)
    try:
        novo = ip not in {x["ip"] for x in pol.ips_servicos(slug)}
        if novo and not (request.form.get("autorizado_por") or "").strip():
            flash("Informe quem da empresa autorizou a liberação.", "erro")
            return _volta_servico(slug)
        api.put("/console/ip-servicos", {"ip": ip, "slug": slug, "by": admin_atual().email,
                                         "tenant_id": request.form.get("tenant_id", type=int),
                                         **{k: request.form.get(k) or "" for k in
                                            ("filial", "departamento", "usuario", "tipo", "autorizado_por")}})
    except AnalyzerError as e:
        flash(f"Falha ao liberar: {e}", "erro")
        return _volta_servico(slug)
    if not novo:
        flash(f"{ip} atualizado.", "ok")
        return _volta_servico(slug)
    try:
        pol.sincronizar()
        isento = ip in dnslib.listar()
        current_app.logger.info("DNS: %s liberou %s só para o IP %s", admin_atual().email, slug, ip)
        flash(f"{slug} liberado para {ip}." + (" Atenção: este IP já está em IPs liberados (isento de todo o filtro)."
                                                if isento else " O DNS aplica em até 2 min."), "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"{ip} gravado, mas não foi aplicado no Technitium: {e}. Entra na próxima sincronização das políticas.", "erro")
    return _volta_servico(slug)


@admin_bp.post("/servicos/<slug>/ips/revogar")
@login_required
def servico_ip_revogar(slug):
    from app import politicas as pol
    ip = dnslib.norm_ip(request.form.get("ip"))
    try:
        if ip:
            api.delete("/console/ip-servicos", ip=ip, slug=slug, by=admin_atual().email)
            pol.sincronizar()
            current_app.logger.info("DNS: %s revogou %s do IP %s", admin_atual().email, slug, ip)
            flash(f"{slug} revogado de {ip} (volta a valer só a política da rede dele).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao revogar: {e}", "erro")
    return _volta_servico(slug)


@admin_bp.post("/servicos/<slug>/dominios")
@login_required
@super_required
def servico_dominios(slug):
    acao, dom = request.form.get("acao"), (request.form.get("dominio") or "").strip().lower().rstrip(".")
    try:
        if acao == "rem":
            api.delete(f"/liberacao/{quote(slug, safe='')}/dominios/{quote(dom, safe='')}")
            flash(f"{dom} saiu.", "ok")
        else:
            doms = [x.strip() for x in (request.form.get("dominio") or "").replace(",", "\n").splitlines() if x.strip()]
            r = api.post(f"/liberacao/{quote(slug, safe='')}/dominios", {"domains": doms, "by": admin_atual().email})
            flash(f"{r.get('dominios', 0)} domínio(s) adicionado(s). Vale no DNS em até 2 min.", "ok")
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
