"""Telas de DNS do console: Grupos (quem usa cada política), Domínios (o que cada grupo bloqueia), Liberados (IPs isentos do
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
    return redirect(url_for("admin.grupos"))




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


def _sem_technitium():
    return render_template("admin/nao_configurado.html", oque="Technitium (TECHNITIUM_URL/TECHNITIUM_TOKEN)")


@admin_bp.get("/bloqueios")
@login_required
def bloqueios():
    """Tela antiga (dividida em Grupos e Domínios): links antigos seguem funcionando."""
    args = request.args.to_dict()
    destino = "admin.dominios" if (args.get("q") or args.get("qg")) else "admin.grupos"
    return redirect(url_for(destino, **args))


@admin_bp.get("/grupos")
@login_required
def grupos():
    """Tela antiga: grupos agora são internos (um por empresa, mantidos pelas políticas).
    Quem aplica o quê fica em Empresas e em Listas de bloqueio. ?antigo=1 ainda mostra."""
    if not request.args.get("antigo"):
        return redirect(url_for("analise.empresas"))
    if not current_app.config.get("TECHNITIUM_ENABLED"):
        return _sem_technitium()
    from app import empresas as emp
    cfg, nomes = {}, []
    try:
        cfg = dnslib._get_config()
        nomes = sorted(g.get("name") for g in cfg.get("groups", []) if g.get("name"))
    except Exception as e:  # noqa: BLE001
        flash(f"Não foi possível consultar o Technitium: {e}", "erro")
    grupo = (request.args.get("grupo") or (nomes[0] if nomes else "")).strip()
    ngm = cfg.get("networkGroupMap", {})
    redes_por = {}
    for k, v in ngm.items():
        redes_por.setdefault(v, []).append(dnslib.norm_ip(k) or k)
    rotulos = emp.rotulos_de_redes([r for rs in redes_por.values() for r in rs]) if ngm else {}
    resumo = [{"nome": g.get("name"), "bloqueia": g.get("enableBlocking", True),
               "dominios": len(g.get("blocked") or []), "redes": len(redes_por.get(g.get("name"), [])),
               "empresas": sorted({rotulos[r].split(" · ")[0] for r in redes_por.get(g.get("name"), []) if r in rotulos})}
              for g in sorted(cfg.get("groups", []), key=lambda g: (g.get("name") or "").lower())]
    redes = sorted(redes_por.get(grupo, []), key=dnslib._sort_key)
    # IPs individuais (/32, /128) à parte: no grupo Liberados são os da tela Liberados
    ips = [r for r in redes if r.endswith(("/32", "/128"))]
    faixas = [r for r in redes if r not in ips]
    desc_ip = {}
    if ips:
        try:
            desc_ip = {m["ip"]: " · ".join(x for x in (m.get("tenant_name") or m.get("empresa"), m.get("filial"),
                                                       m.get("departamento"), m.get("usuario"), m.get("tipo")) if x)
                       for m in api.get("/console/liberados-meta")}
        except AnalyzerError:
            pass
    redes_emp = {r: rotulos[r] for r in redes if r in rotulos}
    empresas_grupo = sorted({v.split(" · ")[0] for v in redes_emp.values()})
    cadastro = sorted(({"id": e["id"], "name": e["name"],
                        "redes": [{"cidr": n["cidr"], "unit": n.get("unit") or ""} for n in e.get("networks", [])]}
                       for e in emp.lista() if e.get("networks")), key=lambda e: e["name"].lower())
    gobj = next((x for x in cfg.get("groups", []) if x.get("name") == grupo), {})
    esp = emp.grupos_especificos()
    por_nome = {x.get("name"): x for x in cfg.get("groups", [])}
    for r in resumo:
        r["listas"] = dnslib.listas_assinadas(por_nome.get(r["nome"], {}))
        r["pacotes"] = dnslib.pacotes_liberados(por_nome.get(r["nome"], {}))
        r["especifico"] = r["nome"] in esp
    mapa = _mapa_empresas(emp.lista(), cfg)
    return render_template("admin/grupos.html", grupos=nomes, grupo=grupo, resumo=resumo, redes=redes, mapa=mapa,
                           categorias_lista=dnslib.CATEGORIAS_LISTA, assinadas=dnslib.listas_assinadas(gobj),
                           categorias_risco=sorted(dnslib.CATEGORIAS_RISCO),
                           pacotes=[(k, v[0], v[1]) for k, v in dnslib.PACOTES.items()],
                           grupo_bloqueia=gobj.get("enableBlocking", True),
                           redes_emp=redes_emp, empresas_grupo=empresas_grupo, cadastro=cadastro,
                           faixas=faixas, ips=ips, desc_ip=desc_ip, especificos=emp.grupos_especificos(),
                           sem_grupo=_sem_grupo(emp.lista(), ngm))


def _mapa_empresas(empresas: list[dict], cfg: dict) -> list[dict]:
    """Uma linha por rede (CIDR) do cadastro de Empresas: o grupo atribuído a ELA (exato) e o
    que vale de fato (exato, herdado de uma faixa maior ou o default)."""
    ngm = dnslib.ngm_de(cfg)
    exato = {str(k): v for k, v in ngm.items()}
    out = []
    for e in empresas:
        for n in e.get("networks") or []:
            cidr = dnslib.norm_ip(n.get("cidr")) or n.get("cidr")
            try:
                vale = dnslib.grupo_da_rede(cidr, ngm) or "default"
            except ValueError:
                continue
            out.append({"empresa": e["name"], "tid": e["id"], "unidade": n.get("unit") or "", "cidr": cidr,
                        "grupo": exato.get(cidr, ""), "vale": vale, "auto": bool(e.get("auto_created"))})
    return sorted(out, key=lambda r: (r["auto"], r["empresa"].lower(), r["unidade"].lower(), dnslib._sort_key(r["cidr"])))


def _sem_grupo(empresas: list[dict], ngm: dict) -> list[dict]:
    """Redes do cadastro de Empresas (inclui as criadas sozinhas a partir dos logs) que
    nenhum grupo cobre: caem no `default`. `parciais` = pedaços dela que já têm grupo."""
    import ipaddress
    mapa = []
    for k, g in ngm.items():
        try:
            n = ipaddress.ip_network(k, strict=False)
        except ValueError:
            continue
        if n.prefixlen:                      # 0.0.0.0/0 e ::/0 = o próprio default
            mapa.append((n, g))
    out = []
    for e in empresas:
        for r in e.get("networks", []):
            try:
                net = ipaddress.ip_network(r["cidr"], strict=False)
            except ValueError:
                continue
            if any(net.version == n.version and net.subnet_of(n) for n, _ in mapa):
                continue
            parciais = sorted(((str(n), g) for n, g in mapa if n.version == net.version and n.subnet_of(net)),
                              key=lambda x: dnslib._sort_key(x[0]))
            out.append({"empresa": e["name"], "unidade": r.get("unit") or "", "cidr": str(net),
                        "auto": e.get("auto_created"), "pcs": e.get("clients"), "visto": e.get("last_seen"),
                        "parciais": parciais})
    return sorted(out, key=lambda x: (not x["auto"], x["empresa"].lower(), dnslib._sort_key(x["cidr"])))


@admin_bp.get("/dominios")
@login_required
def dominios():
    """Domínios: em quais listas de bloqueio cada domínio está (busca em todas + editor)."""
    q = (request.args.get("q") or request.args.get("qg") or "").strip().lower()
    achados, cap = {}, False
    if q and current_app.config.get("ANALYZER_ENABLED"):
        for c, _ in dnslib.CATEGORIAS_LISTA:
            try:
                for r in api.get(f"/listas/{quote(c, safe='')}", q=q, limit=500):
                    achados.setdefault(r["domain"], []).append(c)
            except AnalyzerError as e:
                flash(f"Falha ao buscar na lista {c}: {e}", "erro")
                break
        cap = len(achados) > 500
    linhas = sorted(achados.items())[:500]
    return render_template("admin/dominios.html", q=q, linhas=linhas, cap=cap, categorias=dnslib.CATEGORIAS_LISTA,
                           cats_risco=sorted(dnslib.CATEGORIAS_RISCO))


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
    return redirect(url_for("admin.dominios", grupo=grupo))


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
    return redirect(url_for("admin.dominios", grupo=grupo))


@admin_bp.post("/bloqueios/renomear")
@login_required
def bloqueios_renomear():
    velho = (request.form.get("grupo") or "").strip()
    novo = (request.form.get("novo_nome") or "").strip()
    try:
        n, msg = dnslib.renomear_grupo(velho, novo)
        if n:
            flash(f"Grupo '{velho}' {msg} para '{n}'.", "ok")
            try:   # a config do grupo (ex.: específico) acompanha o nome
                api.put("/console/group-settings", {"name": velho, "rename_to": n, "by": admin_atual().email})
            except AnalyzerError:
                pass
            return redirect(url_for("admin.grupos", grupo=n))
        flash(msg, "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao renomear: {e}", "erro")
    return redirect(url_for("admin.grupos", grupo=velho))


@admin_bp.post("/bloqueios/deletar")
@login_required
def bloqueios_deletar():
    grupo = (request.form.get("grupo") or "").strip()
    try:
        n, info = dnslib.deletar_grupo(grupo)
        if n:
            try:
                api.delete(f"/console/group-settings?name={quote(n, safe='')}")
            except AnalyzerError:
                pass
            extra = f" ({info} rede(s) desatribuída(s))" if info else ""
            flash(f"Grupo '{n}' removido{extra}.", "ok")
            return redirect(url_for("admin.grupos"))
        flash(info, "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover grupo: {e}", "erro")
    return redirect(url_for("admin.grupos", grupo=grupo))


@admin_bp.post("/bloqueios/grupo")
@login_required
def bloqueios_grupo():
    nome = (request.form.get("nome") or "").strip()
    clonar = (request.form.get("clonar_de") or "").strip() or None
    try:
        n, msg = dnslib.criar_grupo(nome, clonar)
        if n:
            flash(f"Grupo '{n}' {msg}.", "ok")
            return redirect(url_for("admin.grupos", grupo=n))
        flash(msg, "erro")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao criar grupo: {e}", "erro")
    return redirect(url_for("admin.grupos"))


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
    return redirect(url_for("admin.grupos", grupo=grupo))


@admin_bp.post("/bloqueios/empresa")
@login_required
def bloqueios_empresa_add():
    """Atribui ao grupo todas as redes (CIDR) de uma empresa do cadastro (ou só de uma filial)."""
    from app import empresas as emp
    grupo = (request.form.get("grupo") or "").strip()
    tid = request.form.get("empresa", type=int)
    filial = (request.form.get("filial") or "").strip()
    e = next((x for x in emp.lista() if x["id"] == tid), None)
    redes = [n["cidr"] for n in (e or {}).get("networks", []) if not filial or (n.get("unit") or "") == filial]
    if not e:
        flash("Escolha uma empresa do cadastro.", "erro")
    elif not redes:
        flash(f"{e['name']} não tem rede (CIDR) cadastrada"
              + (f" na filial {filial}" if filial else "") + " — cadastre em Empresas.", "erro")
    else:
        try:
            feitos, invalidos = dnslib.atribuir_redes(redes, grupo)
            antes = [f"{c} (antes: {a})" for c, a in feitos if a]
            nome = e["name"] + (f" · {filial}" if filial else "")
            flash(f"{nome}: {len(feitos)} rede(s) atribuída(s) a {grupo}: {', '.join(c for c, _ in feitos)}."
                  + (f" Mudaram de grupo: {'; '.join(antes)}." if antes else ""), "ok")
            if invalidos:
                flash(f"Redes inválidas no cadastro, ignoradas: {', '.join(invalidos)}", "erro")
            current_app.logger.info("DNS: %s atribuiu %s (%s) a %s", admin_atual().email, nome, redes, grupo)
        except Exception as ex:  # noqa: BLE001
            flash(f"Falha ao atribuir: {ex}", "erro")
    return redirect(url_for("admin.grupos", grupo=grupo))


@admin_bp.post("/grupos/config")
@login_required
def grupo_config():
    """Grupo específico (ex.: Anúncios): fica de fora do "Bloquear em todas"."""
    grupo = (request.form.get("grupo") or "").strip()
    esp = bool(request.form.get("especifico"))
    try:
        api.put("/console/group-settings", {"name": grupo, "especifico": esp, "by": admin_atual().email})
        flash(f"{grupo}: " + ("grupo específico — não entra mais no \"Bloquear em todas\"." if esp
                              else "volta a entrar no \"Bloquear em todas\"."), "ok")
    except AnalyzerError as e:
        flash(f"Falha ao salvar: {e}", "erro")
    return redirect(url_for("admin.grupos", grupo=grupo))


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
    return redirect(url_for("admin.grupos", grupo=grupo))


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
        return redirect(url_for("admin.dominios", qg=qg))
    return redirect(url_for("admin.dominios", grupo=grupo, q=(request.form.get("q") or "")))


@admin_bp.post("/bloqueios/rem-todos")
@login_required
def bloqueios_rem_todos():
    doms = request.form.getlist("dominios")
    qg = (request.form.get("qg") or "").strip()
    voltar = (request.form.get("voltar") or "").strip()
    try:
        rem, gruposaf = dnslib.rem_dominios_todos(doms)
        try:   # listas de bloqueio por categoria (+ decisão 'manter liberado')
            nl = api.post("/listas-remover", {"domains": doms}).get("removidos", 0)
            if nl:
                rem, gruposaf = rem + nl, gruposaf + nl
                for d in doms:
                    _decisao_global(d, "allowed")
        except AnalyzerError:
            pass
        if rem == 0:
            flash("Nenhum domínio removido.", "erro")
        else:
            alvo = ", ".join(doms) if len(doms) <= 3 else f"{len(doms)} domínios"
            flash(f"{alvo}: {rem} remoção(ões) em {gruposaf} lista(s).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao remover de todas as listas: {e}", "erro")
    if next_local(voltar):  # veio da tela de logs: volta pra ela
        return redirect(voltar)
    return redirect(url_for("admin.dominios", qg=qg))


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
    return redirect(url_for("admin.dominios", grupo=grupo, q=(request.form.get("q") or "")))


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
    grupo = (request.args.get("grupo") or "").strip()       # grupo de bloqueio (política) do Technitium
    if empresa and not empresa.isdigit():                   # links antigos: empresa=<grupo>
        grupo, empresa = empresa, ""
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
        elif grupo:
            redes = dnslib.empresa_redes(grupo, mapa)
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
        # empresa/unidade pelo cadastro (o "empresa" do Technitium é o grupo de bloqueio)
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


# ------------------------------------------------- Listas por categoria (analisador) assinadas pelos grupos
@admin_bp.post("/grupos/listas")
@login_required
def grupo_listas():
    """Quais listas por categoria o grupo assina (Technitium baixa de hora em hora)."""
    grupo = (request.form.get("grupo") or "").strip()
    try:
        ass = dnslib.assinar_listas(grupo, request.form.getlist("cats"))
        rot = dict(dnslib.CATEGORIAS_LISTA)
        current_app.logger.info("DNS: %s: grupo %s assina listas %s", admin_atual().email, grupo, ass)
        flash(f"{grupo}: assina " + (", ".join(rot[c] for c in ass) if ass else "nenhuma lista por categoria") + ".", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Falha ao salvar as listas do grupo: {e}", "erro")
    return redirect(url_for("admin.grupos", grupo=grupo))


@admin_bp.get("/listas-categoria")
@login_required
def listas_categoria():
    """Listas de bloqueio por categoria: o que está em cada uma e quem assina."""
    if not current_app.config.get("ANALYZER_ENABLED"):
        return render_template("admin/nao_configurado.html", oque="Analisador (ANALYZER_URL/ANALYZER_TOKEN)")
    cat = (request.args.get("cat") or "apostas").strip()
    q = (request.args.get("q") or "").strip().lower()
    resumo, itens, ass = {"categorias": [], "auto": [], "auto_24h": 0}, [], {}
    try:
        resumo = api.get("/listas")
        itens = api.get(f"/listas/{quote(cat, safe='')}", q=q or None, limit=2000)
    except AnalyzerError as e:
        flash(f"Falha ao carregar as listas: {e}", "erro")
    from app import empresas as emp
    from app import politicas as pol
    sugestoes, empresas_pol, default_tem = [], [], False
    try:
        if cat in ("redes_sociais", "streaming", "publicidade", "compras", "noticias"):
            sugestoes = api.get(f"/listas/{quote(cat, safe='')}/sugestoes", limit=300)
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
    return render_template("admin/listas_categoria.html", cat=cat, q=q, resumo=resumo, itens=itens,
                           categorias=dnslib.CATEGORIAS_LISTA, sugestoes=sugestoes, empresas_pol=empresas_pol,
                           default_tem=default_tem)


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


@admin_bp.post("/grupos/api/rede")
@login_required
def grupos_api_rede():
    """Grupo de UMA rede do cadastro. grupo vazio = tira a atribuição (vale a faixa maior/default)."""
    d = request.get_json(silent=True) or {}
    cidr, grupo = (d.get("cidr") or "").strip(), (d.get("grupo") or "").strip()
    try:
        cfg = dnslib._get_config()
        atual = next((v for k, v in cfg.get("networkGroupMap", {}).items() if dnslib.norm_ip(k) == dnslib.norm_ip(cidr)), "")
        if not grupo:
            if atual:
                dnslib.remover_rede(cidr, atual)
            msg = f"{cidr}: sem grupo próprio (vale a faixa maior ou o default)."
        else:
            ipn, ant = dnslib.atribuir_rede(cidr, grupo)
            if not ipn:
                return _json(False, ant)
            msg = f"{ipn} → {grupo}" + (f" (antes: {ant})" if ant else "")
        vale = dnslib.grupo_da_rede(cidr, dnslib.ngm_de(dnslib._get_config())) or "default"
        current_app.logger.info("DNS: %s: rede %s -> %s", admin_atual().email, cidr, grupo or "(sem grupo)")
        return _json(True, msg, vale=vale)
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


@admin_bp.post("/grupos/api/listas")
@login_required
def grupos_api_listas():
    d = request.get_json(silent=True) or {}
    grupo = (d.get("grupo") or "").strip()
    try:
        ass = dnslib.assinar_listas(grupo, d.get("cats") or [])
        current_app.logger.info("DNS: %s: grupo %s assina listas %s", admin_atual().email, grupo, ass)
        rot = dict(dnslib.CATEGORIAS_LISTA)
        return _json(True, f"{grupo}: " + (", ".join(rot[c] for c in ass) if ass else "nenhuma lista por categoria"), listas=ass)
    except Exception as e:  # noqa: BLE001
        return _json(False, f"Falha: {e}")


@admin_bp.post("/grupos/api/especifico")
@login_required
def grupos_api_especifico():
    d = request.get_json(silent=True) or {}
    grupo, esp = (d.get("grupo") or "").strip(), bool(d.get("especifico"))
    try:
        api.put("/console/group-settings", {"name": grupo, "especifico": esp, "by": admin_atual().email})
        return _json(True, f"{grupo}: " + ("específico (fora do “Bloquear em todas”)" if esp else "entra no “Bloquear em todas”"))
    except AnalyzerError as e:
        return _json(False, f"Falha: {e}")


@admin_bp.post("/grupos/api/pacotes")
@login_required
def grupos_api_pacotes():
    """Serviços liberados como exceção no grupo (vencem as listas assinadas)."""
    d = request.get_json(silent=True) or {}
    grupo = (d.get("grupo") or "").strip()
    try:
        lib = dnslib.liberar_pacotes(grupo, d.get("servicos") or [])
        current_app.logger.info("DNS: %s: grupo %s libera %s", admin_atual().email, grupo, lib)
        return _json(True, f"{grupo}: libera " + (", ".join(dnslib.PACOTES[k][0] for k in lib) if lib else "nenhum serviço"),
                     pacotes=lib)
    except Exception as e:  # noqa: BLE001
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
                                                           "by": admin_atual().email})
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
                                                               "by": admin_atual().email})
                mudou += 1
        r = pol.sincronizar() if mudou else {"redes": None}
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
