"""DNS Inativo (01/10, pedido do usuário): domínio que NÃO resolve (não devolve IP) vai, já na etapa 1 e sem IA, para a
lista de bloqueio "DNS Inativo" — não há site p/ analisar, bloquear não muda nada p/ o usuário e, se o domínio for
ativado depois (golpe que reaproveita domínio expirado), já nasce bloqueado até ser reavaliado.

Cuidados (um nome só é "inativo" com TODOS):
- o DNS PÚBLICO não devolve IP — em dois resolvedores; falha de rede/timeout conta como "não sei", nunca como inativo;
- vale p/ os nomes de fato consultados (amostra dos FQDNs), a raiz e o www: ssiloc.com não tem IP, 1.ssiloc.com tem;
- os logs do Technitium não têm NENHUMA resposta com IP em 7 dias: nome interno do cliente (zona do AD) não resolve
  no DNS público, mas resolve na rede dele;
- o domínio não tem MX: domínio só de e-mail não tem site, e bloqueá-lo quebraria o envio de e-mail p/ ele;
- sem lista de ameaça (DGA de malware também não resolve: fica no fluxo normal) e fora do catálogo.
Quem voltar a ser consultado passa pelo teste de novo; resolvendo, sai da lista e segue a análise normal.

(07/10, pedido do usuário) O que o próprio Technitium acabou de responder vale antes de perguntar de novo: com a cópia
dos logs (query_log), nome que recebeu IP há pouco = o domínio resolve (nenhuma consulta externa); nome que recebeu
NXDOMAIN há pouco não é consultado de novo. Fora do log continuam a raiz e o www quando ninguém os consultou (o
bloqueio vale p/ o domínio inteiro) e o MX (domínio só de e-mail).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from . import catalog, db, eventos, listas

log = logging.getLogger(__name__)
RESOLVEDORES = ("1.1.1.1", "8.8.8.8")   # públicos: não passam pelo Technitium (que responde 0.0.0.0 ao que bloqueia)
POR = "regras (DNS inativo)"
_STATUS = re.compile(r"status: (\w+)")
_IP = re.compile(r"\sIN\s+(?:A|AAAA|MX)\s+\S+")


def testavel(nome: str) -> bool:
    """Só domínio de alguém passa pelo teste. Sufixo público (com.br, gov.br) e raiz de plataforma (cloudfront.net,
    blogspot.com) não têm IP na raiz e NUNCA são "inativos": na lista, bloqueariam tudo o que está sob eles (07/10:
    com.br entrou aqui e todo *.com.br ficou bloqueado). Nome sem ponto é nome de máquina, não domínio."""
    from .features import is_public_suffix
    return "." in nome and not is_public_suffix(nome)


def consulta(nome: str, resolvedor: str, tipo: str = "A") -> str:
    """'ip' (respondeu com endereço), 'vazio' (NXDOMAIN ou resposta sem endereço), 'falha' (o resolvedor respondeu
    SERVFAIL/REFUSED: o DNS do domínio está quebrado) ou 'erro' (timeout/rede: não deu p/ saber)."""
    if not shutil.which("dig"):
        return "erro"
    try:
        r = subprocess.run(["dig", "+noall", "+comments", "+answer", "+time=2", "+tries=1", f"@{resolvedor}", tipo, nome],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return "erro"
    m = _STATUS.search(r.stdout)
    if not m:   # sem cabeçalho de resposta: timeout / rede fora
        return "erro"
    if _IP.search(r.stdout):
        return "ip"
    return "vazio" if m.group(1) in ("NXDOMAIN", "NOERROR") else "falha"


def resolve(nome: str) -> bool | None:
    """True = tem endereço; False = não resolve nos dois resolvedores (A e AAAA); None = não deu p/ saber.
    Para no primeiro endereço (a maioria resolve na 1ª consulta)."""
    r = {}
    for tipo in ("A", "AAAA"):
        for res in RESOLVEDORES:
            r[(res, tipo)] = consulta(nome, res, tipo)
            if r[(res, tipo)] == "ip":
                return True
            if r[(res, tipo)] == "erro":   # timeout: não vai dar p/ afirmar que não resolve — desiste já (01/10: um
                return None                # domínio com o DNS mudo levava minutos nas 24 consultas)
    # sem endereço em TODAS as consultas dos dois resolvedores (vazio, ou DNS do domínio quebrado): não resolve
    return False if all(v in ("vazio", "falha") for v in r.values()) else None


def pelos_logs(c, ids: list[int]) -> dict[int, dict[str, bool]]:
    """O que o Technitium respondeu há pouco, por domínio e nome consultado: True = devolveu IP, False = NXDOMAIN (o
    nome não existe). Só respostas resolvidas na internet (Recursive/Cached): bloqueio e zona local não dizem se o nome
    resolve. Resposta vazia e SERVFAIL ficam p/ o teste ativo (pode ser site só IPv6 ou falha passageira). Janela
    curta: NXDOMAIN velho não pode segurar na lista um domínio que voltou."""
    out: dict[int, dict[str, bool]] = {}
    if not ids:
        return out
    for r in c.execute(
            "SELECT domain_id, qname, bool_or(rcode = 'NoError' AND answer ~ '(^|, )(A|AAAA) ') AS ip, "
            " bool_or(rcode = 'NxDomain') AS nx FROM query_log WHERE domain_id = ANY(%s) AND ts > now() - interval '2 hours' "
            "AND rtype IN ('Recursive', 'Cached') AND qtype IN ('A', 'AAAA') GROUP BY 1, 2", (list(ids),)):
        if r["ip"] or r["nx"]:
            out.setdefault(r["domain_id"], {})[r["qname"]] = bool(r["ip"])
    return out


def inativo(nomes: list[str], sabidos: dict[str, bool] | None = None) -> bool:
    """Nenhum dos nomes resolve, o domínio (1º nome) não recebe e-mail (MX) e deu p/ testar tudo. `sabidos` = o que os
    logs já responderam (pelos_logs): algum nome com IP = resolve; nome com NXDOMAIN não é consultado de novo."""
    sabidos = sabidos or {}
    if any(sabidos.values()):
        return False
    for n in dict.fromkeys(nomes):
        if sabidos.get(n) is False:
            continue
        if resolve(n) is not False:   # resolveu, ou não deu p/ saber: não é inativo
            return False
    return bool(nomes) and all(consulta(nomes[0], r, "MX") in ("vazio", "falha") for r in RESOLVEDORES)


def _motivo(nomes: list[str], sabidos: dict[str, bool] | None, resto: str = "") -> str:
    pelo_log = [n for n in nomes if (sabidos or {}).get(n) is False]
    return ("não resolve no DNS (sem IP em " + ", ".join(nomes[:3]) + ")" + resto
            + (f"; NXDOMAIN no log do Technitium: {', '.join(pelo_log[:3])}" if pelo_log else ""))


def _nomes(c, drow: dict) -> list[str]:
    fq = [r["name"] for r in c.execute(
        "SELECT f.name FROM fqdns f LEFT JOIN query_agg q ON q.fqdn_id = f.id AND q.domain_id = f.domain_id WHERE f.domain_id = %s "
        "GROUP BY f.name ORDER BY sum(q.queries) DESC NULLS LAST LIMIT 4", (drow["id"],))]
    return list(dict.fromkeys([drow["name"], "www." + drow["name"]] + fq))


def _com_ip(c, domain_id: int) -> int:
    """Respostas COM IP que os clientes receberam em 7 dias (logs do Technitium)."""
    return c.execute("SELECT COALESCE(sum(ip_q) - sum(sem_ip), 0) AS n FROM query_agg WHERE domain_id = %s "
                     "AND bucket >= now() - interval '7 days'", (domain_id,)).fetchone()["n"]


def marcar(c, drow: dict, motivo: str) -> None:
    """Põe na lista DNS Inativo e tira das filas da IA (kind = 'inexistente', como o "Sem resposta" dos logs)."""
    nome = drow["name"]
    if not testavel(nome):   # última barreira: quem chama já filtra
        log.error("DNS Inativo: %s é sufixo público/raiz de plataforma — não entra na lista", nome)
        return
    listas.contexto(c, POR, motivo)
    c.execute("DELETE FROM category_lists WHERE domain = %s AND category IN ('para_revisar', 'nao_identificado') "
              "AND coalesce(added_by, '') NOT LIKE '%%@%%'", (nome,))   # (o que uma pessoa pôs fica)
    novo = c.execute("INSERT INTO category_lists (category, domain, added_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                     (listas.DNS_INATIVO, nome, POR)).rowcount
    c.execute("UPDATE domains SET kind = 'inexistente', llm_pending = false, lista_duvida = false, needs_analysis = false, "
              " claimed_at = NULL, lista_ia = %s, lista_wl = NULL, lista_conf = 1, lista_motivo = %s, lista_fonte = 'regras', "
              " lista_at = now(), lista_aplicada_at = now(), revisado_at = now() WHERE id = %s",
              (listas.DNS_INATIVO, motivo[:500], drow["id"]))
    if novo:   # (quem já estava na lista e continua sem resolver não repete o evento)
        eventos.lista("lista_add", nome, listas.DNS_INATIVO, motivo, drow["id"], "regras", drow.get("classification"))


def desmarcar(c, drow: dict) -> bool:
    """Voltou a resolver: sai da lista DNS Inativo (a análise normal segue)."""
    n = c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (listas.DNS_INATIVO, drow["name"])).rowcount
    if n:
        c.execute("UPDATE domains SET lista_ia = NULL, lista_at = NULL, lista_aplicada_at = NULL WHERE id = %s AND lista_ia = %s",
                  (drow["id"], listas.DNS_INATIVO))
        eventos.lista("lista_rem", drow["name"], listas.DNS_INATIVO, "voltou a resolver no DNS: análise normal", drow["id"], "regras")
    return bool(n)


def etapa1(drow: dict) -> bool:
    """Teste da etapa 1, antes da IA: True = não resolve e foi p/ a lista DNS Inativo (a IA não é chamada)."""
    nome = drow["name"]
    if drow.get("kind") != "public" or (drow.get("ti_signature") or "") or catalog.match(nome) or not testavel(nome):
        return False
    with db.conn() as c:
        com_ip = _com_ip(c, drow["id"])
        em = {r["category"] for r in c.execute("SELECT category FROM category_lists WHERE domain = %s", (nome,))}
        nomes = _nomes(c, drow)
        sabidos = pelos_logs(c, [drow["id"]]).get(drow["id"], {})
    na_lista, bloqueado = listas.DNS_INATIVO in em, bool(em)
    # fora de lista de bloqueio os logs valem: o cliente recebe IP (nome interno, ou resolve mesmo) = não é inativo.
    # Numa lista de bloqueio o Technitium responde 0.0.0.0 a quem a aplica: aí só vale a resposta de verdade que
    # alguém recebeu há pouco (`sabidos`: grupo que não aplica a lista) ou o DNS público.
    if com_ip > 0 and not bloqueado:
        return False
    morto = inativo(nomes, sabidos)
    with db.conn() as c:
        if morto:
            marcar(c, drow, _motivo(nomes, sabidos, "" if bloqueado else " nem nos logs em 7 dias"))
            return True
        if na_lista:
            desmarcar(c, drow)
    return False


TESTE = "dns_teste"   # lookup_cache.kind: candidato dos logs que o teste ativo NÃO confirmou (não testa de novo em 24 h)


def confirmar(c, drow: dict) -> bool:
    """Os logs dizem que o nome não resolve; o teste ativo (DNS público + MX) confirma? Confirmado: lista DNS Inativo.
    (01/10, pedido do usuário: destino único — antes os logs sozinhos mandavam p/ a whitelist "Sem resposta", que nunca
    era publicada; p/ uma lista de BLOQUEIO os logs não bastam: domínio só de e-mail tem MX e não tem site.)"""
    if (drow.get("ti_signature") or "") or catalog.match(drow["name"]) or not testavel(drow["name"]):
        return False
    nomes = _nomes(c, drow)
    sabidos = pelos_logs(c, [drow["id"]]).get(drow["id"], {})
    if not inativo(nomes, sabidos):
        c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES (%s, %s, true, '{}') ON CONFLICT (kind, key) "
                  "DO UPDATE SET fetched_at = now()", (TESTE, drow["name"]))
        return False
    marcar(c, drow, _motivo(nomes, sabidos, " — logs do Technitium e DNS público"))
    return True


def dos_logs(c, limite: int = 150) -> list[str]:
    """Ciclo de manutenção: domínios que os logs dizem não resolver (7 dias) passam pelo teste ativo; os confirmados
    vão p/ DNS Inativo. Devolve os nomes marcados."""
    from concurrent.futures import ThreadPoolExecutor
    rows = c.execute(
        "SELECT d.id, d.name, d.kind, d.classification, d.ti_signature FROM domains d "
        "WHERE d.kind = 'public' AND NOT d.locked AND coalesce(d.ti_signature, '') = '' AND d.id IN (" + listas.NAO_RESOLVE_SQL + ") "
        " AND NOT EXISTS (SELECT 1 FROM lookup_cache l WHERE l.kind = %s AND l.key = d.name AND l.fetched_at > now() - interval '1 day') "
        "ORDER BY d.total_queries DESC LIMIT %s", (TESTE, limite)).fetchall()
    rows = [r for r in rows if not catalog.match(r["name"]) and testavel(r["name"])]
    nomes = {r["id"]: _nomes(c, r) for r in rows}
    sabidos = pelos_logs(c, [r["id"] for r in rows])
    with ThreadPoolExecutor(24) as pool:   # os testes em paralelo (nenhuma linha fica presa: só leitura até aqui)
        mortos = list(pool.map(lambda r: inativo(nomes[r["id"]], sabidos.get(r["id"])), rows))
    out = []
    for r, morto in zip(rows, mortos):
        if morto:
            marcar(c, r, _motivo(nomes[r["id"]], sabidos.get(r["id"]), " — logs do Technitium e DNS público"))
            out.append(r["name"])
        else:
            c.execute("INSERT INTO lookup_cache (kind, key, ok, value) VALUES (%s, %s, true, '{}') ON CONFLICT (kind, key) "
                      "DO UPDATE SET fetched_at = now()", (TESTE, r["name"]))
    return out


def migrar_sem_resposta(aplicar: bool = False, threads: int = 48) -> dict:
    """Passada única (01/10): os que o mecanismo antigo pôs na whitelist "Sem resposta" pelo teste ativo — não resolve:
    DNS Inativo; resolve (ou recebe e-mail): sai de "Sem resposta" e volta p/ a análise normal."""
    from concurrent.futures import ThreadPoolExecutor
    with db.conn() as c:
        rows = c.execute("SELECT d.id, d.name, d.kind, d.classification, d.ti_signature FROM whitelist_domains w "
                         "JOIN domains d ON d.name = w.domain WHERE w.category = 'sem_resposta' ORDER BY d.total_queries DESC").fetchall()
        ids = [r["id"] for r in rows]
        fq: dict[int, list[str]] = {}
        for r in c.execute("SELECT domain_id, name FROM fqdns WHERE domain_id = ANY(%s) ORDER BY domain_id, length(name)", (ids,)):
            if len(fq.setdefault(r["domain_id"], [])) < 4:
                fq[r["domain_id"]].append(r["name"])
    nomes = {r["id"]: list(dict.fromkeys([r["name"], "www." + r["name"]] + fq.get(r["id"], []))) for r in rows}
    with ThreadPoolExecutor(threads) as pool:
        mortos = list(pool.map(lambda r: testavel(r["name"]) and inativo(nomes[r["id"]]) and not catalog.match(r["name"]), rows))
    ina = [r for r, m in zip(rows, mortos) if m]
    vivos = [r for r, m in zip(rows, mortos) if not m]
    if aplicar:
        with db.conn() as c:
            listas.contexto(c, POR, "whitelist Sem resposta -> DNS Inativo (destino único)")
            c.execute("DELETE FROM whitelist_domains WHERE category = 'sem_resposta' AND domain = ANY(%s)", ([r["name"] for r in rows],))
            for r in ina:
                marcar(c, r, "não resolve no DNS (logs do Technitium e DNS público, sem IP em " + ", ".join(nomes[r["id"]][:3]) + ")")
            c.execute("UPDATE domains SET kind = 'public', needs_analysis = true, lista_wl = NULL, revisado_at = NULL "
                      "WHERE id = ANY(%s)", ([r["id"] for r in vivos],))
    return {"sem_resposta": len(rows), "inativos": len(ina), "voltam_p_analise": len(vivos), "aplicado": aplicar,
            "exemplos_que_resolvem": [r["name"] for r in vivos[:12]]}


def varrer(aplicar: bool = False, threads: int = 48) -> dict:
    """Passada única (01/10, pedido do usuário): todos os DESCONHECIDOS e a lista Não identificados pelo teste de DNS;
    quem não resolve vai p/ DNS Inativo. Quem não está em lista de bloqueio só entra se os logs também não têm resposta
    com IP em 7 dias (nome interno do cliente). aplicar=False só conta."""
    import time
    from concurrent.futures import ThreadPoolExecutor
    t0 = time.time()
    with db.conn() as c:
        rows = c.execute(
            "SELECT d.id, d.name, d.kind, d.classification, d.total_queries, "
            " EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name) AS em_lista FROM domains d "
            "WHERE d.kind = 'public' AND NOT d.locked AND coalesce(d.ti_signature, '') = '' "
            " AND (d.classification = 'DESCONHECIDO' OR EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name "
            "      AND l.category = 'nao_identificado')) ORDER BY d.total_queries DESC").fetchall()
        ids = [r["id"] for r in rows]
        fq: dict[int, list[str]] = {}
        for r in c.execute("SELECT domain_id, name FROM fqdns WHERE domain_id = ANY(%s) ORDER BY domain_id, length(name)", (ids,)):
            if len(fq.setdefault(r["domain_id"], [])) < 4:
                fq[r["domain_id"]].append(r["name"])
        com_ip = {r["domain_id"]: r["n"] for r in c.execute(
            "SELECT domain_id, sum(ip_q) - sum(sem_ip) AS n FROM query_agg WHERE bucket >= now() - interval '7 days' "
            "AND domain_id = ANY(%s) GROUP BY 1", (ids,))}
    nomes = {r["id"]: list(dict.fromkeys([r["name"], "www." + r["name"]] + fq.get(r["id"], []))) for r in rows}
    # fora de lista de bloqueio, os logs valem: resposta com IP em 7 dias = não testa (resolve p/ o cliente)
    alvo = [r for r in rows if not catalog.match(r["name"]) and testavel(r["name"])
            and (r["em_lista"] or (com_ip.get(r["id"]) or 0) <= 0)]
    with ThreadPoolExecutor(threads) as pool:
        mortos = list(pool.map(lambda r: inativo(nomes[r["id"]]), alvo))
    ina = [r for r, m in zip(alvo, mortos) if m]
    if aplicar:
        for r in ina:
            with db.conn() as c:
                marcar(c, r, "não resolve no DNS público (sem IP em " + ", ".join(nomes[r["id"]][:3]) + ")")
    out = {"candidatos": len(rows), "testados": len(alvo), "inativos": len(ina), "aplicado": aplicar,
           "segundos": round(time.time() - t0), "mais_acessados": [(r["name"], r["total_queries"]) for r in ina[:15]]}
    log.info("DNS inativo (varredura): %s", {k: v for k, v in out.items() if k != "mais_acessados"})
    return out
