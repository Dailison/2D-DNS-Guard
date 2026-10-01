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


def consulta(nome: str, resolvedor: str, tipo: str = "A") -> str:
    """'ip' (respondeu com endereço), 'vazio' (NXDOMAIN ou resposta sem endereço) ou 'erro' (não deu p/ saber)."""
    if not shutil.which("dig"):
        return "erro"
    try:
        r = subprocess.run(["dig", "+noall", "+comments", "+answer", "+time=3", "+tries=2", f"@{resolvedor}", tipo, nome],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return "erro"
    m = _STATUS.search(r.stdout)
    if not m:   # sem cabeçalho de resposta: timeout / rede fora
        return "erro"
    if _IP.search(r.stdout):
        return "ip"
    return "vazio" if m.group(1) in ("NXDOMAIN", "NOERROR") else "erro"   # SERVFAIL/REFUSED: não dá p/ afirmar


def resolve(nome: str) -> bool | None:
    """True = tem endereço; False = não resolve nos dois resolvedores (A e AAAA); None = não deu p/ saber."""
    vazios = 0
    for res in RESOLVEDORES:
        r = [consulta(nome, res, t) for t in ("A", "AAAA")]
        if "ip" in r:
            return True
        if r == ["vazio", "vazio"]:
            vazios += 1
    return False if vazios == len(RESOLVEDORES) else None


def inativo(nomes: list[str]) -> bool:
    """Nenhum dos nomes resolve, o domínio (1º nome) não recebe e-mail (MX) e deu p/ testar tudo."""
    for n in dict.fromkeys(nomes):
        if resolve(n) is not False:   # resolveu, ou não deu p/ saber: não é inativo
            return False
    return bool(nomes) and all(consulta(nomes[0], r, "MX") == "vazio" for r in RESOLVEDORES)


def _nomes(c, drow: dict) -> list[str]:
    fq = [r["name"] for r in c.execute(
        "SELECT f.name FROM fqdns f LEFT JOIN query_agg q ON q.fqdn_id = f.id WHERE f.domain_id = %s "
        "GROUP BY f.name ORDER BY sum(q.queries) DESC NULLS LAST LIMIT 4", (drow["id"],))]
    return list(dict.fromkeys([drow["name"], "www." + drow["name"]] + fq))


def _com_ip(c, domain_id: int) -> int:
    """Respostas COM IP que os clientes receberam em 7 dias (logs do Technitium)."""
    return c.execute("SELECT COALESCE(sum(ip_q) - sum(sem_ip), 0) AS n FROM query_agg WHERE domain_id = %s "
                     "AND bucket >= now() - interval '7 days'", (domain_id,)).fetchone()["n"]


def marcar(c, drow: dict, motivo: str) -> None:
    """Põe na lista DNS Inativo e tira das filas da IA (kind = 'inexistente', como o "Sem resposta" dos logs)."""
    nome = drow["name"]
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
    if drow.get("kind") != "public" or (drow.get("ti_signature") or "") or catalog.match(nome):
        return False
    with db.conn() as c:
        com_ip = _com_ip(c, drow["id"])
        na_lista = c.execute("SELECT 1 FROM category_lists WHERE category = %s AND domain = %s",
                             (listas.DNS_INATIVO, nome)).fetchone()
        nomes = _nomes(c, drow)
    if com_ip > 0 and not na_lista:   # os clientes recebem IP (nome interno, ou resolve mesmo): não é inativo
        return False
    morto = inativo(nomes)
    with db.conn() as c:
        if morto and (com_ip <= 0 or na_lista):   # (na lista, o Technitium responde 0.0.0.0: os logs não dizem nada)
            marcar(c, drow, "não resolve no DNS público (sem IP em " + ", ".join(nomes[:3]) + ") nem nos logs em 7 dias")
            return True
        if not morto and na_lista:
            desmarcar(c, drow)
    return False


def varrer(categoria: str = "nao_identificado", limite: int = 5000) -> dict:
    """Passada única numa lista (ex.: Não identificados): quem não resolve no DNS público vai p/ DNS Inativo."""
    from concurrent.futures import ThreadPoolExecutor
    with db.conn() as c:
        rows = c.execute("SELECT d.id, d.name, d.kind, d.classification, d.ti_signature FROM category_lists l "
                         "JOIN domains d ON d.name = l.domain WHERE l.category = %s AND coalesce(d.ti_signature, '') = '' "
                         "AND NOT d.locked ORDER BY d.total_queries DESC LIMIT %s", (categoria, limite)).fetchall()
        nomes = {r["id"]: _nomes(c, r) for r in rows}
    with ThreadPoolExecutor(12) as pool:
        mortos = list(pool.map(lambda r: inativo(nomes[r["id"]]), rows))
    n = 0
    for r, morto in zip(rows, mortos):
        if morto and not catalog.match(r["name"]):
            with db.conn() as c:
                marcar(c, r, "não resolve no DNS público (sem IP em " + ", ".join(nomes[r["id"]][:3]) + ")")
            n += 1
    log.info("DNS inativo: %d de %d da lista %s", n, len(rows), categoria)
    return {"testados": len(rows), "inativos": n}
