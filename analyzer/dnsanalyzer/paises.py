"""Bloqueio por país (22/10, pedido do usuário): domínios da China e da Rússia (domínio de país) vão direto para a
lista "China e Rússia", aplicada a todos os clientes, sem passar por nenhuma etapa da IA.

Decidido na fase A (regras), antes de qualquer fila: sai sem pendência p/ a IA local, com classificação da regra
(Não trabalho; Suspeito/Malicioso se as regras ou listas de ameaça já disserem), com a lista gravada (a pergunta de
lista, a IA online e a investigação não pegam) e com decisão global "bloquear". Sai das outras listas de bloqueio e
das whitelists postas pela IA/catálogo/migração; a liberação feita por pessoa fica (vence no DNS, como sempre).
"""

from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)

LISTA = "china_russia"
POR = "regra: domínio da China/Rússia"
# domínios de país: China .cn (+ .中国/.中國) e Rússia .ru, .su (antiga URSS, hoje russo) e .рф
TLDS = ("cn", "xn--fiqs8s", "xn--fiqz9s", "ru", "su", "xn--p1ai")
_RE = re.compile(r"\.(" + "|".join(TLDS) + r")$")
def sql(col: str = "name") -> str:
    """Filtro SQL (filas da IA, migração): sql("d.name"), sql("domain")."""
    return f"{col} ~ '\\.(" + "|".join(TLDS) + ")$'"
TOPICO = "Domínio da China/Rússia (bloqueio por país)"


def bloqueado(nome: str | None) -> bool:
    return bool(nome) and bool(_RE.search(nome.strip().lower().rstrip(".")))


def _pessoa(por: str | None) -> bool:
    """Entrada posta por pessoa (fica): não é IA, catálogo, migração, regra nem decisão automática."""
    p = (por or "").lower()
    return bool(p) and not p.startswith(("ia ", "ia(", "ia automática", "catálogo", "migração", "regra", "bloqueio automático",
                                         "investigação", "decisão humana (liberado)", "verificação"))


def aplicar(c, ids: list[int]) -> int:
    """Põe os domínios (já da China/Rússia) na lista e os tira de todas as etapas da IA. Retorna quantos."""
    from . import listas
    rows = c.execute("SELECT id, name, classification FROM domains WHERE id = ANY(%s)", (ids,)).fetchall()
    rows = [r for r in rows if bloqueado(r["name"])]
    if not rows:
        return 0
    nomes = [r["name"] for r in rows]
    listas.contexto(c, POR, "domínio da China/Rússia: direto p/ a lista, sem IA")
    # sai das outras listas de bloqueio e das whitelists automáticas (a de pessoa fica)
    for r in c.execute("SELECT category, domain, added_by FROM category_lists WHERE domain = ANY(%s) AND category <> %s",
                       (nomes, LISTA)).fetchall():
        if not _pessoa(r["added_by"]):
            c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (r["category"], r["domain"]))
    for r in c.execute("SELECT category, domain, added_by FROM whitelist_domains WHERE domain = ANY(%s)", (nomes,)).fetchall():
        if not _pessoa(r["added_by"]):
            c.execute("DELETE FROM whitelist_domains WHERE category = %s AND domain = %s", (r["category"], r["domain"]))
    c.execute("INSERT INTO category_lists (category, domain, added_by) SELECT %s, n, %s FROM unnest(%s::text[]) n "
              "ON CONFLICT DO NOTHING", (LISTA, POR, nomes))
    c.execute(
        "UPDATE domains SET llm_pending = false, aguarda_recorrencia = false, needs_analysis = false, claimed_at = NULL, "
        " reanalise_pedida = false, lista_duvida = false, online_pedido_at = NULL, "
        " classification = CASE WHEN classification IN ('SUSPEITO', 'MALICIOSO') THEN classification ELSE 'NAO_TRABALHO' END, "
        " topic = CASE WHEN classification IN ('SUSPEITO', 'MALICIOSO') THEN topic ELSE %s END, "
        " lista_ia = %s, lista_conf = 1, lista_fonte = 'regra', lista_fase = 0, lista_wl = NULL, "
        " lista_at = now(), lista_aplicada_at = now(), revisado_at = coalesce(revisado_at, now()) "
        "WHERE id = ANY(%s)", (TOPICO, LISTA, [r["id"] for r in rows]))
    ids_ = [r["id"] for r in rows]
    # decisão global "bloquear" (= decidido: nenhuma fila da IA pega); a de pessoa fica
    for g in c.execute("SELECT domain_id, reviewed_by FROM global_reviews WHERE domain_id = ANY(%s)", (ids_,)).fetchall():
        if not _pessoa(g["reviewed_by"]):
            c.execute("UPDATE global_reviews SET status = 'blocked', reviewed_by = %s, reviewed_at = now() WHERE domain_id = %s",
                      (POR, g["domain_id"]))
    c.execute("INSERT INTO global_reviews (domain_id, status, reviewed_by) SELECT id, 'blocked', %s FROM unnest(%s::bigint[]) id "
              "ON CONFLICT (domain_id) DO NOTHING", (POR, ids_))
    return len(rows)


def migrar(c, lote: int = 500) -> int:
    """Uma vez (22/10): todos os domínios da China/Rússia já vistos vão p/ a lista. Retorna quantos."""
    from . import listas
    ids = [r["id"] for r in c.execute("SELECT id FROM domains WHERE kind = 'public' AND " + sql("name"))]
    n = 0
    for i in range(0, len(ids), lote):
        n += aplicar(c, ids[i:i + lote])
    # entradas de lista sem domínio ativo (inexistente — DNS Inativo — ou nunca visto nos logs): também p/ a lista; as
    # automáticas saem das outras, a de pessoa fica
    resto = c.execute("SELECT category, domain, added_by FROM category_lists WHERE category <> %s AND " + sql("domain"),
                      (LISTA,)).fetchall()
    if resto:
        listas.contexto(c, POR, "domínio da China/Rússia: direto p/ a lista, sem IA")
        c.execute("INSERT INTO category_lists (category, domain, added_by) SELECT %s, n, %s FROM unnest(%s::text[]) n "
                  "ON CONFLICT DO NOTHING", (LISTA, POR, sorted({r["domain"] for r in resto})))
        for r in resto:
            if not _pessoa(r["added_by"]):
                c.execute("DELETE FROM category_lists WHERE category = %s AND domain = %s", (r["category"], r["domain"]))
    log.info("bloqueio por país: %d domínio(s) da China/Rússia na lista %s (+%d entradas de outras listas)", n, LISTA, len(resto))
    return n
