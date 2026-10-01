"""Ajustes das listas por empresa/unidade (01/10, pedido do usuário: "as listas vão ter que ser por unidade").

A lista de bloqueio é uma só (a IA alimenta p/ todas as empresas); cada escopo — empresa (`tenant:<id>`) ou unidade
(`unit:<id>:<unidade>`) — guarda os próprios ajustes: `liberar` (o site sai das listas só ali) ou `bloquear` (bloqueado
só ali). Unidade herda os ajustes da empresa e o ajuste dela vence o da empresa. O Technitium assina, no grupo do
escopo, as duas listas já resolvidas: /ajustes/liberar/<token>.txt e /ajustes/bloquear/<token>.txt.
"""

from __future__ import annotations

import base64
import re

ACOES = ("liberar", "bloquear")
_ESCOPO = re.compile(r"tenant:\d+|unit:\d+:.{1,120}")
_DOMINIO = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}")


def escopo_ok(scope: str) -> bool:
    return bool(_ESCOPO.fullmatch(scope or ""))


def empresa_do(scope: str) -> str | None:
    """Escopo da empresa de uma unidade (None se já é a empresa)."""
    return "tenant:" + scope.split(":")[1] if scope.startswith("unit:") else None


def token(scope: str) -> str:
    """Escopo -> nome seguro p/ URL (o nome da unidade tem espaço e acento)."""
    return base64.urlsafe_b64encode(scope.encode()).decode().rstrip("=")


def escopo_do_token(t: str) -> str | None:
    try:
        scope = base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    return scope if escopo_ok(scope) else None


def normalizar(dominios: list[str]) -> list[str]:
    out = []
    for d in dominios:
        d = (d or "").strip().lower().rstrip(".")
        d = re.sub(r"^https?://", "", d).split("/")[0]
        if _DOMINIO.fullmatch(d) and d not in out:
            out.append(d)
    return out


def proprios(c, scope: str) -> list[dict]:
    return c.execute("SELECT scope, domain, acao, por, em FROM ajustes_lista WHERE scope = %s ORDER BY domain", (scope,)).fetchall()


def efetivo(c, scope: str) -> dict[str, list[str]]:
    """{"liberar": [...], "bloquear": [...]} que valem no escopo: os da empresa + os da unidade (que vencem)."""
    vale: dict[str, str] = {}
    for s in (empresa_do(scope), scope):   # empresa primeiro; a unidade sobrescreve
        if s:
            for r in c.execute("SELECT domain, acao FROM ajustes_lista WHERE scope = %s", (s,)):
                vale[r["domain"]] = r["acao"]
    return {a: sorted(d for d, x in vale.items() if x == a) for a in ACOES}


def gravar(c, scope: str, dominios: list[str], acao: str, por: str | None) -> int:
    n = 0
    for d in normalizar(dominios):
        c.execute("INSERT INTO ajustes_lista (scope, domain, acao, por) VALUES (%s, %s, %s, %s) ON CONFLICT (scope, domain) "
                  "DO UPDATE SET acao = EXCLUDED.acao, por = EXCLUDED.por, em = now()", (scope, d, acao, por))
        c.execute("INSERT INTO ajustes_lista_log (scope, domain, acao, por) VALUES (%s, %s, %s, %s)", (scope, d, acao, por))
        n += 1
    return n


def desfazer(c, scope: str, dominios: list[str], por: str | None) -> int:
    n = 0
    for d in normalizar(dominios):
        if c.execute("DELETE FROM ajustes_lista WHERE scope = %s AND domain = %s", (scope, d)).rowcount:
            c.execute("INSERT INTO ajustes_lista_log (scope, domain, acao, por) VALUES (%s, %s, 'desfazer', %s)", (scope, d, por))
            n += 1
    return n


def resumo(c) -> dict[str, dict[str, int]]:
    """{escopo: {"liberar": n, "bloquear": n}} dos escopos com ajuste próprio (o console cria o grupo deles)."""
    out: dict[str, dict[str, int]] = {}
    for r in c.execute("SELECT scope, acao, count(*) AS n FROM ajustes_lista GROUP BY 1, 2"):
        out.setdefault(r["scope"], {"liberar": 0, "bloquear": 0})[r["acao"]] = r["n"]
    return out
