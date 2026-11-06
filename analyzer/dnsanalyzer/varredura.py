"""Computadores em varredura (06/11/2026, pedido do usuário).

Um computador comum traz ~1 domínio INÉDITO por hora (nunca visto por nenhum outro computador de nenhuma empresa;
mediana medida em 06/11; 99% das horas até 34). Dispositivo infectado/robô que percorre listas de domínios traz
centenas (192.168.21.165 na Cotrel: 424/h, 15 mil domínios que ninguém mais acessou, 13 mil deles gastando a IA).

* Acima de VARREDURA_LIMITE_HORA (padrão 50) domínios inéditos numa janela de 60 min, o computador fica TRAVADO
  (dispositivos_varredura) e sai um alerta ("varredura", alta).
* Domínio que só computadores travados/confirmados acessaram fica retido (domains.varredura): nenhuma fase da IA
  (regras, IA local, busca, WHOIS, IA online, listas, investigação) o pega. Se um computador comum acessar o domínio,
  ele volta sozinho ao fluxo normal (a retenção só segura, não apaga nem classifica).
* Pessoa avalia em IA ao vivo → "Computadores travados": LIBERAR (falso positivo: os domínios voltam para a fila e o
  computador não é mais travado) ou CONFIRMAR (segue travado; os domínios seguem retidos).
"""
from __future__ import annotations

import logging
import time

from psycopg.types.json import Jsonb

from . import db
from .config import settings

log = logging.getLogger(__name__)

TRAVA = ("travado", "confirmado")      # estados que retêm os domínios
_ULTIMA_VARREDURA_COMPLETA = [0.0]

# dispositivos com mais de N domínios inéditos na última hora. Parte dos domínios NOVOS para o analisador (~250/h no
# total) e acha quem os trouxe na cópia do log: ~0,1 s (medido 06/11).
_DETECTAR = """
SELECT q.tenant_id, q.client_ip AS ip, count(DISTINCT q.domain_id) AS n,
       (array_agg(DISTINCT d.name))[1:12] AS exemplos
FROM query_log q JOIN domains d ON d.id = q.domain_id
WHERE q.ts > now() - interval '60 minutes' AND d.first_seen > now() - interval '62 minutes'
  AND q.ts <= d.first_seen + interval '2 minutes' AND d.kind = 'public'
GROUP BY 1, 2 HAVING count(DISTINCT q.domain_id) > %(limite)s
"""

# domínio (visto nos últimos `dias`) que algum computador travado acessou e nenhum outro acessou (cópia do log)
_RETER = """
UPDATE domains d SET varredura = true
WHERE NOT d.varredura AND d.kind = 'public' AND d.first_seen > now() - %(janela)s::interval
  AND EXISTS (SELECT 1 FROM query_log q JOIN dispositivos_varredura v
                ON v.tenant_id = q.tenant_id AND v.ip = q.client_ip AND v.estado = ANY(%(trava)s)
              WHERE q.domain_id = d.id)
  AND NOT EXISTS (SELECT 1 FROM query_log q LEFT JOIN dispositivos_varredura v
                    ON v.tenant_id = q.tenant_id AND v.ip = q.client_ip AND v.estado = ANY(%(trava)s)
                  WHERE q.domain_id = d.id AND v.ip IS NULL)
RETURNING d.id
"""

# retido que um computador comum passou a acessar: volta ao fluxo normal
_SOLTAR = """
UPDATE domains d SET varredura = false
WHERE d.varredura
  AND EXISTS (SELECT 1 FROM query_log q LEFT JOIN dispositivos_varredura v
                ON v.tenant_id = q.tenant_id AND v.ip = q.client_ip AND v.estado = ANY(%(trava)s)
              WHERE q.domain_id = d.id AND q.ts > now() - %(janela)s::interval AND v.ip IS NULL)
RETURNING d.id
"""

# domínios antigos (fora da cópia do log, 7 dias) que só o computador travado tem — na hora em que ele é travado.
# Soma de computadores por empresa (tenant_domains) = quantos computadores travados o acessaram.
_RETER_HISTORICO = """
WITH dele AS (
  SELECT cd.domain_id, count(*) AS travados
  FROM dispositivos_varredura v JOIN client_domains cd ON cd.tenant_id = v.tenant_id AND cd.client_id = v.client_id
  WHERE v.estado = ANY(%(trava)s)
    AND cd.domain_id IN (SELECT domain_id FROM client_domains WHERE tenant_id = %(tid)s AND client_id = %(cid)s)
  GROUP BY cd.domain_id),
td AS (SELECT td.domain_id, sum(td.clients_count) AS todos FROM tenant_domains td JOIN dele USING (domain_id)
       GROUP BY td.domain_id)
UPDATE domains d SET varredura = true FROM dele JOIN td USING (domain_id)
WHERE d.id = dele.domain_id AND NOT d.varredura AND d.kind = 'public' AND td.todos <= dele.travados
RETURNING d.id
"""


def _limite() -> int:
    return max(settings().varredura_limite_hora, 1)


def detectar(c) -> list[dict]:
    """Trava (e alerta) quem passou do limite agora. Liberado por pessoa não volta a ser travado."""
    from .behavior import _upsert_alert
    novos = []
    for r in c.execute(_DETECTAR, {"limite": _limite()}).fetchall():
        cli = c.execute("SELECT id FROM clients WHERE tenant_id = %s AND ip = %s", (r["tenant_id"], r["ip"])).fetchone()
        if not cli:
            continue
        atual = c.execute("SELECT estado FROM dispositivos_varredura WHERE tenant_id = %s AND client_id = %s",
                          (r["tenant_id"], cli["id"])).fetchone()
        ex = list(r["exemplos"] or [])
        if atual:
            c.execute("UPDATE dispositivos_varredura SET ultima_hora = %s, pior_hora = greatest(pior_hora, %s), "
                      "visto_em = now(), exemplos = %s WHERE tenant_id = %s AND client_id = %s",
                      (r["n"], r["n"], Jsonb(ex), r["tenant_id"], cli["id"]))
            continue
        c.execute("INSERT INTO dispositivos_varredura (tenant_id, client_id, ip, pior_hora, ultima_hora, exemplos) "
                  "VALUES (%s, %s, %s, %s, %s, %s)", (r["tenant_id"], cli["id"], r["ip"], r["n"], r["n"], Jsonb(ex)))
        _upsert_alert(c, r["tenant_id"], "varredura", "high",
                      f"{r['ip']}: {r['n']} domínios inéditos em 1 hora (varredura) — computador travado para avaliação",
                      f"varredura:{cli['id']}", {"ip": str(r["ip"]), "count": r["n"], "examples": ex}, client_id=cli["id"])
        novos.append({"tenant_id": r["tenant_id"], "client_id": cli["id"], "ip": str(r["ip"]), "n": r["n"]})
    return novos


def reter_historico(c, tid: int, cid: int) -> int:
    return len(c.execute(_RETER_HISTORICO, {"trava": list(TRAVA), "tid": tid, "cid": cid}).fetchall())


def ciclo() -> dict:
    """Roda a cada minuto (thread de tarefas do coletor): trava quem passou do limite, retém os domínios só deles e
    solta os que um computador comum passou a acessar. De hora em hora, a retenção olha os 7 dias da cópia do log."""
    if not settings().varredura_enabled:
        return {}
    out = {"travados": 0, "retidos": 0, "soltos": 0}
    completa = time.monotonic() - _ULTIMA_VARREDURA_COMPLETA[0] > 3600
    with db.conn() as c:
        novos = detectar(c)
        out["travados"] = len(novos)
        for n in novos:
            out["retidos"] += reter_historico(c, n["tenant_id"], n["client_id"])
            log.warning("varredura: %s (empresa %s) com %d domínios inéditos em 1 h — travado para avaliação",
                        n["ip"], n["tenant_id"], n["n"])
        tem = c.execute("SELECT 1 FROM dispositivos_varredura WHERE estado = ANY(%s) LIMIT 1", (list(TRAVA),)).fetchone()
        if tem:
            out["retidos"] += len(c.execute(_RETER, {"trava": list(TRAVA), "janela": "7 days" if completa else "3 hours"}).fetchall())
        out["soltos"] = len(c.execute(_SOLTAR, {"trava": list(TRAVA), "janela": "10 minutes"}).fetchall()) if tem or completa else 0
    if completa:
        _ULTIMA_VARREDURA_COMPLETA[0] = time.monotonic()
    if any(out.values()):
        log.info("varredura: %s", out)
    return out


def listar(c) -> list[dict]:
    """Computadores travados (e decididos) com o que está retido por causa deles."""
    return c.execute(
        "SELECT v.tenant_id, t.name AS empresa, v.client_id, host(v.ip) AS ip, v.estado, v.detectado_em, v.visto_em, "
        "       v.pior_hora, v.ultima_hora, v.exemplos, v.decidido_por, v.decidido_em, "
        "       (SELECT count(*) FROM client_domains cd JOIN domains d ON d.id = cd.domain_id "
        "        WHERE cd.tenant_id = v.tenant_id AND cd.client_id = v.client_id AND d.varredura) AS retidos "
        "FROM dispositivos_varredura v JOIN tenants t ON t.id = v.tenant_id "
        "ORDER BY (v.estado = 'travado') DESC, v.detectado_em DESC").fetchall()


def decidir(c, tid: int, cid: int, acao: str, por: str) -> dict:
    """liberar = falso positivo (não trava mais; os domínios só dele voltam para a fila); confirmar = segue travado."""
    if acao not in ("liberar", "confirmar"):
        raise ValueError("ação inválida (liberar | confirmar)")
    r = c.execute("UPDATE dispositivos_varredura SET estado = %s, decidido_por = %s, decidido_em = now() "
                  "WHERE tenant_id = %s AND client_id = %s RETURNING host(ip) AS ip",
                  ("liberado" if acao == "liberar" else "confirmado", por or "manual", tid, cid)).fetchone()
    if not r:
        raise LookupError("computador não está na lista de varredura")
    soltos = 0
    if acao == "liberar":   # o que só ele (ou outro travado) segurava volta; outro travado retém de novo no próximo ciclo
        soltos = c.execute(
            "UPDATE domains d SET varredura = false FROM client_domains cd "
            "WHERE cd.tenant_id = %s AND cd.client_id = %s AND d.id = cd.domain_id AND d.varredura", (tid, cid)).rowcount
    c.execute("UPDATE alerts SET status = 'closed', ack_by = %s, updated_at = now() WHERE dedup_key = %s AND tenant_id = %s "
              "AND status <> 'closed'", (por or "manual", f"varredura:{cid}", tid))
    log.info("varredura: %s %s por %s (%d domínio(s) de volta à fila)", r["ip"], acao, por, soltos)
    return {"ok": True, "ip": r["ip"], "estado": "liberado" if acao == "liberar" else "confirmado", "soltos": soltos}
