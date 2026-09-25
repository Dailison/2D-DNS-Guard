"""Aviso à TI por webhook quando surge um alerta de RISCO.

Payload JSON genérico com os campos do alerta + `text` (Slack/Teams/Google Chat/n8n)
e `content` (Discord). Configuração:
  WEBHOOK_URLS          URLs separadas por vírgula (vazio = desligado)
  WEBHOOK_KINDS         tipos de alerta enviados (padrão: malicious_access,suspicious_access,dga_burst)
  PORTAL_URL            base do link no aviso (padrão https://dns-guard.2dtecnologia.com)
  PUSH_API_URL/TOKEN    push no celular pelo mesmo canal do 2D-Monitoramento: API do ERP
                        (POST <url>/push/send, inscritos no app PUSH_APP_NAME)
Cada alerta é enviado uma vez (alerts.notified_at); falhas ficam em notify_error e
são tentadas de novo por até 1 hora.
"""

from __future__ import annotations

import logging

import httpx

from .config import settings

log = logging.getLogger(__name__)
SEV_ICON = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "⚪"}


def _payload(a: dict) -> dict:
    cfg = settings()
    base = cfg.portal_url.rstrip("/")
    link = f"{base}/analise/dominio/{a['domain']}?t={a['tenant_id']}" if a.get("domain") \
        else f"{base}/analise/alertas?t={a['tenant_id']}"
    det = a.get("details") or {}
    ips = det.get("ips") or ([det["ip"]] if det.get("ip") else [])
    linhas = [f"{SEV_ICON.get(a['severity'], '•')} [DNS · {a['tenant_name']}] {a['title']}"]
    if a.get("domain"):
        linhas.append(f"Domínio: {a['domain']}" + (f" (risco {det.get('risk')})" if det.get("risk") else ""))
    if ips:
        linhas.append("Computador(es): " + ", ".join(ips[:10]) + (" …" if len(ips) > 10 else ""))
    linhas.append(f"Ver no DNS Guard: {link}")
    text = "\n".join(linhas)
    return {"event": "dns_alert", "id": a["id"], "severity": a["severity"], "kind": a["kind"],
            "tenant": a["tenant_name"], "title": a["title"], "domain": a.get("domain"), "ips": ips,
            "details": det, "created_at": a["created_at"].isoformat(), "url": link,
            "text": text, "content": text[:1900]}


def _push(a: dict, body: dict) -> None:
    """Notificação push (Web Push) pelos celulares inscritos no 2D-Monitoramento."""
    cfg = settings()
    det = a.get("details") or {}
    title = f"{SEV_ICON.get(a['severity'], '•')} DNS · {a['tenant_name']}"
    texto = a["title"] + (f" — {a['domain']}" if a.get("domain") and a["domain"] not in a["title"] else "")
    if body["ips"]:
        texto += f" ({', '.join(body['ips'][:3])}{' …' if len(body['ips']) > 3 else ''})"
    r = httpx.post(cfg.push_api_url.rstrip("/") + "/push/send", timeout=30,
                   headers={"Authorization": f"Bearer {cfg.push_api_token}"},
                   json={"title": title, "body": texto[:240], "url": body["url"], "app_name": cfg.push_app_name,
                         "data": {"source": "dns-guard", "alert_id": a["id"], "severity": a["severity"],
                                  "kind": a["kind"], "domain": a.get("domain"), "risk": det.get("risk")}})
    r.raise_for_status()


def notify_pending(c) -> dict:
    cfg = settings()
    urls = cfg.webhook_urls
    push = bool(cfg.push_api_url and cfg.push_api_token)
    if not urls and not push:
        return {"enabled": False}
    rows = c.execute(
        "SELECT a.*, t.name AS tenant_name, d.name AS domain FROM alerts a JOIN tenants t ON t.id=a.tenant_id "
        "LEFT JOIN domains d ON d.id=a.domain_id "
        "WHERE a.notified_at IS NULL AND a.kind = ANY(%s) AND a.status='open' "
        "AND a.created_at > now() - interval '1 hour' ORDER BY a.created_at LIMIT 50",
        (cfg.webhook_kinds,)).fetchall()
    sent, failed = 0, 0
    for a in rows:
        body = _payload(a)
        erros = []
        for u in urls:
            try:
                r = httpx.post(u, json=body, timeout=10)
                if r.status_code >= 300:
                    erros.append(f"{u[:40]}…: HTTP {r.status_code}")
            except httpx.HTTPError as e:
                erros.append(f"{u[:40]}…: {e.__class__.__name__}")
        if push:
            try:
                _push(a, body)
            except httpx.HTTPError as e:
                erros.append(f"push: {e.__class__.__name__}")
        if erros and len(erros) == len(urls) + push:
            c.execute("UPDATE alerts SET notify_error=%s WHERE id=%s", ("; ".join(erros)[:500], a["id"]))
            failed += 1
        else:
            c.execute("UPDATE alerts SET notified_at=now(), notify_error=%s WHERE id=%s",
                      ("; ".join(erros)[:500] or None, a["id"]))
            sent += 1
    if sent or failed:
        log.info("webhook: %d aviso(s) enviado(s), %d falha(s)", sent, failed)
    return {"enabled": True, "sent": sent, "failed": failed}
