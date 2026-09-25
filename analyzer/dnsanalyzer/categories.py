"""Categoria do site (vocabulário fixo da tabela site_categories).

A IA escolhe a categoria direto no JSON (enum). Este módulo mapeia um "assunto"
em texto livre para a categoria — usado no catálogo e para preencher domínios
classificados antes da categoria existir.
"""

from __future__ import annotations

import unicodedata

# (palavras-chave, categoria) — primeira que casar vence (específicas primeiro)
_RULES: list[tuple[tuple[str, ...], str]] = [
    (("malware", "phishing", "comando e controle", "c2", "ameaca", "badware"), "ameaca"),
    (("vpn", "proxy", "doh", "contorno de filtro"), "vpn_proxy"),
    (("aposta", "cassino", "casino", "bet"), "apostas"),
    (("adulto", "porn"), "adulto"),
    (("publicidade", "rastreamento", "anuncio", "analytics", "marketing digital", "atribuicao"), "publicidade"),
    (("rede social", "redes sociais", "social", "videos curtos"), "redes_sociais"),
    (("jogo", "game", "gaming"), "jogos"),
    (("streaming", "video", "musica", "filme", "serie"), "streaming"),
    (("compra", "e-commerce", "ecommerce", "loja", "marketplace"), "compras"),
    (("delivery", "transporte", "viage", "comida"), "servicos_pessoais"),
    (("noticia", "portal", "entretenimento", "revista", "jornal"), "noticias"),
    (("banco", "pagamento", "financ", "contab", "credito"), "financas"),
    (("governo", "judicia", "fiscal", "tribunal", "prefeitura", "registro de dominios"), "governo"),
    (("antivirus", "seguranca", "edr", "firewall"), "seguranca"),
    (("desenvolvimento", "suporte remoto", "github", "programa"), "desenvolvimento"),
    (("educa", "curso", "enciclopedia", "documentacao", "escola", "universidade"), "educacao"),
    (("saude", "clinica", "hospital", "odonto", "medic"), "saude"),
    (("e-mail", "email", "mensageiro", "comunicacao", "videoconferencia", "chat"), "comunicacao"),
    (("cdn", "infraestrutura", "nuvem", "azure", "atualizac", "certificado", "pki", "ntp", "hora",
      "windows", "sistema", "dns", "api", "conectividade", "navegador"), "infraestrutura"),
    (("erp", "microsoft 365", "office", "sharepoint", "onedrive", "produtividade", "design", "armazenamento",
      "crm", "suporte ao cliente", "gestao", "rede profissional", "microsoft", "google", "apple", "adobe",
      "zendesk", "atendimento"), "produtividade"),
    (("interno",), "interno"),
]


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return s


def from_topic(topic: str | None) -> str | None:
    """Assunto livre -> categoria. Chaves curtas (<= 4 letras: api, dns, bet, jogo...) só
    casam no INÍCIO de uma palavra (jogo->jogos), nunca no meio ("terapia", "alphabet")."""
    import re
    t = _norm(topic or "")
    if not t:
        return None
    words = re.findall(r"[a-z0-9]+", t)
    for keys, cat in _RULES:
        if any(any(w.startswith(k) for w in words) if len(k) <= 4 else (k in t) for k in keys):
            return cat
    return None


def catalog_category(entry: dict) -> str:
    return entry.get("category") or from_topic(entry.get("topic")) or "outros"
