"""Recomendação para AMBIENTE CORPORATIVO (todos os clientes são empresas).

A IA sugere BLOQUEAR / LIBERAR / REVISAR com uma frase de justificativa; esta
política dá o padrão por categoria e trava sugestões perigosas:
* nunca recomenda BLOQUEAR infraestrutura/ferramenta de trabalho (quebraria sistemas);
* nunca recomenda LIBERAR ameaça, apostas, adulto ou VPN/proxy (contorna o filtro);
* MALICIOSO sempre BLOQUEAR; desconhecido sempre REVISAR.
É só recomendação: quem bloqueia é uma pessoa, na fila de decisão.
"""

from __future__ import annotations

ACTIONS = ["BLOQUEAR", "LIBERAR", "REVISAR"]

# padrão por categoria de site (quando a IA não opinou ou foi travada)
DEFAULT: dict[str, tuple[str, str]] = {
    "redes_sociais": ("BLOQUEAR", "rede social de uso pessoal: distrai e não tem uso profissional na maioria dos setores"),
    "streaming": ("BLOQUEAR", "vídeo/música de lazer: distrai e consome banda da empresa"),
    "jogos": ("BLOQUEAR", "jogos não têm uso profissional e consomem banda"),
    "apostas": ("BLOQUEAR", "apostas: sem uso profissional e risco jurídico/financeiro para a empresa"),
    "adulto": ("BLOQUEAR", "conteúdo adulto: inadequado no ambiente de trabalho"),
    "vpn_proxy": ("BLOQUEAR", "VPN/proxy permite contornar o filtro de DNS da empresa"),
    "ameaca": ("BLOQUEAR", "ameaça: expõe os computadores da empresa a malware/golpes"),
    "publicidade": ("REVISAR", "anúncios/rastreamento: bloquear reduz rastreamento, mas pode quebrar sites"),
    "compras": ("REVISAR", "compras online: pessoal na maioria dos casos, mas setores de compras podem usar"),
    "noticias": ("REVISAR", "portal de notícias: uso pessoal comum; avaliar conforme a política da empresa"),
    "servicos_pessoais": ("REVISAR", "serviço pessoal: avaliar conforme a política da empresa"),
    "outros": ("REVISAR", "sem categoria clara: avaliar o uso na empresa"),
    "desconhecido": ("REVISAR", "a IA não reconhece o serviço: acompanhar antes de decidir"),
    "produtividade": ("LIBERAR", "ferramenta de trabalho"),
    "comunicacao": ("LIBERAR", "comunicação usada no trabalho (e-mail, mensagens, reuniões)"),
    "financas": ("LIBERAR", "bancos e finanças usados pela empresa"),
    "governo": ("LIBERAR", "órgão público/serviço governamental usado pela empresa"),
    "infraestrutura": ("LIBERAR", "infraestrutura que sistemas e aplicativos precisam: bloquear pode quebrar algo"),
    "seguranca": ("LIBERAR", "serviço de segurança (antivírus, certificados, autenticação)"),
    "desenvolvimento": ("LIBERAR", "ferramenta de TI/desenvolvimento"),
    "educacao": ("LIBERAR", "educação/referência útil ao trabalho"),
    "saude": ("LIBERAR", "serviço de saúde"),
    "interno": ("LIBERAR", "rede interna da empresa"),
}
NEVER_BLOCK = {"produtividade", "comunicacao", "financas", "governo", "infraestrutura", "seguranca",
               "desenvolvimento", "educacao", "saude", "interno"}
NEVER_ALLOW = {"apostas", "adulto", "vpn_proxy", "ameaca"}
LEISURE = {"redes_sociais", "streaming", "jogos"}


def recommend(classification: str | None, category: str | None, risk: int | None, protected: bool = False,
              ai_action: str | None = None, ai_reason: str | None = None) -> tuple[str, str, str] | None:
    """-> (ação, justificativa, origem 'ia'|'politica') ou None (ainda sem categoria)."""
    risk = risk or 0
    if classification == "MALICIOSO":
        return "BLOQUEAR", "ameaça confirmada por fonte de Threat Intelligence", "politica"
    if protected:
        return "LIBERAR", "serviço essencial protegido (bloquear quebraria sistemas)", "politica"
    if classification == "SUSPEITO":
        if risk >= 75:
            return "BLOQUEAR", f"sinais técnicos de risco alto ({risk}): bloquear por precaução e investigar", "politica"
        return "REVISAR", f"sinais técnicos de risco ({risk}): investigar antes de decidir", "politica"
    if classification == "DESCONHECIDO" or not category:
        if not category:
            return None
        return "REVISAR", DEFAULT["desconhecido"][1], "politica"
    base, why = DEFAULT.get(category, DEFAULT["outros"])
    if classification == "TRABALHO" and category in LEISURE:
        return "REVISAR", "classificação (trabalho) e categoria (lazer) divergem: conferir", "politica"
    act = (ai_action or "").upper()
    reason = (ai_reason or "").strip()
    if act in ACTIONS and reason:
        if act == "BLOQUEAR" and (category in NEVER_BLOCK or classification == "TRABALHO"):
            return base, why, "politica"
        if act == "LIBERAR" and (category in NEVER_ALLOW or category in LEISURE):
            return base, why, "politica"
        return act, reason, "ia"
    return base, why, "politica"
