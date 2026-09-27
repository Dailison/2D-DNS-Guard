"""Whitelists por categoria: sites de TRABALHO que não podem ser bloqueados, publicados p/ o Technitium
(/whitelist/<cat>.txt, assinados por todos os grupos — vencem qualquer bloqueio, inclusive por CNAME).

Entra sozinho (pedido do usuário 2026-09-26: "a IA põe sozinha o que tiver certeza"):
- DOIS modelos online de acordo (volume + segunda opinião), ambos ≥ 0,9: TRABALHO, reconhecido, lista "nenhuma"
  (na simulação de 26/09 um modelo só punha rastreamento, CDN de streaming e até "creditcardsbay.com");
- infraestrutura protegida do catálogo.
Nunca entra site cujo nome ou descrição indique CDN/estáticos, analytics/rastreamento/anúncio, streaming ou jogo
(furaria as listas de bloqueio das empresas).
Travas (a whitelist vence tudo e vale p/ os subdomínios): nunca com acerto em feed de ameaça, nunca SUSPEITO/
MALICIOSO, nunca plataforma de hospedagem compartilhada (evidência "platform" ou raiz de CDN/hospedagem), nunca
se o domínio (ou um pai) está numa lista de bloqueio, nunca "pai" de algo que está numa lista de bloqueio.
Sai sozinho quando cai numa trava (acerto em feed = sai na hora do ciclo; entrada manual só sai por feed).
"""

from __future__ import annotations

import logging
import re

from . import catalog, eventos, listas
from .config import settings

log = logging.getLogger(__name__)
CATEGORIAS = {
    "essenciais": "Essenciais (catálogo)",
    "produtividade": "Produtividade e escritório",
    "comunicacao": "Comunicação corporativa",
    "erp_gestao": "ERP, gestão e fiscal",
    "financas": "Bancos, pagamentos e maquininhas",
    "governo": "Governo e órgãos públicos",
    "juridico": "Jurídico, cartórios e conselhos",
    "rh_beneficios": "RH, folha e benefícios",
    "vendas_crm": "Vendas, CRM e atendimento",
    "logistica": "Logística, transporte e entregas",
    "fornecedores": "Fornecedores, indústria e B2B",
    "institucional": "Sites institucionais de empresas",
    "telecom": "Telecom e internet",
    "infraestrutura": "Infraestrutura e sistemas",
    "cdn": "CDN e entrega de conteúdo",
    "seguranca": "Segurança",
    "desenvolvimento": "TI e desenvolvimento",
    "educacao": "Educação e cursos",
    "saude": "Saúde",
    "utilidades": "Utilidades (conversores, PDF, tradutores)",
    "servicos": "Serviços do dia a dia (mapas, clima, viagens)",
    "outros_trabalho": "Outros de trabalho",
    "outros_liberados": "Outros liberados (não é trabalho, sem lista de bloqueio)",
    "sem_resposta": "Sem resposta (não resolve no DNS)",   # pelo log do Technitium, antes da IA; nunca publicado
}
SEM_RESPOSTA = "sem_resposta"
# o que cada whitelist abrange — vai no prompt das IAs (fases 1-4 escolhem a categoria de quem é liberado)
DESCRICOES = {
    "produtividade": "Microsoft 365/Office, Google Workspace, e-mail, documentos, agenda, armazenamento da empresa, SaaS de escritório",
    "comunicacao": "videoconferência e telefonia corporativa (Teams, Zoom, Meet, Webex, PABX em nuvem), e-mail corporativo",
    "erp_gestao": "ERP e sistemas de gestão (TOTVS, SAP, Omie, Bling, Sankhya), contabilidade, emissão de NF-e, sistemas fiscais",
    "financas": "bancos, fintechs, meios de pagamento, maquininhas (Ton, Stone, Cielo), boletos, cartões, investimentos tradicionais",
    "governo": "gov.br, Receita, SEFAZ, prefeituras, eSocial, INSS, tribunais, órgãos públicos",
    "juridico": "cartórios, OAB, conselhos de classe (CRC, CREA, CRM), sindicatos, associações, escritórios de advocacia",
    "rh_beneficios": "folha, ponto, benefícios (VR, Alelo, Pluxee, Caju), recrutamento, planos de saúde corporativos",
    "vendas_crm": "CRM, automação de marketing, atendimento e helpdesk (RD Station, HubSpot, Salesforce, Zendesk), loja da própria empresa",
    "logistica": "transportadoras, rastreio, Correios, fretes, entregas, gestão de frota, rastreamento de veículos",
    "fornecedores": "fabricantes, distribuidores, indústria, atacado B2B, catálogos de produtos, portais de compras corporativas",
    "institucional": "site institucional de empresa, cliente ou parceiro (apresenta a empresa, sem ser loja nem sistema)",
    "telecom": "operadoras de telefonia e internet, provedores regionais",
    "infraestrutura": "nuvem para sistemas, APIs, atualizações de sistema e drivers, certificados, telemetria técnica (CDN tem categoria própria)",
    "cdn": "CDN genérica e entrega de conteúdo: CloudFront, Akamai, Fastly, Azure Front Door, Cloudflare, Bunny, jsDelivr, "
           "subdomínio aleatório de CDN (d1abc.cloudfront.net) e CDN sem serviço identificado; CDN de um serviço conhecido "
           "vai para a lista do serviço",
    "seguranca": "antivírus, EDR, firewall, bloqueadores de anúncio, gerenciadores de senha, autenticação, VPN corporativa",
    "desenvolvimento": "ferramentas de TI e desenvolvimento, repositórios, documentação técnica, suporte técnico",
    "educacao": "escolas, faculdades, cursos, plataformas de ensino, enciclopédias, dados educacionais",
    "saude": "hospitais, clínicas, laboratórios, planos de saúde, sistemas de saúde",
    "utilidades": "ferramentas online legítimas: conversores de arquivo, PDF, tradutores, calculadoras, encurtadores",
    "servicos": "mapas, trânsito, clima, viagens, mobilidade, serviços do dia a dia",
    "outros_trabalho": "trabalho, mas nenhuma das categorias acima",
    "outros_liberados": "não é de trabalho e não se encaixa em nenhuma lista de bloqueio (religião, cultura, ONGs, pessoal)",
}
AUTO_BY = "IA whitelist"
CATALOGO_BY = "catálogo (protegido)"
# raízes de CDN/hospedagem compartilhada: liberar a raiz liberaria qualquer site hospedado nela
_COMPARTILHADOS = ("akamaihd.net", "akamaized.net", "akamai.net", "edgekey.net", "edgesuite.net", "cloudfront.net",
                   "amazonaws.com", "azureedge.net", "azurefd.net", "trafficmanager.net", "azurewebsites.net",
                   "cloudapp.net", "cloudapp.azure.com", "fastly.net", "fastlylb.net", "cloudflare.net", "workers.dev",
                   "pages.dev", "googleusercontent.com", "appspot.com", "firebaseapp.com", "web.app", "herokuapp.com",
                   "herokudns.com", "github.io", "githubusercontent.com", "vercel.app", "netlify.app", "blogspot.com",
                   "wordpress.com", "wixsite.com", "b-cdn.net", "cdn77.org", "impervadns.net", "incapdns.net",
                   "ngrok.io", "ngrok-free.app", "duckdns.org", "no-ip.com", "ddns.net", "000webhostapp.com")


_CONF = 0.9
_NOME_RUIM = re.compile(r"(cdn|static|img|image|assets|media|video|stream|analytic|pixel|track|tag|ads?\b|advert|metric|telemetr|beacon)",
                        re.I)
_SERVICO_RUIM = re.compile(r"(cdn|distribui[çc][ãa]o de conte[úu]do|est[áa]tic|imagens|m[íi]dia|analytic|rastreament|publicidad|an[úu]nc|"
                           r"tag manager|pixel|telemetri|streaming|v[íi]deo|jogo|game|aposta|cassino|adult|cripto|trading)", re.I)


def _dois_modelos(r) -> bool:
    antes = r.get("antes") or {}
    try:
        return ((antes.get("lista") in (None, "nenhuma") or str(antes.get("lista") or "").startswith("wl:"))
                and antes.get("classificacao") == "TRABALHO"
                and float(antes.get("confianca") or 0) >= _CONF and float(r.get("lista_conf") or 0) >= _CONF)
    except (TypeError, ValueError):
        return False


def _cara_de_bloqueio(nome: str, servico: str | None) -> bool:
    return bool(_NOME_RUIM.search(nome.split(".")[0]) or _SERVICO_RUIM.search(servico or ""))


_DE_SITE = {"servicos_pessoais": "servicos"}   # categoria de site (classificação) -> whitelist


def _categoria(cat_ia: str | None, classificacao: str | None = None) -> str:
    """Whitelist de quem é liberado sem categoria de whitelist escolhida pela IA (respostas antigas)."""
    cat_ia = _DE_SITE.get(cat_ia or "", cat_ia)
    if cat_ia in CATEGORIAS and cat_ia not in ("essenciais", "outros_trabalho", "outros_liberados"):
        return cat_ia
    return "outros_liberados" if classificacao == "NAO_TRABALHO" else "outros_trabalho"


def _compartilhado(nome: str, evidencia: list | None) -> bool:
    if any(e.get("kind") == "platform" for e in evidencia or []):
        return True
    return any(nome == s or nome.endswith("." + s) for s in _COMPARTILHADOS)


def _bloqueio(c) -> tuple[set[str], set[str]]:
    """(domínios nas listas de bloqueio, os pais de cada um) — p/ as travas de conflito."""
    em = {r["domain"] for r in c.execute("SELECT DISTINCT domain FROM category_lists WHERE category <> 'para_revisar'")}
    pais = set()
    for d in em:
        p = d.split(".")
        pais.update(".".join(p[i:]) for i in range(1, len(p) - 1))
    return em, pais


_AMEACA = ("high", "medium")   # feeds de ameaça (URLhaus, ThreatFox, HaGeZi TIF); "low" = sinal (bypass, phishing_db…)


def _sinais(hits) -> tuple[list[str], list[str]]:
    """(fontes de ameaça — confiança alta/média —, fontes de sinal — baixa; em geral num SUBDOMÍNIO: dns.google.com na
    lista de contorno, página de golpe em sites.google.com)."""
    amea, sinal = set(), set()
    for h in hits or []:
        (amea if h.get("confidence") in _AMEACA else sinal).add(h.get("source") or "?")
    return sorted(amea), sorted(sinal)


def _protegido(nome: str) -> bool:
    return bool((catalog.match(nome) or {}).get("protected"))


def aplicar(c) -> dict:
    """Um ciclo: tira o que caiu numa trava e põe o que passou a merecer whitelist.
    Publicar no DNS vale p/ o domínio E TODOS os subdomínios: com qualquer sinal em feed (mesmo de baixa confiança, num
    subdomínio) a entrada fica só na lista (publicar = false) — senão liberaria dns.google.com (DoH) ou sites.google.com
    (golpe). Sai da whitelist só com feed de ameaça (alta/média) ou MALICIOSO (SUSPEITO só deixa de valer no DNS); protegido
    do catálogo nunca sai."""
    cfg = settings()
    out = {"entrou": [], "saiu": []}
    em, pais = _bloqueio(c)
    # 1) saídas
    for r in c.execute("SELECT w.category, w.domain, w.added_by, w.publicar, d.ti_hits, d.classification FROM whitelist_domains w "
                       "LEFT JOIN domains d ON d.name = w.domain").fetchall():
        nome, auto = r["domain"], (r["added_by"] or "").startswith(("IA", CATALOGO_BY))
        amea, sinal = _sinais(r["ti_hits"])
        # (27/09, sem fase 5) SUSPEITO não tira da whitelist: só deixa de valer no DNS — a entrada da IA já não vai ao
        # DNS, e a decisão de liberar (IA ou pessoa) fica registrada; MALICIOSO ou feed de ameaça tiram
        risco = f"feed de ameaça ({', '.join(amea)})" if amea else (
            "classificação MALICIOSO" if r["classification"] == "MALICIOSO" else None)
        suspeito = "classificação SUSPEITO" if r["classification"] == "SUSPEITO" else None
        motivo = so_lista = None
        if risco and not _protegido(nome):
            motivo = risco
        elif r["publicar"] and (risco or suspeito or (auto and sinal)):
            so_lista = risco or suspeito or f"sinal de baixa confiança em subdomínio ({', '.join(sinal)})"
        elif auto and listas._em_lista(nome, em):
            motivo = "está numa lista de bloqueio"
        elif auto and nome in pais and r["publicar"]:
            # pai de algo bloqueado (amazonaws.com, fastly.net): no DNS liberaria o subdomínio; fica só na lista. Antes
            # saía da whitelist e o site ficava sem categoria nenhuma, em "Aprovados" (27/09)
            so_lista = "tem subdomínio numa lista de bloqueio"
        if motivo:
            listas.contexto(c, "whitelist (trava)", motivo)
            c.execute("DELETE FROM whitelist_domains WHERE category = %s AND domain = %s", (r["category"], nome))
            eventos.lista("lista_rem", nome, f"wl:{r['category']}", f"saiu da whitelist: {motivo}", origem="regras",
                          classificacao=r["classification"])
            out["saiu"].append(nome)
        elif so_lista:
            c.execute("UPDATE whitelist_domains SET publicar = false WHERE category = %s AND domain = %s", (r["category"], nome))
            eventos.lista("lista_rem", nome, f"wl:{r['category']}", f"deixou de valer no DNS (fica na lista): {so_lista}", origem="regras",
                          classificacao=r["classification"])
    # 2) entradas: protegidos do catálogo (Essenciais) + IA online com 2 modelos de acordo (TRABALHO, reconhecido, whitelist)
    ja = {r["domain"]: r["publicar"] for r in c.execute("SELECT domain, bool_or(publicar) AS publicar FROM whitelist_domains GROUP BY domain")}
    cands = c.execute(
        "SELECT d.id, d.name, d.category, d.evidence, d.ti_hits, d.online_resp->>'categoria' AS cat_online, d.topic, "
        " d.online_resp->>'servico' AS servico, d.online_resp->'_meta'->'antes' AS antes, "
        " d.online_resp->>'classificacao' AS cls_online, (d.online_resp->>'reconhecido')::boolean AS rec, "
        " d.lista_conf, d.lista_ia, d.lista_wl, d.lista_fonte, d.classification FROM domains d "
        "WHERE d.kind = 'public' AND d.classification NOT IN ('SUSPEITO', 'MALICIOSO') "
        " AND ((d.lista_fonte LIKE 'online%%' AND d.lista_ia IS NULL AND d.lista_conf >= %s "
        "       AND d.online_resp->>'classificacao' = 'TRABALHO' AND (d.online_resp->>'reconhecido')::boolean) "
        "      OR d.classified_by = 'catalog')", (cfg.online_confianca_min,)).fetchall()
    for r in cands:
        nome = r["name"]
        if ja.get(nome) or _compartilhado(nome, r["evidence"]) or listas._em_lista(nome, em) or nome in pais:
            continue   # (já publicado; plataforma compartilhada; conflita com bloqueio)
        amea, sinal = _sinais(r["ti_hits"])
        if _protegido(nome):
            cat, por, motivo = "essenciais", CATALOGO_BY, f"catálogo: {(catalog.match(nome) or {}).get('topic') or 'protegido'}"
        elif not amea and (r["lista_fonte"] or "").startswith("online") and _dois_modelos(r) \
                and not _cara_de_bloqueio(nome, f"{r['servico'] or ''} {r['topic'] or ''}"):
            cat, por, motivo = (r["lista_wl"] or _categoria(r["cat_online"] or r["category"], r["cls_online"]), AUTO_BY,
                                "IA online (2 modelos): trabalho, sem lista de bloqueio")
        else:
            continue
        pub = not (amea or sinal)   # com sinal num subdomínio: só na lista (publicar liberaria o subdomínio)
        if nome in ja and not pub and cat != "essenciais":
            continue   # já está na lista (sem publicar) e continua sem poder publicar
        listas.contexto(c, por, motivo)
        if cat == "essenciais" or nome not in ja:   # protegido: vai p/ Essenciais (sai da categoria que a IA escolheu)
            c.execute("DELETE FROM whitelist_domains WHERE domain = %s AND category <> %s", (nome, cat))
            c.execute("INSERT INTO whitelist_domains (category, domain, added_by, publicar) VALUES (%s, %s, %s, %s) "
                      "ON CONFLICT (category, domain) DO UPDATE SET publicar = EXCLUDED.publicar, added_by = EXCLUDED.added_by",
                      (cat, nome, por, pub))
        else:   # já estava na whitelist sem publicar (posto pela IA): passa a valer no DNS, na categoria escolhida
            c.execute("UPDATE whitelist_domains SET publicar = true WHERE domain = %s", (nome,))
        c.execute("UPDATE domains SET revisado_at = coalesce(revisado_at, now()) WHERE id = %s", (r["id"],))
        ja[nome] = pub
        out["entrou"].append((nome, cat, "catalogo" if por == CATALOGO_BY else "f4:online", pub, r["classification"]))
    if out["entrou"] or out["saiu"]:
        log.info("whitelist: %d entraram/publicados, %d saíram", len(out["entrou"]), len(out["saiu"]))
        if len(out["entrou"]) <= 50:
            for nome, cat, org, pub, cls in out["entrou"]:
                eventos.lista("lista_add", nome, f"wl:{cat}", "whitelist: " + CATEGORIAS[cat] + ("" if pub else " (só na lista: sinal em subdomínio)"),
                              origem=org, classificacao=cls)
        else:
            eventos.registrar("decisao", None, detail=f"wl|whitelist: {len(out['entrou'])} sites de trabalho liberados",
                              origem="f4:online")
    return out


def dominios(c, cat: str) -> list[str]:
    """Publicados no DNS (/whitelist/<cat>.txt): pessoa, catálogo ou dois modelos online. O que só a IA pôs fica na
    categoria sem publicar — fora de listas de bloqueio o site já está liberado; a whitelist vence qualquer bloqueio."""
    return [r["domain"] for r in c.execute("SELECT domain FROM whitelist_domains WHERE category = %s AND publicar "
                                           "ORDER BY domain", (cat,))]
