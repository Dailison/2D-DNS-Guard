"""Características léxicas de nomes DNS (sem rede): domínio registrável, entropia, DGA.

Usa a Public Suffix List embutida no tldextract (sem baixar nada) COM sufixos
privados: `x.github.io`, `bucket.s3.amazonaws.com`, `y.duckdns.org` são tratados
como unidades próprias — um site malicioso em plataforma compartilhada não
contamina a plataforma inteira.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_EXTRACT_ICANN = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_VOWELS = set("aeiou")


@dataclass
class NameInfo:
    fqdn: str
    kind: str                 # public | internal | reverse | ip | invalid
    registrable: str          # unidade de classificação
    icann_registrable: str    # eTLD+1 só ICANN (p/ popularidade: github.io, amazonaws.com)
    suffix: str
    tld: str
    candidates: list[str] = field(default_factory=list)  # fqdn -> ... -> registrable
    private_suffix: bool = False  # registrável está sob sufixo privado (plataforma)


def normalize(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


def is_public_suffix(name: str) -> bool:
    """True se o nome é, ele próprio, um sufixo público (ex.: s3.us-east-1.amazonaws.com)."""
    name = normalize(name)
    if not name:
        return False
    ext = _EXTRACT(name)
    return not ext.domain and bool(ext.suffix)


def analyze_name(name: str, internal_suffixes: list[str] | None = None) -> NameInfo:
    fqdn = normalize(name)
    internal_suffixes = internal_suffixes or []
    if not fqdn:
        return NameInfo(fqdn, "invalid", fqdn, fqdn, "", "")
    try:
        ipaddress.ip_address(fqdn)
        return NameInfo(fqdn, "ip", fqdn, fqdn, "", "")
    except ValueError:
        pass
    if fqdn.endswith(".in-addr.arpa") or fqdn.endswith(".ip6.arpa"):
        return NameInfo(fqdn, "reverse", "reverse.arpa", "reverse.arpa", "arpa", "arpa")
    for suf in internal_suffixes:
        if fqdn == suf or fqdn.endswith("." + suf):
            # nomes internos: agrupa pelo domínio interno (ex.: 2d.local)
            parts = fqdn.split(".")
            reg = ".".join(parts[-(len(suf.split(".")) + 1):]) if len(parts) > len(suf.split(".")) else fqdn
            return NameInfo(fqdn, "internal", reg, reg, suf, suf.split(".")[-1], [fqdn])
    if "." not in fqdn:
        return NameInfo(fqdn, "internal", fqdn, fqdn, "", "", [fqdn])

    labels = fqdn.split(".")
    if any(not _LABEL_RE.match(lbl) for lbl in labels):
        return NameInfo(fqdn, "invalid", fqdn, fqdn, "", labels[-1])

    ext = _EXTRACT(fqdn)
    if not ext.domain:  # o próprio nome é um sufixo público
        return NameInfo(fqdn, "public", fqdn, fqdn, ext.suffix, labels[-1], [fqdn])
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    ext_i = _EXTRACT_ICANN(fqdn)
    icann_reg = f"{ext_i.domain}.{ext_i.suffix}" if ext_i.domain and ext_i.suffix else registrable
    private = registrable != icann_reg

    # candidatos para casar com listas: do fqdn até o registrável (nunca acima:
    # o sufixo/plataforma não é "o domínio")
    candidates = []
    reg_len = len(registrable.split("."))
    for i in range(0, len(labels) - reg_len + 1):
        candidates.append(".".join(labels[i:]))
    return NameInfo(fqdn, "public", registrable, icann_reg, ext.suffix, labels[-1], candidates, private)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _max_consonant_run(s: str) -> int:
    best = cur = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def dga_score(label: str) -> float:
    """Heurística 0..1 de 'parece gerado por algoritmo' para um rótulo DNS.

    Combina entropia, proporção de dígitos, sequência de consoantes e ausência
    de vogais. Não é prova de DGA — é um sinal para regras e para a IA.
    """
    lbl = (label or "").lower().replace("-", "")
    if len(lbl) < 7:
        return 0.0
    ent = shannon_entropy(lbl)
    digits = sum(ch.isdigit() for ch in lbl) / len(lbl)
    letters = [ch for ch in lbl if ch.isalpha()]
    vowel_ratio = (sum(ch in _VOWELS for ch in letters) / len(letters)) if letters else 0.0
    cons_run = _max_consonant_run(lbl)

    score = 0.0
    score += min(max((ent - 3.0) / 1.2, 0.0), 1.0) * 0.40          # entropia alta
    score += min(digits / 0.4, 1.0) * 0.20 if 0 < digits < 0.9 else 0.0  # dígitos misturados
    score += min(max((cons_run - 3) / 4, 0.0), 1.0) * 0.20          # sequência de consoantes
    score += (1.0 - min(vowel_ratio / 0.3, 1.0)) * 0.10              # poucas vogais
    score += min(max((len(lbl) - 12) / 12, 0.0), 1.0) * 0.10         # rótulo longo
    return round(min(score, 1.0), 3)


def name_features(info: NameInfo) -> dict:
    """Características do FQDN (nível onde DGA aparece)."""
    labels = info.fqdn.split(".")
    reg_labels = info.registrable.split(".")
    sub_labels = labels[: max(len(labels) - len(reg_labels), 0)]
    sld = reg_labels[0] if reg_labels else ""
    longest_sub = max(sub_labels, key=len) if sub_labels else ""
    return {
        "length": len(info.fqdn),
        "depth": len(sub_labels),
        "sld": sld,
        "sld_entropy": round(shannon_entropy(sld), 3),
        "sld_dga": dga_score(sld),
        "sub_max_len": len(longest_sub),
        "sub_entropy": round(shannon_entropy(longest_sub), 3) if longest_sub else 0.0,
        "sub_dga": dga_score(longest_sub),
        "digits_ratio": round(sum(ch.isdigit() for ch in info.fqdn) / max(len(info.fqdn), 1), 3),
        "punycode": "xn--" in info.fqdn,
    }


def domain_features(registrable: str) -> dict:
    """Características do domínio registrável (unidade de classificação)."""
    labels = registrable.split(".")
    sld = labels[0]
    return {
        "length": len(registrable),
        "sld": sld,
        "sld_len": len(sld),
        "sld_entropy": round(shannon_entropy(sld), 3),
        "sld_dga": dga_score(sld),
        "digits_ratio": round(sum(ch.isdigit() for ch in sld) / max(len(sld), 1), 3),
        "hyphens": sld.count("-"),
        "punycode": "xn--" in registrable,
    }
