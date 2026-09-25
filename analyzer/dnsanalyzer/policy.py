"""Combina regras + IA com salvaguardas (funções puras).

Salvaguardas:
* razões da IA que citam evidência inexistente são DESCARTADAS (anti-alucinação);
* MALICIOSO exige evidência de feed de alta confiança — senão vira SUSPEITO;
* o risco final fica ancorado nas regras (IA ajusta no máximo ±15);
* BLOCK_CANDIDATE só com MALICIOSO, ou SUSPEITO com risco >= 75; nunca em
  infraestrutura protegida. Nada é bloqueado automaticamente;
* recomendação corporativa (BLOQUEAR/LIBERAR/REVISAR): ver corporate.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import corporate
from .llm import LLMResult
from .rules import RuleResult

RISK_KINDS = {"ti", "tld", "lexical", "age", "tunnel", "logs"}
# identidade externa confiável (curada/validada por terceiros). "site" NÃO entra: é autodeclarado.
TRUSTED_ID_KINDS = {"wikidata", "cert"}


@dataclass
class Final:
    classification: str
    risk: int
    work: int | None
    topic: str | None
    confidence: float
    action: str
    reasons: list[dict]
    classified_by: str
    notes: list[str]
    category: str | None = None
    corp_action: str | None = None      # BLOQUEAR | LIBERAR | REVISAR (ambiente corporativo)
    corp_reason: str | None = None
    corp_by: str | None = None          # ia | politica


def _corp(f: Final, protected: bool, ai_action: str | None = None, ai_reason: str | None = None) -> Final:
    r = corporate.recommend(f.classification, f.category, f.risk, protected, ai_action, ai_reason)
    if r:
        f.corp_action, f.corp_reason, f.corp_by = r
    return f


def validate_reasons(llm: LLMResult, evidence: list[dict]) -> tuple[list[dict], int]:
    ids = {e["id"] for e in evidence}
    valid = [{"evidence_id": r.evidence_id.strip(), "text": r.text.strip(), "by": "ia"}
             for r in llm.reasons if r.evidence_id.strip() in ids and r.text.strip()]
    return valid, len(llm.reasons) - len(valid)


def rules_only(rule: RuleResult, pending_llm: bool) -> Final:
    by = "rules"
    if rule.final:
        kinds = {e.kind for e in rule.evidence}
        by = "internal" if "internal" in kinds else "catalog" if "catalog" in kinds else "rules"
    notes = ["aguardando análise da IA"] if pending_llm else []
    cat = rule.category or (None if pending_llm else "desconhecido")
    return _corp(Final(rule.classification, rule.risk, rule.work, rule.topic, rule.confidence, rule.action,
                       rule.reasons, by, notes, cat), bool(rule.flags.get("protected")))


def combine(rule: RuleResult, llm: LLMResult, evidence: list[dict]) -> Final:
    notes: list[str] = []
    valid, dropped = validate_reasons(llm, evidence)
    if dropped:
        notes.append(f"{dropped} razão(ões) da IA descartada(s) por citar evidência inexistente")
    if not valid:
        f = rules_only(rule, False)
        f.notes = notes + ["IA não apresentou justificativa válida; mantida a classificação das regras"]
        return f

    ev_by_id = {e["id"]: e for e in evidence}
    cited_risk = any(ev_by_id[r["evidence_id"]]["kind"] in RISK_KINDS and ev_by_id[r["evidence_id"]]["risk"]
                     for r in valid)

    cls = llm.classification
    if cls == "MALICIOSO" and not rule.flags.get("ti_high"):
        cls = "SUSPEITO"
        notes.append("IA indicou MALICIOSO sem evidência de feed de alta confiança: rebaixado para SUSPEITO")
    work_forced = None
    if cls in ("TRABALHO", "NAO_TRABALHO"):
        if not llm.recognized:
            notes.append(f"IA não reconhece o serviço (sugeriu {cls}): classificado como DESCONHECIDO")
            cls, work_forced = "DESCONHECIDO", 50
        elif not rule.flags.get("ranked") and not any(
                ev_by_id[r["evidence_id"]]["kind"] in TRUSTED_ID_KINDS for r in valid):
            # modelos pequenos "reconhecem" domínios da cauda longa por chute: fora do top 1M
            # só vale se a IA se apoiou numa identidade externa confiável (Wikidata/certificado)
            notes.append(f"domínio fora do top 1M (Tranco) e sem identificação externa confiável citada: "
                         f"reconhecimento da IA não é confiável (sugeriu {cls}); classificado como DESCONHECIDO")
            cls, work_forced = "DESCONHECIDO", 50
    if rule.classification == "SUSPEITO" and cls not in ("SUSPEITO", "MALICIOSO"):
        notes.append(f"regras indicam risco {rule.risk} (>=50): mantido SUSPEITO (IA sugeriu {cls})")
        cls = "SUSPEITO"
    if cls == "SUSPEITO" and rule.classification != "SUSPEITO":
        cites_name = any(ev_by_id[r["evidence_id"]]["kind"] == "identity" for r in valid)
        if not (cited_risk or (cites_name and llm.confidence >= 0.6)):
            cls = "DESCONHECIDO"
            notes.append("IA indicou SUSPEITO sem citar evidência de risco: rebaixado para DESCONHECIDO")

    # risco ancorado nas regras
    risk = round(0.7 * rule.risk + 0.3 * llm.risk_score)
    risk = max(rule.risk - 15, min(rule.risk + 15, risk))
    if llm.risk_score > rule.risk and not cited_risk:
        risk = min(risk, rule.risk + 5)
    if cls == "SUSPEITO":
        risk = max(risk, 50)
    elif cls in ("TRABALHO", "NAO_TRABALHO", "DESCONHECIDO"):
        risk = min(risk, 49)
    risk = max(0, min(100, risk))

    work = work_forced if work_forced is not None else llm.work_score
    if cls == "DESCONHECIDO":
        work = 50          # não sabemos o que é: relação com trabalho neutra
    if cls in ("MALICIOSO", "SUSPEITO"):
        work = min(work, 20)

    action = llm.recommended_action
    if action == "BLOCK_CANDIDATE" and not (cls == "MALICIOSO" or (cls == "SUSPEITO" and risk >= 75)):
        action = "REVIEW"
    if rule.flags.get("protected") and action == "BLOCK_CANDIDATE":
        action = "REVIEW"
    if cls == "SUSPEITO" and action == "NONE":
        action = "REVIEW"

    confidence = round(llm.confidence * (len(valid) / max(len(llm.reasons), 1)), 2)
    svc = (llm.service or "").strip()
    if svc and llm.recognized:
        valid.insert(0, {"evidence_id": "E0", "text": f"serviço: {svc}", "by": "ia"})
    reasons = rule.reasons[:4] + valid
    # categoria: a da IA quando o reconhecimento foi aceito; senão a das regras / desconhecido
    if cls == "MALICIOSO":
        category = "ameaca"
    elif work_forced is None and llm.category and llm.category != "desconhecido":
        category = llm.category
    else:
        category = rule.category or "desconhecido"
    f = Final(cls, int(risk), int(work), (llm.topic or "").strip() or None, confidence, action,
              reasons, "llm", notes, category)
    # recomendação corporativa da IA só vale se o reconhecimento foi aceito
    trusted = work_forced is None
    return _corp(f, bool(rule.flags.get("protected")), llm.corp_action if trusted else None,
                 llm.corp_reason if trusted else None)
