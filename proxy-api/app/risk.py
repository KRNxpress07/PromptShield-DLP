"""PromptShield risk engine.

Occludra's stock policy is binary: `redact` or `block`, applied globally to
every request. PromptShield's brief calls for a *contextual* four-way
decision — allow / mask / warn / block — driven by the severity of what was
actually found. This module adds that layer on top of the existing Presidio
violation list without touching how detection itself works.

Design notes for the report:
- Severity weights are a simple, auditable lookup table rather than a
  trained classifier — deliberately so, since the brief calls for a
  "lightweight, real-time" mechanism, not a second model to maintain.
- Thresholds are configurable constants (RISK_THRESHOLDS) rather than
  hardcoded branches, so the policy can be tuned per deployment — this is
  the "configurable security policies" requirement from the problem
  statement.
- PROMPT_INJECTION always forces BLOCK regardless of score: an injection
  attempt isn't a confidentiality risk to weigh, it's an integrity attack,
  so it doesn't belong on the same severity scale as PII/secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Action(str, Enum):
    ALLOW = "allow"
    MASK = "mask"
    WARN = "warn"
    BLOCK = "block"


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Entity → severity weight (0-100). Higher = more sensitive.
# Extend this as you add recognizers (see recognizers_additions.yaml).
#
# Calibration intent (see RISK_THRESHOLDS below): weight >=90 blocks,
# 50-89 warns, 1-49 masks silently. So routine, common PII (a lone email,
# a phone number) should land under 50 — auto-redact and move on — while
# anything that grants access (keys, tokens, connection strings) should
# land at or above 90, since redacting a secret after the fact is not a
# safe default the way redacting a name is.
SEVERITY_WEIGHTS: dict[str, int] = {
    # Developer secrets — grant access, not just identify someone
    "PRIVATE_KEY": 100,
    "AWS_ACCESS_KEY": 100,
    "AWS_SECRET_KEY": 100,
    "API_KEY": 95,
    "GITHUB_TOKEN": 95,
    "DB_CONNECTION_STRING": 93,
    "SLACK_WEBHOOK": 90,
    "JWT_TOKEN": 78,
    "BEARER_TOKEN": 72,
    "GENERIC_SECRET_ASSIGNMENT": 55,
    # Internal system details — proprietary, not personal, but still sensitive
    "INTERNAL_HOSTNAME": 65,
    "PRIVATE_IP": 45,
    # Regulated PII — high because of legal/compliance exposure
    "US_SSN": 85,
    "CREDIT_CARD": 80,
    "IBAN_CODE": 70,
    # Everyday PII — sensitive but common enough that auto-redact (not an
    # interrupt) is the right default
    "EMAIL_ADDRESS": 40,
    "PHONE_NUMBER": 35,
    "IP_ADDRESS": 30,
    "PERSON": 20,
    "LOCATION": 15,
    "NRP": 10,
    "DATE_TIME": 8,
    # Integrity attack — handled specially, see assess() below
    "PROMPT_INJECTION": 95,
}

DEFAULT_WEIGHT = 50  # unknown entity types are treated as medium by default

# score thresholds → risk level. Tune these per deployment.
RISK_THRESHOLDS: list[tuple[int, RiskLevel]] = [
    (90, RiskLevel.CRITICAL),
    (70, RiskLevel.HIGH),
    (50, RiskLevel.MEDIUM),
    (1, RiskLevel.LOW),
    (0, RiskLevel.NONE),
]

# risk level → default action. This is the "policy" in policy.yaml terms —
# swap this for a config-file lookup if you want it hot-reloadable.
LEVEL_TO_ACTION: dict[RiskLevel, Action] = {
    RiskLevel.NONE: Action.ALLOW,
    RiskLevel.LOW: Action.MASK,
    RiskLevel.MEDIUM: Action.WARN,
    RiskLevel.HIGH: Action.WARN,
    RiskLevel.CRITICAL: Action.BLOCK,
}


@dataclass
class RiskAssessment:
    score: int
    level: RiskLevel
    action: Action
    reason: str
    entity_types: list[str]


def _level_for_score(score: int) -> RiskLevel:
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.NONE


def assess(violations: list[dict]) -> RiskAssessment:
    """Turn a list of Presidio-style violations into a risk decision.

    Each violation dict must have at least an "entity_type" key (this is
    exactly the shape DLPViolation.model_dump() produces, so you can pass
    dlp.process_messages()'s output straight in).
    """
    if not violations:
        return RiskAssessment(
            score=0,
            level=RiskLevel.NONE,
            action=Action.ALLOW,
            reason="No sensitive content detected.",
            entity_types=[],
        )

    entity_types = sorted({v["entity_type"] for v in violations})
    has_injection = "PROMPT_INJECTION" in entity_types

    weights = [SEVERITY_WEIGHTS.get(et, DEFAULT_WEIGHT) for et in entity_types]
    max_weight = max(weights)

    # Modest bump for volume: many low-severity hits (e.g. a document full of
    # names) should read as riskier than a single one, capped so it can't
    # alone push a low-severity finding into block territory.
    count_bonus = min(len(violations) - 1, 4) * 2
    score = min(max_weight + count_bonus, 100)

    level = _level_for_score(score)
    action = LEVEL_TO_ACTION[level]

    if has_injection:
        # Integrity attacks always block, independent of the score above.
        level = RiskLevel.CRITICAL
        action = Action.BLOCK
        reason = "Prompt injection / jailbreak pattern detected — request blocked."
    else:
        worst = max(entity_types, key=lambda et: SEVERITY_WEIGHTS.get(et, DEFAULT_WEIGHT))
        reason = _reason_for(action, worst, len(violations))

    return RiskAssessment(
        score=score,
        level=level,
        action=action,
        reason=reason,
        entity_types=entity_types,
    )


def _reason_for(action: Action, worst_entity: str, count: int) -> str:
    plural = "item" if count == 1 else "items"
    if action is Action.ALLOW:
        return "No sensitive content detected."
    if action is Action.MASK:
        return f"Low-sensitivity content found ({count} {plural}, e.g. {worst_entity}) — redacted automatically."
    if action is Action.WARN:
        return f"Sensitive content found ({count} {plural}, highest: {worst_entity}) — confirm before sending."
    return f"High-severity content found ({count} {plural}, highest: {worst_entity}) — request blocked."
