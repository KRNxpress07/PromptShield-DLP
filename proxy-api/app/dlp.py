"""Validated scanner contract and one fail-closed inspection/egress policy."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import get_settings, validate_dlp_policy
from .models import ChatMessage, DLPViolation
from . import risk

PLACEHOLDER = "[REDACTED]"


class PresidioError(Exception):
    """Scanner unavailable or invalid; never retain response/input text."""
    status_code = 503
    code = "security_processing_error"
    message = "Safety processing is unavailable or invalid. Request not forwarded."


class SanitizationError(PresidioError):
    status_code = 422
    code = "sanitization_verification_failed"
    message = "Sanitization could not be verified. Request not forwarded."


class _ScannerViolation(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    entity_type: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    score: float = Field(ge=0, le=1, allow_inf_nan=False)


class _ScannerResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    results: list[_ScannerViolation]
    anonymized_text: str | None = None


@dataclass
class ProcessResult:
    violations: list[DLPViolation] = field(default_factory=list)
    redacted_messages: list[ChatMessage] | None = field(default=None, repr=False)


@dataclass
class PolicyResult:
    scan: ProcessResult
    assessment: risk.RiskAssessment
    messages: list[ChatMessage] = field(repr=False)
    sanitized: bool = False


async def process_messages(
    client: httpx.AsyncClient,
    messages: list[ChatMessage],
    entities: list[str] | None = None,
    score_threshold: float = 0.4,
    anonymize: bool = False,
    ignore_placeholders: bool = False,
) -> ProcessResult:
    """One scanner pass; validate spans and never fall back on detected raw text."""
    if client is None:
        raise PresidioError(PresidioError.message)
    base = get_settings().presidio_url.rstrip("/")
    all_violations: list[DLPViolation] = []
    redacted: list[ChatMessage] = []
    responses: dict[str, _ScannerResponse] = {}
    for msg in messages:
        text = _message_text(msg)
        if not text:
            if anonymize:
                redacted.append(msg)
            continue
        payload: dict[str, Any] = {
            "text": text, "language": "en", "entities": entities or None,
            "score_threshold": score_threshold, "anonymize": anonymize,
        }
        if anonymize:
            payload["operators"] = {
                "DEFAULT": {"type": "replace", "new_value": PLACEHOLDER},
            }
        try:
            if text not in responses:
                resp = await client.post(f"{base}/process", json=payload, timeout=5.0)
                resp.raise_for_status()
                responses[text] = _ScannerResponse.model_validate(resp.json())
            data = responses[text]
        except (httpx.HTTPError, ValueError, TypeError, ValidationError):
            raise PresidioError(PresidioError.message) from None
        for finding in data.results:
            if not finding.start < finding.end <= len(text):
                raise PresidioError(PresidioError.message)
            if entities is not None and finding.entity_type not in entities:
                raise PresidioError(PresidioError.message)
            if ignore_placeholders and any(
                offset <= finding.start < finding.end <= offset + len(PLACEHOLDER)
                for offset in _placeholder_offsets(text)
            ):
                continue
            all_violations.append(DLPViolation(**finding.model_dump()))
        if anonymize:
            if data.results:
                sanitized = data.anonymized_text
                if not isinstance(sanitized, str) or not sanitized.strip():
                    raise PresidioError(PresidioError.message)
                if any(text[r.start:r.end] in sanitized for r in data.results):
                    raise SanitizationError(SanitizationError.message)
                redacted.append(msg.model_copy(update={"content": sanitized}))
            else:
                redacted.append(msg)
    return ProcessResult(all_violations, redacted if anonymize else None)


async def inspect_messages(
    client: httpx.AsyncClient,
    messages: list[ChatMessage],
    policy: dict[str, Any],
) -> PolicyResult:
    """Shared policy: scan+replace once, then at most one verification pass."""
    config = validate_dlp_policy(policy)
    scan = await process_messages(
        client, messages, entities=config.entities,
        score_threshold=config.confidence_threshold, anonymize=True,
    )
    assessment = risk.decide(
        [v.model_dump() for v in scan.violations], config.action,
    )
    if assessment.action is risk.Action.BLOCK or not scan.violations:
        return PolicyResult(scan, assessment, messages)
    sanitized = scan.redacted_messages
    if sanitized is None or len(sanitized) != len(messages):
        raise PresidioError(PresidioError.message)
    if any(
        _message_text(original).strip() and not _message_text(replacement).strip()
        for original, replacement in zip(messages, sanitized)
    ):
        raise PresidioError(PresidioError.message)
    changed_messages = [
        replacement for original, replacement in zip(messages, sanitized)
        if _message_text(original) != _message_text(replacement)
    ]
    if not changed_messages:
        raise SanitizationError(SanitizationError.message)
    verification = await process_messages(
        client, changed_messages, entities=config.entities,
        score_threshold=config.confidence_threshold, anonymize=False,
        ignore_placeholders=True,
    )
    if verification.violations:
        raise SanitizationError(SanitizationError.message)
    return PolicyResult(scan, assessment, sanitized, sanitized=True)


def _placeholder_offsets(text: str):
    offset = text.find(PLACEHOLDER)
    while offset != -1:
        yield offset
        offset = text.find(PLACEHOLDER, offset + len(PLACEHOLDER))


def violations_breakdown(violations: list[DLPViolation]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in violations:
        counts[v.entity_type] = counts.get(v.entity_type, 0) + 1
    return counts


def _message_text(msg: ChatMessage) -> str:
    """Extract supported text; never coerce malformed parts."""
    if isinstance(msg.content, str):
        return msg.content
    if isinstance(msg.content, list):
        parts: list[str] = []
        for part in msg.content:
            if isinstance(part, dict) and part.get("type") == "text":
                value = part.get("text")
                if not isinstance(value, str):
                    raise PresidioError(PresidioError.message)
                parts.append(value)
            elif isinstance(part, str):
                parts.append(part)
        return " ".join(parts)
    return ""
