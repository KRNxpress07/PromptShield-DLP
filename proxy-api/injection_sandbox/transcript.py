"""Structured audit text with recognized synthetic canaries redacted."""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TranscriptEntry:
    sequence: int
    role: str
    kind: str
    text: str = ''
    tool_name: str | None = None
    tool_call_id: str | None = None
    allowed: bool | None = None
    reason: str | None = None


def redact(text, registry):
    for canary in registry.entries:
        text = text.replace(canary.token, '[CANARY:' + canary.canary_id + ']')
    return text
