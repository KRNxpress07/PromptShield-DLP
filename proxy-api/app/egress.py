"""Inspect the exact provider payload without flattening its structure."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import math
import re

import httpx

from . import dlp
from .models import ChatMessage
from .providers import COMPLETION_PARAMS
from .risk import RiskAssessment

MAX_DEPTH = 20
MAX_NODES = 20_000
MAX_STRINGS = 2_000
_ROLES = frozenset({"system", "developer", "user", "assistant", "tool", "function"})
_SCHEMA_TYPES = frozenset({"object", "array", "string", "number", "integer", "boolean", "null"})
_CREDENTIAL_HEADERS = frozenset({
    "authorization", "proxy-authorization", "api-key", "x-api-key",
    "x-goog-api-key", "x-amz-security-token",
})


class UnsupportedDLPContent(dlp.PresidioError):
    status_code = 422
    code = "unsupported_dlp_content"
    message = "Request content or structure cannot currently be inspected safely. Request not forwarded."


@dataclass
class OutboundResult:
    payload: dict[str, Any] = field(repr=False)
    scan: dlp.ProcessResult
    assessment: RiskAssessment
    sanitized: bool


def _protocol_identifier(path: tuple) -> bool:
    if path == ("model",) or (path and path[-1] in {"$ref", "$id"}):
        return True
    if path and path[-1] == "name":
        return (
            len(path) == 3 and path[0] in {"messages", "functions"}
            or len(path) == 4 and path[0] == "tools" and path[-2] == "function"
            or path in {("tool_choice", "function", "name"), ("function_call", "name"),
                        ("response_format", "json_schema", "name")}
        )
    return False


def _validate_messages(messages: Any) -> None:
    if not isinstance(messages, list):
        raise UnsupportedDLPContent()
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in _ROLES:
            raise UnsupportedDLPContent()
        content = message.get("content")
        if isinstance(content, str) or content is None:
            continue
        if not isinstance(content, list):
            raise UnsupportedDLPContent()
        for part in content:
            if isinstance(part, str):
                continue
            if (not isinstance(part, dict) or set(part) != {"type", "text"}
                    or part.get("type") != "text" or not isinstance(part.get("text"), str)):
                raise UnsupportedDLPContent()


def provider_text_inventory(payload: dict[str, Any], *, trusted_model: bool = False):
    """The single Phase 2 forwarding inventory, shared with behavioral preflight.

    Returns the filtered payload, path/key metadata, and validated text leaves.
    """
    _validate_messages(payload.get("messages"))
    headers = payload.get("extra_headers") or {}
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", key)
        for key in headers
    ):
        raise UnsupportedDLPContent()
    if any(key.lower().replace("_", "-") in _CREDENTIAL_HEADERS for key in headers):
        # Provider credentials are server-owned; opaque auth overrides are not BYOK.
        raise UnsupportedDLPContent()
    paths: list[tuple[tuple, bool]] = []
    texts: list[ChatMessage] = []
    nodes = 0

    def add(text: str, path: tuple, is_key: bool = False):
        if text:
            if len(texts) >= MAX_STRINGS:
                raise UnsupportedDLPContent()
            paths.append((path, is_key))
            texts.append(ChatMessage(role="user", content=text))

    def walk(value: Any, path: tuple, depth: int):
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise UnsupportedDLPContent()
        if isinstance(value, str):
            if value.lower().startswith("data:") and ";base64," in value.lower():
                raise UnsupportedDLPContent()
            # Exact protocol constants are validated, not free-form data.
            role = len(path) == 3 and path[0] == "messages" and path[-1] == "role"
            control_type = path and path[-1] == "type" and value in (_SCHEMA_TYPES | {"function", "text"})
            if not role and not control_type and not (trusted_model and path == ("model",)):
                add(value, path)
            return value
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise UnsupportedDLPContent()
                # Schema property names, headers, enum maps, etc. can also leak.
                if path and path[0] != "messages":
                    add(key, path + (key,), is_key=True)
                result[key] = walk(item, path + (key,), depth + 1)
            return result
        if isinstance(value, list):
            return [walk(item, path + (index,), depth + 1) for index, item in enumerate(value)]
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        raise UnsupportedDLPContent()

    output = walk(
        {key: value for key, value in payload.items() if key in COMPLETION_PARAMS or key == "model"},
        (), 0,
    )
    return output, paths, texts


async def inspect_outbound_payload(
    client: httpx.AsyncClient,
    payload: dict[str, Any],
    policy: dict[str, Any],
    *,
    trusted_model: bool = False,
) -> OutboundResult:
    """Bounded leaf inspection, shared Phase 1 policy, safe reconstruction."""
    output, paths, texts = provider_text_inventory(payload, trusted_model=trusted_model)
    decision = await dlp.inspect_messages(client, texts, policy)
    if decision.assessment.action.value == "block":
        return OutboundResult(output, decision.scan, decision.assessment, False)

    for (path, is_key), original, replacement in zip(paths, texts, decision.messages):
        if replacement.content == original.content:
            continue
        if is_key:
            # Renaming keys would invalidate schema references or HTTP headers.
            raise UnsupportedDLPContent()
        if _protocol_identifier(path):
            # Generic placeholders are not valid routing/function/reference IDs.
            raise dlp.SanitizationError()
        container = output
        for component in path[:-1]:
            container = container[component]
        container[path[-1]] = replacement.content
    return OutboundResult(output, decision.scan, decision.assessment, decision.sanitized)

