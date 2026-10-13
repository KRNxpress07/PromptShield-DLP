"""Secret-safe log utilities. Mask values completely, never preserve fragments."""
from __future__ import annotations

import logging
import re
from typing import Any, Iterable

REDACTED = "[REDACTED]..."
_KNOWN_SECRETS: set[str] = set()
_SENSITIVE_FIELDS = frozenset({
    "key", "apikey", "providerkey", "gatewaykey", "rawkey", "authorization",
    "headers", "token", "password", "secret", "credentials", "prompt",
    "messages", "content", "input", "errors", "exception", "excinfo",
    "stack", "traceback", "detail", "body", "text", "rawprompt",
    "awssecretaccesskey", "awssecretkey", "awssessiontoken", "sessiontoken",
    "apisecret", "clientsecret", "accesstoken",
})
_KEY_PATTERNS = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*"
    r"|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|mssql|amqp)://[^\s]+"
    r"|(?i:Bearer)\s+\S+"
    r"|(?:gsk_|tok_|sk-|AKIA|ASIA|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|AIza)[A-Za-z0-9_.\-]+"
    r"|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|(?i:(?:password|passwd|pwd|secret|api[_-]?key|api_secret|client_secret|access[_-]?token|aws_secret_access_key|aws_session_token|secretAccessKey|sessionToken)[\x27\"]?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)


def register_secrets(values: Iterable[str]) -> None:
    """Protect opaque configured credentials even inside incidental log strings."""
    _KNOWN_SECRETS.update(value for value in values if isinstance(value, str) and value)


def mask_key(key: str) -> str:
    """Never expose a prefix/suffix of any credential, including short keys."""
    return REDACTED


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):
            value = value.replace(secret, REDACTED)
        return _KEY_PATTERNS.sub(REDACTED, value)
    if isinstance(value, dict):
        return {
            _scrub_value(k): (
                REDACTED if re.sub(r"[^a-z]", "", str(k).lower()) in _SENSITIVE_FIELDS
                else _scrub_value(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(_scrub_value(v) for v in value)
    return value


def log_scrubber(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return _scrub_value(event_dict)


class SecretSafeFormatter(logging.Formatter):
    """Standard logging (including dependencies) must not echo exception bodies."""
    def format(self, record: logging.LogRecord) -> str:
        safe = logging.makeLogRecord(record.__dict__.copy())
        safe.msg = _scrub_value(record.getMessage())
        safe.args = ()
        safe.exc_info = None
        safe.exc_text = None
        safe.stack_info = None
        return super().format(safe)
