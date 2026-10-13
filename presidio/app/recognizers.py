"""
Configure the Presidio AnalyzerEngine with custom recognizers.

Built-in recognizers already cover EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD,
US_SSN, IP_ADDRESS, IBAN_CODE, PERSON, LOCATION via spaCy NER + regex.

This module adds:
  1. Developer secret recognizers (API keys, AWS keys, PEM keys, GitHub tokens)
  2. A basic prompt injection / jailbreak detector
"""

from __future__ import annotations

import logging
import base64
import json
import re
import csv
from pathlib import Path

import phonenumbers
from presidio_analyzer.predefined_recognizers import UsSsnRecognizer

from presidio_analyzer import AnalyzerEngine, EntityRecognizer, RecognizerResult, PatternRecognizer, Pattern

_log = logging.getLogger(__name__)
RETIRED_RECOGNIZER_PATH = Path(__file__).resolve().parents[1] / "recognizers.yaml"


REQUIRED_ENTITIES = frozenset({
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
})


def _custom_recognizers() -> list[EntityRecognizer]:
    """Core custom recognizers for OSS release — developer secrets + basic injection."""
    return [
        *_additional_recognizers(),
        # ── Developer Secrets ─────────────────────────────────────────────
        PatternRecognizer(
            supported_entity="API_KEY",
            name="ApiKeyRecognizer",
            supported_language="en",
            patterns=[
                Pattern("openai_key", r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{20,256}(?![A-Za-z0-9_-])", 0.9),
                Pattern("openai_project_service", r"(?<![A-Za-z0-9_-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,256}(?![A-Za-z0-9_-])", 0.95),
                Pattern("groq_key", r"(?<![A-Za-z0-9_-])gsk_[A-Za-z0-9]{20,256}(?![A-Za-z0-9_-])", 0.95),
                Pattern("anthropic_key", r"(?<![A-Za-z0-9_-])sk-ant-(?:(?:api03|admin01)-)?[A-Za-z0-9_-]{20,256}(?![A-Za-z0-9_-])", 0.95),
                Pattern("google_ai_key", r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])", 0.9),
            ],
        ),
        PatternRecognizer(
            supported_entity="AWS_ACCESS_KEY",
            name="AwsAccessKeyRecognizer",
            supported_language="en",
            patterns=[
                Pattern("aws_access_key_id", r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])", 0.95),
            ],
        ),
        PatternRecognizer(
            supported_entity="PRIVATE_KEY",
            name="PrivateKeyRecognizer",
            supported_language="en",
            patterns=[
                Pattern(
                    "pem_private_key",
                    r"-----BEGIN (?P<key_type>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
                    r"[\s\S]*?-----END (?P=key_type)-----",
                    0.99,
                ),
                # Unterminated/mismatched keys stay critical and cover the tail.
                Pattern(
                    "incomplete_private_key",
                    r"-----BEGIN (?P<incomplete_type>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
                    r"(?![\s\S]*?-----END (?P=incomplete_type)-----)[\s\S]*\Z",
                    0.95,
                ),
            ],
        ),
        PatternRecognizer(
            supported_entity="GITHUB_TOKEN",
            name="GitHubTokenRecognizer",
            supported_language="en",
            patterns=[
                Pattern("github_family", r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,255}(?![A-Za-z0-9_])", 0.95),
                Pattern("github_fine_grained", r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82,255}(?![A-Za-z0-9_])", 0.95),
            ],
        ),
        PatternRecognizer(
            supported_entity="SLACK_WEBHOOK",
            name="SlackWebhookRecognizer",
            supported_language="en",
            patterns=[
                Pattern("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", 0.95),
            ],
        ),

        # ── Prompt Injection / Jailbreak Detection (core patterns) ────────
        PatternRecognizer(
            supported_entity="PROMPT_INJECTION",
            name="PromptInjectionRecognizer",
            supported_language="en",
            patterns=[
                Pattern("ignore_previous",
                        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|rules?|prompts?|directives?|guidelines?|constraints?)",
                        0.85),
                Pattern("disregard_instructions",
                        r"(?i)(disregard|forget|override|bypass|skip|drop)\s+(all\s+)?(previous|prior|above|your|the|system)?\s*(instructions?|rules?|prompts?|guidelines?|constraints?|programming|training)",
                        0.85),
                Pattern("reveal_system_prompt",
                        r"(?i)(reveal|show|display|print|output|repeat|echo|tell\s+me|give\s+me|what\s+(is|are))\s+(your|the)\s+(system|initial|original|hidden|secret|internal)\s*(prompt|instructions?|rules?|message|configuration|directives?)",
                        0.9),
                Pattern("dan_jailbreak",
                        r"(?i)(you\s+are|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|imagine\s+you\s+are|from\s+now\s+on\s+you\s+are)\s+(DAN|an?\s+unrestricted|an?\s+uncensored|an?\s+unfiltered|a\s+jailbroken|evil|Developer\s*Mode|god\s*mode)",
                        0.9),
                Pattern("developer_mode",
                        r"(?i)(enable|activate|enter|switch\s+to|turn\s+on)\s+(developer|debug|admin|god|unrestricted|jailbreak|sudo)\s*(mode|access)",
                        0.85),
            ],
        ),
    ]


def build_analyzer() -> AnalyzerEngine:
    """Programmatic definitions are the only project recognizer source."""
    if RETIRED_RECOGNIZER_PATH.exists() and any(
        line.strip() and not line.lstrip().startswith("#")
        for line in RETIRED_RECOGNIZER_PATH.read_text(encoding="utf-8").splitlines()
    ):
        raise RuntimeError("recognizers.yaml is retired; use programmatic definitions")
    recognizers = _custom_recognizers()
    names = [rec.name for rec in recognizers]
    if len(names) != len(set(names)):
        raise RuntimeError("Duplicate custom recognizer names")
    for rec in recognizers:
        rec.global_regex_flags = 0
        for pattern in getattr(rec, "patterns", []):
            try:
                re.compile(pattern.regex)
            except re.error:
                raise RuntimeError("Invalid custom recognizer pattern") from None

    engine = AnalyzerEngine()
    # Replace only the built-in SSN validator to add the reserved 900-series rule.
    engine.registry.remove_recognizer("UsSsnRecognizer")
    for rec in recognizers:
        engine.registry.add_recognizer(rec)
    loaded = {ent for rec in engine.registry.recognizers for ent in rec.supported_entities}
    required = REQUIRED_ENTITIES | {ent for rec in recognizers for ent in rec.supported_entities}
    if not required <= loaded:
        raise RuntimeError("Required protected recognizers are missing")
    return engine


class _JwtRecognizer(PatternRecognizer):
    def validate_result(self, pattern_text: str) -> bool:
        try:
            parts = pattern_text.split(".")
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            return isinstance(header, dict) and isinstance(header.get("alg"), str) and isinstance(payload, dict)
        except (ValueError, UnicodeError, TypeError):
            return False


class _InternationalPhoneRecognizer(PatternRecognizer):
    def validate_result(self, pattern_text: str) -> bool:
        try:
            return phonenumbers.is_possible_number(phonenumbers.parse(pattern_text, None))
        except phonenumbers.NumberParseException:
            return False


class _ValidatedSsnRecognizer(UsSsnRecognizer):
    def invalidate_result(self, pattern_text: str) -> bool:
        digits = "".join(char for char in pattern_text if char.isdigit())
        return super().invalidate_result(pattern_text) or len(digits) != 9 or int(digits[:3]) >= 900


def _additional_recognizers() -> list[EntityRecognizer]:
    """Context-bound secrets and explicit PII shapes; no entropy-only scanning."""
    def rule(entity, name, expression, score=0.85):
        return PatternRecognizer(
            supported_entity=entity, name=name, supported_language="en",
            patterns=[Pattern(name, expression, score)], global_regex_flags=0,
        )

    octet = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    return [
        _CsvNameRecognizer(),
        _JwtRecognizer(
            supported_entity="JWT_TOKEN", name="JwtTokenRecognizer",
            patterns=[Pattern("jwt", r"(?<![\w.-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w.-])", 0.85)],
        ),
        rule("BEARER_TOKEN", "BearerTokenRecognizer",
             r"(?i)\bBearer[ \t]+[A-Za-z0-9_.~+/=-]{16,4096}(?![A-Za-z0-9_.~+/=-])"),
        rule("DB_CONNECTION_STRING", "DbConnectionStringRecognizer",
             r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|mssql|amqp)://"
             r"[^\s:/@\"'<>]*:[^\s/@\"'<>]+@[^\s\"'<>{}\[\](),;]+", 0.95),
        rule("GENERIC_SECRET_ASSIGNMENT", "GenericSecretAssignmentRecognizer",
             r"(?i)(?<![\w])['\"]?(?:password|passwd|pwd|secret|api[_-]?key|api_secret|client_secret|access_token"
             r"|(?:openai|anthropic|gemini|groq|together|mistral|deepinfra|xai)[_-](?:api[_-]?(?:key|token)))['\"]?"
             r"\s*[:=]\s*(?:\"[^\"\\\r\n]{4,4096}\"|'[^'\\\r\n]{4,4096}'|"
             r"(?!null\b|true\b|false\b)[A-Za-z0-9/+_.@%:=-]{4,4096})", 0.65),
        rule("AWS_SECRET_KEY", "AwsSecretKeyRecognizer",
             r"(?i)(?<![\w])['\"]?(?:aws_secret_access_key|awsSecretAccessKey|secretAccessKey)['\"]?"
             r"\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])['\"]?", 0.95),
        rule("AWS_SESSION_TOKEN", "AwsSessionTokenRecognizer",
             r"(?i)(?<![\w])['\"]?(?:aws_session_token|awsSessionToken|sessionToken)['\"]?"
             r"\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,4096}(?![A-Za-z0-9/+=])['\"]?", 0.95),
        rule("PRIVATE_IP", "PrivateIpRecognizer",
             rf"(?<![\w.])(?:10\.{octet}\.{octet}\.{octet}|172\.(?:1[6-9]|2\d|3[01])\.{octet}\.{octet}|192\.168\.{octet}\.{octet})(?![\w.])", 0.9),
        rule("INTERNAL_HOSTNAME", "InternalHostnameRecognizer",
             r"(?i)(?<![\w.-])[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
             r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*\.(?:internal|local|corp|lan)(?![\w.-])", 0.8),
        _InternationalPhoneRecognizer(
            supported_entity="PHONE_NUMBER", name="InternationalPhoneShapeRecognizer",
            patterns=[Pattern("international_phone", r"(?<!\w)\+[1-9]\d{0,2}(?:[ .()-]?\d){7,12}(?![\w\d])", 0.85)],
        ),
        _ValidatedSsnRecognizer(name="ValidatedSsnRecognizer"),
        rule("MASKED_US_SSN", "MaskedSsnRecognizer",
             r"(?<![\w])(?:[Xx]{3}|\*{3})-(?:[Xx]{2}|\*{2})-\d{4}(?!\d)", 0.85),
        rule("STREET_ADDRESS", "StreetAddressRecognizer",
             r"(?i)\b(?:\d{1,6}[A-Z]?\s+(?:[A-Z][A-Z'-]*\s+){1,5}"
             r"(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|boulevard|blvd|way|court|ct)\b\.?"
             r"|P\.?\s*O\.?\s+Box\s+\d{1,8}\b)", 0.85),
        rule("POSTAL_CODE", "UkPostalCodeRecognizer",
             r"(?i)(?<![A-Z0-9])(?:GIR\s?0AA|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})(?![A-Z0-9])", 0.85),
        rule("POSTAL_CODE", "ContextPostalCodeRecognizer",
             r"(?i)\b(?:(?:PIN(?:\s+code)?|postal(?:\s+code)?|Mumbai|Delhi|Bengaluru|Chennai|Kolkata|Pune)"
             r"[\s,:=-]+[1-9]\d{5}\b|(?:ZIP(?:\s+code)?|(?-i:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC))[ \t:=-]+\d{5}(?:-\d{4})?\b)", 0.75),
    ]


class _CsvNameRecognizer(EntityRecognizer):
    """Alphabetic name-like values only under explicit CSV name headers."""
    def __init__(self):
        super().__init__(supported_entities=["PERSON"], name="CsvNameRecognizer", supported_language="en")

    def load(self):
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        lines = text.splitlines(keepends=True)
        if len(lines) < 2:
            return []
        try:
            headers = next(csv.reader([lines[0]]))
        except (csv.Error, StopIteration):
            return []
        columns = {
            index for index, header in enumerate(headers)
            if header.strip().lower() in {"name", "first_name", "last_name", "full_name", "patient_name"}
        }
        if not columns:
            return []
        results = []
        offset = len(lines[0])
        for line in lines[1:]:
            try:
                values = next(csv.reader([line]))
            except (csv.Error, StopIteration):
                offset += len(line)
                continue
            if len(values) != len(headers):
                offset += len(line)
                continue
            cursor = 0
            for index, value in enumerate(values):
                start = line.find(value, cursor)
                if start < 0:
                    break
                cursor = start + len(value)
                if index in columns and 2 <= len(value) <= 100 and re.fullmatch(r"[^\W\d_]+(?:[ '-][^\W\d_]+){0,4}", value):
                    results.append(RecognizerResult(
                        entity_type="PERSON", start=offset + start,
                        end=offset + cursor, score=0.85,
                    ))
            offset += len(line)
        return results
