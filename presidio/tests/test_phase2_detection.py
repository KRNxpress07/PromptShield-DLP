"""Phase 2 detector registration, complete spans and false-positive controls."""
import base64
import json
import importlib.util
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient
from app.main import app
from app.recognizers import _custom_recognizers

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

JWT = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"sub": "dummy", "scope": "test"}) + "." + "A" * 43
POSITIVE = [
    ("API_KEY", "sk-" + "A" * 30),
    ("API_KEY", "sk-proj-" + "A_" * 24),
    ("API_KEY", "sk-svcacct-" + "A" * 48),
    ("API_KEY", "sk-admin-" + "A" * 48),
    ("API_KEY", "sk-ant-" + "A" * 32),
    ("API_KEY", "sk-ant-api03-" + "A" * 93 + "AA"),
    ("API_KEY", "sk-ant-admin01-" + "A" * 93 + "AA"),
    ("API_KEY", "AIza" + "A" * 35),
    ("API_KEY", "gsk_" + "A" * 48),
    *[("GITHUB_TOKEN", prefix + "A" * 36) for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")],
    ("GITHUB_TOKEN", "github_pat_" + "A" * 82),
    ("AWS_ACCESS_KEY", "AKIA" + "A" * 16),
    ("AWS_ACCESS_KEY", "ASIA" + "A" * 16),
    ("JWT_TOKEN", JWT),
    ("SLACK_WEBHOOK", "https://hooks.slack.com/services/T00000000/B00000000/DUMMYTOKEN0123456789"),
    ("BEARER_TOKEN", "Bearer " + "A" * 32),
    ("BEARER_TOKEN", "bearer " + "A" * 32),
    *[("DB_CONNECTION_STRING", scheme + "://demo:dummysecret@db.example.com:5432/database?sslmode=require")
      for scheme in ("postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "rediss", "mssql", "amqp")],
    ("DB_CONNECTION_STRING", "redis://:dummysecret@host.example.com:6379"),
    *[("GENERIC_SECRET_ASSIGNMENT", key + ' = "dummy-value-1234"')
      for key in ("password", "passwd", "pwd", "secret", "api_key", "api_secret", "client_secret", "access_token", "TOGETHER_API_KEY", "DEEPINFRA_API_TOKEN")],
    ("GENERIC_SECRET_ASSIGNMENT", "password: dummy-value-1234"),
    *[("AWS_SECRET_KEY", key + ' = "' + "A" * 40 + '"')
      for key in ("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "secretAccessKey", "awsSecretAccessKey")],
    ("AWS_SESSION_TOKEN", "AWS_SESSION_TOKEN: " + "A" * 100),
    ("AWS_SESSION_TOKEN", '"sessionToken": "' + "A" * 100 + '"'),
    *[("PRIVATE_IP", value) for value in ("10.0.0.0", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1")],
    *[("INTERNAL_HOSTNAME", value) for value in ("db.internal", "host.local", "api.corp", "files.lan", "db.team.internal")],
    *[("PHONE_NUMBER", value) for value in ("+1-555-010-9988", "+1 202 555 0198", "+44 20 7946 0123", "+91 22 2781 0000")],
    *[("STREET_ADDRESS", value) for value in ("1122 Hosberg Rd", "45 Main St", "P.O. Box 1234", "10 Downing Street")],
    *[("POSTAL_CODE", value) for value in ("E1 6AN", "SW1A 1AA", "Mumbai 400001", "ZIP: 62704", "IL 62704")],
    ("MASKED_US_SSN", "XXX-XX-1234"),
    ("MASKED_US_SSN", "***-**-5678"),
    ("US_SSN", "321-54-6789"),
    ("US_SSN", "321 54 6789"),
    ("CREDIT_CARD", "4111-1111-1111-1111"),
]

NEGATIVE = [
    ("SLACK_WEBHOOK", "https://slack.com/docs"),
    ("SLACK_WEBHOOK", "https://hooks.slack.com/services/"),
    *[("JWT_TOKEN", value) for value in ("version.1.2", "example.com/path", "file.config.json", "eyJnotjson.AAAAAAAAAA.BBBBBBBBBB")],
    *[("BEARER_TOKEN", value) for value in ("The word bearer appears here", "Bearer short")],
    *[("DB_CONNECTION_STRING", value) for value in ("postgresql documentation without credentials", "postgresql://db.example.com/db", "mysql://demo@host/db")],
    *[("GENERIC_SECRET_ASSIGNMENT", value) for value in ("password policy description", "client_secret", "count = 1234", "password = ''", "password: null", "password_policy = 'strict'")],
    *[("AWS_SECRET_KEY", value) for value in ("A" * 40, "secretAccessKey: short", "aws_secret_access_key documentation")],
    *[("AWS_SESSION_TOKEN", value) for value in ("A" * 100, "sessionToken: short", "session token docs")],
    *[("PRIVATE_IP", value) for value in ("8.8.8.8", "172.15.1.1", "172.32.1.1", "192.169.1.1", "10.999.0.1", "192.168.1.999", "127.0.0.1")],
    *[("INTERNAL_HOSTNAME", value) for value in ("example.com", "localhost documentation", "db.internal.example.com", "prefixinternal")],
    *[("API_KEY", value) for value in ("sk-", "sk-proj-", "sk-proj-" + "A" * 19, "sk-svcacct-", "sk-admin-", "sk-ant-api03-short", "AIza" + "A" * 34, "gsk_short")],
    *[("GITHUB_TOKEN", value) for value in ("ghp_", "gho_short", "ghu_short", "ghs_short", "ghr_short", "github_pat_short")],
    *[("AWS_ACCESS_KEY", value) for value in ("AKIA", "ASIAshort", "AKIA" + "A" * 15, "ASIA" + "A" * 17)],
    *[("PHONE_NUMBER", value) for value in ("+1-12", "version 1.2.3", "1985-05-12")],
    *[("STREET_ADDRESS", value) for value in ("I have 5 cats and 3 dogs", "street address policy", "42 main iterations")],
    *[("POSTAL_CODE", value) for value in ("123456", "version is 12345", "build 400001", "ABCD 123")],
    *[("MASKED_US_SSN", value) for value in ("XXX-XX", "XX-XXX-1234", "XXXX-XX-1234", "1234")],
    *[("US_SSN", value) for value in ("000-00-0000", "666-12-3456", "900-12-3456", "321-00-6789", "321-54-0000", "123-45-6789")],
    *[("CREDIT_CARD", value) for value in ("4111-2222-3333-4444", "4000 0000 0000 0000", "Visa ending 4444", "1985-05-12")],
]

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.mark.parametrize("entity,value", POSITIVE)
def test_positive_complete_span_and_sanitization(client, entity, value):
    response = client.post("/process", json={
        "text": value, "entities": [entity], "anonymize": True, "score_threshold": 0.4,
        "operators": {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}},
    })
    assert response.status_code == 200
    result = response.json()
    assert any(r["entity_type"] == entity and r["start"] == 0 and r["end"] == len(value) for r in result["results"]), result
    assert result["anonymized_text"] == "[REDACTED]"

@pytest.mark.parametrize("entity,value", NEGATIVE)
def test_negative_control(client, entity, value):
    result = client.post("/process", json={"text": value, "entities": [entity], "anonymize": False}).json()
    assert not result["results"], result

def test_jwt_in_surrounding_text(client):
    text = "Use token " + JWT + " for this dummy example."
    result = client.post("/process", json={"text": text, "entities": ["JWT_TOKEN"]}).json()
    assert result["results"][0]["start"] == len("Use token ")
    assert JWT not in result["anonymized_text"]

def test_custom_entity_registration_gateway_weights_consistent(client):
    root = Path(__file__).resolve().parents[2]
    gateway_entities = set(yaml.safe_load((root / "config/gateway.yaml").read_text(encoding="utf-8"))["dlp"]["entities"])
    custom = {entity for rec in _custom_recognizers() for entity in rec.supported_entities}
    loaded = set(client.get("/health").json()["entities"])
    spec = importlib.util.spec_from_file_location("phase2_risk", root / "proxy-api/app/risk.py")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert custom <= loaded
    assert custom <= gateway_entities
    assert gateway_entities <= loaded
    assert gateway_entities <= set(module.SEVERITY_WEIGHTS)

def test_unknown_requested_entity_rejected(client):
    assert client.post("/process", json={"text": "Harmless", "entities": ["EMAIL_ADDRESS", "MISSING_ENTITY"]}).status_code == 422

def test_invalid_project_pattern_refuses_analyzer_startup(monkeypatch):
    from app import recognizers
    from presidio_analyzer import Pattern, PatternRecognizer
    invalid = PatternRecognizer(supported_entity="BROKEN", patterns=[Pattern("invalid", "valid", .9)])
    invalid.patterns[0].regex = "["
    monkeypatch.setattr(recognizers, "_custom_recognizers", lambda: [invalid])
    with pytest.raises(RuntimeError, match="Invalid custom recognizer pattern"):
        recognizers.build_analyzer()



@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_csv_name_column_has_complete_original_spans(client, newline):
    text = newline.join(["id,name,email", "1,Jane Smith,jane@example.com", "2,John Doe,john@example.com"])
    result = client.post("/process", json={
        "text": text, "entities": ["PERSON"], "anonymize": True,
        "operators": {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}},
    }).json()
    spans = [text[r["start"]:r["end"]] for r in result["results"]]
    assert "Jane Smith" in spans and "John Doe" in spans
    assert "Jane Smith" not in result["anonymized_text"]
    assert "John Doe" not in result["anonymized_text"]
    assert "jane@example.com" in result["anonymized_text"]

@pytest.mark.parametrize("text", [
    "description,value\nordinary text,other text",
    "name\n123456", "name\nnot_a_name", "names are personal information",
    "id,name,email\n1,extra,columns,here",
])
def test_csv_name_rule_negative_context_and_values(text):
    from app.recognizers import _CsvNameRecognizer
    assert _CsvNameRecognizer().analyze(text, ["PERSON"]) == []

def test_contained_date_does_not_discard_valid_ssn(client):
    result = client.post("/process", json={"text": "SSN: 880 32 4565", "anonymize": False}).json()
    assert any(r["entity_type"] == "US_SSN" for r in result["results"])
    assert not any(r["entity_type"] == "DATE_TIME" for r in result["results"])



def test_retired_yaml_cannot_silently_add_inactive_detectors(tmp_path, monkeypatch):
    from app import recognizers
    path = tmp_path / "recognizers.yaml"
    path.write_text("- supported_entity: INERT_ENTITY\n", encoding="utf-8")
    monkeypatch.setattr(recognizers, "RETIRED_RECOGNIZER_PATH", path)
    with pytest.raises(RuntimeError, match="retired"):
        recognizers.build_analyzer()

def test_iban_builtin_enabled_and_validated(client):
    bban = "123456781234567890"
    iban = "DE" + str(98 - int(bban + "131400") % 97).zfill(2) + bban
    good = client.post("/process", json={
        "text": iban, "entities": ["IBAN_CODE"],
        "operators": {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}},
    }).json()
    assert good["anonymized_text"] == "[REDACTED]"
    bad = client.post("/process", json={"text": "DE00" + bban, "entities": ["IBAN_CODE"]}).json()
    assert not bad["results"]

