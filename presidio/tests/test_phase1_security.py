"""Full PEM spans and scanner error/log confidentiality; all bodies are dummy."""
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from app.main import app
from app.post_processor import filter_false_positives


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("kind", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
                                  "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_entire_dummy_pem_span_removed(client, kind, newline):
    pem = newline.join([f"-----BEGIN {kind}-----", "AAAAAAAAAAAAAAAAAAAA",
                        "BBBBBBBBBBBBBBBBBBBB", f"-----END {kind}-----"])
    text = "Before\n" + pem + "\nAfter"
    response = client.post("/process", json={
        "text": text, "entities": ["PRIVATE_KEY"], "anonymize": True,
        "operators": {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}},
    })
    assert response.status_code == 200
    data = response.json()
    assert data["anonymized_text"] == "Before\n[REDACTED]\nAfter"
    assert data["results"] == [{
        "entity_type": "PRIVATE_KEY", "start": len("Before\n"),
        "end": len("Before\n") + len(pem), "score": 0.99,
    }]
    assert "AAAA" not in data["anonymized_text"]
    assert "BBBB" not in data["anonymized_text"]
    assert "END " not in data["anonymized_text"]


@pytest.mark.parametrize("ending", ["", "\n-----END EC PRIVATE KEY-----"])
def test_incomplete_or_mismatched_key_stays_protected(client, ending):
    text = "-----BEGIN RSA PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAA" + ending
    data = client.post("/process", json={
        "text": text, "entities": ["PRIVATE_KEY"],
        "operators": {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}},
    }).json()
    assert data["results"][0]["entity_type"] == "PRIVATE_KEY"
    assert data["anonymized_text"] == "[REDACTED]"


def test_multiple_key_blocks_do_not_mask_surrounding_text(client):
    key = "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----"
    data = client.post("/process", json={
        "text": key + "\nBetween\n" + key, "entities": ["PRIVATE_KEY"],
        "operators": {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}},
    }).json()
    assert data["anonymized_text"] == "[REDACTED]\nBetween\n[REDACTED]"


@pytest.mark.parametrize("entity", ["PRIVATE_KEY", "AWS_ACCESS_KEY", "API_KEY", "PROMPT_INJECTION"])
def test_blocking_entity_not_suppressed_by_high_confidence_pii(entity):
    protected = SimpleNamespace(entity_type=entity, start=0, end=10, score=0.8)
    pii = SimpleNamespace(entity_type="PERSON", start=0, end=10, score=1.0)
    assert protected in filter_false_positives("dummy text", [protected, pii])


def test_partial_overlap_keeps_sensitive_tail():
    a = SimpleNamespace(entity_type="PERSON", start=0, end=5, score=1.0)
    b = SimpleNamespace(entity_type="LOCATION", start=3, end=10, score=0.5)
    assert filter_false_positives("dummy text", [a, b]) == [a, b]


def test_scanner_validation_never_logs_or_echoes_input(client, capsys, caplog):
    caplog.set_level(logging.INFO)
    secret = "opaque-dummy-validation-secret"
    response = client.post("/process", json={"text": secret, "score_threshold": secret})
    assert response.status_code == 422
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err + caplog.text + response.text


@pytest.mark.parametrize("engine", ["_analyzer", "_anonymizer"])
def test_processing_exception_never_logs_or_echoes_secret(client, capsys, caplog, engine):
    from app import main
    secret = "opaque-dummy-processing-secret"
    attribute = "analyze" if engine == "_analyzer" else "anonymize"
    caplog.set_level(logging.INFO)
    with patch.object(getattr(main, engine), attribute, side_effect=RuntimeError(secret)):
        response = client.post("/process", json={"text": "demo@example.com", "anonymize": True})
    assert response.status_code == 422
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err + caplog.text + response.text

