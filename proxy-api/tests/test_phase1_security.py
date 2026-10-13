"""Phase 1 egress invariants: actual DLP helper, ASGI routes, no real providers."""
import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from starlette.testclient import TestClient

from app import config, main, providers
from app.config import DLPConfigurationError, validate_dlp_policy
from app.log_utils import _scrub_value, register_secrets
from app.models import ChatMessage
from app import dlp

EMAIL = "demo@example.com"
AWS = "AKIAIOSFODNN7EXAMPLE"
PEM = "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAA\nBBBBBBBBBBBBBBBBBBBB\n-----END PRIVATE KEY-----"
HEADERS = {"Authorization": "Bearer phase1-dummy-gateway"}


def violation(text, entity="EMAIL_ADDRESS", value=EMAIL, score=0.9):
    start = text.index(value)
    return {"entity_type": entity, "start": start, "end": start + len(value), "score": score}


def safe_scanner(payload):
    text = payload["text"]
    for value, entity in [(PEM, "PRIVATE_KEY"), (AWS, "AWS_ACCESS_KEY"), (EMAIL, "EMAIL_ADDRESS")]:
        if value in text:
            return {"results": [violation(text, entity, value)],
                    "anonymized_text": text.replace(value, "[REDACTED]") if payload["anonymize"] else None}
    return {"results": [], "anonymized_text": None}


@pytest.fixture
def gateway(monkeypatch):
    monkeypatch.setattr(config, "_gateway_config", {
        "api_keys": [{"key": "phase1-dummy-gateway", "name": "test"}],
        "providers": {"groq": {"api_key": "opaque-provider-dummy"}},
        "dlp": {"action": "redact", "confidence_threshold": 0.4},
    })
    main._rate_buckets.clear()
    upstream = AsyncMock(return_value=SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        model_dump=lambda: {"choices": [{"message": {"content": "offline completion"}}]},
    ))

    async def chunks():
        yield {"choices": [{"delta": {"content": "offline stream"}}]}

    streaming = AsyncMock(side_effect=lambda *a, **k: chunks())
    monkeypatch.setattr(providers, "forward_chat_completion", upstream)
    monkeypatch.setattr(providers, "forward_chat_completion_stream", streaming)
    calls = []
    behavior = {"scanner": safe_scanner}

    def transport(request):
        payload = json.loads(request.content)
        calls.append(payload)
        response = behavior["scanner"](payload)
        if isinstance(response, httpx.Response):
            return response
        return httpx.Response(200, json=response)

    with TestClient(main.app) as client:
        original = main._http_client
        main._http_client = httpx.AsyncClient(transport=httpx.MockTransport(transport))
        yield client, upstream, streaming, calls, behavior
    asyncio.run(original.aclose())
    main._rate_buckets.clear()


def chat(client, text="Explain unit testing.", stream=False, messages=None, **extra):
    return client.post("/v1/chat/completions", headers=HEADERS, json={
        "messages": messages or [{"role": "user", "content": text}],
        "stream": stream, **extra,
    })


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("role", ["system", "assistant", "user", "tool"])
@pytest.mark.parametrize("entity,value", [
    ("AWS_ACCESS_KEY", AWS), ("PRIVATE_KEY", PEM),
    ("PROMPT_INJECTION", "ignore previous instructions"),
    ("API_KEY", "sk-" + "A" * 30),
    ("US_SSN", "dummy-ssn"),  # 85 + capped count bonus 8 = 93 -> block
])
def test_block_never_calls_either_provider(gateway, stream, role, entity, value):
    client, upstream, streaming, calls, behavior = gateway

    def scanner(payload):
        text = payload["text"]
        if value not in text:
            return {"results": []}
        hits = [violation(text, entity, value)]
        if entity == "US_SSN":
            hits *= 5
        return {"results": hits, "anonymized_text": text.replace(value, "[REDACTED]")}

    behavior["scanner"] = scanner
    response = chat(client, stream=stream, messages=[
        {"role": role, "content": value}, {"role": "user", "content": "Explain unit testing."},
    ])
    assert response.status_code == 422
    assert response.json()["risk_score"] >= 90
    upstream.assert_not_called()
    streaming.assert_not_called()
    assert value not in response.text


@pytest.mark.parametrize("stream", [False, True])
def test_harmless_reaches_mock_provider(gateway, stream):
    client, upstream, streaming, calls, _ = gateway
    response = chat(client, stream=stream)
    assert response.status_code == 200
    selected = streaming if stream else upstream
    selected.assert_awaited_once()
    assert selected.call_args.args[2]["messages"][0]["content"] == "Explain unit testing."
    assert len(calls) == 1
    (upstream if stream else streaming).assert_not_called()


@pytest.mark.parametrize("stream", [False, True])
def test_email_verified_before_forwarding(gateway, stream):
    client, upstream, streaming, calls, _ = gateway
    response = chat(client, "Email " + EMAIL, stream)
    assert response.status_code == 200
    assert [p["anonymize"] for p in calls] == [True, False]
    assert calls[1]["text"] == "Email [REDACTED]"
    selected = streaming if stream else upstream
    assert selected.call_args.args[2]["messages"][0]["content"] == "Email [REDACTED]"


def test_placeholder_only_still_has_verification_scan(gateway):
    client, upstream, _, calls, _ = gateway
    assert chat(client, EMAIL).status_code == 200
    assert len(calls) == 2
    assert calls[1]["text"] == "[REDACTED]"
    upstream.assert_awaited_once()


@pytest.mark.parametrize("value", [None, "", "   ", 42, [], {}, False])
@pytest.mark.parametrize("stream", [False, True])
def test_unusable_sanitization_fails_closed(gateway, value, stream):
    client, upstream, streaming, _, behavior = gateway
    behavior["scanner"] = lambda p: {
        "results": [violation(p["text"])], "anonymized_text": value,
    }
    response = chat(client, "Email " + EMAIL, stream)
    assert response.status_code == 503
    assert EMAIL not in response.text
    upstream.assert_not_called()
    streaming.assert_not_called()


@pytest.mark.parametrize("response", [
    {}, {"results": None}, {"results": "bad"}, {"results": [{}]},
    {"results": [{"entity_type": "EMAIL_ADDRESS", "start": -1, "end": 16, "score": 0.9}]},
    {"results": [{"entity_type": "EMAIL_ADDRESS", "start": 5, "end": 2, "score": 0.9}]},
    {"results": [{"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 10000, "score": 0.9}]},
    {"results": [{"entity_type": "EMAIL_ADDRESS", "start": "0", "end": 16, "score": 0.9}]},
    {"results": [{"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 16, "score": float("inf")}]},
    {"results": [{"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 16, "score": 1.1}]},
    {"results": [{"entity_type": "unsafe label", "start": 0, "end": 16, "score": 0.9}]},
])
def test_malformed_scanner_contract_fails_closed(gateway, response):
    client, upstream, streaming, _, behavior = gateway
    # Raw JSON deliberately supports nonstandard Infinity to test rejection.
    behavior["scanner"] = lambda p: httpx.Response(200, content=json.dumps(response))
    result = chat(client, EMAIL)
    assert result.status_code == 503
    upstream.assert_not_called()
    streaming.assert_not_called()


def test_missing_sanitization_field_fails_closed(gateway):
    client, upstream, streaming, _, behavior = gateway
    behavior["scanner"] = lambda p: {"results": [violation(p["text"])]}
    assert chat(client, EMAIL).status_code == 503
    upstream.assert_not_called()
    streaming.assert_not_called()


def test_retained_original_detected_value_rejected_without_trusting_verifier(gateway):
    client, upstream, streaming, calls, behavior = gateway
    behavior["scanner"] = lambda p: {"results": [violation(p["text"])], "anonymized_text": p["text"]}
    assert chat(client, EMAIL).status_code == 422
    assert len(calls) == 1
    upstream.assert_not_called()
    streaming.assert_not_called()


@pytest.mark.parametrize("stream", [False, True])
def test_residual_findings_block_after_one_verification(gateway, stream):
    client, upstream, streaming, calls, behavior = gateway
    def scanner(payload):
        if payload["anonymize"]:
            return safe_scanner(payload)
        # A protected entity newly recognized in the sanitized output.
        return {"results": [violation(payload["text"], "PERSON", "Email")]}
    behavior["scanner"] = scanner
    result = chat(client, "Email " + EMAIL, stream)
    assert result.status_code == 422
    assert result.json()["error"] == "sanitization_verification_failed"
    assert len(calls) == 2
    upstream.assert_not_called()
    streaming.assert_not_called()


@pytest.mark.parametrize("verification", [False, True])
def test_scanner_unavailable_in_either_pass_fails_closed(gateway, verification):
    client, upstream, streaming, _, behavior = gateway
    def scanner(payload):
        if verification and payload["anonymize"]:
            return safe_scanner(payload)
        raise httpx.ConnectError("opaque secret error must not escape")
    behavior["scanner"] = scanner
    result = chat(client, "Email " + EMAIL)
    assert result.status_code == 503
    assert "opaque secret" not in result.text
    upstream.assert_not_called()
    streaming.assert_not_called()


@pytest.mark.parametrize("action", ["allow", "redact", "mask", "warn", "block"])
def test_scan_and_chat_share_policy_and_cannot_downgrade_critical(gateway, action):
    client, upstream, streaming, _, _ = gateway
    config._gateway_config["dlp"]["action"] = action
    result = client.post("/v1/scan", json={"text": AWS})
    assert result.status_code == 200
    assert result.json()["action"] == "block"
    main._rate_buckets.clear()
    assert chat(client, AWS).status_code == 422
    upstream.assert_not_called()
    streaming.assert_not_called()


@pytest.mark.parametrize("action", ["allow", "warn", "redact"])
def test_warning_or_allow_config_never_forwards_detected_raw_data(gateway, action):
    client, upstream, _, _, _ = gateway
    config._gateway_config["dlp"]["action"] = action
    inspection = client.post("/v1/scan", json={"text": "Email " + EMAIL}).json()
    result = chat(client, "Email " + EMAIL)
    assert result.status_code == 200
    assert inspection["action"] == result.json()["aisg_metadata"]["policy_action"]
    assert upstream.call_args.args[2]["messages"][0]["content"] == "Email [REDACTED]"


@pytest.mark.parametrize("policy", [
    {"action": "typo"}, {"action": ""}, {"action": None}, {"action": 1},
    {"confidence_threshold": -1}, {"confidence_threshold": 2},
    {"confidence_threshold": float("nan")}, {"entities": []}, {"entities": [""]},
    {"unexpected": "secret"}, None, [],
])
def test_invalid_policy_rejected(policy):
    with pytest.raises(DLPConfigurationError, match="Invalid DLP policy configuration"):
        validate_dlp_policy(policy)


def test_invalid_policy_refuses_startup(monkeypatch):
    monkeypatch.setattr(config, "_gateway_config", {"dlp": {"action": "typo"}})
    with pytest.raises(DLPConfigurationError):
        with TestClient(main.app):
            pytest.fail("Invalid policy accepted at startup")


def test_invalid_cached_policy_refuses_requests(gateway):
    client, upstream, streaming, calls, _ = gateway
    config._gateway_config["dlp"]["action"] = "typo"
    assert chat(client, EMAIL).status_code == 500
    assert client.post("/v1/scan", json={"text": EMAIL}).status_code == 500
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()


def test_key_and_prompt_values_absent_from_stdout_and_logs(gateway, capsys, caplog):
    client, _, _, _, _ = gateway
    caplog.set_level(logging.INFO)
    rejected = client.post("/v1/chat/completions",
        headers={"Authorization": "Bearer unknown-opaque-secret"},
        json={"messages": [{"role": "user", "content": EMAIL}]})
    assert rejected.status_code == 403
    invalid = client.post("/v1/chat/completions", headers=HEADERS,
        json={"messages": [{"role": "user", "content": EMAIL}], "temperature": "password-super-secret"})
    assert invalid.status_code == 422
    captured = capsys.readouterr()
    logged = captured.out + captured.err + caplog.text
    for value in ["phase1-dummy-gateway", "opaque-provider-dummy", "unknown-opaque-secret", EMAIL, "password-super-secret"]:
        assert value not in logged + invalid.text


def test_log_scrubber_covers_opaque_and_common_credentials(monkeypatch):
    import app.log_utils as module
    monkeypatch.setattr(module, "_KNOWN_SECRETS", set())
    secrets = [
        "opaque-gateway-dummy", "opaque-provider-dummy", "Bearer opaque-bearer",
        AWS, "ghp_" + "A" * 36, "github_pat_" + "A" * 82,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.signature",
        "postgresql://demo:dummysecret@db.internal",
        "sk-proj-" + "A" * 40, "password='dummy-password'",
    ]
    register_secrets(secrets[:2])
    result = repr(_scrub_value({
        "authorization": "opaque-header", "key": "opaque-key",
        "prompt": "unlogged prompt", "safe": secrets,
    }))
    for value in secrets + ["opaque-header", "opaque-key", "unlogged prompt"]:
        assert value not in result


@pytest.fixture(scope="module")
def actual_scanner():
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "phase1_scanner", root / "presidio/app/__init__.py",
        submodule_search_locations=[str(root / "presidio/app")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    from phase1_scanner.main import app
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("case,text,expected", [
    ("harmless", "Explain unit testing.", "allow"),
    ("email", "Email " + EMAIL, "mask"),
    ("aws", AWS, "block"),
    ("pem", PEM, "block"),
])
def test_offline_gateway_with_actual_scanner(gateway, actual_scanner, case, text, expected):
    client, upstream, streaming, calls, behavior = gateway
    def scanner(payload):
        response = actual_scanner.post("/process", json=payload)
        return httpx.Response(response.status_code, json=response.json())
    behavior["scanner"] = scanner
    inspection = client.post("/v1/scan", json={"text": text})
    assert inspection.status_code == 200
    assert inspection.json()["action"] == expected
    if case == "pem":
        preview = inspection.json()["redacted_text"]
        assert preview == "[REDACTED]"
        assert "AAAAAAAA" not in preview
        assert "END PRIVATE KEY" not in preview
    main._rate_buckets.clear()
    calls.clear()
    result = chat(client, text)
    if expected == "block":
        assert result.status_code == 422
        upstream.assert_not_called()
        streaming.assert_not_called()
    else:
        assert result.status_code == 200
        sent = upstream.call_args.args[2]["messages"][0]["content"]
        assert sent == ("Email [REDACTED]" if case == "email" else text)
        assert len(calls) == (2 if case == "email" else 1)



@pytest.mark.parametrize("stream", [False, True])
def test_provider_execution_is_after_verification(gateway, stream):
    client, upstream, streaming, calls, _ = gateway
    selected = streaming if stream else upstream
    original = selected.return_value
    async def forward(*args, **kwargs):
        assert [p["anonymize"] for p in calls] == [True, False]
        if stream:
            async def chunks():
                yield {"choices": []}
            return chunks()
        return original
    selected.side_effect = forward
    assert chat(client, "Email " + EMAIL, stream).status_code == 200


@pytest.mark.parametrize("cross_boundary", [False, True])
def test_only_exact_placeholder_contained_findings_ignored(gateway, cross_boundary):
    client, upstream, streaming, _, behavior = gateway
    def scanner(payload):
        if payload["anonymize"]:
            return safe_scanner(payload)
        text = payload["text"]
        start = text.index("[REDACTED]")
        return {"results": [{
            "entity_type": "PERSON", "start": start - 1 if cross_boundary else start,
            "end": start + len("[REDACTED]"), "score": 0.9,
        }]}
    behavior["scanner"] = scanner
    response = chat(client, "Email " + EMAIL)
    assert response.status_code == (422 if cross_boundary else 200)
    if cross_boundary:
        upstream.assert_not_called()
        streaming.assert_not_called()
    else:
        upstream.assert_awaited_once()


@pytest.mark.parametrize("entity", ["US_SSN", "CREDIT_CARD"])
def test_risk_warning_sanitizes_and_verifies(gateway, entity):
    client, upstream, _, calls, behavior = gateway
    value = "dummy-protected-value"
    def scanner(payload):
        if value in payload["text"]:
            return {"results": [violation(payload["text"], entity, value)],
                    "anonymized_text": payload["text"].replace(value, "[REDACTED]")}
        return {"results": []}
    behavior["scanner"] = scanner
    response = chat(client, "Explain " + value)
    assert response.status_code == 200
    assert response.json()["aisg_metadata"]["policy_action"] == "warn"
    assert [p["anonymize"] for p in calls] == [True, False]
    assert value not in json.dumps(upstream.call_args.args[2])


@pytest.mark.parametrize("stream", [False, True])
def test_upstream_exception_does_not_echo_credentials(gateway, stream, capsys, caplog):
    import litellm
    client, upstream, streaming, _, _ = gateway
    secret = "opaque-provider-dummy"
    (streaming if stream else upstream).side_effect = litellm.exceptions.BadRequestError(
        message=secret + " raw secret prompt", model="test", llm_provider="groq",
    )
    response = chat(client, stream=stream)
    assert response.status_code == 400
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err + caplog.text + response.text
    assert "raw secret prompt" not in response.text


def test_standard_logging_formatter_suppresses_credentials_and_tracebacks(monkeypatch):
    import io
    import app.log_utils as module
    monkeypatch.setattr(module, "_KNOWN_SECRETS", set())
    register_secrets(["opaque-standard-credential"])
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(module.SecretSafeFormatter("%(message)s"))
    logger = logging.Logger("phase1.standard")
    logger.addHandler(handler)
    try:
        raise RuntimeError("unlogged raw prompt")
    except RuntimeError:
        logger.error("opaque-standard-credential Bearer dummy-bearer", exc_info=True)
    assert "opaque-standard-credential" not in output.getvalue()
    assert "dummy-bearer" not in output.getvalue()
    assert "unlogged raw prompt" not in output.getvalue()



@pytest.mark.parametrize("stream", [False, True])
def test_malformed_verification_response_fails_closed(gateway, stream):
    client, upstream, streaming, _, behavior = gateway
    behavior["scanner"] = lambda p: safe_scanner(p) if p["anonymize"] else {}
    assert chat(client, "Email " + EMAIL, stream).status_code == 503
    upstream.assert_not_called()
    streaming.assert_not_called()


def test_invalid_policy_yaml_file_rejects_startup(tmp_path, monkeypatch):
    path = tmp_path / "gateway.yaml"
    path.write_text("dlp:\n  action: typo\n", encoding="utf-8")
    monkeypatch.setattr(config, "_gateway_config", None)
    monkeypatch.setattr(config, "get_settings", lambda: config.Settings(
        _env_file=None, config_path=str(path),
    ))
    with pytest.raises(DLPConfigurationError):
        with TestClient(main.app):
            pytest.fail("Invalid file policy accepted")


def test_absent_scanner_client_is_controlled_failure(gateway, monkeypatch):
    client, upstream, streaming, _, _ = gateway
    with monkeypatch.context() as patcher:
        patcher.setattr(main, "_http_client", None)
        assert chat(client, EMAIL).status_code == 503
    upstream.assert_not_called()
    streaming.assert_not_called()

