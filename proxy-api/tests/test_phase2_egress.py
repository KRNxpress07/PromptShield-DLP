"""Complete outbound leaf inspection and actual-scanner offline demonstrations."""
import asyncio
import base64
import copy
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from app import dlp, egress, providers, main, config
from app.models import ChatCompletionRequest
from tests.test_phase1_security import (
    gateway, actual_scanner, chat, safe_scanner, violation, AWS, PEM, EMAIL, HEADERS,
)

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

JWT = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"sub": "dummy"}) + "." + "A" * 43
KEY = "sk-proj-" + "A" * 48
DB = "postgresql://demo:dummysecret@db.example.com:5432/database"
AWS_SECRET = "aws_secret_access_key = " + "A" * 40
TOOL = {
    "type": "function",
    "function": {"name": "fetch_status", "description": "Inspect status",
                 "parameters": {"type": "object", "properties": {"input": {"type": "string"}},
                                "required": ["input"]}},
}

FIELDS = [
    {"messages": [{"role": "user", "content": "Harmless", "name": AWS}]},
    {"model": AWS},
    {"tools": [{"type": "function", "function": {"name": "fetch_status", "description": AWS}}]},
    {"tools": [{"type": "function", "function": {"name": AWS}}]},
    {"tools": [{"type": "function", "function": {"name": "fetch_status", "parameters": {"description": AWS}}}]},
    {"functions": [{"name": "fetch_status", "description": AWS}]},
    {"tool_choice": {"type": "function", "function": {"name": AWS}}},
    {"function_call": {"name": AWS}},
    {"response_format": {"type": "json_schema", "json_schema": {"name": "result", "schema": {"description": AWS}}}},
    {"stop": [AWS]},
    {"user": AWS},
    {"thinking": {"context": AWS}},
    {"extra_headers": {"x-context": AWS}},
    {"stream_options": {"label": AWS}},
    {"logit_bias": {AWS: 0.1}},
    {"reasoning_effort": AWS},
    {"service_tier": AWS},
]

@pytest.mark.parametrize("extra", FIELDS)
@pytest.mark.parametrize("stream", [False, True])
def test_every_forwarded_text_field_blocks_critical_data(gateway, extra, stream):
    client, upstream, streaming, _, _ = gateway
    result = chat(client, stream=stream, **extra)
    assert result.status_code == 422
    assert result.json()["error"] == "pii_policy_violation"
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.parametrize("stream", [False, True])
def test_nested_descriptions_sanitized_and_shape_preserved(gateway, stream):
    client, upstream, streaming, calls, _ = gateway
    tool = copy.deepcopy(TOOL)
    tool["function"]["description"] = "Contact " + EMAIL
    tool["function"]["parameters"]["properties"]["input"]["description"] = "Mail " + EMAIL
    tool["function"]["parameters"]["examples"] = [{"details": ["Reply to " + EMAIL, 7, True, None]}]
    result = chat(client, stream=stream, tools=[tool])
    assert result.status_code == 200
    sent = (streaming if stream else upstream).call_args.args[2]["tools"][0]
    expected = copy.deepcopy(tool)
    expected["function"]["description"] = "Contact [REDACTED]"
    expected["function"]["parameters"]["properties"]["input"]["description"] = "Mail [REDACTED]"
    expected["function"]["parameters"]["examples"][0]["details"][0] = "Reply to [REDACTED]"
    assert sent == expected
    assert tool["function"]["description"] == "Contact " + EMAIL  # input unmodified
    assert EMAIL not in json.dumps(sent)
    assert any(not entry["anonymize"] for entry in calls)

@pytest.mark.parametrize("stream", [False, True])
def test_nested_sanitization_fault_blocks_egress(gateway, stream):
    client, upstream, streaming, _, behavior = gateway
    def scanner(payload):
        response = safe_scanner(payload)
        if EMAIL in payload["text"]:
            response["anonymized_text"] = None
        return response
    behavior["scanner"] = scanner
    result = chat(client, stream=stream, tools=[{
        "type": "function", "function": {"name": "fetch_status", "parameters": {"description": EMAIL}},
    }])
    assert result.status_code == 503
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.parametrize("parts", [
    [{"type": "image_url", "image_url": {"url": "data:image/png;base64,QUJD"}}],
    [{"type": "text", "text": "Harmless"}, {"type": "image_url", "image_url": {"url": "https://example.com/dummy.png"}}],
    [{"type": "input_audio", "input_audio": {"data": "QUJD", "format": "wav"}}],
    [{"type": "file", "file": {"file_data": "QUJD"}}],
    [{"type": "unknown", "data": "anything"}],
    [{"type": "text", "text": {"nested": "unsafe"}}],
    [{"type": "text", "text": "Harmless", "image_url": "hidden"}],
])
@pytest.mark.parametrize("stream", [False, True])
def test_unsupported_modalities_rejected_before_scan_or_provider(gateway, parts, stream):
    client, upstream, streaming, calls, _ = gateway
    response = chat(client, stream=stream, messages=[{"role": "user", "content": parts}])
    assert response.status_code == 422
    assert response.json()["error"] == "unsupported_dlp_content"
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()

def test_supported_text_parts_preserve_structure(gateway):
    client, upstream, _, _, _ = gateway
    parts = [{"type": "text", "text": "Contact " + EMAIL}, {"type": "text", "text": "Explain unit testing."}]
    assert chat(client, messages=[{"role": "user", "content": parts}]).status_code == 200
    sent = upstream.call_args.args[2]["messages"][0]["content"]
    assert sent == [{"type": "text", "text": "Contact [REDACTED]"}, parts[1]]

@pytest.mark.parametrize("stream", [False, True])
def test_harmless_tools_and_schemas_are_unchanged(gateway, stream):
    client, upstream, streaming, _, _ = gateway
    response = chat(client, stream=stream, tools=[TOOL],
                    response_format={"type": "json_schema", "json_schema": {
                        "name": "result", "schema": {"type": "object", "properties": {"input": {"type": "string"}}},
                    }})
    assert response.status_code == 200
    sent = (streaming if stream else upstream).call_args.args[2]
    assert sent["tools"] == [TOOL]
    assert sent["response_format"]["json_schema"]["schema"]["properties"] == {"input": {"type": "string"}}

def test_excessive_nesting_rejected(gateway):
    client, upstream, streaming, calls, _ = gateway
    nested = "leaf"
    for _ in range(egress.MAX_DEPTH + 1):
        nested = {"child": nested}
    response = chat(client, tools=[{"type": "function", "function": {"name": "fetch_status", "parameters": nested}}])
    assert response.status_code == 422
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [b"binary-dummy", object(), float("inf")])
async def test_uninspectable_values_rejected(gateway, bad):
    _, upstream, streaming, _, _ = gateway
    with pytest.raises(egress.UnsupportedDLPContent):
        await egress.inspect_outbound_payload(main._http_client, {
            "messages": [{"role": "user", "content": "Harmless"}], "thinking": {"blob": bad},
        }, {"action": "redact"})
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.parametrize("limit", ["MAX_STRINGS", "MAX_NODES"])
def test_outbound_walk_budget_enforced(gateway, monkeypatch, limit):
    client, upstream, streaming, calls, _ = gateway
    monkeypatch.setattr(egress, limit, 2)
    assert chat(client, tools=[TOOL]).status_code == 422
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()

def test_identical_text_scanned_once_but_occurrences_count_for_risk(gateway):
    client, upstream, streaming, calls, behavior = gateway
    value = "dummy-protected-ssn"
    def scanner(p):
        if value in p["text"]:
            return {"results": [violation(p["text"], "US_SSN", value)], "anonymized_text": "[REDACTED]"}
        return {"results": []}
    behavior["scanner"] = scanner
    response = chat(client, messages=[{"role": "user", "content": value}] * 5)
    assert response.status_code == 422
    assert response.json()["risk_score"] == 93
    assert len(calls) == 1
    upstream.assert_not_called()
    streaming.assert_not_called()

def test_sensitive_schema_key_rejected_instead_of_renamed(gateway):
    client, upstream, streaming, _, _ = gateway
    response = chat(client, tools=[{"type": "function", "function": {"name": "fetch_status", "parameters": {
        "type": "object", "properties": {EMAIL: {"type": "string"}},
    }}}])
    assert response.status_code == 422
    upstream.assert_not_called()
    streaming.assert_not_called()

def test_resolved_x_model_header_inspected(gateway):
    client, upstream, streaming, _, _ = gateway
    result = client.post("/v1/chat/completions",
        headers={**HEADERS, "x-model": AWS},
        json={"messages": [{"role": "user", "content": "Harmless"}]})
    assert result.status_code == 422
    upstream.assert_not_called()
    streaming.assert_not_called()

def test_incoming_authorization_not_sent_for_prompt_scanning(gateway):
    client, _, _, calls, _ = gateway
    assert chat(client).status_code == 200
    assert "phase1-dummy-gateway" not in json.dumps(calls)

def test_all_forwarded_parameters_come_from_single_allowlist():
    model_fields = set(ChatCompletionRequest.model_fields) - {"model"}
    assert model_fields == providers.COMPLETION_PARAMS

@pytest.mark.parametrize("case,text,expected", [
    ("harmless", "Explain unit testing.", "allow"),
    ("modern_openai", KEY, "block"),
    ("jwt", JWT, "warn"),
    ("postgres", DB, "block"),
    ("aws_secret", AWS_SECRET, "block"),
    ("private_key", PEM, "block"),
])
@pytest.mark.parametrize("stream", [False, True])
def test_actual_gateway_scanner_offline_demonstrations(gateway, actual_scanner, case, text, expected, stream):
    client, upstream, streaming, _, behavior = gateway
    def scanner(payload):
        response = actual_scanner.post("/process", json=payload)
        return httpx.Response(response.status_code, json=response.json())
    behavior["scanner"] = scanner
    # Use the actual checked-in policy with all active protected entities.
    from pathlib import Path
    import yaml
    config._gateway_config["dlp"] = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "config/gateway.yaml").read_text(encoding="utf-8")
    )["dlp"]
    inspect = client.post("/v1/scan", json={"text": text})
    assert inspect.status_code == 200
    assert inspect.json()["action"] == expected
    main._rate_buckets.clear()
    response = chat(client, text, stream)
    if expected == "block":
        assert response.status_code == 422
        upstream.assert_not_called()
        streaming.assert_not_called()
    else:
        assert response.status_code == 200
        sent = (streaming if stream else upstream).call_args.args[2]["messages"][0]["content"]
        assert sent == (text if expected == "allow" else "[REDACTED]")

def test_actual_internal_hostname_in_tool_and_nested_array(gateway, actual_scanner):
    client, upstream, _, _, behavior = gateway
    def scanner(payload):
        response = actual_scanner.post("/process", json=payload)
        return httpx.Response(response.status_code, json=response.json())
    behavior["scanner"] = scanner
    tool = copy.deepcopy(TOOL)
    tool["function"]["description"] = "Internal server db.internal"
    tool["function"]["parameters"]["examples"] = [{"servers": ["api.corp", "db.internal"]}]
    response = chat(client, tools=[tool])
    assert response.status_code == 200, response.text
    sent = upstream.call_args.args[2]["tools"][0]
    assert sent["function"]["name"] == "fetch_status"
    assert sent["function"]["description"] == "Internal server [REDACTED]"
    assert sent["function"]["parameters"]["examples"] == [{"servers": ["[REDACTED]", "[REDACTED]"]}]

def test_actual_harmless_tool_schema_demonstration(gateway, actual_scanner):
    client, upstream, _, _, behavior = gateway
    behavior["scanner"] = lambda p: httpx.Response(200, json=actual_scanner.post("/process", json=p).json())
    assert chat(client, tools=[TOOL]).status_code == 200
    assert upstream.call_args.args[2]["tools"] == [TOOL]

def test_actual_scanner_with_nested_sanitization_fault(gateway, actual_scanner):
    client, upstream, streaming, _, behavior = gateway
    def scanner(payload):
        response = actual_scanner.post("/process", json=payload)
        result = response.json()
        if EMAIL in payload["text"] and payload["anonymize"]:
            result["anonymized_text"] = None
        return httpx.Response(response.status_code, json=result)
    behavior["scanner"] = scanner
    tool = copy.deepcopy(TOOL)
    tool["function"]["parameters"]["description"] = EMAIL
    assert chat(client, tools=[tool]).status_code == 503
    upstream.assert_not_called()
    streaming.assert_not_called()



def test_actual_scanner_available_but_image_rejected_before_processing(gateway, actual_scanner):
    client, upstream, streaming, calls, behavior = gateway
    behavior["scanner"] = lambda p: httpx.Response(200, json=actual_scanner.post("/process", json=p).json())
    result = chat(client, messages=[{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,QUJD"}},
    ]}])
    assert result.status_code == 422
    assert result.json()["error"] == "unsupported_dlp_content"
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.parametrize("value", [
    "data:image/png;base64,QUJD", "data:audio/wav;base64,QUJD",
    "data:application/pdf;base64,QUJD", "data:text/plain;base64,QUJD",
])
def test_embedded_encoded_blob_rejected(gateway, value):
    client, upstream, streaming, calls, _ = gateway
    assert chat(client, thinking={"blob": value}).status_code == 422
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.asyncio
async def test_cyclic_in_memory_structure_fails_closed(gateway):
    _, upstream, streaming, calls, _ = gateway
    data = {}
    data["child"] = data
    with pytest.raises(egress.UnsupportedDLPContent):
        await egress.inspect_outbound_payload(main._http_client, {
            "messages": [{"role": "user", "content": "Harmless"}], "thinking": data,
        }, {"action": "redact"})
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()



@pytest.mark.parametrize("value", [
    "AWS_SECRET_ACCESS_KEY=" + "A" * 40,
    '"secretAccessKey": "' + "A" * 40 + '"',
    "AWS_SESSION_TOKEN=" + "A" * 100,
    "client_secret=dummy-client-secret",
    "mssql://demo:dummysecret@host.example.com/db",
    "rediss://demo:dummysecret@host.example.com",
])
def test_new_secret_contexts_scrubbed_from_incidental_logs(value):
    from app.log_utils import _scrub_value
    assert value not in _scrub_value(value)
    for secret in ["A" * 40, "A" * 100, "dummy-client-secret", "dummysecret"]:
        assert secret not in _scrub_value(value)



@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization", "api-key", "X-API-Key", "x-goog-api-key", "x-amz-security-token"])
def test_outbound_credential_header_overrides_rejected(gateway, header):
    client, upstream, streaming, calls, _ = gateway
    response = chat(client, extra_headers={header: "opaque-dummy-override"})
    assert response.status_code == 422
    assert response.json()["error"] == "unsupported_dlp_content"
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()



@pytest.mark.parametrize("header", [" Authorization", "authorization ", "bad:header", "api_key"])
def test_invalid_or_alternate_credential_header_names_rejected(gateway, header):
    client, upstream, streaming, calls, _ = gateway
    assert chat(client, extra_headers={header: "opaque-dummy"}).status_code == 422
    assert not calls
    upstream.assert_not_called()
    streaming.assert_not_called()

@pytest.mark.parametrize("role", ["developer", "function"])
def test_other_standard_text_roles_keep_block_invariant(gateway, role):
    client, upstream, streaming, _, _ = gateway
    assert chat(client, messages=[{"role": role, "content": AWS}]).status_code == 422
    upstream.assert_not_called()
    streaming.assert_not_called()



def test_unchanged_literals_not_rechecked_during_verification(gateway):
    client, upstream, _, calls, _ = gateway
    tool = copy.deepcopy(TOOL)
    tool["function"]["description"] = "Contact " + EMAIL
    assert chat(client, tools=[tool]).status_code == 200
    original_values = [entry["text"] for entry in calls if entry["anonymize"]]
    verified_values = [entry["text"] for entry in calls if not entry["anonymize"]]
    assert "Explain unit testing." in original_values
    assert verified_values == ["Contact [REDACTED]"]
    upstream.assert_awaited_once()



@pytest.mark.parametrize("extra", [
    {"model": EMAIL},
    {"messages": [{"role": "user", "content": "Harmless", "name": EMAIL}]},
    {"tools": [{"type": "function", "function": {"name": EMAIL}}]},
    {"response_format": {"type": "json_schema", "json_schema": {"name": EMAIL}}},
])
def test_sensitive_protocol_identifiers_not_forwarded_as_invalid_placeholders(gateway, extra):
    client, upstream, streaming, _, _ = gateway
    result = chat(client, **extra)
    assert result.status_code == 422
    assert result.json()["error"] == "sanitization_verification_failed"
    upstream.assert_not_called()
    streaming.assert_not_called()

