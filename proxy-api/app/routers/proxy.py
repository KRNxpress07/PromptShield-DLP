"""POST /v1/chat/completions — the core proxy handler.

Request lifecycle:
1. Authenticate via gateway.yaml API keys
2. Resolve provider + model from headers or defaults
3. Resolve provider API key from gateway.yaml
4. DLP: scan text messages via Presidio, block or redact per policy
5. Forward to upstream provider via LiteLLM
6. Return response with gateway metadata headers
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import litellm
import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .. import dlp, providers, risk, egress
from ..auth import authenticate
from ..config import get_settings, get_provider_keys, get_dlp_policy
from ..models import (
    ChatCompletionRequest,
    DLPBlockResponse,
    Usage,
)

log = structlog.get_logger()
router = APIRouter(prefix="/v1", tags=["proxy"])


def _generate_request_id() -> str:
    """Generate a unique opaque request ID (req_ + 16 hex chars)."""
    return f"req_{uuid.uuid4().hex[:16]}"


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
):
    """Core proxy handler: authenticate, DLP-scan, and forward to upstream LLM."""
    request_id = _generate_request_id()
    start = time.monotonic()
    settings = get_settings()

    client_ip = getattr(request.state, "client_ip", "unknown")
    rlog = log.bind(request_id=request_id, client_ip=client_ip)

    # ── 0. Validate request ──────────────────────────────────────────────────
    if not body.messages:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "message": "messages array must not be empty."})

    last_msg = body.messages[-1]
    last_content = last_msg.content
    if isinstance(last_content, str):
        last_empty = last_content.strip() == ""
    elif isinstance(last_content, list):
        last_empty = len(last_content) == 0
    else:
        last_empty = last_content is None

    if last_empty:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "message": "Last message content cannot be empty."})

    # ── 1. Auth ──────────────────────────────────────────────────────────────
    raw_header = request.headers.get("Authorization", "")
    raw_key = raw_header.removeprefix("Bearer ").strip()

    key_record = authenticate(raw_key)
    if key_record is None:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")

    # ── 2. Provider resolution ───────────────────────────────────────────────
    model_name = request.headers.get("x-model") or body.model or settings.default_model
    provider_name = request.headers.get("x-provider") or settings.default_provider
    trusted_model = not (request.headers.get("x-model") or body.model)
    body.model = model_name

    provider_spec = providers.get_provider(provider_name)
    if not provider_spec:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider. Available: {', '.join(providers.list_providers())}",
        )

    # ── 3. Resolve provider API key from config.yaml ─────────────────────────
    provider_keys = get_provider_keys()
    api_key = provider_keys.get(provider_name)
    if not api_key:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "no_credentials",
                "message": f"No API key configured for provider '{provider_name}'. "
                f"Add it to gateway.yaml under providers.{provider_name}.api_key",
            },
        )

    # ── 4. DLP policy enforcement ────────────────────────────────────────────
    dlp_start = time.monotonic()
    decision = await egress.inspect_outbound_payload(
        request.state.http_client, body.model_dump(exclude_none=True), get_dlp_policy(),
        trusted_model=trusted_model,
    )
    assessment = decision.assessment
    raw_violations = decision.scan.violations
    violations_list = [v.model_dump() for v in raw_violations]
    pii_detected = bool(raw_violations)
    dlp_latency_ms = int((time.monotonic() - dlp_start) * 1000)
    rlog.info(
        "dlp_scan_complete", dlp_latency_ms=dlp_latency_ms,
        policy_action=assessment.action.value, findings=len(raw_violations),
        entity_types=assessment.entity_types,
    )
    if assessment.action is risk.Action.BLOCK:
        return JSONResponse(
            status_code=422,
            content=DLPBlockResponse(
                request_id=request_id,
                message=assessment.reason,
                violations=raw_violations,
                risk_level=assessment.level.value,
                risk_score=assessment.score,
                entity_types=assessment.entity_types,
            ).model_dump(),
            headers={"x-request-id": request_id},
        )
    # Both provider entry points are strictly below the final safety decision.
    upstream_body = decision.payload
    model_name = upstream_body["model"]
    rlog.info("provider_resolved", provider=provider_name, model=model_name)
    upstream_start = time.monotonic()

    # ── 5a. Streaming path ────────────────────────────────────────────────
    if body.stream:
        try:
            stream_response = await providers.forward_chat_completion_stream(
                provider_spec, api_key, dict(upstream_body),
            )
        except litellm.exceptions.Timeout:
            rlog.error("upstream_timeout", provider=provider_name)
            raise HTTPException(status_code=504, detail="The AI provider took too long to respond. Please try again.")
        except litellm.exceptions.AuthenticationError:
            rlog.error("upstream_auth_error", provider=provider_name)
            raise HTTPException(status_code=502, detail="Your API key was rejected by the provider. Check gateway.yaml.")
        except litellm.exceptions.BadRequestError:
            rlog.error("upstream_bad_request", provider=provider_name)
            raise HTTPException(status_code=400, detail={"error": "upstream_bad_request", "message": "Provider rejected the request."})
        except Exception:
            rlog.error("upstream_unexpected_error")
            raise HTTPException(status_code=502, detail={"error": "upstream_error", "message": f"Could not complete request to '{provider_name}'. Please retry."})

        async def _sse_generator():
            try:
                async for chunk in stream_response:
                    chunk_dict = chunk.model_dump() if hasattr(chunk, "model_dump") else dict(chunk)
                    chunk_dict["model"] = model_name
                    yield f"data: {json.dumps(chunk_dict)}\n\n"
                yield "data: [DONE]\n\n"
            except Exception:
                rlog.error("stream_chunk_error", provider=provider_name)
                yield f"data: {json.dumps({'error': {'message': 'Stream interrupted', 'type': 'server_error'}})}\n\n"
                yield "data: [DONE]\n\n"
            finally:
                _now = time.monotonic()
                rlog.info(
                    "stream_completed",
                    status_code=200,
                    provider=provider_name,
                    model=model_name,
                    latency_ms=int((_now - start) * 1000),
                    dlp_latency_ms=dlp_latency_ms,
                    pii_detected=pii_detected,
                    is_streaming=True,
                )

        return StreamingResponse(
            _sse_generator(),
            media_type="text/event-stream",
            headers={
                "x-request-id": request_id,
                "x-aisg-latency": str(int((time.monotonic() - start) * 1000)),
                "x-dlp-latency": str(dlp_latency_ms),
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # ── 5b. Non-streaming path ────────────────────────────────────────────
    try:
        response: litellm.ModelResponse = await providers.forward_chat_completion(
            provider_spec, api_key, upstream_body,
        )
    except litellm.exceptions.Timeout:
        rlog.error("upstream_timeout", provider=provider_name)
        raise HTTPException(status_code=504, detail="The AI provider took too long to respond. Please try again.")
    except litellm.exceptions.AuthenticationError:
        rlog.error("upstream_auth_error", provider=provider_name)
        raise HTTPException(status_code=502, detail="Your API key was rejected by the provider. Check gateway.yaml.")
    except litellm.exceptions.BadRequestError:
        rlog.error("upstream_bad_request", provider=provider_name)
        raise HTTPException(status_code=400, detail={"error": "upstream_bad_request", "message": "Provider rejected the request."})
    except litellm.exceptions.RateLimitError:
        rlog.error("upstream_rate_limit", provider=provider_name)
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limit", "message": f"Provider '{provider_name}' rate-limited this request. Retry shortly."},
        )
    except Exception:
        rlog.error("upstream_unexpected_error")
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_error", "message": f"Could not complete request to '{provider_name}'. Please retry."},
        )

    upstream_latency_ms = int((time.monotonic() - upstream_start) * 1000)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    usage_info = response.usage
    usage = Usage(
        prompt_tokens=usage_info.prompt_tokens or 0,
        completion_tokens=usage_info.completion_tokens or 0,
        total_tokens=usage_info.total_tokens or 0,
    )

    hub_latency_ms = max(elapsed_ms - upstream_latency_ms, 0)

    rlog.info(
        "request_completed",
        status_code=200,
        provider=provider_name,
        model=model_name,
        tokens=usage.total_tokens,
        latency_ms=elapsed_ms,
        hub_latency_ms=hub_latency_ms,
        dlp_latency_ms=dlp_latency_ms,
        pii_detected=pii_detected,
    )

    # ── 6. Response ──────────────────────────────────────────────────────────
    data = response.model_dump()
    data["model"] = model_name
    data["x_request_id"] = request_id

    aisg_meta: dict[str, Any] = {
        "provider_selected": provider_name,
        "latency_ms": hub_latency_ms,
        "dlp_latency_ms": dlp_latency_ms,
        "pii_detected": pii_detected,
        "upstream_latency_ms": upstream_latency_ms,
        "policy_action": assessment.action.value,
        "risk_level": assessment.level.value,
        "risk_score": assessment.score,
    }
    if violations_list:
        aisg_meta["dlp_action"] = "redact" if decision.sanitized else assessment.action.value
        aisg_meta["violations_count"] = len(violations_list)
        aisg_meta["entity_types_detected"] = sorted({v["entity_type"] for v in violations_list})
    data["aisg_metadata"] = aisg_meta

    resp_headers = {
        "x-request-id": request_id,
        "x-aisg-latency": str(hub_latency_ms),
        "x-dlp-latency": str(dlp_latency_ms),
    }
    return JSONResponse(content=data, headers=resp_headers)
