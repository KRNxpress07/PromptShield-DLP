"""POST /v1/scan — direct risk assessment, no LLM forwarding.

This is the standalone "our model decides" step from the PromptShield
methodology diagram: text goes in, a risk decision comes out. It reuses
Occludra's existing Presidio-backed dlp.process_messages() so detection
stays identical to the full chat-completions proxy — this endpoint only
uses the same authoritative risk/action path as chat forwarding.

Deliberately provider-independent: it works with zero LLM API keys
configured, which matters for a demo — you can show the interception and
decision step live without needing a live OpenAI/Anthropic/Groq key on
stage.
"""

from __future__ import annotations

import time
import uuid

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from .. import dlp
from ..config import get_dlp_policy
from ..models import ChatMessage, DLPViolation

log = structlog.get_logger()
router = APIRouter(prefix="/v1", tags=["scan"])


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=200_000)
    source: str = "prompt"  # "prompt" | "document" | "log" — for UI labeling only


class ScanResponse(BaseModel):
    request_id: str
    action: str  # allow | mask | warn | block
    risk_level: str  # none | low | medium | high | critical
    risk_score: int
    reason: str
    entity_types_detected: list[str]
    violations: list[DLPViolation]
    redacted_text: str | None
    original_length: int
    dlp_latency_ms: int


async def run_text_scan(text: str, http_client, request_id: str) -> ScanResponse:
    """Core scan logic, shared by /v1/scan and the document-upload endpoint.

    Kept as a plain function (not a route handler) so routers/documents.py
    can call it directly after extracting text from a PDF/DOCX/code file,
    without duplicating the DLP + risk-assessment plumbing.
    """
    message = ChatMessage(role="user", content=text)
    dlp_start = time.monotonic()
    decision = await dlp.inspect_messages(http_client, [message], get_dlp_policy())
    result = decision.scan
    assessment = decision.assessment
    dlp_latency_ms = int((time.monotonic() - dlp_start) * 1000)

    redacted_text = None
    if result.redacted_messages:
        redacted_text = result.redacted_messages[0].content

    log.info(
        "scan_complete",
        request_id=request_id,
        action=assessment.action.value,
        risk_level=assessment.level.value,
        risk_score=assessment.score,
        violations=len(result.violations),
        dlp_latency_ms=dlp_latency_ms,
    )

    return ScanResponse(
        request_id=request_id,
        action=assessment.action.value,
        risk_level=assessment.level.value,
        risk_score=assessment.score,
        reason=assessment.reason,
        entity_types_detected=assessment.entity_types,
        violations=result.violations,
        redacted_text=redacted_text,
        original_length=len(text),
        dlp_latency_ms=dlp_latency_ms,
    )


@router.post("/scan", response_model=ScanResponse)
async def scan(body: ScanRequest, request: Request):
    """Scan raw text for sensitive content and return a risk decision.

    Always computes the redacted version (regardless of the eventual
    action) so the UI can preview what masking *would* produce even on a
    warn/block decision.
    """
    if not body.text.strip():
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "message": "text must not be empty."})

    request_id = f"scan_{uuid.uuid4().hex[:16]}"
    return await run_text_scan(body.text, request.state.http_client, request_id)
