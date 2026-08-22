"""POST /v1/documents/scan — upload a file, get a risk decision back.

Covers the "source code, logs, and attached content" part of the
PromptShield problem statement. Extracts text depending on file type, then
hands off to scan.run_text_scan() so detection and risk-scoring logic
stays in exactly one place.

Supported today: .pdf, .docx, and any plain-text/code file (.txt, .md,
.py, .js, .ts, .java, .go, .rb, .php, .c, .cpp, .json, .yaml, .yml, .env,
.log, .sql, .csv, .ini, .cfg, .sh). Anything else is rejected with a
clear 415 rather than silently mis-decoding binary data.
"""

from __future__ import annotations

import io
import uuid
from pathlib import Path

import structlog
from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from .scan import ScanResponse, run_text_scan

log = structlog.get_logger()
router = APIRouter(prefix="/v1", tags=["documents"])

MAX_UPLOAD_BYTES = 15 * 1024 * 1024  # 15MB — matches typical dev-tool attachment limits

PLAIN_TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".log", ".csv",
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rs", ".kt", ".swift",
    ".json", ".yaml", ".yml", ".env", ".ini", ".cfg", ".toml",
    ".sql", ".sh", ".bash", ".ps1",
}


async def _extract_pdf_text(raw: bytes) -> str:
    try:
        import pdfplumber
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": "missing_dependency", "message": "pdfplumber not installed — add it to requirements.txt"},
        ) from exc

    text_parts: list[str] = []
    with pdfplumber.open(io.BytesIO(raw)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            if page_text:
                text_parts.append(page_text)
    return "\n\n".join(text_parts)


async def _extract_docx_text(raw: bytes) -> str:
    try:
        import docx
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": "missing_dependency", "message": "python-docx not installed — add it to requirements.txt"},
        ) from exc

    document = docx.Document(io.BytesIO(raw))
    parts = [p.text for p in document.paragraphs if p.text]
    for table in document.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text:
                    parts.append(cell.text)
    return "\n".join(parts)


def _extract_plain_text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


@router.post("/documents/scan", response_model=ScanResponse)
async def scan_document(request: Request, file: UploadFile = File(...)):
    """Extract text from an uploaded file and scan it for sensitive content."""
    raw = await file.read()

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "payload_too_large", "message": f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit."},
        )
    if not raw:
        raise HTTPException(status_code=400, detail={"error": "empty_file", "message": "Uploaded file is empty."})

    filename = file.filename or "upload"
    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        text = await _extract_pdf_text(raw)
    elif ext == ".docx":
        text = await _extract_docx_text(raw)
    elif ext in PLAIN_TEXT_EXTENSIONS or ext == "":
        text = _extract_plain_text(raw)
    else:
        raise HTTPException(
            status_code=415,
            detail={
                "error": "unsupported_file_type",
                "message": f"'{ext}' is not supported. Supported: .pdf, .docx, or plain-text/code files.",
            },
        )

    if not text.strip():
        raise HTTPException(
            status_code=422,
            detail={"error": "no_extractable_text", "message": "No text could be extracted from this file."},
        )

    request_id = f"doc_{uuid.uuid4().hex[:16]}"
    log.info("document_scan_start", request_id=request_id, filename=filename, ext=ext, chars=len(text))

    return await run_text_scan(text, request.state.http_client, request_id)
