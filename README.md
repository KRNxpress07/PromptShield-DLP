# PromptShield

PromptShield is a local AI prompt firewall. It inspects prompts, source code, logs, and uploaded documents before they are sent to an external large-language model (LLM).

It detects sensitive data and prompt-injection attempts, produces a redacted preview, calculates a risk score, and returns one of four decisions: **allow**, **mask**, **warn**, or **block**.

## Demo features

- Sensitive-data detection for emails, API keys, AWS keys, database URLs, private keys, GitHub tokens, JWTs, private IP addresses, and internal hostnames.
- Prompt-injection and jailbreak-pattern detection.
- Four-way risk policy: allow, mask, warn, and block.
- PDF, DOCX, source-code, log, and plain-text scanning.
- Browser-based inspection console.
- Optional OpenAI-compatible gateway for forwarding approved prompts to a configured LLM provider.

## Architecture

```text
Browser console / application
            |
            v
       PromptShield API
            |
            +--> Presidio detection service --> risk policy --> allow / mask / warn / block
            |
            +--> optional LLM provider forwarding for approved content
```

## Run locally

### Prerequisites

- Docker Desktop with the WSL 2 engine enabled.
- Python 3 (only needed to serve the static frontend).

### Start the backend

```powershell
docker compose up --build
```

The API is available at `http://localhost:8000`. The direct scanner works without a Groq, OpenAI, or other provider key.

### Start the inspection console

In a second terminal:

```powershell
cd frontend
python -m http.server 5500
```

Open `http://localhost:5500`. Keep Docker running while using the console.

## Quick test

```powershell
$body = @{ text = 'My AWS key is AKIAIOSFODNN7EXAMPLE and email is demo@example.com' } | ConvertTo-Json
Invoke-RestMethod -Uri http://localhost:8000/v1/scan -Method Post -ContentType 'application/json' -Body $body
```

Expected result: a high-risk or blocked decision, a violation manifest, and a redacted preview. The value above is a public dummy test key; never test with a real credential.

## API endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/scan` | Scan text and return the risk decision. |
| `POST /v1/documents/scan` | Upload and scan a PDF, DOCX, or supported text/code file. |
| `POST /v1/chat/completions` | Optionally forward approved content to an LLM provider. |
| `GET /health` | Check service health. |

## Risk decisions

| Decision | Meaning |
| --- | --- |
| **allow** | No meaningful risk was detected. |
| **mask** | Low-risk sensitive data is redacted before it can be forwarded. |
| **warn** | Content needs explicit human review. |
| **block** | High-risk secrets or prompt injection were detected; do not forward it. |

## Configuration

Copy `.env.example` to `.env`. A provider API key is only required for `POST /v1/chat/completions`; the scan and document endpoints run locally.

```env
GROQ_API_KEY=
AISG_API_KEY=choose-a-long-random-local-key
```

Detection policy and provider configuration are in `config/gateway.yaml`. Custom recognition patterns are in `presidio/recognizers.yaml`.

## Project structure

```text
frontend/                 Static inspection console
proxy-api/app/risk.py     Four-way risk score and policy
proxy-api/app/routers/    Scan, document, health, and proxy endpoints
presidio/                 Detection and anonymization service
config/gateway.yaml       Provider, authentication, and DLP policy
docs/api/                 API reference artifacts
```

## Presentation notes

1. Start Docker and open the local console.
2. Scan a harmless prompt to show an **allow** result.
3. Scan a dummy credential or injection prompt to show **block**, the score, violations, and redaction.
4. Upload a sample `.txt`, `.py`, `.log`, PDF, or DOCX file to demonstrate document handling.
5. Explain the trade-off: regex-based lightweight detection is fast and transparent, but may produce more false positives than a heavier model-based approach.

## Attribution

Presidio-based detection pipeline. PromptShield adds the four-way risk policy, direct scan endpoints, document scanning, custom recognizers, and inspection console. See [LICENSE](LICENSE) for the upstream Apache 2.0 license.
