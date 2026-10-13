# PromptShield

PromptShield is an academic prototype for local inspection of text before optional forwarding to an external LLM. It uses Microsoft Presidio, spaCy English NER, and project-specific rules.

## Active protection

- PII: emails, phones, checksum-valid credit cards, structurally valid SSNs, masked SSN fragments, names/locations, dates, IBANs, IP addresses, bounded English street/PO-box shapes and selected postal-code formats.
- Secrets: legacy/project/service/admin OpenAI-style shapes, Anthropic-style shapes, Google/Gemini shapes, Groq shapes, selected GitHub token families, AKIA/ASIA AWS access IDs, context-labeled AWS secret/session values, complete/incomplete PEM private-key blocks, Slack webhook URLs, structurally JSON-valid JWTs, bearer tokens, credential-bearing database URIs, and keyword-based secret assignments.
- Infrastructure: RFC1918 IPv4 and .internal/.local/.corp/.lan hostnames.
- Integrity: selected English prompt-injection patterns.

Detection is based on format/context, not credential liveness. Provider integration does not imply reliable provider-specific key detection. Together, Mistral, DeepInfra and xAI have **no provider-specific key-format detector verified in this phase**; explicit key assignments and bearer contexts can still be inspected.

## Enforcement and outbound coverage

Scan and chat share one risk/policy decision. Blocked content never starts either provider forwarder. Nonblocking detected content is sanitized, checked for retained original values, and re-scanned once before forwarding; scanner/sanitization uncertainty fails closed.

The gateway inspects message text parts and names; tool/function names, descriptions, schemas and nested arrays; response formats/schemas; stop strings; user identifiers; thinking/options; user-supplied model names (including x-model); and extra-header values. User-defined structural keys are also inspected and rejected when safe renaming is impossible. Sensitive routing/function/reference identifiers are rejected when replacement would leave an unusable protocol identifier. All these fields come from the same allowlist used by LiteLLM forwarding.

Exact validated protocol constants (message roles, known type tags), numbers/booleans/null, server-selected routing defaults, incoming gateway authentication, and server provider credentials are control data rather than free-form prompt content. Supplied extra_headers are outbound data and are inspected. Credential-bearing header overrides (Authorization, Proxy-Authorization, api-key, x-api-key, x-goog-api-key, x-amz-security-token) are rejected; provider authentication remains server-owned.

**Unsupported non-text message content is rejected** with HTTP 422 / unsupported_dlp_content: images, audio, raw files, unknown multimodal objects, binary objects and encoded data-URI blobs. No OCR, image analysis, output/response DLP, or media bypass is implemented. Text-part arrays preserve their original structure.

Walk limits: depth 20, 20,000 nodes, 2,000 nonempty textual slots per outbound request. Excessive structure fails closed. Repeated identical text uses a per-pass response cache while every occurrence still contributes to risk. Verification scans only changed values; unchanged literals retain their already-inspected values.

## Limits

This is not a complete enterprise DLP system. It does not classify proprietary/confidential prose semantically, discover every opaque credential, guarantee zero false negatives, verify signatures/issuance, or inspect LLM output. Postal/street rules are bounded heuristics; phone detection does not prove a number is assigned. Credit cards retain checksum validation; invalid card samples and invalid/excluded SSNs are not treated as valid identifiers. CVV and card-expiry-specific detection are out of scope.

PDF/DOCX upload endpoints inspect extracted text, not images or every document part. Identity, secure per-user key storage, deployment/TLS hardening, benchmarking, and general detector tuning remain separate work. Do not use real secrets in a demonstration.

## Run locally

Docker Desktop is required for the provided deployment. Create a root .env (the repository has no root .env.example):

~~~env
GROQ_API_KEY=
AISG_API_KEY=choose-a-long-random-local-key
~~~

A provider key is required only for chat forwarding. No provider key is needed for text/document inspection.

~~~powershell
docker compose up --build
~~~

Serve the frontend in another terminal:

~~~powershell
cd frontend
python -m http.server 5500
~~~

Open http://localhost:5500; default API URL is http://localhost:8000. The browser's API Key is the gateway authentication key, not a per-user provider key.

| Endpoint | Purpose |
|---|---|
| POST /v1/scan | Text inspection, decision and sanitized preview |
| POST /v1/documents/scan | Supported extracted-document/text inspection |
| POST /v1/chat/completions | Complete supported textual payload inspection and optional forwarding |
| GET /health | Dependency/recognizer information |

| Decision | Server behavior |
|---|---|
| allow | No detected finding; forward unchanged |
| mask | Replace protected text and verify before egress |
| warn | Require sanitization and verification before egress; no raw warning override |
| block | Return 422; no provider function executes |

Gateway policy/provider keys: config/gateway.yaml. Provider adapters: config/providers.json. The sole project detector definition source is presidio/app/recognizers.py. presidio/recognizers.yaml is a retired explanatory stub; edits there have no effect. Invalid project pattern configuration refuses scanner startup. Unknown requested entities are rejected; gateway entity lists require explicit risk weights.

## Verification and reports

Repository tests reject external TCP/DNS and use synthetic values, in-memory transports, and mocked providers. Run service suites separately because both use an app package:

~~~powershell
cd proxy-api
python -m pytest tests -q
~~~

Run the scanner suite from presidio and SDK suite from sdk/python. Use an isolated environment with dummy/no credential variables and disabled dotenv loading, as recorded in the reports.

- docs/DLP_IMPLEMENTATION_AUDIT.md — historical baseline
- docs/PHASE1_SECURITY_HARDENING_REPORT.md — fail-closed enforcement
- docs/PHASE2_BASELINE_TEST_TRIAGE.md — requirement/fixture decisions
- docs/PHASE2_DETECTION_COVERAGE_REPORT.md — active coverage, exact test outcomes, and remaining gaps

The project builds on Occludra Gateway (Apache 2.0). Presidio/spaCy supply core recognition/anonymization; PromptShield adds inspection workflows, risk integration, document handling, and bounded outbound inspection.
