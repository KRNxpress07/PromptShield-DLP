# DLP Project — Implementation Audit & Technical Handoff

**Audit date:** 13 October 2026 (Asia/Calcutta)  
**Repository:** `C:\CNS\PromptShield-DLP`  
**Base commit:** `cdea5b28fc2c71ddc1c8dd42d5f2092e036e6abb`  
**Scope:** Current working tree, including uncommitted changes; read-only implementation and offline security audit.  
**Deliverable:** `docs/DLP_IMPLEMENTATION_AUDIT.md`

## 1. Scope, evidence standard, and overall assessment

The repository contains a functioning local Presidio inspection service, a FastAPI gateway, a static browser console, a Python SDK, and Docker Compose packaging. It is a useful academic prototype, but it does **not yet implement a consistently enforced enterprise DLP gateway**. The console's four-way risk decision is disconnected from the forwarding endpoint's policy. Several advertised detectors exist only in an unused YAML file. Important request fields are forwarded without scanning, and private-key redaction leaves the key body intact.

The audit executed all three existing test suites: **134 passed, 25 failed, 0 skipped, 159 total**. Additional offline checks connected the actual gateway and actual detector through in-memory HTTP transports, with the provider replaced by a dummy response. These checks verified multiple leakage paths without transmitting prompts to an external LLM.

### Evidence conventions

- **Verified by source:** A behavior follows directly from an identified function or configuration.
- **Verified offline:** A local synthetic check or existing test exercised the behavior.
- **NOT VERIFIED:** Deployment behavior, live provider compatibility, security guarantees, or measurements that were not established.
- “Forwarded” in the offline results means passed to the **mocked provider boundary**, not sent over the Internet.
- Missing functionality means no implementing source, configuration wiring, or tests were found in the current repository; it does not describe an external service.

No application code, configuration, schemas, or dependencies were changed. The three pre-existing modified files were `frontend/index.html`, `proxy-api/app/config.py`, and `proxy-api/tests/test_config.py`. They are part of the audited implementation and were preserved. No AGENTS.md was found in the workspace inventory. Generated environments, Git internals, and caches were not treated as application source.

The root `.env` exists and is Git-ignored. Its variable names and empty/nonempty states were inspected without printing secret values. `GROQ_API_KEY` and `AISG_API_KEY` are nonempty; the other seven provider key variables are empty. **Validity of those values is NOT VERIFIED**, and none was used for testing. No dependency installation, container build, paid provider request, or browser transmission of sensitive information was performed.

### Highest-impact conclusions

| Finding | Evidence | Consequence |
|---|---|---|
| Gateway authentication secrets are printed to stdout | `proxy-api/app/routers/proxy.py:78–85` | Even an invalid chat request can cause all configured gateway key records to be logged. |
| The scan endpoint's block decision does not govern chat forwarding | `routers/scan.py:50`, `risk.py:121`, `routers/proxy.py:46` | A synthetic AWS key is “block” in scan but accepted and redacted by chat; a PEM body survives that redaction. |
| Six advertised recognizers are not loaded | `presidio/app/recognizers.py:105` versus `presidio/recognizers.yaml` | JWTs, bearer tokens, generic passwords, DB credentials, and internal hostnames lack their intended detectors. |
| Modern OpenAI-style project-key syntax is missed | `presidio/app/recognizers.py:38` | `sk-proj-` plus 48 alphanumeric characters is allowed and passed unchanged to the mock provider. |
| Only message text is inspected | `proxy-api/app/dlp.py:103`; forwarding parameter allowlist in `providers.py` | Tool descriptions, schemas, other metadata, and image content are not protected. |
| Scanner success is trusted without a sanitization invariant | `proxy-api/app/dlp.py:79–84` | A 200 response with a detected email but null anonymized text forwards the original email. |
| Broad enterprise confidentiality protection and benchmarking are absent | No classifier/dataset/evaluator in inventory | Academic effectiveness and enterprise protection claims are not established. |

## 2. Repository and architecture

### 2.1 Important directory tree

```text
PromptShield-DLP/
├── .env                         # local plaintext values; ignored; values withheld
├── .gitignore
├── .github/profile/
│   ├── README.md                # upstream/product profile, not implementation
│   └── banner.png               # presentation asset
├── README.md                    # project/demo instructions
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE                      # Apache 2.0 text
├── docker-compose.yml
├── config/
│   ├── gateway.yaml             # provider keys, gateway keys, DLP settings
│   └── providers.json           # eight provider prefixes/model metadata
├── frontend/
│   └── index.html               # all UI HTML, CSS, browser JavaScript
├── proxy-api/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py              # FastAPI startup, middleware, error handlers
│   │   ├── config.py            # settings, env substitution, YAML cache
│   │   ├── auth.py              # shared bearer-key authentication
│   │   ├── models.py            # chat and violation models
│   │   ├── dlp.py               # message text extraction, scanner HTTP calls
│   │   ├── risk.py              # severity weights and four-way assessment
│   │   ├── providers.py         # registry and LiteLLM forwarding
│   │   ├── log_utils.py         # partial structured-log secret scrubbing
│   │   └── routers/
│   │       ├── health.py
│   │       ├── proxy.py
│   │       ├── scan.py
│   │       └── documents.py
│   └── tests/
│       ├── conftest.py
│       ├── test_auth.py
│       ├── test_config.py
│       ├── test_dlp.py
│       ├── test_health.py
│       ├── test_log_utils.py
│       ├── test_models.py
│       └── test_proxy.py
├── presidio/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env.example              # scanner-only example
│   ├── recognizers.yaml          # contains unwired additions
│   ├── app/
│   │   ├── main.py              # /process and /health
│   │   ├── models.py
│   │   ├── recognizers.py       # actual registered custom patterns
│   │   └── post_processor.py    # overlap suppression
│   └── tests/test_sovereign_safety.py
├── sdk/python/
│   ├── pyproject.toml
│   ├── README.md
│   ├── CHANGELOG.md
│   ├── LICENSE
│   ├── aisg/
│   │   ├── client.py            # synchronous/asynchronous HTTP clients
│   │   ├── models.py
│   │   ├── exceptions.py
│   │   ├── _version.py          # 0.1.1
│   │   ├── __init__.py
│   │   └── py.typed
│   └── tests/
│       ├── test_client.py
│       └── test_models.py
└── docs/
    ├── api/openapi.yaml
    ├── api/postman-collection.json
    └── DLP_IMPLEMENTATION_AUDIT.md
```

Package-marker `__init__.py` files are omitted from the tree where uninformative. There is no root `.env.example`, despite README instructions to copy it. No CI workflow, database migration, web build system, benchmark dataset, or evaluation runner was found.

### 2.2 Languages, frameworks, and major components

| Area | Actual implementation |
|---|---|
| Backend | Python; two FastAPI applications; Uvicorn; Pydantic models |
| Frontend | One static HTML document with inline CSS and vanilla JavaScript; no React/Vue/router/build pipeline |
| Detection | Microsoft Presidio Analyzer; spaCy English NLP/NER; built-in recognizers and six programmatically registered custom recognizers |
| Sanitization | Microsoft Presidio Anonymizer, called by the scanner |
| LLM routing | LiteLLM asynchronous completion calls |
| Service communication | HTTPX; gateway sends raw message text to scanner `/process` |
| Configuration | Pydantic Settings, YAML, JSON, environment substitution, python-dotenv |
| Documents | pdfplumber for PDFs; python-docx for DOCX; UTF-8 text decoding |
| Logging | Gateway structlog processors; scanner's custom JSON handler for Python logging |
| SDK | Typed dataclasses plus synchronous/asynchronous HTTPX clients |
| Tests | pytest; pytest-asyncio for gateway; Starlette TestClient; mocks |
| Packaging/deployment | Two Python 3.12 Docker images and Docker Compose; frontend served separately |

**Database and schema:** NOT IMPLEMENTED. There is no SQL/NoSQL connector, ORM, migration, persisted user table, prompt history database, or organization-policy schema. Pydantic API schemas and configuration files are not a database. In-memory configuration caches and token buckets are the only application-managed state identified beyond request processing.

### 2.3 Component interactions and trust boundaries

```mermaid
flowchart LR
    U[Browser console or API client] --> G[FastAPI gateway]
    G -->|Original extracted text over HTTP| P[Presidio service]
    P --> N[spaCy and regex recognizers]
    N --> A[Presidio anonymizer]
    A --> G
    G --> S[Scan response plus risk assessment]
    G -->|Separate chat policy| L[LiteLLM]
    L --> E[External provider]
    E -->|Uninspected completion or SSE| G
    G --> U
```

1. **Browser → gateway:** Treat browser decisions and settings as untrusted. The browser may select any gateway URL. Default communication is HTTP. Browser controls are advisory; the API must independently enforce security.
2. **Gateway → scanner:** Raw text crosses this boundary before sanitization. Compose keeps the scanner off published host ports, but there is no scanner authentication or TLS. Network access to this service grants access to its processing API.
3. **Gateway → provider:** This is the intended sensitive-data egress boundary. Only message text undergoes inspection; other accepted fields may cross unchanged.
4. **Runtime → logs:** Stdout is a separate retention/exposure surface. Direct debug prints bypass gateway scrubbing.
5. **Operator → configuration:** Configuration controls keys, entity filtering, and action. It is trusted, cached, and not validated as a policy schema. A typo in the action can change security behavior.
6. **Client → SDK destination:** The SDK defaults to an external managed-service URL, not this local gateway. A local demo must explicitly set `base_url="http://localhost:8000/v1"`.

This is an opt-in application proxy. No network appliance, transparent interception, browser extension, firewall egress rule, or mechanism forcing users/apps to use this gateway exists.

### 2.4 Configuration and deployment details

`Settings` in `proxy-api/app/config.py:21` defaults to scanner `http://localhost:3000`, provider `groq`, model `openai/gpt-oss-120b`, 60-second upstream timeout, wildcard CORS, 10 requests/second, and a 50 MiB declared-body limit. Compose overrides scanner URL to `http://presidio:3000`.

`get_gateway_config()` checks `CONFIG_PATH`, then (if that path is missing) `AISG_CONFIG_PATH` or the repository's `config/gateway.yaml`. It returns an empty configuration when none exists. The current `PROJECT_ROOT = Path(__file__).resolve().parents[2]` resolves to the repository root. The explicit dotenv call targets `proxy-api/.env`; no such file was found. Pydantic also loads `.env` relative to the current directory, so local startup behavior depends on working directory. Compose explicitly injects root `.env`.

Environment interpolation supports `${NAME}` and `${NAME:-default}`. An unset variable without a default remains literal; an explicitly empty variable does not take the default. Settings and YAML are cached; editing policy is not a documented hot-reload operation.

Compose publishes the gateway on `${GATEWAY_PORT:-8000}:8000`, without restricting the host address to loopback. Scanner port 3000 is only exposed on the Compose network. Both images run as a non-root `aisg` user, which is a useful control. Config is mounted read-only. There is no configured TLS reverse proxy, secret manager, resource limit, network policy, or production ingress layer. Container runtime reachability and production security are **NOT VERIFIED**.

The gateway health endpoint returns HTTP 207 when the scanner is degraded. Container checks call `raise_for_status()`, which accepts 207: this can report a degraded gateway as healthy. Scanner health reports registered entities, not detection accuracy. `WEB_CONCURRENCY` is supplied as an environment variable; actual worker count was not tested.

### 2.5 Dependencies and reproducibility

Gateway requirements use compatible-release ranges for FastAPI, Uvicorn, Pydantic, HTTPX, LiteLLM, structlog, and YAML. PDF/DOCX/multipart packages are unpinned. Scanner requirements include Presidio, spaCy, phonenumbers, HTTPX, and several transitive minimum-version constraints. Its image downloads `en_core_web_lg` at build time. No application-wide lockfile or pinned model artifact/checksum exists. `config.py` imports python-dotenv directly, but the gateway does not declare it directly; it was available transitively in this environment.

The shared local Python 3.12.10 environment reported:

| Package | Installed version |
|---|---|
| fastapi | 0.115.14 |
| httpx | 0.27.2 |
| pydantic | 2.10.6 |
| litellm | 1.56.10 |
| presidio-analyzer / presidio-anonymizer | 2.2.362 / 2.2.364 |
| spacy / en-core-web-lg | 3.8.16 / 3.8.0 |
| pytest / pytest-asyncio | 8.3.5 / 0.24.0 |
| python-dotenv | 1.2.3 |
| pdfplumber / python-docx | 0.11.10 / 1.2.0 |

The installed HTTPX version satisfies the gateway declaration but not the scanner's `httpx~=0.28.0`. Tests establish behavior in this **shared local environment**, not fresh, separately built containers. Dependency CVE status and container-image vulnerabilities are **NOT VERIFIED**; no vulnerability or exploitability conclusion is inferred from version numbers.

## 3. Feature-by-feature implementation audit

### A. Prompt input and interception

The console's `runScan()` (`frontend/index.html:1186`) sends text to `POST /v1/scan` or a file to `POST /v1/documents/scan`. These endpoints do not forward to an LLM. `sendToLLM()` (`:1319`) subsequently posts a single user message to `POST /v1/chat/completions`.

Chat requests are intercepted server-side in `chat_completions()`. Authentication and provider-key resolution precede DLP. `dlp.process_messages()` loops through **all messages**, regardless of role, and scans extracted nonempty text before the forwarding function is called. Both streaming and nonstreaming chat share that initial DLP stage.

For ordinary detected text under valid `redact` policy, the upstream receives replaced text, not the original. Original text **is** sent first to the local scanner. No source path sends a standard text prompt to the provider before running that scan. However, “the scan was called” does not mean all data was scanned:

- `_message_text()` extracts strings and list parts whose type is `text`; it ignores image parts and other content structures.
- Images with no text skip scanner processing entirely.
- Tool/function definitions, schemas, `user`, `name`, stop strings, and other forwarded parameters are outside message-text scanning.
- Data missed by the selected recognizers passes unchanged.
- Invalid action values do not block or redact.
- Missing anonymized output falls back to the original message.
- The console's block banner prevents ordinary UI forwarding but does not bind API behavior; a client can call chat directly.
- The SDK can target the cloud service by default, bypassing this repository's local gateway entirely.
- Apps can call a provider directly; mandatory organization-wide egress enforcement is absent.

There is browser-only workflow gating for allow/mask/warn/block, but actual text inspection also exists on the backend. No embeddings, audio, file-to-provider, or other provider API routes were found. Unsupported routes are absent rather than automatically DLP-protected.

### B. PII detection

**Microsoft Presidio is used.** The scanner builds `AnalyzerEngine()` in `presidio/app/recognizers.py:105`; lifespan initializes this and `AnonymizerEngine()`. This default engine loads the locally installed spaCy English model. The implementation is **not regex-only**: PERSON/LOCATION and related entities use spaCy NER alongside Presidio pattern recognizers and their built-in validation/context behavior.

The exact operational pipeline is:

1. Gateway extracts message text and calls `POST /process` with language `en`, configured entity list, threshold 0.4, and anonymize flag.
2. Scanner optionally adds per-request custom recognizers (only callers of the internal service can supply these).
3. `analyzer.analyze()` runs enabled recognizers and applies the requested threshold.
4. Temporary recognizers are removed.
5. `filter_false_positives()` suppresses lower-confidence **different-type overlapping spans**.
6. Scanner returns entity type, offsets, and score.
7. If anonymization was requested and results exist, Presidio anonymizes those spans using supplied operators.
8. Gateway converts results to `DLPViolation`; scan assesses risk or chat applies its separate global action.

The configured gateway entities are exactly:

```text
EMAIL_ADDRESS PHONE_NUMBER CREDIT_CARD US_SSN PERSON LOCATION IP_ADDRESS
API_KEY AWS_ACCESS_KEY PRIVATE_KEY GITHUB_TOKEN SLACK_WEBHOOK PROMPT_INJECTION
```

An offline scanner health check showed **23 registered recognizers and 25 supported entity types**:

```text
API_KEY AWS_ACCESS_KEY CREDIT_CARD CRYPTO DATE_TIME EMAIL_ADDRESS GITHUB_TOKEN
IBAN_CODE IP_ADDRESS LOCATION MAC_ADDRESS MEDICAL_LICENSE NRP PERSON
PHONE_NUMBER PRIVATE_KEY PROMPT_INJECTION SLACK_WEBHOOK UK_NHS URL
US_BANK_NUMBER US_DRIVER_LICENSE US_ITIN US_PASSPORT US_SSN
```

Registration is not equivalent to gateway coverage. The configured list excludes IBAN_CODE, DATE_TIME, NRP, URL, UK_NHS, and several other built-ins. Merely adding an entity name to the gateway list cannot create a missing recognizer.

Custom secret/injection patterns carry fixed scores, typically 0.85–0.95. Presidio's built-in recognizers supply their own scores, validation, and context logic. No learned project-specific confidence calibration, labeled threshold tuning, or probability interpretation exists. Gateway threshold is configurable; detector language is fixed to English.

Overlap handling compares every different-type overlapping pair; higher score wins, ties retain the earlier item. STREET_ADDRESS with LOCATION or PERSON is exempt, although STREET_ADDRESS is not registered in the audited runtime. Same-type overlap handling is left to Presidio. Suppression is not evidence that the discarded item is actually false: a partially overlapping discarded span can contain an uncovered sensitive tail. No project-specific allowlist, validated placeholder suppression, or semantic false-positive classifier exists.

Existing tests passed for basic email, a valid space-separated credit card, several phone formats, and injection patterns. Twenty-four scanner tests failed across SSN fixtures, card/PCI edge cases, postal/street address cases, and compound CSV scenarios. Some fixtures may deliberately represent invalid identifiers: for example `123-45-6789` fails detection. These failures demonstrate a mismatch with the project's test expectations, **not a measured population recall rate** or proof that every valid SSN is missed.

Limitations include English-only NLP, no OCR, obfuscation/encoding and split-token evasion, missing organization identifiers, confidence-based overlap loss, and no benchmark-backed accuracy.

### C. API secret and credential detection

| Category | Implemented behavior and evidence | Assessment |
|---|---|---|
| OpenAI keys | `sk-[a-zA-Z0-9]{20,}` in `_custom_recognizers()` | PARTIALLY COMPLETE: legacy-shaped strings; synthetic `sk-proj-` syntax misses completely. |
| Anthropic keys | `sk-ant-[a-zA-Z0-9]{20,}` | PARTIALLY COMPLETE: limited syntax; separators/extensions can truncate a match. Current live key coverage NOT VERIFIED. |
| Gemini/Google keys | `AIza[0-9A-Za-z\\-_]{35}`, score 0.9 | Implemented shape detector; no key validity check. |
| Groq/other providers | No dedicated `gsk_`, Together, Mistral, DeepInfra, or xAI patterns | NOT IMPLEMENTED as provider-specific recognizers. Incidental PII matches are not secret coverage. |
| AWS access key ID | `AKIA[0-9A-Z]{16}`, score 0.95 | PARTIALLY COMPLETE: AKIA format only; no dedicated temporary ASIA access-key pattern. |
| AWS secret/session credentials | No registered AWS_SECRET_KEY detector; a risk weight alone exists | NOT IMPLEMENTED. |
| GitHub tokens | `ghp_`/ `gho_` plus 36 chars; `github_pat_` plus 82 chars | PARTIALLY COMPLETE: selected formats; no token validation and no broad token-family coverage. |
| PEM/private keys | Matches BEGIN marker only, score 0.95 | PARTIALLY COMPLETE detection; **unsafe redaction** because payload/end marker remain. |
| Slack webhooks | URL regex in registered custom recognizer | Implemented narrow URL shape; no general Slack token detector. |
| JWT | Regex in YAML only; not registered | NOT IMPLEMENTED in active pipeline. Synthetic JWT allowed unchanged. |
| Bearer tokens | Regex in YAML only; not registered | NOT IMPLEMENTED in active pipeline. Gateway bearer authentication is a different feature. |
| Database URLs | Credential-bearing URL regex in YAML only | NOT IMPLEMENTED in active pipeline. Synthetic PostgreSQL credentials allowed unchanged. |
| Password/generic secret assignments | YAML patterns only | NOT IMPLEMENTED in active pipeline. Synthetic quoted password allowed unchanged. |

`build_analyzer()` registers only the list returned by `_custom_recognizers()`. It never opens `recognizers.yaml`. The YAML's DB_CONNECTION_STRING, JWT_TOKEN, BEARER_TOKEN, GENERIC_SECRET_ASSIGNMENT, PRIVATE_IP, and INTERNAL_HOSTNAME additions are therefore inert. Even if loaded, the current gateway entity allowlist would also need updating.

There is no entropy analysis, credential-provider validation, secret liveness check, signature validation, high-entropy fallback, or secret-specific contextual ML. Scores and regular expressions are shape heuristics; they do not establish that a string is a valid or active credential. Offline checks used dummy shapes only.

### D. Enterprise confidential information

| Requested capability | Actual status |
|---|---|
| Internal project names | NOT IMPLEMENTED: no organization vocabulary/configuration |
| Confidential document classification | NOT IMPLEMENTED: extracting text is not classifying confidentiality |
| Financial/business-sensitive information | PARTIALLY COMPLETE for selected payment/PII identifiers; no financial-document or business-information classifier |
| Proprietary source code | Can upload/decode code as text; no proprietary-code classification or fingerprint matching |
| Internal domains | Inactive YAML suffix rule for .internal/.local/.corp/.lan |
| Private infrastructure IPs | General IP_ADDRESS is active; specialized PRIVATE_IP rule is inactive |
| Organization keywords and policies | No tenant/organization policy store or gateway configuration interface |
| Custom regex rules | Internal scanner supports temporary request rules; gateway/UI do not expose or forward them |
| Embeddings/semantic classification | NOT IMPLEMENTED |
| Document labels/fingerprints | NOT IMPLEMENTED |

There is no definition of what is confidential **for a particular organization**. No tenant identity, policy namespace, project dictionary, classification label, document corpus, or permission mapping is present. A private IP being masked as general IP_ADDRESS is not enterprise confidentiality classification. Confidential prose without recognizable PII/secrets can be allowed.

### E. Sanitization and redaction

The gateway always requests a DEFAULT Presidio **replace** operator with `new_value="[REDACTED]"` when anonymizing. Direct text/document scan always requests anonymization, including on warn/block; chat requests it only when global action is `redact`.

The internal scanner's `OperatorConfig` and `_to_presidio_operator()` (`presidio/app/main.py:268`) expose replace, mask, and hash-related parameters. These are a lower-level interface to Presidio, not selectable console options. Mask/hash execution was not independently tested in this audit; their full operator support is **NOT VERIFIED**.

Verified synthetic transformations with the actual scanner:

```text
Email demo@example.com
→ Email [REDACTED]

My AWS key is AKIAIOSFODNN7EXAMPLE
→ My AWS key is [REDACTED]

-----BEGIN PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----
→ [REDACTED]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----
```

The last example is a deliberately dummy PEM-like payload. It demonstrates that only the header is covered by the recognizer. A real key body could survive the same algorithm; no real private key was used.

Text outside matched spans generally stays intact, but replacements change lengths, identifiers, referential consistency, and sometimes syntax. Multiple values receive the same placeholder; there is no reversible token map, stable per-entity pseudonym, or measured intent preservation. A multimodal message with detected email and an image was converted to the single string `[REDACTED]`, dropping the image. Thus message structure is not reliably preserved.

Important gaps:

- No second scan of sanitized text.
- No output/LLM-response scan, including SSE.
- No check that detected original values have been removed.
- `anonymized_text=None` on successful scanner response retains original content even when violations exist.
- Missed detector categories, unscreened fields, and PEM bodies survive.
- Original text remains in textarea, browser variables, backend memory, and the scanner request. No application prompt-history database was found.
- File uploads are read wholly into memory; framework multipart handling may spool to temporary storage. Disk retention/secure erasure is **NOT VERIFIED**.
- Logging/error handlers can retain inputs or credentials; see Section I.

The console offers an expandable sanitized preview and buttons to send sanitized/original content for warning decisions. It does not highlight the original sensitive spans inline; it groups entity types/counts in a manifest.

### F. Risk assessment and policy engine

`risk.assess()` computes:

```text
entity_types = distinct detected entity types
max_weight = maximum SEVERITY_WEIGHTS value (unknown type → 50)
count_bonus = min(number_of_violations - 1, 4) × 2
risk_score = min(max_weight + count_bonus, 100)
```

Thresholds are 90 critical, 70 high, 50 medium, 1 low, and 0 none. Actions are critical→block, high/medium→warn, low→mask, none→allow. PROMPT_INJECTION forces critical/block. Example weights: PRIVATE_KEY/AWS_ACCESS_KEY 100, API_KEY/GITHUB_TOKEN 95, DB_CONNECTION_STRING 93, JWT_TOKEN 78, US_SSN 85, CREDIT_CARD 80, EMAIL_ADDRESS 40, PHONE_NUMBER 35, PERSON 20.

Confidence scores are not included in severity after threshold filtering. Repeated low-weight entities add at most eight points; volume alone therefore has limited effect. This is deterministic heuristic scoring, not a trained contextual model or calibrated risk probability. Threshold/weight/action maps are Python constants, requiring code changes; they are not deployed YAML-configurable or organization-specific.

**Critical integration distinction:**

- `run_text_scan()` invokes `risk.assess()` and returns its action.
- `chat_completions()` never invokes `risk.assess()`. It reads global `dlp.action` and blocks any detected injection; otherwise it blocks only if action is exactly `block`, redacts only if exactly `redact`, and forwards in other cases.
- No signed approval, scan token, server-side warning confirmation, policy version, or authorization record links scan to send.
- Default chat policy redacts severe secrets rather than enforcing the scan endpoint's critical block.
- Invalid action `typo` was verified to forward a detected email unchanged.
- The UI's “Send anyway” under default redact policy still leads to a second backend scan/redaction; its claim of sending “original text” describes the submitted body, not necessarily provider egress.
- A sanitized injection can lose its recognizable injection phrase on rescan; there is no memory of the original block assessment. The normal UI prevents sending block results, but this is not durable API policy.

Policies have server-side enforcement for the narrower redact/block behavior; the advertised unified four-way policy is only partially integrated.

### G. LLM integration and user keys

Eight provider entries are registered in `config/providers.json`: **Groq, OpenAI, Anthropic, Together, Gemini, Mistral, DeepInfra, and xAI**. Prefixes map to LiteLLM. The JSON's `enabled` and `default_model` fields are not enforced/used by the registry logic: it extracts prefixes for every entry. Model resolution uses `x-model`, body model, or one global default; provider resolution uses `x-provider` or global default.

`forward_chat_completion()` and its streaming counterpart construct `prefix/model`, filter to a known completion-parameter list, and call `litellm.acompletion(api_key=..., timeout=...)`. This reduces arbitrary top-level parameter forwarding but retains unscanned semantic fields. An optional base-URL override exists in the helper signature but is not passed by the route.

**Implemented BYOK:** The deployment operator supplies provider keys through environment/YAML.  
**Missing requested BYOK:** Individual browser users cannot register their own provider credentials, associate them with accounts, encrypt/store them per user, or select their own stored key. The console's “API Key” is the **gateway authentication key**, not the provider API key. No provider-key header/body input is accepted for this purpose.

Provider keys are plaintext environment/config values and cached in process memory. No encryption-at-rest/key vault/rotation/revocation workflow exists. There is no user/tenant isolation or provider authorization per gateway key.

Streaming exists server-side as SSE after the same initial DLP stage. The console consumes JSON responses and does not request streaming. SDK clients have SSE iterators. Upstream response chunks/content are returned without DLP.

Nonstreaming errors map timeout→504, upstream auth→502, bad request→400, rate limit→429, generic failure→502. Streaming setup has similar handling, but no separate RateLimitError branch; interruption emits an error event then DONE. Raw upstream bad-request exception text is returned, so its contents can leak if a provider exception includes sensitive context. Actual provider message content is **NOT VERIFIED**.

Live compatibility, credentials, model existence, and response behavior for all eight providers are **NOT VERIFIED**. The offline checks verify gateway forwarding decisions, not working calls to each external API. Multi-provider routing code is real; fully tested multi-provider operation is not established.

### H. User interface and experience

There is one inspection page, with:

- Gateway URL, gateway key, provider name, and model text inputs.
- Text/file tabs; file selection and drag/drop.
- Analyze button and status indicator.
- Risk level/score, finding count, injection status, grouped entity manifest.
- Expandable sanitized preview.
- Allow→send, mask→send sanitized, warn→sanitized/send anyway, block→edit-and-rescan.
- LLM result rendered as a user/assistant conversation; fenced code formatting and clipboard copy.

There are no login/account pages, saved history, organization admin page, policy editor, provider-key vault, model discovery dropdown, or account-scoped settings. Provider/model entries are free text.

Security/usability issues include:

1. Gateway key input is visible `type="text"`, prefilled with a known development key.
2. “Policy enforced” and the footer's category list overstate effective protection; DB/JWT/internal rules are inactive and IBAN is excluded by gateway configuration.
3. Gauge ticks 35/65/90 differ from risk thresholds 50/70/90.
4. Errors can label policy/parser/server failures as “gateway unreachable.”
5. Health status is not established by a startup health probe; initial “Gateway ready” is cosmetic.
6. Input/file edits do not invalidate the last assessment; forwarding uses cached text/scan state. Stale results can confuse what is being reviewed/sent.
7. File original text is unavailable in browser state; “Send anyway” falls back to redacted extracted text.
8. There is no inline span highlighting or semantic explanation of individual matches.
9. Browser plaintext remains in DOM/variables; no application clearing/retention controls.
10. Google Fonts stylesheet requests are external. This is not evidence that prompt text is sent to Google; it disproves a literal all-assets-local interpretation.
11. Escaping is used for original text, previews, error strings, and assistant prose/code. No verified executable HTML injection was established by source review. Browser behavior and accessibility were **NOT VERIFIED** through a live UI test.

### I. Security architecture

| Area | Verified controls | Verified weakness or assessment limit |
|---|---|---|
| Authentication | Constant-time `hmac.compare_digest` for configured gateway keys | Chat only; scan/doc endpoints unauthenticated. No configured keys means open mode without checking whether deployment is local. |
| Authorization | Supported-provider lookup | No roles, tenant/user ownership, provider/model authorization, budgets, or policy permissions |
| Key handling | Config/environment lookup; some structured-log masking | Raw gateway keys and all configured gateway records printed before auth completes |
| Input validation | Pydantic message array minimum; scan text 1–200,000 chars; empty checks | Chat role unrestricted; numeric params not bounded; list[Any]/dict fields permissive; policy schema unvalidated |
| Body limits | Reject declared Content-Length >50 MiB; file >15 MiB | No streamed byte-count cap; file fully read before limit; extracted text has no scan-request length cap |
| Rate limits | In-memory token bucket | Bucket uses first 32 characters of unvalidated supplied Authorization, allowing new buckets on unauthenticated scans; unbounded bucket dictionary; not shared across workers |
| Scanner outages | HTTP errors stop chat forwarding; 5-second per-message timeout | Successful malformed/missing sanitization result can retain originals; blank/non-text content skipped |
| Injection | Five English regex patterns; detected injection blocks chat | No semantic/encoded attack coverage or adversarial benchmark; quoting an attack can trigger false positives |
| Database | No database attack surface in current app | No database-backed identity, policies, history, or key protection exists |
| Transport | Scanner not host-published in Compose | Local/default HTTP; no TLS or service auth; gateway host port not loopback-bound |
| Error/log controls | Generic unhandled-error response; gateway 422 removes input from response details | Gateway still logs `exc.errors()`; scanner logs/returns raw validation details; upstream bad-request text returned |
| Retention | No explicit persistent prompt store | Secrets in stdout; originals in browser/process memory; log lifetime/temp-file handling NOT VERIFIED |
| Response safety | Browser escaping | No completion/SSE confidentiality scan |
| Observability | IDs, times, violation metadata, provider logging | No tamper-evident security audit trail, policy version, approval audit, or retention specification |

Verified code-level leak: `routers/proxy.py:80` prints `get_api_keys()` before authentication, exposing all gateway keys even for an attacker with no valid key if logs are accessible. Debug auth-result records may include the matched key. These `print()` calls do not pass through `log_scrubber`.

`log_utils.py` scrubs selected prefixes (gsk_, tok_, sk-, sk-ant-, AKIA, Bearer) and preserves fragments through `mask_key()`. It does not scrub all passwords, email addresses, JWTs, database URLs, GitHub tokens, or arbitrary gateway keys. It is not a general sensitive-log policy.

DoS/resource risks follow from synchronous NLP/document parsing within async handlers, permissive internal regex rules, size limits based on headers or post-read checks, and bucket growth. **A successful DoS exploit, regex catastrophic-backtracking exploit, container compromise, SQL injection, or RCE is NOT VERIFIED.** There is no SQL or shell execution in the request processing code that would justify claiming those vulnerabilities.

The scanner's temporary custom recognizers mutate a shared registry and cleanup is name-based with exceptions suppressed. Current synchronous processing reduces same-event-loop interleaving, but isolation/collision behavior and future concurrency safety are **NOT VERIFIED**. Keep this as a design concern, not a proven cross-user leak.

## 4. Actual end-to-end flow

### 4.1 Inspection-only path

`User → runScan → /v1/scan → run_text_scan → process_messages → /process → Presidio analysis → overlap filtering → anonymization → risk.assess → preview/action → user`

No LLM is contacted. Text/document assessment is available without provider keys and without authentication.

### 4.2 Chat forwarding path

| Stage | Source/function | Data and controls | Failure/leakage behavior |
|---|---|---|---|
| User entry | `frontend/index.html`, textarea/file selection | Raw prompt or file; browser state | Original remains visible/in memory; selected gateway may be remote |
| Optional preview | `runScan()`; `routers/scan.py:115` | Raw text to backend; length/empty validation | No auth; preview decision not an authorization artifact |
| Document extraction | `routers/documents.py:84`, extraction helpers | File bytes → PDF text or DOCX paragraphs/tables or UTF-8 text | No OCR, DOCX headers/comments/etc not traversed; parser failures may become generic 500; expansion limits absent |
| Send request | `sendToLLM()` | Cached original or redacted text; gateway bearer key; provider/model headers | UI block is bypassable via direct API; file “original” option falls back to redacted text |
| Middleware | `main.py`, RequestContext/PayloadGuard/RateLimit | Shared HTTP client, claimed body size, supplied key prefix | No complete byte-count guard; spoofable forwarded-IP logging; rate bucket not authenticated identity |
| Validation/auth | `chat_completions()`; `authenticate()` | Parsed messages, header key | 400/422 invalid input; 403 invalid key; stdout leaks keys first |
| Provider resolution | `get_provider()`, `get_provider_keys()` | Provider/model and server key | 400 unknown provider; 402 missing server credentials; scan not reached if credentials absent |
| Detection | `process_messages()`; `_message_text()` | Each nonempty extracted message text to local scanner | Image/nontext fields skip; HTTP errors block; missed entities pass |
| Scanner processing | `presidio/app/main.py:163` | NLP/regex spans → filtered spans | Required-recognizer check covers only email/phone/card/SSN; no guarantee of coverage quality |
| Policy | `routers/proxy.py` | Global redact/block plus injection override | Four-way risk layer is not called; invalid actions permit raw forwarding |
| Sanitization | `AnonymizerEngine.anonymize`; `dlp.py:79` | Replace detected spans | Header-only PEM, missed data, null anonymized response; no rescan/invariant |
| Provider request | `providers.py:80/124` | model + processed messages + accepted params + server API key | Other forwarded fields unscreened; no organization-wide route enforcement |
| Provider response | route response/SSE generator | Completion/chunks plus IDs/timing metadata | No output scan; errors may include upstream text |
| User display | `renderAssistantMessage()`, `escapeHtml()` | Browser conversation | Render escaping exists; data retention/visual workflow not runtime-verified |

**Verified example:** With dummy operator credentials, original `Email demo@example.com` reaches the scanner, becomes `Email [REDACTED]`, is assessed as mask, and chat independently re-scans/redacts before the mocked provider receives it. The fake completion returns to the caller with gateway metadata. This proves the local plain-text integration path.

**Verified counterexample:** A synthetic `sk-proj-` key receives allow with no violations; the chat call sends the original unchanged to the mock boundary. Another counterexample marks a dummy PEM block as block in scan but chat forwards a header-redacted body under default redact policy.

## 5. Testing and verification

### 5.1 Existing suite inventory and results

| Location | Coverage focus | Passed | Failed | Skipped | Exit |
|---|---|---:|---:|---:|---:|
| `proxy-api/tests` | Auth, settings/env/YAML, extraction/count helpers, health mocks, log scrubber, models, mocked proxy policies/errors/metadata | 94 | 1 | 0 | 1 |
| `presidio/tests/test_sovereign_safety.py` | Actual scanner API/NLP/anonymizer, PII edge cases, CSV expectations, overlaps, injection, health | 21 | 24 | 0 | 1 |
| `sdk/python/tests` | Client construction, URLs/keys, error mapping, typed response parsing | 19 | 0 | 0 | 0 |
| **Total** | **159 existing tests** | **134** | **25** | **0** | — |

Reported suite durations were gateway 12.55 s, scanner 7.48 s, SDK 0.72 s. These are **test-run durations**, not DLP latency or throughput measurements.

Gateway failure:
`tests/test_config.py::TestGetGatewayConfig::test_missing_file_returns_empty`. It supplies a nonexistent configured path but does not eliminate the real repository fallback; actual configuration is returned instead of `{}`. This is a test expectation/isolation problem with the existing fallback behavior. It is not evidence of a crashing configuration loader.

Scanner failures (24, all in `test_sovereign_safety.py`):

- `TestPIIRedaction::test_ssn_detected`
- `TestCreditCardEdgeCases::test_dash_separated_card`
- `TestCreditCardEdgeCases::test_space_separated_non_luhn_with_context`
- `TestCreditCardEdgeCases::test_card_expiry_slash`
- `TestCreditCardEdgeCases::test_cvv_after_keyword`
- `TestCreditCardEdgeCases::test_full_pci_payload_all_redacted`
- `TestCreditCardEdgeCases::test_dash_card_with_cardholder_context`
- `TestCreditCardEdgeCases::test_mixed_pci_hipaa_prompt`
- `TestTabularDataEdgeCases::test_us_phone_dash_with_country_code`
- `TestTabularDataEdgeCases::test_masked_ssn_xxx`
- `TestTabularDataEdgeCases::test_masked_ssn_star`
- `TestTabularDataEdgeCases::test_uk_postcode`
- `TestTabularDataEdgeCases::test_uk_postcode_sw1a`
- `TestTabularDataEdgeCases::test_india_pin_code`
- `TestTabularDataEdgeCases::test_full_csv_row_redaction`
- `TestTabularDataEdgeCases::test_multi_row_csv`
- `TestFullCsvIntegration::test_complete_csv_redaction`
- `TestStreetAddressRecognizer::test_basic_street_rd`
- `TestStreetAddressRecognizer::test_basic_street_st`
- `TestStreetAddressRecognizer::test_po_box`
- `TestStreetAddressRecognizer::test_street_address_redacted`
- `TestStreetAddressRecognizer::test_uk_road`
- `TestOverlapSuppression::test_ssn_dash_format_no_datetime`
- `TestOverlapSuppression::test_non_overlapping_entities_kept`

Failures include expected entity sets being empty/incomplete and incomplete CSV sanitization. STREET_ADDRESS, POSTAL_CODE, CREDIT_CARD_EXPIRY, and CVV behaviors expected by tests are not supplied by custom recognizers in this source. Fixes should distinguish supported requirements, valid versus invalid identifier fixtures, and missing implementations.

### 5.2 Commands and isolation used

The interpreter was `C:\CNS\PromptShield-DLP\.venv\Scripts\python.exe -B -`. Each suite ran in a separate process and its own directory, because the two services both use an `app` package. No files were added for the audit harness.

Actual pytest argument sets:

```text
# working directory: proxy-api
pytest.main(["tests", "-q", "-p", "no:cacheprovider",
             "-p", "pytest_asyncio.plugin", "--tb=short"])

# working directory: presidio
pytest.main(["tests", "-q", "-p", "no:cacheprovider", "--tb=short"])

# working directory: sdk/python
pytest.main(["tests", "-q", "-p", "no:cacheprovider", "--tb=short"])
```

Each call was sent as Python source through a PowerShell single-quoted here-string to the interpreter above, after this common isolation setup:

```python
import os, socket, sys
keep = {
    k: v for k, v in os.environ.items()
    if k.upper() in {
        "SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "COMSPEC",
        "USERPROFILE", "APPDATA", "LOCALAPPDATA"
    }
}
os.environ.clear()
os.environ.update(keep)
os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
original_connect = socket.socket.connect
def guard(self, address):
    if isinstance(address, tuple) and address[0] not in (
        "127.0.0.1", "::1", "localhost"
    ):
        raise RuntimeError("Audit blocked external network")
    return original_connect(self, address)
socket.socket.connect = guard
import dotenv
dotenv.load_dotenv = lambda *args, **kwargs: False
import pytest
```

For scanner/SDK, current directory was explicitly inserted into `sys.path`; gateway conftest adds its package path. `-B` avoids bytecode writes, cacheprovider was disabled, and pytest's temporary YAML fixtures used its normal temporary directory. Tests were run outside the root `.env` directory, with environment credentials removed and dotenv loading disabled. Loopback socket connections remain permitted for Python's event-loop internals; external TCP connects are rejected.

An important existing test weakness: `test_streaming_not_rejected` mocks the nonstreaming forwarder but **not the streaming forwarder**. It asserts only that a particular rejection string is absent. In this audit any external connection was blocked, so its pass does not demonstrate successful streaming or live-provider operation.

Other commands included `git status --short`, `git rev-parse HEAD`, `git diff --stat`, read-only diffs, `rg --files`/hidden-file inventory, targeted `rg -n`, PowerShell `Get-Content`, module-availability and installed-version checks, and SHA-256 checks of tracked files.

### 5.3 Additional offline integration checks

Harness design: import scanner package under a separate temporary Python module name; start both FastAPI apps using TestClient; route gateway HTTPX requests through MockTransport to actual scanner `/process`; inject dummy config credentials and the checked-in entity list; replace `providers.forward_chat_completion` with an async fake that captures the outbound body and returns one dummy completion. No code/config file was edited.

All cases below completed; they are security observations, not additional pytest pass-rate statistics.

| Synthetic case | Actual scan result | Actual chat/mocked egress result |
|---|---|---|
| `Email demo@example.com` | mask, EMAIL_ADDRESS | 200; email replaced |
| Public dummy AKIA-format AWS key | block, AWS_ACCESS_KEY | 200; key replaced; confirms policy mismatch |
| `sk-proj-` + 48 “A” characters | allow; no hits | 200; original forwarded |
| Three-part JWT-shaped dummy string | allow; no hits | 200; original forwarded |
| `password = "dummysecret123"` | allow; no hits | 200; original forwarded |
| `postgresql://demo:dummysecret@db.internal` | allow; no hits | 200; original forwarded |
| `server db.internal` | allow; no hits | 200; original forwarded |
| Dummy PEM marker + 64 “A” chars + end marker | block, PRIVATE_KEY | 200; body/end marker survive |
| Email in tool function description, harmless message | Not scanned in that field | 200; tool payload preserved unchanged |
| Image-only list using dummy data URL | No message text to scan | 200; image payload preserved unchanged |
| .txt file with email, no auth header | mask | Document endpoint 200 without auth |
| Policy action changed in memory to `typo`; email input | Detection still finds email | 200; original forwarded |
| Email text part plus image part | Email detected | 200; content collapses to `[REDACTED]`, image dropped |
| Scanner mocked to return email violation but null anonymized text | Scanner response contract anomaly | 200; original forwarded |

The checks were repeated with log output disabled to obtain an untruncated result summary, and expanded to resolve tool-field, document-auth, policy-typo, and multimodal questions. Existing suites were not rerun.

### 5.4 Test infrastructure gaps

No coverage result exists, and pytest-cov was unavailable. No coverage percentage is claimed.

There are scanner service integration tests and mocked gateway endpoint tests. There is **no existing full-stack gateway+scanner+provider integration suite**, browser E2E suite, Docker smoke test, or provider-specific compatibility suite. Audit-only in-memory integration checks are not committed regression tests.

No dedicated repository tests were found for `risk.py`, direct scan routing, document parsing/uploads, full secret category coverage, null/malformed scanner responses, invalid policies, outbound non-message fields, output DLP, or risk-decision consistency. DLP helper tests cover extraction/counting, not the complete HTTP/sanitization contract. CI automation is absent.

## 6. Evaluation metrics readiness

Existing test strings are small synthetic fixtures with expected behavior; they are **not a labeled benchmark corpus** with comprehensive spans, negative cases, splits, and category balance. No measurement code for confusion matrices, benchmark reporting, semantic preservation, percentiles, or throughput was found. Per-request timer fields exist, but are not an academic evaluation harness.

| Metric | Currently measurable? | Dataset and measurement code | What is missing / proposed evaluation | Actual result |
|---|---|---|---|---|
| Precision | Not reproducibly benchmarked; predictions available | Fixtures only; no TP/FP evaluator | Annotated spans and negative prompts; define exact/overlap matching; TP/(TP+FP), per category and micro/macro | NOT VERIFIED |
| Recall | Same | No complete positive corpus/evaluator | Broad valid PII/secret examples including formats, obfuscations, languages; TP/(TP+FN) | NOT VERIFIED |
| F1 | No current runner | No precision/recall aggregation | Freeze evaluation split; compute 2PR/(P+R), including zero-denominator policy | NOT VERIFIED |
| False Positive Rate | No | No representative benign/negative benchmark | Define unit (prompt/span candidate); collect TN/FP; FP/(FP+TN). Token/span evaluation needs an explicit negative universe | NOT VERIFIED |
| False Negative Rate | No | No comprehensive labeled positives | FN/(FN+TP), by entity/format/document source; distinguish invalid test credentials from valid-format positives | NOT VERIFIED |
| Secret detection by category | Can inspect outputs, not benchmark | No category-balanced corpus or report runner | Separate legacy/modern provider keys, AWS ID/secret/session, GitHub families, PEM, JWT, bearer, DB, generic credentials; report precision/recall/F1 | Only specific misses/hits in Section 5, no category rates |
| Sanitization effectiveness | Inspectable on examples | No residual-secret/span-removal metric | Ground-truth sensitive spans; count residual full/partial secret exposure at final egress; include all request fields and PEM bodies; independent secondary scanner/human verification | Verified PEM body survival and null-output fallback; no aggregate score |
| Information/intent preservation | No established measure | No paired original/sanitized task corpus or scorer | Human blind ratings and task correctness on synthetic paired prompts; structure-validity checks; assess pseudonym consistency | NOT VERIFIED |
| Average/median/P95 scanning latency | Individual durations instrumented; aggregate runner absent | `dlp_latency_ms` and scanner logs only | Fix hardware/model/version/input sizes, warmup, concurrency, repeats, and timing boundary; compute mean/median/P95 separately for analysis and gateway round trip | No benchmark result |
| Throughput (prompts/sec) | No existing measurement | No load generator/results | Offline realistic mixed corpus; controlled concurrent load; report completed successful scans/sec, error rate and latency; measure saturation without provider cost | NOT VERIFIED |

Gateway `dlp_latency_ms` measures message extraction/HTTP scanner calls/anonymization cumulatively; it is integer milliseconds and chat scans messages sequentially. Scanner analyze timing wraps analysis and overlap processing. Neither is pure regex time. Streaming header latency is time until stream establishment, not full completion time; nonstreaming hub latency excludes upstream time. Do not mix these boundaries.

**Academic benchmarking readiness:** Not ready for defensible effectiveness or performance claims. First repair/wire the evaluated features and define ground truth, threat model, splits, baselines, statistical reporting, and reproducible environment. Testing individual strings cannot support precision/recall or P95 claims.

## 7. Research alignment and contribution

| Research area | Current alignment | Evidence limit |
|---|---|---|
| LLM privacy-risk mitigation | Local inspection and replacement before optional provider requests | Incomplete egress coverage, plaintext logs, and missed detectors prevent a general prevention guarantee |
| PII sanitization algorithms | Real Presidio/NER/anonymizer integration | Core detection/anonymization algorithms are third-party; no demonstrated new algorithm |
| Traditional DLP principles | Content rules, risk categories, decisions, policy configuration, gateway boundary | No organization classification, mandatory egress routing, tenant policy, audit/incident handling, or comprehensive coverage |
| Real-time prompt inspection | On-demand request-time scan with timing instrumentation | UI is click-to-analyze, not continuous typing inspection; no latency/throughput benchmark |

### Attribution and demonstrated work

- **Third-party functionality:** Presidio recognition/anonymization, spaCy NLP/NER, LiteLLM provider adapters, FastAPI/HTTPX/Pydantic infrastructure, PDF/DOCX extraction.
- **Gateway foundation:** The footer and README explicitly identify Occludra Gateway as the base. SDK package metadata and `.github/profile/README.md` retain upstream attribution. Do not claim the whole gateway/SDK was originally built by this academic project.
- **Project-specific implementation identified in source:** Four-way heuristic risk assessment (`risk.py`), scan endpoint and assessment response, document text extraction/scan integration, and the inspection console. The README describes these as additions.
- **Partial additions:** YAML secret/infrastructure patterns, which are authored/configured artifacts but not active detectors.
- **Architectural integration:** A local scanner plus forwarding gateway, inspection preview, upload extraction, and provider routing; it is useful engineering work even without algorithmic novelty.
- **Authorship of each exact file/line:** NOT VERIFIED against upstream history. Local attribution and behavior identify intended contributions; no external upstream comparison was performed.

Potential research contributions **not yet demonstrated** include measured coverage for developer prompts/code/logs, configurable organization rules, consistent severity-aware enforcement, improved redaction with intent preservation, overlap strategy comparisons, and accuracy/latency trade-offs against baselines. Demonstration requires experiments and an explicit comparator, not just combining existing libraries.

No academic novelty, superiority, compliance certification, or measured security effectiveness is established by this repository.

## 8. Implementation status matrix

“COMPLETE” below means the narrowly named implementation exists and was supported by evidence; it does not mean production-grade or comprehensive category accuracy.

| Component | Status | Evidence | Limitations | Priority |
|---|---|---|---|---|
| Static inspection console | COMPLETE | `frontend/index.html`, source-reviewed workflows | Browser execution/layout NOT VERIFIED | P2 |
| Plain-text scan endpoint | COMPLETE | `routers/scan.py`; real offline email/AWS checks | Unauthenticated; heuristic coverage | P0/P1 |
| Chat text interception | PARTIALLY COMPLETE | `routers/proxy.py`, `dlp.process_messages` | Nontext/other fields bypass, no mandatory network routing | P0 |
| Microsoft Presidio integration | COMPLETE | Actual scanner tests and in-memory integration | Model/dependency environment sensitive | P1 |
| General PII coverage | PARTIALLY COMPLETE | Built-ins, selected entity list; 24 scanner failures | Edge cases and excluded entities | P1 |
| NLP/NER | COMPLETE | Analyzer startup loads spaCy en model | English only; accuracy not benchmarked | P2 |
| Legacy-shaped API key patterns | PARTIALLY COMPLETE | Registered API_KEY recognizer | Modern project keys and several providers missing | P0 |
| AWS credential protection | PARTIALLY COMPLETE | AKIA detector | No AWS secret/session/ASIA coverage | P0 |
| GitHub/Slack shapes | PARTIALLY COMPLETE | Registered regex patterns | Narrow formats, no comprehensive tests | P1 |
| Private-key protection | PARTIALLY COMPLETE | Header detector and offline test | Key body survives redaction | P0 |
| JWT/bearer/DB/password detectors | NOT IMPLEMENTED | YAML not loaded; real offline misses | No active recognizers/entity selection | P0 |
| Private-IP/internal-host rules | PARTIALLY COMPLETE | IP_ADDRESS active; additions YAML inactive | No intended subtype/hostname rules | P1 |
| Organization confidentiality classification | NOT IMPLEMENTED | No org corpus/config/model/store | No definition or enforcement | P1 |
| Custom enterprise policies | PARTIALLY COMPLETE | Internal per-request regex interface | Not exposed by gateway/UI; no tenants/policy lifecycle | P1 |
| Default replacement sanitization | PARTIALLY COMPLETE | Actual email/AWS replacements | Incomplete spans, null-output fallback, structure loss | P0 |
| Mask/hash operators | NOT VERIFIED | Internal operator mapping exists | Not independently exercised; no gateway UI option | P2 |
| Sanitized preview | COMPLETE | `renderReadout()`; scan response | No inline original-span highlighting | P2 |
| Sanitization residual checks | NOT IMPLEMENTED | No rescan/invariant after anonymization | Residual secrets reach egress | P0 |
| Four-way risk computation | COMPLETE | `risk.assess`; real scan checks | Hardcoded heuristic, uncalibrated | P2 |
| Unified risk-aware forwarding | NOT IMPLEMENTED | Chat does not call risk engine | Scan block does not bind egress | P0 |
| Warning approval audit | NOT IMPLEMENTED | Browser buttons only | No signed decision/authorization/policy version | P1 |
| Multi-provider adapters | PARTIALLY COMPLETE | Eight registry entries, LiteLLM forwarders | Live providers/models NOT VERIFIED | P1 |
| Operator BYOK | PARTIALLY COMPLETE | Env/YAML key lookup | Plaintext values; no secure lifecycle | P0/P1 |
| Per-user BYOK/account storage | NOT IMPLEMENTED | No credential API/user DB | Console key authenticates gateway only | P1 |
| Server streaming | PARTIALLY COMPLETE | SSE forwarder/generator | Existing test does not verify success; live stream NOT VERIFIED | P1 |
| Output/response DLP | NOT IMPLEMENTED | Responses/chunks returned directly | Provider outputs not inspected | P1 |
| Authentication/authorization | PARTIALLY COMPLETE | Constant-time chat bearer lookup | Open mode, unauthenticated scans, no roles | P0 |
| Secure logging | PARTIALLY COMPLETE | Structlog scrubber | Raw key prints; input-bearing error logs | P0 |
| Resource/rate protection | PARTIALLY COMPLETE | Body/file limits, token bucket | Post-read/header-only limits, arbitrary buckets | P1 |
| Database/persistent history | NOT IMPLEMENTED | No storage/schema source | Required only if product/user-history scope needs it | P1/P2 |
| Docker packaging | PARTIALLY COMPLETE | Two nonroot images + Compose | Fresh build/runtime/TLS NOT VERIFIED; 207 health issue | P1 |
| Tests | PARTIALLY COMPLETE | 159 tests run, 25 failures | Major new/security workflows untested | P1 |
| CI/browser E2E | NOT IMPLEMENTED | No workflows/E2E tooling | No automated whole-system validation | P2 |
| API documentation | PARTIALLY COMPLETE | OpenAPI/Postman files | Missing scan/docs routes; advertises absent model/smart routing features | P1 |
| Benchmark dataset/evaluator | NOT IMPLEMENTED | No corpus/measurement source | No defensible academic metrics | P2 |

## 9. Critical gaps and remaining work

Complexity is relative engineering effort, not a time estimate. The audit suggests resolutions but intentionally implements none.

### P0 — Critical security/core enforcement

| ID | Description and evidence | Impact | Suggested resolution | Complexity |
|---|---|---|---|---|
| P0-1 | Raw key and full key-record prints at `routers/proxy.py:78–85` | Credential exposure to stdout/log collectors, including on rejected requests | Remove raw debug prints; prohibit credential/input logging; review existing log access/retention and rotate exposed keys as appropriate | Low code; Medium operational |
| P0-2 | Four-way policy not used by chat; AWS/PEM scan block becomes chat 200 | UI's critical prohibition does not govern API egress | Use one server-side assessment/action function across scan/chat/doc workflows; enforce block on actual outgoing content with clear approval semantics | Medium |
| P0-3 | PEM recognizer spans BEGIN header only | Private key material remains in redacted prompt and reaches provider | Detect/cover full multiline key blocks; block partial/malformed keys; assert no key body survives at egress | Medium |
| P0-4 | Six YAML additions never registered; modern project keys missed | Actual credentials can leave unchanged | Wire and validate a single recognizer source plus entity list; extend provider formats; add category-specific negative and positive cases | Medium |
| P0-5 | Only extracted message text scanned; actual tool email and image passed unchanged | Sensitive content outside text bypasses the gateway | Define a full outbound schema; recursively inspect/sanitize every textual egress field; reject unsupported modalities or add local OCR/media inspection | High |
| P0-6 | Null anonymized output preserves original; `typo` action forwards detected email | Fail-closed claim fails on success-contract/config anomalies | Validate policy with an action enum at startup; validate scanner schema/spans; require sanitized output when violations exist; enforce residual removal | Medium |
| P0-7 | Shared/default/open auth; scan/doc routes unauthenticated; no local-only restriction | Untrusted clients can consume scanner resources; unsafe deployment can expose paid forwarding with a known/missing key | Authenticate relevant APIs; reject missing/weak config for non-demo deployment; derive auth/rate identity consistently; define local demo mode explicitly | Medium |

P0-7 is a deployment risk plus verified API behavior; no unauthorized paid request was made. P0-5 image check proves lack of scanning/forwarding, not actual image OCR leakage from a real sensitive image.

### P1 — Important objective and product gaps

| ID | Description and evidence | Impact | Suggested resolution | Complexity |
|---|---|---|---|---|
| P1-1 | No organization confidentiality definition/model/rule store | Enterprise project objective unmet | Add organization dictionaries/classification labels, project/domain policies, context rules, then evaluated semantic/fingerprint detection if required | High |
| P1-2 | Provider keys operator-only; no account/tenant credential API | Users cannot bring/store their own provider keys safely | Add authenticated ownership model, encrypted storage/secret vault, scoped access, rotation, and provider-key UI | High |
| P1-3 | 25 tests failing; several expected detectors absent | Faculty demo regressions and claimed coverage unreliable | Triage valid fixtures vs unsupported requirements; implement accepted categories; add egress/security contract tests | Medium |
| P1-4 | Warning buttons lack server approval policy/audit linkage | Review semantics unclear; scan and send disagree | Bind approval to exact content hash, action, user, policy version, and expiry; re-enforce on chat | Medium |
| P1-5 | PDF/DOCX extraction incomplete; no OCR or traversal of all DOCX parts | Sensitive image/header/comment content may be omitted from extracted-text inspection | Declare extraction coverage, scan additional parts, refuse uninspectable attachments where forwarding is supported, add extraction fixtures | Medium/High |
| P1-6 | Header-only/post-read limits; unbounded unauthenticated rate buckets; synchronous CPU parsing | Availability/resource risks | Cap streamed bytes and extracted text; limit parser expansion/pages; use authenticated/IP quotas with bounded storage and appropriate worker execution | Medium/High |
| P1-7 | No TLS/service authentication/production host restrictions | Off-host traffic and scanner access not securely bounded | Provide TLS ingress, loopback demo binding, scanner network isolation/auth, secret injection and retention policy | Medium |
| P1-8 | Response DLP missing | Sensitive provider responses can return without inspection | Define output threat model; scan full responses; buffer or design safe streaming policy where confidentiality is required | High for streaming |
| P1-9 | Provider-specific default/enable metadata ignored; live adapters unverified | Selected providers can get unsuitable model defaults; false support assumptions | Honor enabled/default model metadata; offline adapter tests; later controlled provider smoke tests with authorized dummy prompts | Medium |
| P1-10 | OpenAPI/Postman and SDK advertise absent /v1/models, smart routing/budgets | External advisor/client may infer nonexistent functionality | Generate local API reference from actual routes; remove or clearly label cloud-only features; make SDK local usage explicit | Low/Medium |
| P1-11 | Gateway/scanner validation logs retain input details; upstream exception text exposed | Sensitive data can persist through failures despite sanitizer | Log error type/location/request ID only; sanitize all exception surfaces; avoid echoing upstream details | Medium |
| P1-12 | Healthcheck accepts gateway degraded 207 | Readiness status misleading | Require healthy scanner state/200 in readiness check and test it | Low |

### P2 — Evaluation, usability, and maintainability

| ID | Description and evidence | Impact | Suggested resolution | Complexity |
|---|---|---|---|---|
| P2-1 | No labeled benchmark/evaluator | Cannot defend effectiveness or novelty claims | Build synthetic/de-identified corpus, annotation spec, splits, baselines, category metrics and confidence intervals | High |
| P2-2 | No performance/load benchmark | “Real-time,” scalability, and P95 unsubstantiated | Offline load runner with fixed versions/hardware, warmup, input strata, concurrency, error counts, percentiles | Medium |
| P2-3 | Visible key input, stale preview state, mismatched gauge ticks, vague errors | Risk misunderstanding and accidental wrong workflow | Mask key input; invalidate scan on input changes; align policy displays; distinguish network/parser/policy/provider errors | Low/Medium |
| P2-4 | No inline spans/type-preserving pseudonyms/intent evaluation | Limited explainability and prompt usefulness | Highlight original spans; evaluate stable typed placeholders and task preservation | Medium |
| P2-5 | No CI/full-stack/browser suite | Regressions unnoticed | Add offline CI, real scanner+gateway mock-provider tests, document tests, and browser workflow checks | Medium |
| P2-6 | Unlocked dependencies/model download; shared environment version mismatch | Reproducibility and container/local drift | Pin evaluated versions/model artifacts; separate service environments; record complete runtime provenance | Medium |
| P2-7 | SDK default external destination and inherited cloud-specific types | Accidental wrong endpoint in local research | Clearly document explicit local base URL; consider local-oriented wrapper/default; test local contracts | Low |
| P2-8 | Overlap suppression not validated for coverage preservation | Potential sensitive-span tails and severity distortions | Compare overlap union/priority strategies on labeled spans; preserve coverage during anonymization | Medium |

Recommended sequence: fix P0 log/egress/redaction/contract defects first; then active detector coverage and tests; then organization/per-user scope; then benchmark and faculty evidence. Adding dashboards or completion percentages before these controls would not resolve the central security gaps.

## 10. Academic project readiness

| Faculty demonstration claim | Assessment today |
|---|---|
| Working DLP application | **Credible as a limited prototype:** actual local inspection, preview, and mocked safe forwarding demonstrated |
| Real-time PII detection | **Partial:** request-time Presidio/NER works on examples; comprehensive detection and latency target not established |
| Credential/API secret detection | **Partial:** selected legacy key/AKIA/GitHub/Slack patterns; serious modern/unwired category gaps |
| Enterprise confidentiality protection | **Not credibly demonstrated:** no organization definition/classification pipeline |
| Sanitization before transmission | **Partial:** email/AWS examples sanitize; other fields, missed patterns, and PEM bodies escape |
| External LLM integration | **Implemented routing code; live operation NOT VERIFIED** |
| Measurable security effectiveness | **Not ready:** test outcomes exist, academic precision/recall/F1 and performance metrics do not |

A faculty review can credibly show the architecture, actual local scanner, safe synthetic hits/misses, deterministic score calculation, sanitized preview, and actual code boundaries. It should acknowledge failing tests and demonstrate how the planned fixes address verified egress gaps.

A realistic safe demonstration today:

1. Use dummy values and run the scanner locally.
2. Show a harmless text assessment and an email replacement.
3. Show a dummy AKIA key/injection pattern receiving a high-risk/block inspection result.
4. Scan a plain-text upload containing a dummy email.
5. Explain that chat policy currently differs from inspection policy; use a mock provider to show the actual boundary.
6. Show an explicit known miss and explain evaluation plans rather than claim universal protection.
7. Do not require a live key to demonstrate detection; live forwarding can be verified separately after security fixes and explicit operational authorization.

Fresh Docker startup, browser workflow, PDF/DOCX runtime extraction, and each live provider should be validated before promising them for a presentation. No arbitrary completion percentage is assigned: readiness is judged by demonstrated paths, implemented controls, unresolved failure modes, and availability of reproducible evidence.

## 11. Final executive summary

1. **Successfully built:** A local FastAPI/Presidio detection-and-anonymization service; a static inspection console; text and document scan endpoints; a deterministic four-way risk layer; a gateway with server-side plain-text inspection, operator-configured provider routing, and SSE code; a Python SDK and Docker packaging. Basic email redaction and gateway-to-real-scanner integration were verified offline.

2. **Partially functional:** Broad PII and secret detection, document coverage, sanitization, authentication/rate limiting/logging, warning workflow, provider integration, and testing. The existing suites produced 134 passes and 25 failures. Eight provider adapters are registered, but no live provider call was verified.

3. **Missing:** Active JWT/bearer/DB/password/infrastructure additions, modern key coverage, per-user provider-key management, organization confidentiality classification/policies, complete outbound-field inspection, sanitized-output guarantees, output DLP, unified risk-aware forwarding, benchmark datasets/evaluators, CI/browser E2E, and faithful local API documentation.

4. **Most serious security risks:** Raw authentication keys in stdout; original secrets allowed through missed/unwired detectors and unscanned fields; PEM bodies left after redaction; scan block decisions not enforced by chat; raw forwarding on invalid actions or missing anonymized output; unauthenticated scan/upload APIs and unsafe open/default deployment modes.

5. **Architecture suitability:** A separate local inspection service plus a gateway is appropriate for the academic prototype. It needs a single server-side egress policy, validated contracts, complete supported-payload coverage, explicit unsupported-modality handling, secure identity/key boundaries, and reproducible evaluation before it can support enterprise security claims.

6. **Implement next:** Remove key disclosure, enforce one risk/policy path, cover full secret spans and all egress fields, validate policies/scanner outputs, activate/test intended detectors, and fix test expectations/coverage. Then implement organization/per-user requirements and benchmarking.

7. **Realistic faculty demonstration today:** Local synthetic scanning, entity/risk output, email/AKIA redaction, text-upload inspection, selected injection detection, and a mocked provider handoff. Explain observed misses and unresolved security controls. Live provider success and broad PDF/DOCX/UI behavior remain NOT VERIFIED in this audit.

8. **Claims to avoid:** “All secrets are detected,” “enterprise confidentiality is protected,” “critical risks are blocked on every path,” “no raw sensitive data can leave,” “all eight providers are tested,” “users securely store their own keys,” “regex-only detection,” “zero external assets/calls,” “production-ready,” “compliant,” “novel detection algorithm,” and any fabricated precision/recall/F1, performance figure, or completion percentage.

