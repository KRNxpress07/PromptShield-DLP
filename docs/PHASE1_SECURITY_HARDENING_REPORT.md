# Phase 1 Security Hardening

**Date:** 13 October 2026 (Asia/Calcutta)  
**Repository:** `C:\CNS\PromptShield-DLP`  
**Baseline commit:** `cdea5b28fc2c71ddc1c8dd42d5f2092e036e6abb` plus pre-existing working-tree changes.  
**Scope:** Existing message-text DLP enforcement, sanitization, policy validation, PEM protection, logging, and offline regression tests.

## Changes implemented

**FIXED:** Scan and chat now share `dlp.inspect_messages()` → `risk.decide()` → existing `risk.assess()`. Configuration can make the result stricter, but cannot downgrade a critical/injection block.

**FIXED:** Both provider functions execute only after a non-block decision and successful required sanitization verification. All message roles participate; risk is assessed across the complete message list.

**FIXED:** The gateway validates scanner response shape, result fields, score finiteness/range, integer span offsets/order/bounds, configured entity membership, and required sanitized text. Missing/null/wrong-type/empty sanitization never falls back to the original. A retained original detected value is rejected even if a later scanner might claim no findings.

**FIXED:** Nonblocking detected content gets one verification pass over the exact outgoing text. Any remaining protected finding blocks egress. There is no recursive sanitization. Findings wholly contained in the exact literal `[REDACTED]` placeholder are excluded from verification decisions; findings extending outside it remain protected.

**FIXED:** The active PRIVATE_KEY recognizer covers matching complete multiline PEM blocks for generic, RSA, EC, DSA, OPENSSH, and ENCRYPTED PRIVATE KEY forms. Incomplete/mismatched blocks remain critical and cover the remaining text. Overlap post-processing cannot suppress blocking entity types or discard a partially overlapping sensitive tail.

**FIXED:** Authentication debug prints, raw key-record logging, partial key identifiers, raw prompt-bearing validation errors, and upstream exception-body logging were removed. Known opaque configuration secrets are registered for complete masking. Nested sensitive log fields and common secret shapes are scrubbed; standard logging suppresses raw exception traces. Scanner service diagnostics report counts/error types rather than request values, arbitrary paths, custom labels, or exception text.

**FIXED:** Invalid policy actions fail startup or produce a hard runtime configuration error. A typed policy also rejects invalid thresholds, empty entity lists/labels, and unknown policy fields. Existing `redact` configuration remains accepted as an alias of `mask`.

**PARTIALLY FIXED:** General DLP protection remains limited by existing detector coverage and the existing message-text extraction boundary. Phase 1 establishes enforcement invariants for classified message text; it does not make unscanned tools/images or undetected credentials safe.

No accounts, database, BYOK product workflow, providers, semantic models, dashboards, benchmark datasets, or frontend redesign were added. No credentials, prompts, or private keys were transmitted to real providers.

## Files changed

The following **21 files** were changed/created for this phase:

| File | Change |
|---|---|
| `conftest.py` | New repository-wide test guard rejecting external TCP connections and DNS; local LiteLLM cost metadata |
| `proxy-api/app/config.py` | Typed DLP policy, normalization, configuration errors |
| `proxy-api/app/dlp.py` | Validated scanner contract, shared inspection, removal check, bounded verification |
| `proxy-api/app/risk.py` | Shared decision applying configuration as a severity floor; warning requires sanitization |
| `proxy-api/app/routers/proxy.py` | Remove raw auth prints; shared policy; block before both forwarders; safe upstream errors/metadata |
| `proxy-api/app/routers/scan.py` | Reuse same inspection/decision helper |
| `proxy-api/app/models.py` | Safe block-response risk metadata |
| `proxy-api/app/main.py` | Validate startup; register secrets; safe logging/error handlers |
| `proxy-api/app/log_utils.py` | Complete masking, nested-field/pattern scrubber, standard-log formatter |
| `presidio/app/recognizers.py` | Full and incomplete PEM block recognition |
| `presidio/app/post_processor.py` | Preserve blocking findings and partial-overlap coverage |
| `presidio/app/main.py` | Remove input/exception-bearing logs and validation/error echoes |
| `proxy-api/tests/test_phase1_security.py` | New egress, contracts, policy, logging, actual-scanner integration tests |
| `presidio/tests/test_phase1_security.py` | New PEM, overlap, and scanner confidentiality tests |
| `proxy-api/tests/test_proxy.py` | Update intentional 422/503 contracts; mock verification and streaming; assert successful offline SSE |
| `proxy-api/tests/test_config.py` | Update normalized-policy expectations only, preserving existing unrelated fallback failure |
| `proxy-api/tests/test_log_utils.py` | Assert full masking instead of secret fragments |
| `sdk/python/aisg/client.py` | Preserve actual DLP block status in existing typed exception |
| `sdk/python/aisg/exceptions.py` | Accept actual block status while retaining legacy default 400 |
| `sdk/python/tests/test_client.py` | Typed DLP error compatibility at HTTP 422 |
| `docs/PHASE1_SECURITY_HARDENING_REPORT.md` | This handoff |

Pre-existing modifications in `frontend/index.html` were preserved without additional edits. The pre-existing settings defaults in `config.py` and corresponding default tests were also preserved. `docs/DLP_IMPLEMENTATION_AUDIT.md` remains the unchanged historical baseline. No configuration files, requirements, dependency installations, schemas, or environment secrets were modified. There is no commit or deployment as part of this work.

## Previous vulnerability

The audit demonstrated that:

- Authentication printed raw headers, keys, and all configured gateway key records.
- Scan could classify a dummy AWS/PEM input as block while chat separately redacted and forwarded it.
- A successful scanner response with null sanitized text silently retained the original.
- Invalid `dlp.action="typo"` allowed detected raw sensitive content to reach the mocked provider.
- PEM recognition covered only the BEGIN marker, leaving body and END marker.
- There was no verification scan or residual-value check.
- Error/exception logs could retain prompts or credentials.

These particular enforcement paths now have regression coverage.

## New behavior

### Authoritative policy

```text
Supported message text
  → validated local scanner analysis + replacement (one /process pass per message)
  → risk.assess + configured minimum action via risk.decide
  → BLOCK: return 422; never call either provider
  → findings + MASK/WARN: require usable sanitized messages
      → one local verification pass over outgoing messages
      → residual findings or uncertainty: return 422/503; no provider
      → verification clean: provider receives sanitized messages
  → no findings: ALLOW; provider receives original messages
```

The initial scanner call retains the existing combined analysis/anonymization API, which also provides scan previews. A block decision has no verification requirement because there is no egress. There is at most one combined initial pass and one verification pass **per nonempty message**, with no recursive sanitization.

Supported configured actions: `allow`, `mask`, `redact` (alias of mask), `warn`, `block`. A configured action is a **minimum response to findings**, not permission to override the risk engine:

- `allow` never downgrades detected mask/warn/block content.
- `mask/redact` preserves stronger warning/block decisions.
- `warn` raises low-risk findings to warn; server still sanitizes before sending.
- `block` rejects any detected finding.
- Harmless/no-finding prompts remain allow, including under the “block detected content” policy.
- Prompt injection always blocks.
- No browser warning or “Send anyway” option authorizes raw sensitive egress.

### Error contract

| Condition | Result | Safe machine-readable identifier |
|---|---|---|
| Risk/configured policy block | HTTP 422 | `pii_policy_violation` |
| Scanner unavailable, non-success response, malformed JSON/schema/spans, unusable sanitized output | HTTP 503 | `security_processing_error` |
| Detected original value retained or verification finds protected residual content | HTTP 422 | `sanitization_verification_failed` |
| Invalid configuration at startup | `DLPConfigurationError`; startup refused | Fixed error message, no configuration values |
| Invalid cached policy encountered during a request | HTTP 500; no scanner/provider call | `invalid_dlp_configuration` |

Block responses retain the legacy machine code for SDK compatibility and add risk level/score/entity types. They expose offsets/scores, not matched values. Existing SDK clients still raise `DLPBlockError`; updated SDK code preserves the actual 422 status instead of reporting 400.

No raw upstream exception message is returned for bad requests. Diagnostic detail is intentionally reduced to protect confidentiality.

## Security invariants

| # | Required invariant | Status and verification |
|---|---|---|
| 1 | No plaintext gateway/provider credentials intentionally logged | **FIXED / VERIFIED:** raw prints removed; captured rejected-auth, validation, upstream errors, nested scrubbing and standard logging checks pass |
| 2 | BLOCK means no provider executes | **FIXED / VERIFIED:** both forwarders explicitly assert_not_called across streaming/nonstreaming and system/assistant/user/tool roles |
| 3 | Detected content requiring redaction cannot fall back to raw text | **FIXED / VERIFIED:** null, missing, wrong-type, empty, unchanged, and inconsistent scanner outputs reject |
| 4 | Sanitized text verified before provider egress | **FIXED / VERIFIED:** ordered normal/verification calls checked inside mocked provider execution, in both modes |
| 5 | Complete PEM block removed | **FIXED / VERIFIED:** scanner tests assert full spans and no body/END marker for six types and two newline styles; gateway preview/egress checks pass |
| 6 | Invalid action cannot allow/forward | **FIXED / VERIFIED:** typed-policy, invalid YAML startup, invalid cached policy, and no scanner/provider call tests pass |
| 7 | Scan and chat use the same policy | **FIXED / VERIFIED:** shared helper/decision; endpoint comparisons for all supported action names and real scanner cases |
| 8 | Scanner/sanitization uncertainty fails closed | **FIXED / VERIFIED:** unavailable initial/verification passes, absent client, malformed contracts, bad spans, and residual findings reject before egress |

No unresolved test failures were found in these scoped invariants. This is not a universal detection guarantee or production-readiness statement.

## Tests added

**141 new parametrized regression cases passed:**

- **117 gateway cases** in `proxy-api/tests/test_phase1_security.py`.
- **23 scanner cases** in `presidio/tests/test_phase1_security.py`.
- **1 SDK compatibility case** in `sdk/python/tests/test_client.py`.

The gateway suite includes 40 block combinations: two stream modes × four message roles × five blocking conditions (AWS, PEM, injection, API_KEY, aggregate score reaching block). Each asserts that both provider entry points remain unused.

Other coverage includes null/empty/missing/wrong-type sanitized output, malformed results/JSON-compatible values, negative/reversed/out-of-bounds/noninteger offsets, nonfinite/out-of-range scores, invalid labels, retained originals, verification residuals, placeholder boundaries, one verification maximum, warning sanitization, opaque credential/log suppression, startup/runtime policy rejection, and actual scanner integration.

Scanner tests cover full PEM spans, generic/RSA/EC/DSA/OPENSSH/encrypted forms, LF/CRLF, multiple blocks, incomplete/mismatched blocks, overlap preservation, and validation/analysis/anonymization exception confidentiality.

Existing tests were changed only where the Phase 1 error contract, policy normalization, full masking, or required verification/streaming mocks changed their expected behavior. The unrelated config fallback test and original scanner coverage tests were not changed to obtain green status.

## Test results

Final verification ran **all three complete suites** in separate processes and package directories:

| Suite | Passed | Failed | Skipped | Total | Process exit |
|---|---:|---:|---:|---:|---:|
| Gateway | 211 | 1 | 0 | 212 | 1 |
| Scanner | 44 | 24 | 0 | 68 | 1 |
| SDK | 20 | 0 | 0 | 20 | 0 |
| **Total** | **275** | **25** | **0** | **300** | — |

The 25 failing tests are the same named failures observed before the sprint. All new Phase 1 cases pass. No failures were marked xfail, skipped, deleted, or suppressed.

Final pytest argument sets:

```text
proxy-api:
pytest.main(["tests", "-q", "-p", "no:cacheprovider",
             "-p", "pytest_asyncio.plugin", "--tb=short", "--show-capture=no"])

presidio:
pytest.main(["tests", "-q", "-p", "no:cacheprovider",
             "--tb=short", "--show-capture=no"])

sdk/python:
pytest.main(["tests", "-q", "-p", "no:cacheprovider", "--tb=short"])
```

These calls used the existing `.venv\Scripts\python.exe -B -`, with Python source supplied through PowerShell single-quoted here-strings. Environment credentials were removed, dotenv loading disabled, and suites ran outside root `.env`. Scanner and SDK inserted their package directories into sys.path. Plugin autoload and pytest cache writes were disabled. Existing pytest-asyncio was explicitly enabled for the gateway. Test temporary YAML files contained only dummy/no credentials.

The new root `conftest.py` rejects external connection and DNS attempts; loopback remains available for local Python event-loop internals. HTTPX MockTransport and TestClient provide all service communication; no real provider transport is required.

Final suite durations: gateway 33.81 s, scanner 5.55 s, SDK 0.64 s. These are test execution durations, **not latency/throughput benchmarks**. Dependency/model versions are the existing audit environment; fresh Docker builds/live providers are NOT VERIFIED. Coverage was not measured. `git diff --check` passed.

### Remaining pre-existing failures

Gateway:

- `tests/test_config.py::TestGetGatewayConfig::test_missing_file_returns_empty`: nonexistent requested config falls back to the actual repository YAML; the test expects an empty dictionary without isolating that fallback. This expectation/isolation mismatch predates Phase 1.

Scanner, all in `tests/test_sovereign_safety.py`:

| Class | Failing methods |
|---|---|
| TestPIIRedaction | test_ssn_detected |
| TestCreditCardEdgeCases | test_dash_separated_card; test_space_separated_non_luhn_with_context; test_card_expiry_slash; test_cvv_after_keyword; test_full_pci_payload_all_redacted; test_dash_card_with_cardholder_context; test_mixed_pci_hipaa_prompt |
| TestTabularDataEdgeCases | test_us_phone_dash_with_country_code; test_masked_ssn_xxx; test_masked_ssn_star; test_uk_postcode; test_uk_postcode_sw1a; test_india_pin_code; test_full_csv_row_redaction; test_multi_row_csv |
| TestFullCsvIntegration | test_complete_csv_redaction |
| TestStreetAddressRecognizer | test_basic_street_rd; test_basic_street_st; test_po_box; test_street_address_redacted; test_uk_road |
| TestOverlapSuppression | test_ssn_dash_format_no_datetime; test_non_overlapping_entities_kept |

These reflect existing SSN/phone/card fixture expectations, missing postal/street/PCI entities, and incomplete compound CSV coverage. Some fixtures are invalid/example identifier formats, so they require requirement/fixture triage rather than treating the failed test ratio as an accuracy metric. Phase 1 did not expand those detectors.

## Offline integration results

| Required case | Result | Evidence |
|---|---|---|
| 1. Harmless prompt | **PASS:** allow; mocked provider called with original | Actual gateway + actual scanner `test_offline_gateway_with_actual_scanner[harmless]`; separate stream/nonstream checks |
| 2. Email | **PASS:** mask; second scan passes; provider receives `Email [REDACTED]` | Actual scanner integration plus ordered forwarding test |
| 3. Dummy AWS key | **PASS:** block; neither provider called | Actual scanner integration and role/stream block matrix |
| 4. Dummy PEM | **PASS:** full PRIVATE_KEY span; preview is only `[REDACTED]`; provider not called | Actual scanner integration; full PEM scanner tests |
| 5. Violation + null anonymized_text | **PASS:** 503; neither provider called | In-memory scanner fault response, both stream modes |
| 6. Invalid policy | **PASS:** YAML/cached policy startup rejection or hard runtime 500 before scanner/provider | Invalid-file startup and invalid-cached-policy egress tests |

Cases 1–4 use the real Presidio/spaCy service via an in-memory transport. Cases 5–6 deliberately inject fault/configuration conditions. All credentials and key bodies are synthetic; dummy PEM bodies are repeated A/B characters, not generated private keys.

## Remaining known risks

| Area | Status | Limit |
|---|---|---|
| Scoped Phase 1 enforcement defects | **FIXED** | All eight invariants have passing regression evidence; 25 unrelated baseline failures remain |
| Comprehensive credential detection | **PARTIALLY FIXED** | Full PEM coverage fixed; modern provider formats and inactive JWT/bearer/DB/password YAML additions remain outside this sprint |
| Complete request inspection | **DEFERRED** | Tools/functions/schemas/metadata and images remain outside existing message-text scan; no OCR added |
| General PII/document coverage | **PARTIALLY FIXED** | Detected partial-overlap tails preserved; baseline detector/extraction gaps remain |
| Secure deployment/identity/key storage | **DEFERRED** | Shared/open auth modes, unauthenticated scans/uploads, plaintext keys, wildcard CORS, HTTP/TLS and rate/resource issues unchanged |
| Historical credential exposure | **DEFERRED operational action** | This patch does not delete old logs or rotate previously exposed keys |
| Output DLP | **DEFERRED** | No response/SSE confidentiality inspection |
| Semantic/enterprise confidentiality | **DEFERRED** | No organization classification/policy vocabulary |
| Academic effectiveness/performance | **DEFERRED** | No benchmark dataset/evaluator or performance claim |
| Live adapters/deployment | **NOT VERIFIED** | No external provider calls or Docker deployment during this phase |

Verification reuses the same detector and configured threshold, so it cannot discover every systematic false negative. Literal retained-value checks add protection for **detected** spans, not unknown secrets. Conservative overlap preservation or new residual detections may reject some otherwise useful prompts; the server returns a failure rather than repeatedly sanitizing.

Scan previews are not authorization tokens. Editing/submitting new content results in a new assessment; no persistent approval/block artifact was added, consistent with the phase scope.

## Deferred Phase 2 work

1. Wire and evaluate inactive secret recognizers and modern provider-key formats.
2. Inspect all textual egress fields; reject or safely inspect unsupported media.
3. Triage/fix baseline PII coverage requirements and config-test isolation.
4. Add organization policy definitions, secure identity/credential ownership, and warning-approval lifecycle if required.
5. Address TLS, deployment exposure, scan/upload authorization, resource/rate controls, and retention.
6. Evaluate output/stream DLP, document extraction coverage, accuracy, and reproducible performance.
7. Update broader API/UI claims and documentation to match effective coverage.

**Phase 1 establishes tested fail-closed enforcement for the existing classified message-text path. It does not establish production readiness or universal sensitive-data prevention.**

