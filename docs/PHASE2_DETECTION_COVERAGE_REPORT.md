# Phase 2 Detection Coverage

**Date:** 13 October 2026 (Asia/Calcutta)  
**Repository:** `C:\CNS\PromptShield-DLP`  
**Baseline:** Current Phase 1 working tree, not a reset to Git HEAD.  
**Result:** **FIXED** targeted detection and textual egress gaps; **PARTIALLY FIXED** general detection completeness. No production-readiness or performance claim.

## Objectives

Activate intended secret/infrastructure rules, recognize modern credential shapes, implement accepted PII rules, inspect the actual provider-bound text tree, and reject unsupported content while preserving Phase 1's shared policy, block gates, sanitization checks, and safe logging.

No accounts, database, per-user BYOK, new provider, OCR, semantic classifier, embeddings, output DLP, dashboard, benchmark dataset, dependency installation, or frontend redesign was added.

Baseline suites were run **before implementation**: gateway 211 passed/1 failed, scanner 44 passed/24 failed, SDK 20 passed; **275 passed, 25 failed, 0 skipped**. All 141 Phase 1 regression cases passed.

Final suites: **565 passed, 11 failed, 0 skipped, 576 total**. All **276 new Phase 2 cases** and all **141 Phase 1 cases** passed. **14 baseline failures resolved; zero remaining new failures.**

## Active recognizers after Phase 2

**One source of truth:** `presidio/app/recognizers.py`. Its programmatic factory registers every project recognizer. `presidio/recognizers.yaml` is a retired comments-only stub, with no duplicate detector definitions. Startup refuses any reintroduced non-comment YAML definitions, duplicate recognizer names, invalid patterns, or missing required recognizers.

The actual scanner health check reported **37 recognizers, 36 supported entity types**. There are **21 project recognizer instances protecting 20 distinct entity types**; multiple recognizers share POSTAL_CODE and PERSON also has built-in spaCy recognition. The default gateway enables **26 entity types**.

Unknown requested scanner entities return a controlled 422; they are no longer silently ignored. Gateway entity configuration requires explicit risk weights. A test compares the active custom entities, scanner health entities, checked-in gateway list, and risk map.

“Gateway protected” below refers to the **checked-in policy**. Explicit deployment entity filters/thresholds can narrow coverage. Nominal risk is for one finding before count bonus/configured severity floor.

| Entity | Detection method | Active? | Gateway protected? | Risk level | Tests |
|---|---|---|---|---|---|
| API_KEY | Bounded prefix/length/charset patterns: legacy and modern OpenAI, Anthropic, Google/Gemini, Groq | Yes | Yes | Critical 95 | Phase 2 positive/negative formats; actual egress block |
| AWS_ACCESS_KEY | AKIA/ASIA + 16 uppercase alphanumeric characters, boundaries | Yes | Yes | Critical 100 | Positive both families; short/overlong negatives; Phase 1 block matrix |
| AWS_SECRET_KEY | Explicit AWS secret label + 40-character candidate | Yes | Yes | Critical 100 | Context variants, context-free/short negatives; actual integration |
| AWS_SESSION_TOKEN | Explicit AWS/session label + bounded base64-like candidate | Yes | Yes | Critical 95 (new) | Context positives; bare/short negatives |
| PRIVATE_KEY | Full matching multiline PEM; malformed/unfinished tail protection | Yes | Yes | Critical 100 | Unchanged Phase 1 LF/CRLF/six-type/full-span tests; actual integration |
| GITHUB_TOKEN | ghp_/gho_/ghu_/ghs_/ghr_ and github_pat_ families | Yes | Yes | Critical 95 | Each family positive; prefix/short negatives |
| SLACK_WEBHOOK | Selected hooks.slack.com service URL shape | Yes | Yes | Critical 90 | Complete synthetic URL and malformed/other-domain negatives |
| JWT_TOKEN | Three bounded base64url segments; decoded JSON header with alg and object payload | Yes | Yes | High 78, warn/sanitize | Dotted filenames/versions and invalid JSON negatives; surrounding-text and actual egress |
| BEARER_TOKEN | Bearer keyword plus bounded candidate token, case-insensitive context | Yes | Yes | High 72, warn/sanitize | Token/context positives; ordinary bearer prose/short negatives |
| DB_CONNECTION_STRING | Full credential-bearing URI, including host/path/query | Yes | Yes | Critical 93 | Nine schemes and empty Redis username; complete spans; credential-free negatives |
| GENERIC_SECRET_ASSIGNMENT | Selected secret/password/provider labels with assigned quoted/unquoted value | Yes | Yes | Medium 55 | Label variants, bare keywords/policy prose/null/empty negatives |
| PRIVATE_IP | Valid canonical decimal octets in RFC1918 IPv4 ranges | Yes | Yes | Low 45 | Range edges; public/invalid/loopback negatives |
| INTERNAL_HOSTNAME | Bounded DNS-like labels ending .internal/.local/.corp/.lan | Yes | Yes | Medium 65 | Suffix/subdomain positives; public/localhost/embedded-suffix negatives; real nested egress |
| PROMPT_INJECTION | Existing five English instruction/jailbreak patterns | Yes | Yes | Forced critical/block | Existing scanner and unchanged Phase 1 gateway tests |
| PERSON | spaCy NER plus explicit CSV name-column rule | Yes | Yes | Low 20 | Accepted CSV name spans with LF/CRLF; column/value negatives; existing NER tests |
| PHONE_NUMBER | Built-in phone recognition plus explicit international shape/possible-length validation | Yes | Yes | Low 35 | International formats and malformed/date negatives |
| US_SSN | Existing Presidio validator plus reserved 900-series rejection | Yes | Yes | High 85 | Valid synthetic formats, zero/reserved/sample negatives, contained-date regression |
| MASKED_US_SSN | XXX-XX-dddd / ***-**-dddd partial-identifier shape | Yes | Yes | Medium 55 (new) | Both masks, malformed negatives, complete CSV removal |
| STREET_ADDRESS | Bounded English numbered street/suffix and PO box patterns | Yes | Yes | Low 40 (new) | Full spans; ordinary prose/numbers negatives |
| POSTAL_CODE | UK shapes; context-qualified Indian PIN and US ZIP/state shapes | Yes | Yes | Low 25 (new) | Complete spans; unqualified build numbers/invalid shapes negatives |
| EMAIL_ADDRESS | Presidio built-in | Yes | Yes | Low 40 | Existing scanner; unchanged Phase 1 and Phase 2 nested sanitization |
| CREDIT_CARD | Presidio format recognition with Luhn validation retained | Yes | Yes | High 80 | Valid dashed/space card; checksum-invalid/date/last-four negatives |
| LOCATION | spaCy NER | Yes | Yes | Low 15 | Existing general PII/address cases; no universal geography claim |
| IP_ADDRESS | Presidio built-in | Yes | Yes | Low 30 | Existing enabled category; private subtype regression coverage |
| DATE_TIME | Presidio built-in | Yes | Yes (newly enabled) | Low 8 | Existing ISO/date CSV cases; contained date suppression |
| IBAN_CODE | Presidio built-in with checksum validation | Yes | Yes (newly enabled) | High 70 | Generated dummy checksum-valid IBAN and invalid-checksum negative |

Other scanner built-ins remain registered but are not selected by the checked-in gateway policy: CRYPTO, MAC_ADDRESS, MEDICAL_LICENSE, NRP, UK_NHS, URL, US_BANK_NUMBER, US_DRIVER_LICENSE, US_ITIN, US_PASSPORT. Registration does not mean they are protected under every policy.

## Provider credential coverage

All patterns are **candidate-shape detectors**, not credential authentication, issuer validation, signature validation, or liveness tests. Minimum lengths and boundaries are intentional false-positive controls; exact live-provider key grammar is not asserted.

| Provider | Supported key formats | Unsupported/unknown formats |
|---|---|---|
| OpenAI | sk- legacy candidates; sk-proj-, sk-svcacct-, sk-admin- candidates; bounded 20–256-character bodies | Unprefixed/unknown future formats; real validity NOT VERIFIED |
| Anthropic | sk-ant- candidates, including api03/admin01 prefix styles and separator characters | Exact issuance/suffix validation and unrecognized future families NOT VERIFIED |
| Google/Gemini | AIza + 35-character candidate body | OAuth/service-account credential bundles and other auth mechanisms not comprehensively classified |
| Groq | gsk_ candidates with bounded body | Other opaque/unknown future formats |
| Together | Selected explicit TOGETHER_API_KEY/API_TOKEN assignment and bearer contexts | **NOT IMPLEMENTED:** no reliable provider-specific pattern established from reviewed primary documentation |
| Mistral | Selected explicit MISTRAL_API_KEY/API_TOKEN assignment and bearer contexts | **NOT IMPLEMENTED:** no reliable provider-specific pattern established from reviewed primary documentation |
| DeepInfra | Selected explicit DEEPINFRA_API_KEY/API_TOKEN assignment and bearer contexts | **NOT IMPLEMENTED:** no reliable provider-specific pattern established from reviewed primary documentation |
| xAI | Selected explicit XAI_API_KEY/API_TOKEN assignment and bearer contexts | **NOT IMPLEMENTED:** no reliable provider-specific pattern established from reviewed primary documentation |
| GitHub (credential category, not an LLM provider) | ghp_, gho_, ghu_, ghs_, ghr_ bodies 36–255; github_pat_ bodies 82–255 | Old opaque hexadecimal forms and unknown families without context |
| AWS (credential category, not an added LLM provider) | AKIA/ASIA IDs, labeled secret keys, labeled session tokens | Unlabeled arbitrary base64-like secrets/session tokens; other ID families |

**Provider adapter support does not imply provider-specific key-format detection.** No provider was added or contacted for credential validation.

Primary-source review informed these choices. [GitHub's credential reference](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types) documents token-family prefixes; [AWS access-key guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/securing_access-keys.html) distinguishes AKIA and ASIA. [Groq's security guide](https://console.groq.com/docs/production-readiness/security-onboarding) uses the gsk_ prefix. The maintained [Gitleaks OpenAI rule](https://raw.githubusercontent.com/gitleaks/gitleaks/master/cmd/generate/config/rules/openai.go) and [Anthropic rule](https://raw.githubusercontent.com/gitleaks/gitleaks/master/cmd/generate/config/rules/anthropic.go) show common prefix styles; our broader prefix/length heuristics are an implementation choice, not copies of their validity guarantees.

The reviewed [Mistral key guidance](https://docs.mistral.ai/admin/identity-access/api-keys), [official DeepInfra integration](https://github.com/deepinfra/langchain-deepinfra), and [xAI quickstart](https://docs.x.ai/developers/quickstart) describe obtaining/configuring credentials but did not establish a sufficiently reliable standalone format for this implementation. Together's reviewed documentation/search likewise did not establish a primary-source pattern. This is **NOT VERIFIED**, not proof that distinguishable formats do not exist.

## PII coverage changes

**FIXED:** Explicit international phone syntax is detected when phonenumbers judges its length possible. This is not proof of assignment, region-specific validity, or reachability. No external lookup occurs.

**FIXED:** Bounded English numbered-street and PO-box shapes; UK postal candidates and context-qualified Indian PIN/US ZIP candidates. Arbitrary five/six-digit build numbers are not accepted as postal codes without the appropriate context. These are narrow heuristics, not a global postal/address validator.

**FIXED:** Masked SSN fragments are classified as MASKED_US_SSN. They are privacy-sensitive partial identifiers, not valid complete SSNs.

**FIXED:** Name-like alphabetic values under explicit CSV name/first_name/last_name/full_name/patient_name headers are protected. Offsets use the original text, including CRLF. Malformed rows, arbitrary columns, and numeric/underscore values do not trigger the project CSV name rule. spaCy remains the general NER engine.

**FIXED:** Complete protected spans retain coverage through overlap handling. DATE_TIME findings wholly inside a protected span can be suppressed, while the protected span remains. Partial-overlap tails and blocking findings remain protected.

**Retained validation choices:** Credit cards require Luhn; a formatted but checksum-invalid number is not classified as a valid card solely because prose says “Visa.” SSNs retain zero-group/reserved/sample exclusions, with the 900-series restriction added. The [SSA invalid-number rules](https://secure.ssa.gov/poms.nsf/lnx/0110201035) identify the reserved ranges; there was no issuance lookup.

Valid dashed-card and valid synthetic-format SSN regressions demonstrate accepted formatting. The old failing examples are not transformed into valid identifiers. CVV and CREDIT_CARD_EXPIRY were not implemented or mislabeled as CREDIT_CARD.

## Baseline test triage

[PHASE2_BASELINE_TEST_TRIAGE.md](PHASE2_BASELINE_TEST_TRIAGE.md) was written before implementation and classifies all 25 failures as accepted requirements, invalid/questionable fixtures, unsupported entities, or deferred behavior.

Six test assertions were migrated to the implemented entity category while keeping exact-value/span/removal assertions: two masked-SSN tests, three postal tests, and the compound CSV masked-identifier assertion. No test was deleted, skipped, or marked xfail.

The previously passing composite redaction test used reserved 999-88-7777. It now uses synthetic 321-54-6789, retaining both entity-presence and removal assertions. A negative test confirms that 900-series values are rejected.

Two legacy gateway mocks were adapted to include the newly inspected client-supplied model leaf; their sanitization/metadata assertions were retained. The Phase 1 regression files themselves were not edited and their SHA-256 hashes were checked unchanged.

## Textual egress inspection architecture

`providers.COMPLETION_PARAMS` is the single allowlist for both LiteLLM forwarders and `egress.inspect_outbound_payload()`. A test requires the request model's forwarded fields to match this allowlist, so additions cannot silently bypass enumeration.

```text
Parsed request + resolved client model/header
  → select exactly the provider-forwarded fields
  → validate supported message/content/header shapes
  → bounded walk of dictionary/list tree
  → collect text values and user-defined structural keys
  → existing dlp.inspect_messages → existing risk.decide/risk.assess
  → BLOCK: reject before either forwarder
  → required sanitization: validated output and retained-value removal check
  → verify each changed string once
  → reconstruct only affected string values
  → reject unsafe key/identifier changes
  → provider receives inspected tree
```

### Exact forwarded-field inventory

All nonempty free-form string leaves in these fields are inspected:

- `messages[*].content` strings, plain string-list items, and supported `{type:"text", text:...}` parts; `messages[*].name`.
- Client-supplied `model`, including the resolved `x-model` override.
- `tools`, `functions`, `tool_choice`, `function_call`: names, descriptions, parameter schemas, defaults, examples, enums, required arrays, and arbitrary supported nested string values.
- `response_format`: schema names/descriptions and supported nested schemas/arrays.
- `stop` strings/lists and `user`.
- `thinking`, `stream_options`, `logit_bias` textual map keys, `extra_headers`.
- `reasoning_effort` and `service_tier`.

Numeric/boolean controls are forwarded through the same allowlist but not stringified: temperature, top_p, max_tokens, max_completion_tokens, stream, n, presence_penalty, frequency_penalty, logprobs, top_logprobs, seed, parallel_tool_calls, top_k, and numeric values inside supported structures.

Exact validated role/type constants are protocol controls. Supported role literals include system, developer, user, assistant, tool, function. Known schema/text/function type tags are not arbitrary text. A server-selected default model (when no client model/x-model is supplied) is trusted routing configuration; client-supplied model values are inspected. The incoming gateway Authorization header, configured provider prefix, server provider credential, timeout, and server-added usage flag are not prompt data.

### Reconstruction and bounds

- Original dictionaries/lists/scalars are preserved; the walker builds a new tree rather than modifying the request.
- Supported multimodal **text-part** arrays retain their shape; no flattening/collapse to one string.
- User-defined schema/header/map keys are inspected as extra defense. Sensitive keys are rejected instead of renamed, which could break references.
- Sensitive routing/function/schema/reference identifiers are rejected when replacement would create an unusable protocol identifier; placeholders are not forwarded as model/function names.
- Depth limit **20**, node limit **20,000**, nonempty textual-slot limit **2,000**. Excessive/cyclic/incompatible structures fail closed before scanning/egress.
- Repeated equal strings share scanner responses **within one pass**, but every occurrence still contributes findings to risk. Five repeated SSN findings still reach score 93/block.
- Only changed values need the verification pass; unchanged values are identical to their already-inspected originals. A nonblocking detected result with no changed output rejects. No cross-request prompt cache was introduced.
- Scanner faults anywhere in a nested field abort the entire request. Neither provider is called.
- Extra-header credential overrides are rejected for Authorization, Proxy-Authorization, api-key, x-api-key, x-goog-api-key, x-amz-security-token, case/underscore variants, and invalid header names. Operator-owned provider authentication remains separate.

No request is blindly converted to one JSON/text string for DLP. This preserves tree structure, but does not add semantic classification of every value or reconstruct fragments across separate leaves.

## Unsupported modality behavior

**FIXED:** HTTP **422**, `error="unsupported_dlp_content"`, before provider egress for:

- Image/image_url parts, image-only requests, and mixed text+image.
- Audio, raw file parts, unknown/nonconforming content objects, malformed text parts or extra content-part fields.
- Binary/non-JSON object values, nonfinite numeric values, excessive/cyclic structures.
- Encoded base64 data-URI blobs embedded as string values.
- Unsafe credential-header overrides and structural-key rewrites.

No OCR/media bypass or opt-in uninspected forwarding was added. Ordinary text documents use the existing extracted-text endpoint, whose image/document-part extraction limitations remain.

Post-sanitization residuals/unusable identifiers return 422 `sanitization_verification_failed`. Scanner response/unavailability faults return 503 `security_processing_error`. Risk blocks preserve 422 `pii_policy_violation` for SDK compatibility. Invalid policy still refuses startup or returns a hard configuration failure.

## Phase 1 invariants

| Invariant | Post-Phase-2 evidence |
|---|---|
| BLOCK means neither provider executes | Unchanged Phase 1 role/mode matrix; nested field/mode matrix; actual scanner integration |
| No raw fallback for detected content | Existing null/malformed/retained-value cases plus nested sanitization fault |
| Sanitized content verified before egress | Existing ordered-provider test and changed-leaf verification tests |
| Full PEM removed/blocked | All unchanged Phase 1 PEM cases and actual integration |
| Invalid policy fails closed | Existing startup/cached-policy/YAML tests; unknown-risk entity validation retained |
| Scan/chat use one policy | Shared inspect_messages/risk decision; actual gateway/scanner action comparisons |
| Scanner uncertainty fails closed | Existing initial/verification failures plus nested fault and walker limits |
| No intentional credential logging | Existing capture/scrubber tests; new AWS/session/client-secret/DB logging controls |

All **141 Phase 1 cases pass**. Their two main regression files and the pre-existing frontend were hash-verified unchanged.

## Files changed

These **21 files** were changed/created for Phase 2. Earlier Phase 1 changes remain in the working tree and were not reset.

| File | Phase 2 change |
|---|---|
| README.md | Accurate coverage, limits, modality/error/routing semantics and source locations |
| config/gateway.yaml | Enable all project entities plus date/IBAN built-ins |
| presidio/app/recognizers.py | Sole detector source; validation, new secret/PII rules, CSV names |
| presidio/recognizers.yaml | Retire duplicate definitions; comments-only stub |
| presidio/app/main.py | Reject unsupported entity configuration |
| presidio/app/post_processor.py | Protect new spans; retain contained-date suppression without losing sensitive coverage |
| presidio/tests/test_sovereign_safety.py | Reasoned category/valid-fixture migrations |
| presidio/tests/test_phase2_detection.py | New positive/negative, full-span, registry, startup and CSV tests |
| proxy-api/app/config.py | Require risk handling for configured entity names |
| proxy-api/app/dlp.py | Per-pass deduplication preserving occurrence counts; verification only changed text |
| proxy-api/app/egress.py | New bounded exact-payload walker, validation/reconstruction/modality gates |
| proxy-api/app/providers.py | One shared forwarding parameter allowlist |
| proxy-api/app/risk.py | AWS session, masked ID, street, postal weights |
| proxy-api/app/routers/proxy.py | Apply outbound inspection; use its reconstructed payload; avoid raw provider-name echoes |
| proxy-api/app/log_utils.py | Extend safe logging for new contextual secrets and URI schemes |
| proxy-api/tests/test_proxy.py | Adapt legacy mocks for newly inspected model leaf; retain assertions |
| proxy-api/tests/test_phase2_egress.py | New field/mode/structure/fault/integration/log tests |
| docs/api/openapi.yaml | Actual route-derived local API reference, auth/routing and Phase 2 semantics |
| docs/api/postman-collection.json | Remove absent model discovery; correct critical-block/PII examples |
| docs/PHASE2_BASELINE_TEST_TRIAGE.md | All baseline decisions, prepared before implementation |
| docs/PHASE2_DETECTION_COVERAGE_REPORT.md | This handoff |

No frontend, SDK, dependency files, environment credentials, database schemas, or provider catalog entries were modified in this phase. Historical audit/Phase 1 reports were preserved. No commit/deployment was performed.

## Tests added

**276 new parametrized Phase 2 cases:**

- **166 scanner cases**: credential families/context, minimum length/boundary/JSON controls, complete credential/PII spans, CSV names, Luhn/SSN/IBAN validation choices, registered/configured/weighted consistency, invalid-pattern/retired-YAML startup, false-positive negatives.
- **110 gateway cases**: every forwarded textual root field, nested dictionaries/arrays, key/identifier protection, structure preservation, both stream modes, scanner faults, unsupported media/data blobs, limits/cycles, duplicate counting, no unnecessary verification of unchanged literals, logging, and actual-scanner demonstrations.

No real credential or real private key was copied/generated/used. Values are repeated dummy characters, dummy labeled values, dummy JSON JWTs, and synthetic/checksum-generated identifier examples. Credential liveness was not checked.

## Full test results

| Suite | Before passed | Before failed | Final passed | Final failed | Skipped | Final total |
|---|---:|---:|---:|---:|---:|---:|
| proxy-api | 211 | 1 | 321 | 1 | 0 | 322 |
| presidio | 44 | 24 | 224 | 10 | 0 | 234 |
| sdk/python | 20 | 0 | 20 | 0 | 0 | 20 |
| **Total** | **275** | **25** | **565** | **11** | **0** | **576** |

**Resolved baseline failures: 14. Remaining new failures: 0. Phase 2 new failures: 0.** All Phase 1 cases pass. Remaining failures were not suppressed, deleted, xfailed, or skipped. Coverage was not measured. No performance benchmark was run.

Suites used the existing Python 3.12.10 environment and separate service working directories because both services use an app package. The gateway invocation enabled the existing pytest-asyncio plugin; cache/plugin auto-discovery were disabled. The root offline conftest rejects external TCP/DNS and forces local LiteLLM cost metadata.

Actual pytest argument sets:

```text
proxy-api:
pytest.main(["tests", "-q", "-p", "no:cacheprovider",
             "-p", "pytest_asyncio.plugin", "--tb=short", "--show-capture=no"])

presidio:
pytest.main(["tests", "-q", "-p", "no:cacheprovider",
             "--tb=short", "--show-capture=no"])

sdk/python:
pytest.main(["tests", "-q", "-p", "no:cacheprovider",
             "--tb=short", "--show-capture=no"])
```

Python source was supplied via PowerShell single-quoted here-strings to the existing `.venv\Scripts\python.exe -B -`. Test environments retained OS path/temp variables only; credentials were removed and dotenv loading disabled. In-memory TestClient/MockTransport replaced service/network transport, and both provider functions were mocks. Initial, intermediate and final runs were inspected; introduced failures were corrected, not ignored.

`git diff --check` and Python syntax checks are included in final verification. Deployment/container rebuilds, current live provider/model compatibility, and vulnerability scanning are **NOT VERIFIED**. The shared local HTTPX version remains the previously noted difference from the scanner's declared range; no dependency changes were made.

## Resolved baseline failures

Fourteen formerly failing scanner methods now pass:

- TestTabularDataEdgeCases.test_us_phone_dash_with_country_code
- TestTabularDataEdgeCases.test_masked_ssn_xxx
- TestTabularDataEdgeCases.test_masked_ssn_star
- TestTabularDataEdgeCases.test_uk_postcode
- TestTabularDataEdgeCases.test_uk_postcode_sw1a
- TestTabularDataEdgeCases.test_india_pin_code
- TestTabularDataEdgeCases.test_full_csv_row_redaction
- TestTabularDataEdgeCases.test_multi_row_csv
- TestFullCsvIntegration.test_complete_csv_redaction
- TestStreetAddressRecognizer.test_basic_street_rd
- TestStreetAddressRecognizer.test_basic_street_st
- TestStreetAddressRecognizer.test_po_box
- TestStreetAddressRecognizer.test_street_address_redacted
- TestStreetAddressRecognizer.test_uk_road

Category migrations are disclosed above and in triage; the exact relevant sensitive-value protections remain asserted. The additional valid multi-PII fixture correction is not counted as a resolved baseline failure because that test originally passed.

## Remaining baseline failures

Every remaining failure is explained here.

| Test | Reason retained |
|---|---|
| proxy-api TestGetGatewayConfig.test_missing_file_returns_empty | Real repository YAML fallback violates the fixture's empty-dict expectation; unrelated config isolation deferred |
| TestPIIRedaction.test_ssn_detected | 123-45-6789 is intentionally excluded by the existing sample validator |
| TestCreditCardEdgeCases.test_dash_separated_card | Fixture 4111-2222-3333-4444 is checksum-invalid; valid dashed-format regression passes |
| TestCreditCardEdgeCases.test_space_separated_non_luhn_with_context | Explicitly expects a non-Luhn card to be accepted; validation retained |
| TestCreditCardEdgeCases.test_card_expiry_slash | Expects expiry date to be CREDIT_CARD; distinct expiry category not accepted this phase |
| TestCreditCardEdgeCases.test_cvv_after_keyword | Expects CVV to be CREDIT_CARD; standalone CVV outside scope |
| TestCreditCardEdgeCases.test_full_pci_payload_all_redacted | Invalid card plus unsupported short PCI values; not fixed by falsely expanding CREDIT_CARD |
| TestCreditCardEdgeCases.test_dash_card_with_cardholder_context | Checksum-invalid candidate remains rejected |
| TestCreditCardEdgeCases.test_mixed_pci_hipaa_prompt | Invalid card and 000-00-0000 plus unsupported short PCI fields |
| TestOverlapSuppression.test_ssn_dash_format_no_datetime | Uses excluded 123-45-6789; valid synthetic counterpart passes |
| TestOverlapSuppression.test_non_overlapping_entities_kept | Same excluded sample; email protection remains functional |

All scanner names refer to `presidio/tests/test_sovereign_safety.py`. None is a failing Phase 1 security case or new Phase 2 case. They remain visible pending explicit requirement/fixture decisions.

## Offline integration results

The required ten cases ran through actual gateway + actual Presidio/spaCy service + mocked provider. Fault cases deliberately alter the actual scanner response. Unsupported content is rejected before scanner/provider execution even when the actual scanner is available.

| Required case | Verified outcome |
|---|---|
| 1. Harmless prompt | allow; mocked provider receives original text |
| 2. Modern OpenAI project shape | API_KEY detected; critical block; neither provider receives the raw candidate |
| 3. JWT | JWT_TOKEN detected; warn; verified replacement; provider receives [REDACTED] |
| 4. PostgreSQL credential URI | DB_CONNECTION_STRING covers full URI; critical block; no egress |
| 5. AWS secret assignment | AWS_SECRET_KEY detected; critical block; no raw secret egress |
| 6. Internal hostname in tool description | warn/sanitize; descriptions and nested arrays replaced; harmless schema/name structure preserved |
| 7. Private key | Full PEM span remains critical; no provider call; scan preview removes body/END marker |
| 8. Image-only | 422 unsupported_dlp_content; scanner and provider remain uncalled |
| 9. Harmless tool schema | Provider called; tool structure unchanged |
| 10. Nested sanitization fault | Violation + null sanitized text injected into real-scanner response; 503; neither provider called |

Cases 1–5 and 7 additionally ran in both stream modes; nested/mode fault and unsupported tests separately cover both entry points. No external LLM request or credential-liveness request occurred.

## False-positive protections

- Prefix boundaries, bounded candidate lengths, exact Google/AWS shapes, and short/prefix-only negatives.
- JWT header/payload JSON checks and minimum segments rather than ordinary dotted text.
- Bearer/assignment labels rather than generic entropy.
- DB user:password@ requirement and complete URI span.
- Context required for otherwise indistinguishable AWS secrets/session values and generic opaque provider keys.
- RFC1918 octet validation and explicit internal suffixes; public domains/IPs do not trigger the corresponding private category.
- Possible phone lengths; Luhn cards; structural/sample SSN exclusions; distinct masked-ID category.
- Postal context, bounded street suffixes/PO boxes, explicit CSV name headers.
- Protected overlap coverage retained; date-like tails cannot remove SSN protection.
- Exact introduced placeholders ignored only when a finding is wholly contained; extending findings reject.
- Sensitive structural identifiers reject instead of unsafe renaming or sending invalid placeholders.

These controls have positive/negative unit evidence, not a measured precision/recall/FPR claim. spaCy, context heuristics, names, dates and address patterns can still produce false positives.

## Remaining known detection gaps

**PARTIALLY FIXED:** Credential detection is substantially broader but not complete.

- Unknown/opaque/unprefixed provider keys, future formats, unlabeled AWS secrets/session values, short/atypical JWTs, unusual encodings/escapes/obfuscation and fragmented secrets across leaves can escape shape rules.
- Signature/issuer/liveness validation is absent; candidate matches are not proof of active credentials.
- Structured opaque values with no distinguishable shape or qualifying assignment text may not be classified solely from their dictionary path.
- Numeric JSON scalar values are not stringified for PII detection; only textual leaves are in this phase's inspection scope.
- English NER and bounded address/postal/CSV rules are not universal language/geography/document coverage.
- Malformed/multiline CSV fields, unusual names/addresses and arbitrary organization confidential prose remain limited.
- Entity filters/confidence settings can intentionally narrow detection; default configuration is what the consistency tests verify.
- Protected field offsets are leaf-relative; no full UI tree highlighting/approval artifact was added.
- PDF/DOCX extraction does not inspect images or every document part.
- No response/output DLP, historical log cleanup/key rotation, user isolation, secret vault, TLS/deployment authorization overhaul, or academic benchmarking.
- The SDK's inherited cloud model-discovery namespace still has no corresponding local /v1/models route; local API docs now reflect the actual endpoints.

## Deferred Phase 3 work

**DEFERRED:** Decide remaining fixture/PCI requirements explicitly; broaden evaluated geography/language and encoded/fragmented-secret coverage; build labeled evaluation and reproducible baselines; address identity/key storage, transport/deployment/resource/retention controls; consider safe identifier pseudonyms and richer error/span attribution.

**NOT VERIFIED:** Live adapters/models, production deployment, dependency CVEs, quantitative accuracy, performance, or academic novelty.

Phase 2 closes the enumerated active-detector and supported-textual-field bypasses under the shared Phase 1 enforcement path. It does not establish full enterprise DLP or universal sensitive-data prevention.
