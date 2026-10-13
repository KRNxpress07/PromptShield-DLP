# Presentation Dashboard Handoff

**Date:** 13 October 2026 (Asia/Calcutta)

**Repository:** `C:\CNS\PromptShield-DLP`

**Scope:** Static research dashboard redesign, an isolated read-only local host, frontend state checks and endpoint tests.

## UI redesign summary

The former single scanner page is now a seven-section research console with a fixed desktop navigation rail, restrained dark surfaces, thin borders, electric cyan accents, muted blue comparison data, amber warnings and conspicuous red critical states. Typography uses local system fonts and monospace numerical/code treatment. No external fonts, chart CDN, frontend framework, package installation, stock images or large diagram dependency was added.

The layout targets 1920×1080 presentations and 1366×768 laptops. Responsive rules reduce metric columns, stack scanner panels, turn entity rows into cards on narrow screens and wrap long values. Presentation mode enlarges core numbers and chart text, removes navigation indexes and hides gateway configuration controls. It is browser-only state and does not change a policy or request permission.

**IMPLEMENTED / LOGIC VERIFIED:** Sections, dynamic metrics, chart generation, navigation, presentation state, scanner event/payload logic, endpoint data validation and escaped output.

**NOT VERIFIED:** Actual browser rendering at the target viewport sizes, screenshot fidelity, browser interactions, clipboard behavior and a real browser-to-gateway demo. Computer-use reported no available browser in its inventory; explicit Chrome and in-app-browser creation attempts both returned “Browser is not available.” No native automation workaround or external browser dependency was introduced. No screenshots are supplied. This limitation does not represent a claimed visual pass.

## Open the dashboard

```powershell
cd C:\CNS\PromptShield-DLP
& '.\.venv\Scripts\python.exe' -B frontend/server.py
```

Open **http://127.0.0.1:8787**. The loopback host was started and its actual HTTP summary/assets were checked in this sprint. Port 8080 could not bind in this Windows environment (`WinError 10013`); default port 8787 works. `--port 8788` is available if the default is occupied.

The live gateway remains separate at the configurable URL, default `http://localhost:8000`. Start the gateway/scanner with the existing project workflow, then enter the gateway authentication key, provider and model under **Live scanner → Gateway connection**. This dashboard host does not start the DLP services or use provider credentials.

Direct `file://` viewing cannot load the summary endpoint. Use the local HTTP host. Docker packaging and production/multi-user deployment of the additional host are outside this sprint.

## Frontend sections added

| Section | Content |
|---|---|
| Overview | PromptShield hero, local/default-scope chips, frozen-corpus count, ten headline metrics, conceptual inspection pipeline, baseline F1, explicit missed-output and pending-human notes |
| Live scanner | Text/file input, gateway/provider/model configuration, loading/error/stale states, server risk/action/findings, sanitized or scanned-text preview, authorized forwarding, formatted assistant text/code and code-copy control |
| Benchmarks | Safe/sensitive and dev/test counts, baseline precision/recall/F1/FPR, sensitive-only difficulty breakdown, ordinary-safe vs hard-negative FPR, actual benign false-positive fragments |
| Detection | Filterable/sortable 26-entity strict-span table, relaxed F1, prompt-occurrence FPR, exact test support, per-entity F1 bars, explicit quality ranges and taxonomy limits |
| Sanitization | Success, gold replacement coverage, both exact-leakage denominators, post-rescan residual count, character preservation, actual synthetic before/after pair, action counts and blank human-evaluation status |
| Performance | Scanner/gateway mean/median/P95/P99, mean/P95 input-size comparisons, zero-based throughput and queued-P95 SVG charts, exact worker counts/completions/error rates and local-only measurement boundary |
| Methodology | Corpus/split, prompt vs typed-span units, matching rule, formulas, source-faithful architecture, grouped protected types, historical Phase 3 regression evidence and artifact provenance |

All comparison bars use zero-to-100% axes for proportions. Latency axes start at zero and use a shared maximum across the two stages for a selected size statistic. SVG charts use zero-based vertical axes and worker positions proportional to the actual 1/2/4/8 counts. Values are printed and also appear in bar/point titles. The project’s worse FPR is drawn red alongside its higher recall/F1; it is not hidden or renamed “accuracy.”

F1 indicators use Excellent ≥95%, Strong ≥90%, Moderate ≥75%, and Needs improvement <75%, with distinct cyan/blue/amber/red states. They describe benchmark F1, not a security guarantee. Weak entities appear first by default, and all rows can be sorted by any metric/support or filtered.

The conceptual pipeline notes that blocks stop before forwarding. The detailed architecture puts the actual scanner before risk assessment and explains that the first service pass combines detection/replacement; non-block changed outputs then get the existing verification pass. It does not present a block as reaching LiteLLM.

## Benchmark data source

No values were invented, hardcoded as benchmark scores, re-evaluated or rewritten. The frontend fetches controlled JSON from the dashboard host on load and explicit reload. The host reads these literal Phase 3 artifacts:

- `benchmarks/results/latest/metrics.json`: recorded detector metrics, subsets/difficulty, sanitization, latency aggregates, throughput and historical test counts.
- `benchmarks/results/latest/per_entity_metrics.csv`: project strict/relaxed/prompt-occurrence statistics.
- `benchmarks/results/latest/false_positives.csv`: selected actual benign matched fragments, restricted to public examples such as version/documentation-IP/date text.
- `benchmarks/results/latest/sanitization_results.csv`: one narrowly validated synthetic example-domain email record and its actual replacement output.

The source corpus remains **1,000 prompts**, **400 safe / 600 sensitive**, **300 development / 700 test**. The displayed headline measurements come from the existing test run: prompt precision 89.06%, recall 98.81%, F1 93.68%, FPR 18.21%, strict span F1 87.73%; the underlying JSON floats are preserved. Rates and units remain labeled precisely.

Sanitization displays **0% full-value survival among actually changed sensitive prompts** separately from **1.79% exact-value survival across all non-block sensitive outputs**. Five misses allowed unchanged and two incomplete span removals are called out. Full-value absence and a clean same-detector rescan are not described as universal zero leakage.

Human evaluation remains **PENDING HUMAN EVALUATION**, with the recorded 150 prepared pairs, two independent raters recommended and no fabricated scores. Character preservation is explicitly structural, not semantic utility. Performance is local in-process inspection, excluding startup/TCP/server middleware/provider latency; finite threaded batches do not establish production scalability.

When primary data is missing or cannot be validated, the dashboard shows **Not available**, a visible source-error notice and a reload control. Missing optional CSVs leave their sections unavailable with a warning. Benchmark availability does not disable the independent live-scanner workflow.

## Read-only endpoint and hosting

**Added:** `GET http://127.0.0.1:8787/v1/benchmark/summary` in `frontend/server.py`.

This is an independent, loopback-only FastAPI host using existing installed dependencies. It imports no gateway, DLP, recognizer, risk engine, SDK or benchmark module. It serves only the named index/CSS/two-JS/favicon assets. The summary endpoint accepts no query parameters and no write methods. It has no arbitrary file, report, download, environment, directory-listing or DLP-processing route.

The response projects finite nonnegative numbers, 0–1 rates, known detector/entity/group labels, bounded provenance timestamps/checksums and carefully checked synthetic/benign fragments. It excludes raw prompts, credential values, complete CSVs, predictions, environment metadata, source paths, tracebacks, manifests and arbitrary unknown fields. File reads are restricted to four literal artifact names and bounded to 5 MB each. Missing/malformed primary data returns controlled 503 JSON without source contents or paths. Optional absent CSVs yield a partial summary with explicit warnings.

Headers disable caching, forbid MIME sniffing, suppress referrers and apply a local-script CSP with no objects/frames or remote font/script dependency. The connect policy allows an operator-selected HTTP(S) gateway because gateway CORS/provider behavior remains unchanged. This host is intended for the local academic console, not an authenticated public research service.

**No gateway endpoint or gateway source file was modified.** Adding a router to the gateway would change the Phase 3 source freeze. Isolating the view/summary host preserves both the unchanged DLP execution path and the existing benchmark-framework provenance checks.

## Scanner functionality and policy semantics

The UI preserves `/v1/scan`, `/v1/documents/scan`, `/v1/chat/completions`, text input, supported file uploads, provider/model settings, finding spans/confidence, policy score/level/action, preview, forwarding and assistant rendering.

- The gateway key is password-masked and not persisted in local storage, cookies or a generated artifact.
- Changing text, selected file or connection settings invalidates prior assessments. A result returned after an edit cannot become current; stale send handlers cannot forward.
- Analyze sends only to the existing local DLP scan/document route. It does not call an LLM.
- BLOCK has no send action. MASK/WARN offers sanitized text only. The old “Send anyway” control was removed because the server never authorizes an unredacted warning override.
- ALLOW submits scanned prompt text, or the returned extracted text for a document. No uploaded binary file is forwarded to an LLM.
- Every forwarded request still passes through the existing server inspection path. The frontend does not grant an authorization token or alter backend policy.
- Missing/malformed scan responses and timeouts remove forwarding controls. API rejection is distinguished from a connection failure.
- Findings, reasons, file names, preview and assistant text/code are escaped; assistant response markup is not executed. Code fences, prose, lists, inline formatting and code-copy controls remain available.

The obsolete 35/65 gauge thresholds are gone. The displayed heuristic bands match `risk.py`: none=0, low=1–49, medium=50–69, high=70–89, critical≥90. The server’s action is authoritative: injection or a configured severity floor may require a stricter action. The label explicitly says **Policy risk score — deterministic heuristic**, not a calibrated probability.

## Files changed / created

| File | Change |
|---|---|
| `frontend/index.html` | Replace former scanner-only page with accessible seven-view dashboard and redesigned scanner |
| `frontend/styles.css` | Local dark design system, responsive layouts, charts, scanner, presentation and print treatment |
| `frontend/dashboard.js` | Summary loading, honest metric formatting, SVG/CSS charts, sorting/filtering, navigation/presentation state |
| `frontend/scanner.js` | Existing API workflow, result validation/staleness, server-authoritative actions, safe previews and assistant rendering |
| `frontend/favicon.svg` | Small local icon asset |
| `frontend/server.py` | Isolated loopback host and controlled read-only summary projection |
| `frontend/README.md` | Startup, source, boundaries, verification and limitations |
| `frontend/tests/test_ui_state.js` | Ten dependency-free event/payload/data-state tests using a minimal DOM double |
| `frontend/tests/run_validation.py` | Offline suite/syntax/state/hash validation, separate new test record |
| `proxy-api/tests/test_benchmark_dashboard.py` | 34 endpoint/static-host cases without altering existing regressions |
| `docs/PRESENTATION_DASHBOARD_TEST_RESULTS.json` | New exact test totals, failure IDs/arguments, state-test output and protected-artifact verification |
| `docs/PRESENTATION_DASHBOARD_REPORT.md` | This handoff |

Pre-existing Phase 1/2/3 working-tree edits remain uncommitted. The authorized frontend redesign replaces the former pre-existing page while retaining its functional workflows. No recognizer, `risk.py`, `dlp.py`, `egress.py`, application policy, gateway/scanner/SDK source, benchmark corpus, result, script or existing regression file was edited by this sprint.

## Tests and verification

All complete Python suites ran in separate processes with credentials removed, dotenv loading disabled and the existing external socket/DNS guard. The new runner writes only its own dashboard test record; it does not use the Phase 3 result-writing runner.

| Suite | Passed | Failed | Skipped | Total |
|---|---:|---:|---:|---:|
| Gateway, including 34 new dashboard cases | 355 | 1 | 0 | 356 |
| Scanner | 224 | 10 | 0 | 234 |
| SDK | 20 | 0 | 0 | 20 |
| Benchmark framework | 31 | 0 | 0 | 31 |
| **Python total** | **630** | **11** | **0** | **641** |
| Additional JavaScript state cases | 10 | 0 | 0 | 10 |
| **Combined tests** | **640** | **11** | **0** | **651** |

All **141 Phase 1** and **276 Phase 2** cases pass. Existing regression files remain unchanged; no failures were skipped, xfailed, suppressed or deleted. There are no new test failures.

The 34 new cases cover valid real metrics/CSV projection, missing/malformed/oversized artifacts, invalid numeric values including booleans/NaN/infinity, unknown secret/environment fields, poisoned raw examples, parameter/path traversal attempts, write-method rejection, absent optional CSVs and static asset/security headers.

Ten Node state cases cover MASK sanitized payload and escaped assistant markup, WARN without a raw override, BLOCK without send controls, edits invalidating earlier assessments, malformed responses, edits during pending scans, file upload/text-only forwarding, unavailable benchmark data, navigation/presentation state and actual recorded metrics/leakage-denominator display. They use an event-driven DOM test double and mocked fetch. **They are not browser or layout E2E tests.**

Additional checks pass: `node --check` for both JavaScript files, HTML unique IDs/local script references/no inline handlers, actual loopback HTTP summary, Python syntax, whitespace and `git diff --check`. No provider call, dependency/model installation or benchmark re-run was made. Protected backend/benchmark hashes match the Phase 3 freeze and manifest. Final verification also confirmed that all 117 files in the pre-sprint backend/benchmark/regression snapshot retained outside the repository are byte-for-byte unchanged.

### Remaining pre-existing failures

All scanner failures are in `presidio/tests/test_sovereign_safety.py`. These are the unchanged Phase 2/3 failures, not dashboard failures:

| Test | Existing reason |
|---|---|
| Gateway `TestGetGatewayConfig.test_missing_file_returns_empty` | Repository YAML fallback versus empty-config expectation/isolation mismatch |
| `TestPIIRedaction.test_ssn_detected` | Deliberately excluded sample `123-45-6789` |
| `TestCreditCardEdgeCases.test_dash_separated_card` | Checksum-invalid card fixture |
| `TestCreditCardEdgeCases.test_space_separated_non_luhn_with_context` | Explicitly expects checksum-invalid card acceptance |
| `TestCreditCardEdgeCases.test_card_expiry_slash` | Expiry expected as CREDIT_CARD; unsupported distinct PCI field |
| `TestCreditCardEdgeCases.test_cvv_after_keyword` | CVV expected as CREDIT_CARD; unsupported distinct PCI field |
| `TestCreditCardEdgeCases.test_full_pci_payload_all_redacted` | Invalid card plus unsupported CVV/expiry expectations |
| `TestCreditCardEdgeCases.test_dash_card_with_cardholder_context` | Checksum-invalid card fixture |
| `TestCreditCardEdgeCases.test_mixed_pci_hipaa_prompt` | Invalid card/SSN and unsupported short PCI expectations |
| `TestOverlapSuppression.test_ssn_dash_format_no_datetime` | Deliberately excluded sample SSN |
| `TestOverlapSuppression.test_non_overlapping_entities_kept` | Deliberately excluded sample SSN |

Exact pytest arguments and full failing node IDs are in `PRESENTATION_DASHBOARD_TEST_RESULTS.json`. The original triage remains `PHASE2_BASELINE_TEST_TRIAGE.md`.

## Unresolved UI limitations

- **NOT VERIFIED:** Browser rendering, viewport screenshots, real browser-to-gateway scanning/forwarding and clipboard integration because no browser is enabled in the available computer-use tool. Review the local URL before a faculty presentation.
- Presentation mode is a per-page frontend state; no persistence, fullscreen permission flow or export system is added.
- The read-only endpoint uses the artifact directory structure of this checkout. Missing files do not fabricate results; they produce unavailable sections. An independently deployed static-only copy needs this host or a separately supplied controlled summary endpoint.
- Per-entity support/taxonomy, synthetic/template bias, development-only CSV/config families, partial leakage and human-evaluation limits remain the unchanged Phase 3 methodological limits.
- The live scanner preserves existing text extraction limits; it adds no OCR, output DLP, provider/key-management product or new detector.
- No live provider integration, production deployment, public hosting, auth redesign or production readiness is verified by this sprint.

The footer keeps the required research disclaimer visible: **Academic prototype evaluated on a frozen synthetic dataset. Results do not establish production readiness, live credential validity, universal DLP coverage, or real-world generalization.**
