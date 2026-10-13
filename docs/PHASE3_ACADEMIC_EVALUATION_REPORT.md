# Phase 3 Academic Evaluation


Recorded local experiment started **2026-10-13T04:54:39.425102+00:00**. Dataset `synthetic-v1`, seed `20261013`, SHA-256 `f40f25979a6c328e660a47ebf45d6b7bb81a27a6c94cfd39229a99f6784f34bc`. Production source/policy hashes match the pre-result freeze. Phase 3 changes are isolated to `benchmarks/` and this report; no detector, application policy, SDK, frontend or regression test was changed.

## Research questions

RQ1: How accurately does the system detect protected sensitive data in LLM prompts?

RQ2: How effectively does sanitization remove sensitive information while preserving prompt utility?

RQ3: What runtime overhead does local DLP inspection introduce?

RQ4: How does the project compare with simpler baselines?

## Dataset

| Property | Recorded count |
| --- | --- |
| Total prompts | 1000 |
| Safe / sensitive | 400 / 600 |
| Development / test | 300 / 700 |
| Held-out test safe / sensitive | 280 / 420 |
| Ordinary safe / hard negatives (whole corpus) | 160 / 240 |
| Labeled spans (whole corpus / test) | 720 / 504 |

All values are authored synthetic/hypothetical fixtures: repeated SYNTHETIC key bodies, dummy PEM payloads, unsigned dummy JWT signatures, example-domain emails, documentation IPs, test-card/sample-IBAN shapes and fictional identity fields. No environment file, credential value, production record, external dataset, live secret-validation endpoint or external LLM is used. Structural PII validity does not establish that a number is unassigned; no linkage to a real person is asserted. `validate_dataset` verifies exact regeneration from this authored source and hashes; that provenance check is not a universal real-secret detector.

Sensitive records include 520 single-value records and 80 multi-value records, spanning short/prose/code/log/config/CSV/tool/schema/nested/markdown/JSON/long contexts. Twenty insertion/context families vary wording and structure; values vary by entity, and some repeat. The 400 safe records use 40 ordinary topic families and 60 hard-negative families, with four presentation variants each. This is a manageable template-based corpus, not 1,000 independent real-world scenarios.

| Category | Prompts |
| --- | --- |
| boundary | 26 |
| code | 52 |
| config | 26 |
| csv | 26 |
| hard_negative | 240 |
| json | 26 |
| log | 52 |
| long | 52 |
| markdown | 26 |
| multi_entity | 80 |
| nested | 26 |
| ordinary_safe | 160 |
| prose | 104 |
| schema | 26 |
| short | 52 |
| tool | 26 |

| Category | Dev prompts | Test prompts |
| --- | --- | --- |
| boundary | 0 | 26 |
| code | 26 | 26 |
| config | 26 | 0 |
| csv | 26 | 0 |
| hard_negative | 72 | 168 |
| json | 0 | 26 |
| log | 0 | 52 |
| long | 0 | 52 |
| markdown | 26 | 0 |
| multi_entity | 24 | 56 |
| nested | 0 | 26 |
| ordinary_safe | 48 | 112 |
| prose | 52 | 52 |
| schema | 0 | 26 |
| short | 0 | 52 |
| tool | 0 | 26 |

| Difficulty (all labels) | Prompts |
| --- | --- |
| easy | 264 |
| hard | 502 |
| medium | 234 |

Each sensitive span has type, Python Unicode character start/end (half-open), exact source text, difficulty and synthetic-source metadata. Easy means canonical/short; medium means embedded structured/prose contexts; hard means unusual boundaries, multi-value or longer/nested records. Safe difficulty is recorded but sensitive-only difficulty metrics are reported separately.

The split holds whole template/topic families together: 30% development and 70% test within each family stratum, with seed 20261013 and persisted IDs. Test content was frozen before detector observations, and recognizers were not tuned afterward. Developers authored the formats with detector knowledge; this is not a blind externally annotated holdout. Both splits share entity/value families, so leakage of familiar formats remains a threat.

Grouping entire context families means some structures (notably the single-value CSV/config families) occur only in development. Their presence in the corpus does not establish final-test coverage for those structures. The per-split category table makes this visible; no final-test result is substituted with a development score.

One canonical type is annotated per inserted value. Secondary nested labels, e.g. IP_ADDRESS inside PRIVATE_IP or LOCATION inside an address, may count as extra span predictions. This penalizes some taxonomically defensible overlaps. Partial assignment spans can also fail exact matching. The annotation policy was frozen, not revised to improve scores. Public/documentation names, dates, IPs and attack quotations are task-benign safe controls even when the current policy protects their shape; false positives in this group expose a policy/intent conflict.

## Metrics

Let TP, FP, FN, TN refer to the stated unit. Precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2TP/(2TP+FP+FN); FPR = FP/(FP+TN); FNR = FN/(FN+TP). Zero denominators are JSON null and reported as undefined/NOT VERIFIED; no artificially perfect defaults.

**Prompt-level:** sensitive if any gold protected entity exists; predicted sensitive if any configured protected finding exists. A wrong-type detection still classifies the prompt as sensitive. Processing errors emit no predictions, remain in denominators and count as FN on sensitive prompts; they are also reported separately, not described as safe forwarding.

**Headline span-level:** same entity type and exact start/end. Matching is maximum-cardinality one-to-one, not greedy or many-to-one. Unmatched predictions are FP and unmatched gold spans FN. **Secondary relaxed:** same type and intersection/gold-span length >=0.5, with the same one-to-one matching. A broad span can meet this rule, so it does not prove precise removal. Span TN/FPR are undefined: no finite natural universe of negative character spans was invented. Per-entity prompt occurrence has legitimate TN/FPR and is exported alongside strict/relaxed span metrics.

Entity confusion uses type-agnostic relaxed matching, prefers same-type candidates and retains MISSED/SPURIOUS counts. It distinguishes taxonomy disagreement from no overlapping detection; it is descriptive, not a replacement for strict scores.

Sanitization success = successful actually-sanitized sensitive prompts / actually-sanitized sensitive prompts, requiring full gold offset coverage by replacement spans, no exact gold substring in outgoing text and no protected post-rescan finding. Exact residual leakage is any surviving full gold substring. Denominators are reported for actually sanitized prompts and for ALL non-block sensitive outputs including detector misses. Full-value absence alone misses partial content; gold replacement coverage is reported separately. Block verification failure rate = failed no-provider/status checks / representative checked requests. Processing error rate excludes expected policy blocks.

Local latency is elapsed perf_counter_ns converted to milliseconds. Mean, median, min, max, population SD and linearly interpolated P95/P99 are computed over successful measurements; failures are counted and raw failure durations retained. Throughput = successful completions / timed batch wall seconds; error rate = failed attempts / total attempts. Structural preservation = ordered unchanged non-sensitive source characters aligned into output / non-sensitive source characters, with [REDACTED] removed from the alignment. It is not semantic utility.

## Baselines

Baseline A (`regex_simple`) is a small independent regex set for email, marked phone, card-shaped numbers, dotted IP, SSN shape, legacy sk keys and AKIA IDs. It imports no project recognizer patterns and has no checksum/NER/context/postprocessing. Baseline B (`presidio_builtin`) is a fresh installed AnalyzerEngine using the same NLP engine and confidence threshold 0.4, restricted to nine common protected built-in types: EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, PERSON, LOCATION, IP_ADDRESS, DATE_TIME and IBAN_CODE. It does not register project additions, custom SSN validation or project post-processing.

Unsupported custom labels are counted as misses in full-scope baseline scores because coverage is part of RQ4. `supported_label_strict_span` also provides a secondary within-supported-label score in metrics.json; do not present full-scope improvement as superiority of all common PII recognizers. No optional ablation was introduced. Project detection uses the actual /process analyzer and postprocessor with the frozen default 26-entity policy; no risk decisions are treated as ground-truth detections.

## Detection results

| Detector | Unit | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| regex_simple | prompt | 127 | 36 | 293 | 244 | 77.91% | 30.24% | 43.57% | 12.86% | 69.76% |
| regex_simple | strict_span | 113 | 64 | 391 | undefined | 63.84% | 22.42% | 33.19% | NOT VERIFIED / undefined | 77.58% |
| regex_simple | relaxed_span | 113 | 64 | 391 | undefined | 63.84% | 22.42% | 33.19% | NOT VERIFIED / undefined | 77.58% |
| presidio_builtin | prompt | 189 | 35 | 231 | 245 | 84.38% | 45.00% | 58.70% | 12.50% | 55.00% |
| presidio_builtin | strict_span | 175 | 101 | 329 | undefined | 63.41% | 34.72% | 44.87% | NOT VERIFIED / undefined | 65.28% |
| presidio_builtin | relaxed_span | 183 | 93 | 321 | undefined | 66.30% | 36.31% | 46.92% | NOT VERIFIED / undefined | 63.69% |
| project | prompt | 415 | 51 | 5 | 229 | 89.06% | 98.81% | 93.68% | 18.21% | 1.19% |
| project | strict_span | 479 | 109 | 25 | undefined | 81.46% | 95.04% | 87.73% | NOT VERIFIED / undefined | 4.96% |
| project | relaxed_span | 497 | 91 | 7 | undefined | 84.52% | 98.61% | 91.03% | NOT VERIFIED / undefined | 1.39% |

The project detects more protected categories on this frozen synthetic corpus. Its higher recall/F1 coexists with a higher prompt FPR than both baselines; this is an observed tradeoff, not a universal superiority claim. No confidence intervals or significance tests were computed; template clustering and small per-entity support limit inference.

## Per-entity results

| Type | Whole-corpus spans | Test spans | Strict P | Strict R | Strict F1 | Relaxed F1 | Prompt occurrence FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| API_KEY | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| AWS_ACCESS_KEY | 40 | 28 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| AWS_SECRET_KEY | 40 | 28 | 85.71% | 85.71% | 85.71% | 100.00% | 0.00% |
| AWS_SESSION_TOKEN | 20 | 14 | 85.71% | 85.71% | 85.71% | 100.00% | 0.00% |
| PRIVATE_KEY | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| GITHUB_TOKEN | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| SLACK_WEBHOOK | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| JWT_TOKEN | 20 | 14 | 100.00% | 92.86% | 96.30% | 96.30% | 0.00% |
| BEARER_TOKEN | 20 | 14 | 92.86% | 92.86% | 92.86% | 100.00% | 0.00% |
| DB_CONNECTION_STRING | 20 | 14 | 85.71% | 85.71% | 85.71% | 100.00% | 0.00% |
| GENERIC_SECRET_ASSIGNMENT | 20 | 14 | 54.55% | 85.71% | 66.67% | 77.78% | 1.17% |
| PRIVATE_IP | 20 | 14 | 100.00% | 92.86% | 96.30% | 96.30% | 0.00% |
| INTERNAL_HOSTNAME | 20 | 14 | 100.00% | 92.86% | 96.30% | 96.30% | 0.00% |
| EMAIL_ADDRESS | 40 | 28 | 77.78% | 100.00% | 87.50% | 87.50% | 1.19% |
| PHONE_NUMBER | 40 | 28 | 90.32% | 100.00% | 94.92% | 94.92% | 0.15% |
| US_SSN | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| MASKED_US_SSN | 40 | 28 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| CREDIT_CARD | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| PERSON | 40 | 28 | 58.54% | 85.71% | 69.57% | 75.36% | 2.08% |
| LOCATION | 40 | 28 | 59.09% | 92.86% | 72.22% | 72.22% | 2.53% |
| STREET_ADDRESS | 40 | 28 | 96.43% | 96.43% | 96.43% | 100.00% | 0.00% |
| POSTAL_CODE | 40 | 28 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| IP_ADDRESS | 20 | 14 | 43.75% | 100.00% | 60.87% | 60.87% | 2.62% |
| DATE_TIME | 40 | 28 | 58.54% | 85.71% | 69.57% | 81.16% | 1.64% |
| IBAN_CODE | 20 | 14 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| PROMPT_INJECTION | 20 | 14 | 63.64% | 100.00% | 77.78% | 77.78% | 1.17% |

## Difficulty results

| Sensitive difficulty | Test prompts | Prompt recall | Strict span F1 | Relaxed span F1 |
| --- | --- | --- | --- | --- |
| easy | 78 | 100.00% | 97.50% | 97.50% |
| medium | 130 | 96.92% | 87.12% | 94.70% |
| hard | 212 | 99.53% | 92.86% | 95.45% |

## Hard-negative results

| Detector | Safe subset | FP | TN | FPR |
| --- | --- | --- | --- | --- |
| regex_simple | ordinary | 0 | 112 | 0.00% |
| regex_simple | hard_negative | 36 | 132 | 21.43% |
| presidio_builtin | ordinary | 0 | 112 | 0.00% |
| presidio_builtin | hard_negative | 35 | 133 | 20.83% |
| project | ordinary | 0 | 112 | 0.00% |
| project | hard_negative | 51 | 117 | 30.36% |

A safe subset has no positive gold records: recall/FNR are undefined, not evidence of perfect detection. Prompt FPR and FP/TN counts are the meaningful statistics here. Check public names/dates/IPs and conceptual attack quotations separately from invalid key/card/phone negatives when interpreting the 51 project safe-prompt detections.

## Sanitization results

| Measurement | Observed value |
| --- | --- |
| sensitive_prompts | 420 |
| actually_sanitized_sensitive | 275 |
| sensitive_outgoing | 280 |
| sanitization_success_rate | 99.27% |
| residual_leakage_rate_sanitized | 0.00% |
| residual_leakage_rate_all_nonblock_sensitive | 1.79% |
| gold_span_replacement_coverage_rate | 99.27% |
| post_rescan_residual_prompts | 0 |
| mean_non_sensitive_char_preservation | 99.92% |
| block_subset_prompts | 20 |
| block_subset_requests | 40 |
| block_check_failures | 0 |

Zero full-value leakage among changed prompts does not establish zero egress leakage. Five missed sensitive prompts are allowed unchanged; two changed prompts have incomplete gold-span coverage even though the full original substring is absent and the same detector rescans clean. Exact-substring leakage is insensitive to partial/encoded/semantic remnants. Representative ASGI gateway block checks use the actual scanner and two mocked forwarders in both stream modes; safe false-positive controls are included. Three additional deliberate fault probes verify unsupported image, unavailable scanner and retained-value sanitization rejection, with no provider call.

## Information preservation

**PENDING HUMAN EVALUATION.** No human scores or external LLM ratings are invented. The template contains 150 deterministically selected synthetic original/sanitized pairs with exact spans, blank 1–5 task-understandability/information-preservation/meaning-damage fields, yes/no usability, rater ID and comments. Use two independent raters and retain disagreements. Automated character alignment, placeholder counts and conditional JSON validity are secondary structural measures; they cannot establish intended-task success or semantic preservation.

## Latency results

| Stage | Successful n | Errors | Mean ms | Median ms | P95 ms | P99 ms | Min ms | Max ms | SD ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| scanner_only | 195 | 0 | 23.831 | 7.569 | 78.451 | 83.135 | 3.199 | 156.426 | 28.868 |
| gateway_dlp | 195 | 0 | 40.330 | 14.905 | 157.656 | 167.529 | 4.014 | 187.902 | 51.528 |

| Stage | Size bucket | n | Mean ms | P95 ms |
| --- | --- | --- | --- | --- |
| scanner_only | large | 36 | 29.862 | 29.326 |
| scanner_only | medium | 51 | 7.513 | 9.441 |
| scanner_only | small | 72 | 5.262 | 7.772 |
| scanner_only | very_large | 36 | 78.056 | 83.020 |
| gateway_dlp | large | 36 | 44.473 | 55.830 |
| gateway_dlp | medium | 51 | 12.125 | 18.415 |
| gateway_dlp | small | 72 | 8.683 | 17.124 |
| gateway_dlp | very_large | 36 | 139.437 | 167.564 |

| Stage | Label | n | Mean ms | P95 ms |
| --- | --- | --- | --- | --- |
| scanner_only | safe | 51 | 5.763 | 8.279 |
| scanner_only | sensitive | 144 | 30.230 | 79.615 |
| gateway_dlp | safe | 51 | 6.169 | 8.685 |
| gateway_dlp | sensitive | 144 | 52.428 | 158.156 |

Warmup: 8 prompts per stage. Repetitions: 3. Fixed stratified subset: 65 prompts. Size buckets: <=100, 101–500, 501–2000, >=2001 characters. Some label/bucket combinations do not exist in this corpus; absent groups are not imputed. NLP-heavy/structured grouping is also exported. scanner_only: actual ProcessRequest validation + project /process analyze/postprocess, anonymize=False, direct in-process call. gateway_dlp: actual inspect_outbound_payload including scanner JSON serialization/contract/risk/conditional anonymization/rescan through MockTransport. Excludes app startup, HTTP server/middleware/TCP, provider calls and disk artifacts. Logging disabled. Errors excluded from successful latency statistics, raw failure durations retained.

## Throughput results

| Scanner workers | Completed | Errors | Error rate | Prompts/s | Queued P95 ms |
| --- | --- | --- | --- | --- | --- |
| 1 | 105 | 0 | 0.00% | 39.572 | 770.301 |
| 2 | 105 | 0 | 0.00% | 65.567 | 502.184 |
| 4 | 105 | 0 | 0.00% | 72.442 | 450.158 |
| 8 | 105 | 0 | 0.00% | 79.434 | 433.723 |

Each concurrency uses the same fixed 35-prompt subset and three repetitions, preceded by 2×worker-count warmup tasks. ThreadPoolExecutor; shared read-only analyzer/NLP engine and request-local state; no custom registry mutation. Each worker runs actual /process coroutine. No provider/network. Every completion is checked against its frozen serial type/span/score predictions; mismatch is an error. This comparison overhead is included in timings. Submission to finish (includes queue wait), finite closed batch; not steady-state arrival load. Submission and completion overhead are included in batch wall time; initialization/thread creation is excluded. Increased worker count can increase queued latency or reduce throughput on this CPU-bound workload. This measures a finite in-process batch, not TCP serving capacity or production scalability.

## Environment and reproducibility

| Property | Recorded value |
| --- | --- |
| os | Windows-11-10.0.26200-SP0 |
| python | 3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)] |
| cpu | AMD Ryzen 7 8845HS w/ Radeon 780M Graphics |
| logical_cpus | 16 |
| ram_bytes | 16437858304 |
| network | external TCP/DNS denied; in-memory transports only |

| Installed dependency/model | Version |
| --- | --- |
| en-core-web-lg | 3.8.0 |
| en-core-web-sm | NOT INSTALLED |
| fastapi | 0.115.14 |
| httpx | 0.27.2 |
| litellm | 1.56.10 |
| numpy | 2.5.3 |
| phonenumbers | 8.13.55 |
| presidio-analyzer | 2.2.362 |
| presidio-anonymizer | 2.2.364 |
| pydantic | 2.10.6 |
| pytest | 8.3.5 |
| spacy | 3.8.16 |

The evaluated NLP model is installed `en_core_web_lg` 3.8.0, selected by the actual AnalyzerEngine default. Dependency distribution versions are recorded, not newly installed or pinned by this phase. Source, corpus, split, benchmark-code and output hashes plus the complete installed-package version map are retained in `run_manifest.json`. Exact detector predictions and counters should reproduce in this environment; timing varies with OS background load, thermal state, thread scheduling and other hardware. Performance stages ran sequentially without overlapping application tests or other benchmark processes; unrelated OS load was not controlled.

Run `python -B -m benchmarks.scripts.run_all` from the repository root in the existing .venv. It archives an existing latest run before repeating. See `benchmarks/README.md` for individual commands, human-rating instructions and units. No external request is needed. Missing model/dependency/metric fails or is explicitly NOT VERIFIED. No heavy plotting dependency was added; matplotlib is not installed, so optional PNG charts were omitted.

## Error analysis

| Synthetic false-positive example | Predicted type | Record |
| --- | --- | --- |
| 1.2.3 | DATE_TIME | n-05-0 |
| 1.2.3 | DATE_TIME | n-05-1 |
| 1.2.3 | DATE_TIME | n-05-3 |
| 192.0.2.1 | IP_ADDRESS | n-07-0 |
| 192.0.2.1 | IP_ADDRESS | n-07-1 |
| 192.0.2.1 | IP_ADDRESS | n-07-2 |
| 192.0.2.1 | IP_ADDRESS | n-07-3 |
| January 15, 2025 | DATE_TIME | n-09-0 |
| January 15, 2025 | DATE_TIME | n-09-1 |
| January 15 | DATE_TIME | n-09-2 |

| Synthetic strict-span miss | Gold type | Record |
| --- | --- | --- |
| September 12, 1990 | DATE_TIME | m-05-1 |
| aws_secret_access_key=SYNTHETICHSYNTHETICHSYNTHETICHSYNTHETICH | AWS_SECRET_KEY | m-05-2 |
| eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzeW50aGV0aWMtOSIsInNjb3BlIjoiZHVtbXkifQ.SYNTHETICSIGNATUREONLY | JWT_TOKEN | s-jwt_token-09 |
| Bearer SYNTHETICKSYNTHETICKSYNTHETICKSY | BEARER_TOKEN | s-bearer_token-09 |
| postgresql://synthetic:dummy_pass_9@db.example.invalid:5432/demo | DB_CONNECTION_STRING | s-db_connection_string-09 |
| client_secret=synthetic_dummy_9 | GENERIC_SECRET_ASSIGNMENT | s-generic_secret_assignment-09 |
| 192.168.25.10 | PRIVATE_IP | s-private_ip-09 |
| db-9.corp | INTERNAL_HOSTNAME | s-internal_hostname-09 |
| 51 Willow Street | STREET_ADDRESS | s-street_address-09 |
| Priya Kapoor | PERSON | s-person-14 |

Strict-span misses include correct-type detections with punctuation/quote boundary extensions and genuine sensitivity misses. Prompt misses include trailing-period JWT/internal-hostname contexts and NER misses in terse JSON/markup. The five unchanged outputs are `s-jwt_token-09`, `s-internal_hostname-09`, `s-person-17`, `s-location-17`, and `s-location-19`. Partial-removal failures include `s-person-19` (surname survives) and `s-date_time-19` (leading day survives). Full false-positive/false-negative prompts and entity-confusion counts are inspectable in CSV/JSON. These findings are reported without changing production rules.

| Observed natural event | Count |
| --- | --- |
| scanner_processing_error | 0 |
| security_processing_error | 0 |
| unsupported_dlp_content | 0 |
| pii_policy_violation | 148 |
| sanitization_verification_failed | 0 |

Natural gateway processing-error rate: 0.00%. Expected policy blocks: 148; these are not accuracy-processing errors. Fault-probe outcomes are separate in block_effectiveness.csv. A zero natural error rate does not measure fault tolerance under arbitrary system failures.

An initial sanitization helper run failed while selecting a blocked safe record with no ground-truth spans. Its partial raw observations and failure description are preserved under `benchmarks/results/initial_helper_failure/`. Only evaluation selection/counting logic was fixed; the scanner, policy, labels and frozen detection results were unchanged. The completed sanitization run replaced no detector result. This is distinct from a production scanner failure.

The first valid throughput measurement is retained under `benchmarks/results/throughput_initial/`. The final run additionally compares every concurrent type/span/score output with its frozen serial prediction to check shared-engine stability; comparison overhead is included. Both timing runs remain inspectable, with no recognizer or corpus changes.

## Regression verification

| Suite | Passed | Failed | Skipped | Exit |
| --- | --- | --- | --- | --- |
| gateway | 321 | 1 | 0 | 1 |
| scanner | 224 | 10 | 0 | 1 |
| sdk | 20 | 0 | 0 | 0 |
| framework | 31 | 0 | 0 | 0 |
| TOTAL | 596 | 11 | 0 | — |

Phase 1 regression cases: 141 passed. Phase 2 cases: 276 passed. No existing test was edited, skipped, xfailed or deleted. Application-only totals remain 565 passed / 11 failed / 0 skipped; framework tests are additional. Full test logs, exact pytest arguments and node IDs are retained.

| Suite | Every remaining failure | Reason |
| --- | --- | --- |
| gateway | tests/test_config.py::TestGetGatewayConfig::test_missing_file_returns_empty | Existing config fallback returns repository YAML; test expects empty without isolating fallback. |
| scanner | tests/test_sovereign_safety.py::TestPIIRedaction::test_ssn_detected | Known sample 123-45-6789 is deliberately excluded by Presidio; invalid benchmark expectation. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_dash_separated_card | Checksum-invalid card fixture; Luhn validation intentionally retained. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_space_separated_non_luhn_with_context | Checksum-invalid card fixture; Luhn validation intentionally retained. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_card_expiry_slash | Expiry/CVV expected as CREDIT_CARD; separate unsupported PCI category. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_cvv_after_keyword | Expiry/CVV expected as CREDIT_CARD; separate unsupported PCI category. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_full_pci_payload_all_redacted | Mixed checksum-invalid card, unsupported expiry/CVV and/or invalid SSN fixtures. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_dash_card_with_cardholder_context | Checksum-invalid card fixture; Luhn validation intentionally retained. |
| scanner | tests/test_sovereign_safety.py::TestCreditCardEdgeCases::test_mixed_pci_hipaa_prompt | Mixed checksum-invalid card, unsupported expiry/CVV and/or invalid SSN fixtures. |
| scanner | tests/test_sovereign_safety.py::TestOverlapSuppression::test_ssn_dash_format_no_datetime | Known sample 123-45-6789 is deliberately excluded by Presidio; invalid benchmark expectation. |
| scanner | tests/test_sovereign_safety.py::TestOverlapSuppression::test_non_overlapping_entities_kept | Known sample 123-45-6789 is deliberately excluded by Presidio; invalid benchmark expectation. |

## Limitations

This evaluation does not establish live credential validity, general multilingual/organization confidentiality accuracy, every provider-forwarded field, attachment/OCR coverage, fragmented/encoded secrets, numeric JSON PII, output DLP, production traffic behavior, networking overhead or external LLM latency. Tool/schema records are text renderings, while real nested-field enforcement remains covered by Phase 2 regressions. Exact-value leakage does not detect every partial remnant. Only a representative block subset was checked at actual gateway routes. No semantic score exists before human ratings. Per-entity support is small, and the canonical taxonomy can over-penalize legitimate secondary labels.

## Threats to validity

- **Synthetic/template bias:** Repeated value/context families differ from natural traffic and can favor deterministic patterns. Synthetic key body artifacts can also confuse NER.
- **Detector-aware construction:** Categories and formats were authored with knowledge of supported rules; freezing and a family split prevent tuning this run but do not eliminate design bias.
- **Annotation/policy bias:** One canonical label per insertion and benign public-control labels can count valid protected-shape detections as false positives. No independent annotation adjudication occurred.
- **English-heavy data:** NLP contexts and addresses predominantly English; no claim across languages/geographies.
- **No live secret validation:** Shapes are not evidence of issued/usable credentials or identifiers.
- **Hardware dependence:** One laptop CPU/environment, finite threaded in-process batches, uncontrollable background load, no steady-state/production network study.
- **Limited human evaluation:** Ratings pending; automated preservation does not measure semantics.
- **No production traffic or external LLM latency:** Provider boundary is mocked; accuracy and latency apply only to this corpus and local inspection.
- **Statistical uncertainty:** No confidence intervals/significance tests; correlated templates and small entity counts restrict generalization.

## Changed and created files

All Phase 3 files are listed in `benchmarks/results/latest/phase3_changed_files.txt`, with hash provenance in `run_manifest.json`. They consist of benchmark dataset/splits/freeze metadata, isolated scripts, framework tests, reproducibility README, raw JSON/CSV/test logs, the retained failed-helper observations and this generated report. Pre-existing Phase 1/2 working-tree edits remain uncommitted and preserved.

## Conclusions

RQ1: On this frozen synthetic holdout, the project has high prompt recall but measurable hard-negative false positives and lower exact-span accuracy. RQ2: Actually changed outputs remove complete labeled values in this run, yet missed prompts leak unchanged values and two changed outputs retain partial span content; utility ratings remain pending. RQ3: Local inspection overhead and finite-batch throughput are measured for this environment, with server/network/provider latency excluded. RQ4: The custom integration has higher full-scope recall/F1 than the chosen simpler baselines on this corpus, with a higher prompt FPR; no universal PII superiority, novelty or production-readiness claim follows.

**VERIFIED:** Frozen corpus, machine-readable detection/span/sanitization/performance outputs, baseline comparison and preservation of existing security regressions. **PENDING HUMAN EVALUATION:** Intent/utility ratings. **NOT VERIFIED:** Deployment scalability, live adapters/credential validity, real-world generalization, statistical significance and semantic preservation.
