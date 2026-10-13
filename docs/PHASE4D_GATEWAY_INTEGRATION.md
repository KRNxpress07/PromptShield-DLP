# Phase 4D — Gateway behavioral injection preflight

Phase 4D integrates the Phase 4A virtual tools, Phase 4B local-model executor,
and Phase 4C heuristic risk assessment before provider egress. The feature is
**off by default**. Existing deployments acquire no local-model calls, model
latency, verdict metadata, or enforcement unless they explicitly enable it.

Behavioral sandbox results are heuristic local-model evidence. They are not
proof of malicious intent or universal injection detection. Real local-model
generation remains **NOT VERIFIED**; no operational Ollama detection or real
accuracy claim is made by this phase.

## Layered architecture and execution order

The existing static `PROMPT_INJECTION` recognizer remains the inexpensive
first layer, alongside Presidio PII/secret scanning and static risk policy.
Behavioral preflight is an additional layer, not a replacement.

After existing authentication/provider/credential resolution, the request path
is:

1. Phase 2 egress traversal validates supported payload structure and inventories
   every permitted textual leaf and relevant dictionary key.
2. Existing Presidio scanning and static DLP risk/policy assessment run.
3. Static BLOCK returns the existing DLP 422 response immediately. Neither the
   local model nor either provider forwarding function is called.
4. Required sanitization and residual verification complete. Unsupported
   content, scanner faults, unusable sanitization, residual findings, and
   unsafe protocol/key changes retain existing fail-closed behavior.
5. Behavioral preflight inventories the **final provider-bound sanitized
   payload**, applies its input/capacity bounds, and runs the local adapter in
   a fresh synthetic sandbox session.
6. Phase 4C scores the structured execution evidence. Gateway-only policy
   composition decides whether forwarding may continue.
7. Only after approval does non-streaming provider execution or provider
   stream acquisition begin.

`app/dlp.py`, `app/risk.py`, provider forwarding, scanner recognizers, request
models, and SDK source are unchanged. `app/egress.py` moves its existing walker
into shared `provider_text_inventory`; it retains the same allowlist,
validation, budgets, protocol exclusions, reconstruction, and DLP semantics.
Both DLP and behavioral preprocessing use this single inventory.

## Integration modules and lifecycle

- `behavior_runtime/gateway_config.py`: strict, frozen, literal configuration.
- `behavior_runtime/gateway.py`: canonical input, adapter/runtime management,
  bounded admission, policy mapping, minimal safe metadata, and telemetry.
- `app/config.py`: optional behavioral policy lookup and literal handling of
  its YAML section; existing provider environment resolution is retained.
- `app/main.py`: validates policy and creates one shared runtime at startup;
  shutdown closes its thread pool and the existing HTTP client.
- `app/routers/proxy.py`: calls preflight after static approval, returns
  controlled errors, and adds optional safe success metadata.

The production runtime constructs one trusted configured Ollama adapter per
application lifespan, not a model/download/service per request. Enabled
evaluations use a bounded worker pool; each worker invocation creates a new
executor/sandbox session. No verdict cache exists. Tests inject a trusted
`adapter_factory` returning a new `FakeLocalModelAdapter` per request, avoiding
cross-request script state and all real inference.

## Modes and policy mapping

| Mode | Behavior |
| --- | --- |
| `off` | No executor, adapter construction, worker submission, or canonical input; old forwarding behavior and successful response contract remain |
| `audit` | Run and record preflight; behavioral findings/failures cannot block forwarding; static DLP remains authoritative |
| `enforce` | Apply configured behavioral threshold and failure policy before either provider call |

The default threshold is `HIGH`: LOW, ELEVATED, and SUSPICIOUS continue; HIGH
and CRITICAL return HTTP 422 `behavioral_injection_blocked`. The threshold can
be any Phase 4C severity, without changing its definitions or numeric score.
Scores are not combined with static DLP risk. Existing `risk_score` and
`policy_action` remain static; optional `behavioral.score` and severity are a
separate assessment. Final forwarding is policy composition, not a blended
probability. Neither layer can override a stronger static block or a failed
sanitization/residual check into forwarding.

## Configuration

The user-owned `config/gateway.yaml` is not overwritten. A merge-only example
is provided in `config/gateway.behavioral.example.yaml`. Preserve your existing
gateway authentication, provider credentials, and DLP section when merging.
The section is absent by default, which selects off mode.

```yaml
behavioral_injection:
  mode: audit
  provider: ollama
  model: llama3.2:1b
  base_url: http://127.0.0.1:11434
  timeout_seconds: 10
  block_severity: HIGH
  fail_closed_on_not_evaluated: true
  fail_closed_on_partial: false
  max_steps: 12
  max_model_calls: 12
  max_tool_calls: 16
  max_behavior_input_chars: 12000
  max_concurrent: 2
  max_queue: 16
  queue_timeout_seconds: 2
```

Write `mode: "off"` with quotes: PyYAML's YAML 1.1 parser otherwise treats
unquoted `off` as a boolean, and strict mode validation rejects it. All fields
are checked at startup, including fields in an off-mode section. Unknown
fields/modes/severities, cloud providers, remote/ambiguous URLs, credentials,
invalid/bool quotas, non-finite or out-of-range timeouts, and an absent/empty
model in enabled modes are rejected with a controlled configuration error.

| Field | Default | Accepted bounds |
| --- | --- | --- |
| mode | off | off/audit/enforce |
| provider | ollama | ollama only; fake is trusted test injection |
| model | null | Explicit valid installed model name required when enabled |
| base_url | http://127.0.0.1:11434 | Phase 4B loopback HTTP validation |
| timeout_seconds | 10 | Greater than 0, at most 10 |
| block_severity | HIGH | LOW/ELEVATED/SUSPICIOUS/HIGH/CRITICAL |
| fail_closed_on_not_evaluated | true | Strict boolean |
| fail_closed_on_partial | false | Strict boolean |
| max_steps / max_model_calls | 12 / 12 | 1–64 each |
| max_tool_calls | 16 | 1–128 |
| max_output_chars | 8192 | 1–65536 |
| max_total_transcript_chars | 65536 | 1024–262144 |
| max_response_chars | 32768 | 256–262144 |
| max_behavior_input_chars | 12000 | 1–65536; must not exceed transcript budget |
| max_concurrent | 2 | 1–16 |
| max_queue | 16 | 0–128 additional pending requests |
| queue_timeout_seconds | 2 | Greater than 0, at most 10 |

Behavioral fields are literal YAML: `${ENV_VAR}` is not expanded in this
section. No cloud credentials or environment keys are discovered by the
behavioral layer. Existing gateway provider credential resolution remains
unchanged. Configuration is fixed for a runtime lifespan; restart using your
normal deployment workflow after changing it.

## Canonical behavioral input

`canonical_input` calls the shared Phase 2 `provider_text_inventory` on the
final outbound payload. It creates sorted, compact ASCII JSON:

```json
{"format":"provider-text-v1","leaves":[{"kind":"value","path":["messages",0,"content"],"text":"Sanitized content"}]}
```

Paths, explicit key/value kind, and JSON escaping preserve structure without
ambiguous concatenation. The source walker covers message text/parts/names,
tools/functions and nested schemas/examples/property keys, response formats,
stop strings, user-controlled model fields and the other existing allowed
textual parameters/headers. Its validated role/type constants and trusted
server-default model exclusion are retained. Unknown forwarding parameters
and server-owned credentials are not added to a second independent inventory.
Canonical ordering is independent of dictionary insertion order; list indexes
retain message/array positions. This is a representation of inventoried text,
not a reconstruction of a target model's full message protocol.

The size bound includes JSON structure, paths, labels and escaping. An initial
text-size check avoids encoding oversized textual inputs; incremental encoding
checks the entire canonical representation. No oversized input is silently
truncated or partially evaluated. Oversize produces NOT_EVALUATED with
`BEHAVIOR_INPUT_TOO_LARGE` / `input_too_large`; audit can continue with existing
static approval, enforce applies `fail_closed_on_not_evaluated`.

## Failure and partial-evidence semantics

- Enforce + NOT_EVALUATED defaults to HTTP 503
  `behavioral_security_unavailable`, without provider execution. Explicitly
  setting `fail_closed_on_not_evaluated=false` permits static-approved
  forwarding for such failures, with NOT_EVALUATED metadata.
- Adapter unavailable/error before usable evidence, unexpected disabled
  execution, preprocessing faults, and missing runtime cannot manufacture a
  LOW score. They retain failed assessments and controlled reasons.
- PARTIAL evidence is scored normally by default: HIGH/CRITICAL block;
  below-threshold findings continue with completeness/reasons visible.
- `fail_closed_on_partial=true` rejects any remaining below-threshold PARTIAL
  result with the controlled 503 error. Threshold blocks take precedence and
  remain 422 even if the evidence is partial.
- Capacity/queue failures always return the controlled 503 in enforce mode,
  including when general NOT_EVALUATED fail-closed is explicitly disabled.
  Audit records capacity unavailability and continues.

No exception text, connection URL/details, stack trace, local system policy,
tool argument, transcript, raw assistant output, marker value/ID, or virtual
filesystem path is included in new gateway errors. Their flat `error`/`message`
shape follows the existing gateway contract:

```json
{
  "error": "behavioral_injection_blocked",
  "message": "Request blocked by behavioral prompt-injection policy.",
  "behavioral": {
    "score": 100,
    "severity": "CRITICAL",
    "verdict": "CRITICAL_BEHAVIOR",
    "reasons": ["PROTECTED_READ_ATTEMPT", "NETWORK_ATTEMPT"],
    "completeness": "COMPLETE",
    "assessment_version": "behavior-risk-v1"
  }
}
```

NOT_EVALUATED metadata has null score/severity and FAILED completeness. The
503 message is fixed: “Behavioral prompt-injection analysis could not be
completed.” SDK tests verify both new errors remain compatible generic
`AISGError` responses with status/body retained. Existing typed DLP errors
and SDK source/parsing are unchanged.

## Streaming and successful response compatibility

Preflight completes before `forward_chat_completion_stream` is invoked, not
after the first provider chunk. Behavioral blocks/failures return ordinary
JSON errors before any SSE response or upstream stream opens. OFF responses
and headers remain unchanged. Enabled non-streaming success adds only
`aisg_metadata.behavioral` (the six safe assessment fields above) and separate
`aisg_metadata.behavioral_duration_ms`. SDK successful parsing ignores these
additive fields safely. Streaming chunk/headers are preserved; its behavioral
metadata/latency remain internal telemetry rather than new SSE content.

## Bounded concurrency and cancellation

One semaphore and fixed-size thread pool per application lifespan cap active
local evaluations. Admission counts both active and waiting requests, limiting
their total to `max_concurrent + max_queue`; excess requests receive immediate
capacity unavailability instead of building an unbounded executor backlog.
Admitted requests wait only `queue_timeout_seconds` for a worker slot.
Timed-out or cancelled waiting requests release admission accounting.

Synchronous inference runs off the ASGI event loop. If a client cancels after
worker submission, the protected future retains its slot until the worker
actually finishes. Cancellation cannot allow another worker beyond the configured
limit. Each evaluation has fresh virtual state. There is no cross-request cache.
Limits are per gateway process, not a distributed/global Ollama capacity limit;
multiple gateway workers multiply total capacity.

Known HTTP operations retain Phase 4B timeouts, bounded responses, strict
installed-local-model checks, no environment proxies/authentication, no redirects,
no auto-start/pull/download, and no cloud fallback. A custom trusted Python
adapter can still hang; no process watchdog or absolute whole-preflight deadline
is introduced. Shutdown stops admission and queued work without forcibly killing
an in-progress synchronous worker. Queue overload can affect availability, which
is why initial evaluation should use audit mode.

## Privacy, logs, and latency

`behavioral_preflight_complete` logs only mode, execution-attempted flag,
duration_ms, controlled termination, completeness, severity, score, verdict,
known reason codes and blocked flag. The same safe telemetry is available in
`request.state.behavioral`. Existing log scrubbing remains in place; no raw
prompt, credentials, tool arguments, transcript, protected contents, or local
output is logged. Static short-circuits keep their existing DLP event and run
no behavioral evaluation.

Behavioral duration includes canonical preprocessing, capacity wait and
execution/assessment. It is separate from DLP timing and never written into
historical Phase 3 benchmarks or dashboard metrics. No real-model latency
performance claim is made.

## Verification and historical source freeze

`test_behavior_gateway_integration.py` adds **147 tests** covering the real
gateway → DLP → fake local adapter → sandbox → assessment → policy chain:
modes/severities/failures, static short-circuits, masked/warn sanitized egress,
both streaming modes, nested inventory, size/config bounds, queue admission and
timeouts, cancellation-held capacity, fresh sessions/no cache, literal config,
safe responses/logging, SDK parsing and authorized source provenance.

Complete verification runs gateway, scanner, SDK, unchanged benchmark framework,
dashboard endpoint/state tests, and Phase 4A/4B/4C/4D tests with the offline
bootstrap. The three earlier Phase 4 suites remain 300 / 124 / 200 passing.
Phase 1 remains 141 passing and Phase 2 remains 276 passing across Python
suites. No real local inference or external/cloud model is used in tests.

| Suite | Passed | Failed |
| --- | ---: | ---: |
| Gateway including all four Phase 4 suites | 1126 | 1 old config-fallback mismatch |
| Scanner | 224 | 10 old fixture/recognizer expectation mismatches |
| SDK | 20 | 0 |
| Original benchmark framework | 30 | 1 historical active-source freeze assertion |
| Dashboard JavaScript state tests | 10 | 0 |
| **Combined** | **1410** | **12** |

The **11 old failures** are unchanged. The additional framework failure is
`test_frozen_dataset_and_source_unchanged`: its original assertion requires
the active gateway source hashes to remain exactly those measured in Phase 3.
Gateway integration necessarily changes that active source. The old assertion
is retained, not weakened, skipped, or rebased, and its failure is explicitly
reported. It does not mean the historical benchmark dataset/results changed.

`docs/PHASE4D_SOURCE_DELTA.json` records exactly four authorized active-source
changes with before/after hashes: config, shared egress inventory, app lifecycle,
and proxy route. A new provenance test checks active production hashes against
the historical map plus those four exact deltas, and verifies the historical
freeze manifest itself is unchanged. The Phase 4D runner checks this separately,
preserves existing benchmark code/dataset/result/report digests, and accepts
only the 11 known failures plus the explicitly identified historical assertion.
Any additional failure or source delta rejects verification.

The phase-start preservation baseline covers 183 existing source, tests,
benchmark/dashboard/report/config files. Exactly the four authorized gateway
files change; the other 179 remain byte-identical. Existing tests are unchanged.
No original config or earlier phase report/result is overwritten. The separate
`docs/PHASE4D_TEST_RESULTS.json` records actual counts, failure node IDs, freeze
interpretation, and execution-boundary evidence. `git diff --check` passes.

```powershell
.venv\Scripts\python.exe -B proxy-api\tests\run_phase4d_verification.py
git diff --check
```

## Manual rollout, runtime status, and next phase

Recommended sequence: **OFF → AUDIT → evaluate → ENFORCE**. Merge the example
section into a developer-owned full gateway config, change its mode to audit,
then use the existing `AISG_CONFIG_PATH`/deployment configuration selection
and normal gateway startup workflow. No service is launched by this phase.
Ollama must already be running with the configured installed model. Loopback
refers to the gateway's own network namespace; a gateway container needs a
matching local runtime arrangement rather than a remote-host URL override.

Prior manual local probes returned `LOCAL MODEL NOT AVAILABLE`. No new real
probe is required or performed here, so generation remains NOT VERIFIED and
real-model detection efficacy/latency remain unmeasured. The fake proves policy
composition and isolation, not that prompts reliably elicit these behaviors in
Ollama or a target external model.

Later work should evaluate real local execution on a labeled corpus, compare
target-model behavior, calibrate heuristic thresholds/failure choices, and
measure capacity/latency before operational enforcement. Exact canary and
synthetic-environment limitations from Phase 4B/4C remain. The local runtime and
adapter implementations are trusted components; loopback/installed-model
metadata checks cannot prove that an arbitrary local service never proxies
elsewhere. Phase 3 metrics remain historical evidence of the earlier static
system, not measurements of this new behavioral layer.
