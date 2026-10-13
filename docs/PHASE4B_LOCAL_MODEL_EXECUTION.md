# Phase 4B — Local model behavioral execution

Phase 4B adds an opt-in internal library that executes a prompt against a local
model and the Phase 4A synthetic filesystem. It records behavioral evidence;
it makes no prompt-injection verdict, risk score, or gateway decision.
Behavioral evidence does not itself prove prompt injection. A local model may
behave differently from a target external model. Interpretation is deferred
to Phase 4C.

## Architecture and preserved system

`LocalBehaviorExecutor` sends JSON messages and nine explicit tool definitions
to a `LocalModelAdapter`. It validates returned JSON, dispatches calls exclusively
through a fresh `SandboxSession.tools.invoke`, sends legitimate tool results
back to the adapter, and returns a `BehaviorExecutionResult`.

The pure execution modules live in `proxy-api/injection_sandbox/`:

| Module | Responsibility |
| --- | --- |
| `model_adapter.py` | JSON-only adapter protocol, scripted fake, unavailable error |
| `tool_schema.py` | Nine fixed JSON schemas and argument validation |
| `executor.py` | Fresh-session loop, quotas, validation, safe result serialization |
| `transcript.py` | Frozen transcript entries and canary redaction |
| `behavior.py` | Explicit configuration, loopback URL validation, evidence result |

`proxy-api/behavior_runtime/ollama.py` is a separate optional transport package.
It imports HTTP functionality; the pure virtual package does not. Existing
Phase 4A modules and tests remain intact, including their AST boundary check.
No gateway routes, forwarding, recognizers, DLP, egress, risk engine, dashboard,
benchmark code, dataset, metrics, or earlier reports have been changed.

## Internal API and adapter contract

Run from `proxy-api` (using the repository virtual environment):

```python
from injection_sandbox.behavior import BehaviorModelConfig
from injection_sandbox.executor import LocalBehaviorExecutor
from injection_sandbox.model_adapter import FakeLocalModelAdapter

adapter = FakeLocalModelAdapter([
    {"text": "", "tool_calls": [
        {"id": "one", "name": "read_file",
         "arguments": {"path": "/public/readme.txt"}}
    ]},
    {"text": "Finished the public read.", "tool_calls": []},
])
result = LocalBehaviorExecutor(
    adapter, BehaviorModelConfig(enabled=True)
).run("Read the public readme", run_id="example")
print(result.to_json())  # Redacted audit result; no protected content
```

`execute_behavioral_probe(prompt, adapter, config=None)` is also available.
The default config is disabled and never invokes the adapter.

`LocalModelAdapter.generate(request_json: str) -> str` accepts a JSON string:
`messages`, `tools`, and remaining `max_output_chars`. Messages carry system,
user, assistant tool calls, and tool results. Its JSON response must contain
`text` (string) and `tool_calls` (list), with optional boolean
`output_truncated`. Each call must have exactly `id`, `name`, `arguments`.
Duplicate JSON keys and excessive nesting are rejected. The executor generates
unique context/audit call IDs, rather than trusting model-generated IDs.

The model receives no session, snapshot, state hash, diff, policy object,
canary registry, or trusted Python object. Denied reads return only a controlled
denial with `data: null`. Allowed data is serialized from the actual tool result.
The evaluation system message instructs the model to use only supplied tools,
avoid protected/restricted resources and synthetic secrets, and avoid network
or commands. That instruction is advisory; the dispatcher enforces the boundary.

## Tool surface

| Tool | Exact arguments |
| --- | --- |
| `list_directory` | `path` |
| `read_file` | `path` |
| `write_file` | `path`, `content` |
| `append_file` | `path`, `content` |
| `delete_file` | `path` |
| `file_exists` | `path` |
| `get_file_metadata` | `path` |
| `simulate_network_request` | `target` |
| `simulate_command_execution` | `command` |

Every argument must be a string in an exact JSON object with no extra keys.
Schemas declare `additionalProperties: false`, required keys, and `maxLength`.
Path/content bounds follow `ResourceLimits` (default 256/8192 characters);
simulator target/command bounds are 1024 characters. Phase 4A additionally
enforces canonical virtual paths, ancestry permissions, content/file/depth
limits, and immutable protected/restricted fixtures. The network and command
tools always simulate a denied attempt; they perform no HTTP or process work.

Malformed calls produce controlled, logged Phase 4A denials by invoking the
fixed dispatcher with a deliberately invalid key set. Malformed arguments are
never dispatched as valid inputs. Unknown names become `unsupported_tool`.
No reflection exposes arbitrary functions or methods.

## Bounded loop and termination

| Config field | Default | Meaning |
| --- | ---: | --- |
| `enabled` | false | Explicit execution opt-in |
| `provider` | fake | `fake` or `ollama`; no cloud provider |
| `model_name` | null | Explicit installed model required for Ollama |
| `base_url` | http://127.0.0.1:11434 | Loopback HTTP only |
| `timeout_seconds` | 5 | Transport timeout; at most 10 seconds |
| `max_steps` | 12 | Loop iterations including errors |
| `max_model_calls` | 12 | Adapter invocations including errors |
| `max_tool_calls` | 16 | Dispatched calls including malformed denials |
| `max_output_chars` | 8192 | Cumulative assistant output, including join separators |
| `max_total_transcript_chars` | 65536 | Audit storage budget and private message-history ceiling |
| `max_response_chars` | 32768 | Adapter response envelope before JSON parsing |
| `max_consecutive_errors` | 2 | Repeated adapter exceptions |
| `max_malformed_calls` | 3 | Consecutive malformed envelopes/calls |
| `sandbox_limits` | Phase 4A defaults | Virtual resource/event quotas |

Numeric quotas are strict positive bounded integers; booleans are rejected.
Each loop checks step/model quotas before invocation, each call checks the tool
quota before dispatch, and the first `event_limit` denial stops execution.
Valid calls reset the malformed-call streak. Adapter failures are retried only
within both the error budget and model/step budgets. Exception strings are
never copied into results. Availability failures stop immediately.

Termination reasons: `completed`, `max_steps`, `max_tool_calls`,
`max_model_calls`, `event_limit`, `transcript_limit`, `output_limit`,
`model_error`, `malformed_response`, `disabled`, `unavailable`, `invalid_prompt`.
Budget exhaustion or runtime-reported truncated generation is never reported
as `completed`. Oversized raw responses are not parsed or retained. A failed
transcript capture may occur after a bounded virtual action; that action and
its effect remain in the sandbox observation even when its text cannot fit.

The audit budget counts serialized entries and raw text, using the larger
representation for each entry; the private JSON message history has its own
ceiling using the same configured limit. Tool schemas are fixed configuration,
not growing transcript content. A whole batch is never inserted into history:
only calls actually dispatched are included. This avoids a large response
evading the call quota through history growth.

## Transcript and canary evidence

Each frozen transcript entry has `sequence`, `role`, `kind`, `text`,
`tool_name`, `tool_call_id`, `allowed`, and `reason`. It captures policy, input,
intermediate/final assistant text, proposed/dispatched arguments, returned data,
and controlled errors. All known synthetic canary tokens are replaced with
`[CANARY:<id>]` in the published transcript and model output. Model-controlled
virtual paths in observation events/diffs are redacted too. Denied protected
reads do not put protected contents into either private context or audit text.

Trusted detection runs on bounded decoded intermediate and final assistant
text and call strings, including malformed calls and proposals beyond a call
quota. The result distinguishes:

- `model_output_canary_ids`: literal markers in model-generated assistant text.
- `tool_argument_canary_ids`: literal markers in proposed call arguments or
  other call strings, including invalid calls. This is proposal evidence;
  it does not mean every proposed call was dispatched.
- `authorized_tool_canary_ids`: literal markers actually returned in an allowed
  tool-result body. A canary written into a public file is not itself counted
  as returned tool data. Reading it later can create this channel.
- Denied protected/restricted read and protected write attempts: counted from
  emitted Phase 4A events, independently of any exposure.

`model_output_canary_exposure`, `tool_argument_canary_exposure`, and
`protected_data_exposed` are derived booleans. The latter means a recognized
synthetic marker appeared in one of the three content channels; it does not
prove the model recovered original protected contents. An isolated denied
protected read has `protected_data_exposed = false`.

`canary_scan_complete = false` records incomplete evidence when a raw response
cannot be safely parsed/scanned, the adapter fails, or generation is reported truncated. A false
exposure flag in such a run does not establish absence of exposure. Exact
literal matching does not detect encoding, paraphrasing, split tokens across
outputs, or unknown secrets. Published output is redacted, so analysis should
use the recorded IDs rather than rescan the audit text.

## Result and fresh state

`BehaviorExecutionResult` contains run ID, termination reason, step/model/tool
counts, structured transcript, Phase 4A sandbox observation, redacted assistant
output, the three canary-ID sets, scan completeness, unauthorized/protected
read/restricted read/protected write/network/command attempt counts, and
derived exposure/state-change properties. `to_dict()` and `to_json()` include
these derived properties. There is no final injection label, ALLOW/WARN/BLOCK
field, score, or gateway integration.

Each `run()` creates a new sandbox. Initial/final hashes and final filesystem
diff describe effects; attempted mutations remain visible even if state is
later restored. Adapter state is independent: the fake script cursor advances
on each call; create a new fake adapter to replay its script.

An optional trusted `prepare_session` fixture hook permits seeding a public
file with a synthetic canary for tests. It is never model-facing. The initial
snapshot is captured after fixture setup, and setup events are excluded from
model observations. Setup still consumes the underlying Phase 4A event quota.

## Optional Ollama support and manual probe

The transport requires enabled `provider="ollama"` configuration and an exact
model name. Only numeric IPv4 loopback addresses, `localhost` (canonicalized
to `127.0.0.1`), and `[::1]` are accepted. Userinfo, paths, query/fragment,
ambiguous address forms, non-loopback addresses, and invalid ports are rejected.
HTTP clients use `trust_env=False`, no authentication headers, no redirect
following, bounded response reads, and a short timeout. No credentials or
`.env` files are loaded.

Before every generation, `/api/tags` must show the exact configured model with
positive installed size and a SHA-256 digest. Cloud-named models and remote/
cloud metadata are rejected. Generation uses only `/api/chat`, deterministic
temperature/seed options, non-streaming output, and a bounded prediction count.
There is no `/pull`, install, process launch, auto-discovery of credentials,
cloud fallback, or automatic model download.

From the repository root:

```powershell
.venv\Scripts\python.exe -B proxy-api\tools\run_behavior_probe.py --fake --prompt "List public files"
.venv\Scripts\python.exe -B proxy-api\tools\run_behavior_probe.py --model llama3.2:1b --prompt "List the public files"
```

Without an explicit model, or when the configured service/model is unavailable,
the manual script prints `LOCAL MODEL NOT AVAILABLE` and exits cleanly. Invalid
configuration is a caller error. Real generation is never invoked by automated
tests. This machine already has a running loopback Ollama service and two
installed local models (`llama3.2:1b`, `mistral:latest`); no software was started
or model downloaded during this phase.

Two manual generation probes against `llama3.2:1b` returned
`LOCAL MODEL NOT AVAILABLE`, using 5- and 10-second transport timeouts. Service
and installed-model metadata checks succeeded. Real assistant/tool behavior is
therefore **NOT VERIFIED** on this machine under these limits. The timeout can
be selected with `--timeout-seconds`, within the maximum of 10 seconds. These
manual probes were separate from the automated offline suite; no cloud model
was called, and there was no timeout-driven download, restart, or fallback.

## Security boundaries and limitations

The sandbox/model-facing execution performs no host filesystem, environment,
network, shell, subprocess, import-by-input, or Python evaluation operations.
Only the optional trusted transport accesses the configured loopback model
service. The trusted adapter implementation can execute Python: this protocol
is a boundary against model output, not isolation for untrusted adapter code.
Do not supply an untrusted implementation or fixture hook. A malicious or
hanging custom adapter cannot be preempted by the synchronous quota loop.
Known HTTP operations have transport timeouts, but no independent process
watchdog or overall wall-clock deadline exists in Phase 4B.

The local runtime itself must be trusted to honor its installed-model metadata
and perform local inference. Client-side loopback and metadata checks cannot
prove that an arbitrary service never proxies elsewhere. The synthetic model
environment is intentionally small; it does not emulate browser/enterprise
permissions or establish attack success against an external target model.

## Verification and Phase 4C handoff

`proxy-api/tests/test_behavior_executor.py` covers scripted behaviors A–N,
schema validation, exact bounds and batching, malformed JSON/nesting, output
and transcript limits, errors, separate canary channels/redaction, fresh runs,
host-access tripwires, unavailable/remote/cloud runtime paths, redirects,
loopback validation, and mocked Ollama tool conversion/truncation.
The fake accepts response objects/raw JSON, injected exceptions, repeat-last
loops, and trusted JSON-only callbacks for copying legitimate public data.

Run the complete offline verification:

```powershell
.venv\Scripts\python.exe -B proxy-api\tests\run_phase4b_verification.py
git diff --check
```

The separate [test record](PHASE4B_TEST_RESULTS.json) preserves earlier test
records. At implementation verification, gateway had 779 pass / 1 baseline
failure, scanner 224 pass / 10 baseline failures, SDK 20 pass, framework 31 pass,
and dashboard state tests 10 pass: **1,064 pass / 11 unchanged failures**.
Gateway totals include all **300 Phase 4A and 124 Phase 4B tests passing**.
No tests were removed, skipped, weakened, or marked expected-failure.
The old gateway config-fallback mismatch and ten scanner fixture/recognizer
expectation mismatches remain outside Phase 4B scope. External sockets/DNS are
denied by the existing offline bootstrap; real generation uses neither tests
nor their mock transports. Dedicated fake-execution tripwires observed zero
host accesses. Phase 3 frozen backend, benchmark code/results, and report
hashes remain unchanged; preexisting source/test/dashboard/report hashes are
also checked against the phase-start preservation snapshot.

Phase 4C may interpret these observations, develop behavior-based decisions,
and assess deployment tradeoffs. That work must separately define evidence
thresholds and evaluation semantics before integrating into the gateway or
existing risk engine. Gateway integration and a prompt-injection verdict are
**NOT YET IMPLEMENTED**.
