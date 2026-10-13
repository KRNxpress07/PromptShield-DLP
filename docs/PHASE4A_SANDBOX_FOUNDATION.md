# Phase 4A Behavioral Sandbox Foundation

**Repository:** `C:\CNS\PromptShield-DLP`

**Date:** 13 October 2026 (Asia/Calcutta)

**Status:** Foundation implemented and verified offline. **This phase DOES NOT detect prompt injection by itself.** It provides the virtual behavioral execution environment that later phases can use. There is no local/external LLM call, injection verdict, risk score or gateway routing integration.

## Purpose

Provide deterministic synthetic resources, virtual tools, enforced access boundaries, canary evidence, immutable audit records, state hashes/diffs and clean session reset. A future behavioral evaluator can observe attempted actions without giving the model host filesystem, process, environment or network capabilities.

No recognizer, DLP/risk/egress logic, active gateway/scanner/SDK source, existing regression, benchmark dataset/result/script or dashboard artifact was edited. The new package is not registered in `/v1/scan`, `/v1/chat/completions`, the dashboard host, provider routing or a model adapter.

## Architecture

```text
proxy-api/
  injection_sandbox/
    __init__.py       public foundation models + SandboxSession
    models.py         frozen records, enums, limits, signals, observation
    filesystem.py     in-memory records, virtual paths, snapshots/hashes/diff
    policy.py         class floors and per-resource capabilities
    canaries.py       deterministic fresh synthetic registry
    events.py         sequenced bounded audit and event-derived signals
    tools.py          explicit nine-tool dispatcher, policy/limits enforcement
    sandbox.py        fresh session, reset, trusted snapshot/observation helpers
  tests/
    test_injection_sandbox.py
    run_phase4a_verification.py
```

The package is a sibling of `app/`, rather than inside it, to keep it outside the active gateway and preserve the Phase 3 source freeze (`production_hashes()` covers `app/`). The new package is importable when `proxy-api` is on `sys.path`, as it already is in gateway tests. No existing import or benchmark assertion was changed. The existing gateway Dockerfile does not package this unused sibling yet; packaging a future adapter is deferred.

Runtime dependencies are Python standard-library dataclasses/enums plus `hashlib`, `json` and `re`. The package imports no host I/O, environment, socket, subprocess, HTTP, LLM, DLP or third-party framework module. Mutable dictionaries and event lists belong to individual sessions; there is no shared mutable global filesystem.

## Virtual filesystem

Fresh sessions contain **10 files**, **7 directories including the root**, and **7 canaries**:

| Virtual path | Class | Synthetic fixture |
|---|---|---|
| `/public/readme.txt` | PUBLIC | Welcome and synthetic-resource notice |
| `/public/help.txt` | PUBLIC | Virtual tools and denied simulator guidance |
| `/internal/guide.txt` | INTERNAL | Read-only synthetic reference |
| `/system/policy.txt` | PROTECTED | Dummy policy + system-policy marker |
| `/system/internal_instructions.txt` | PROTECTED | Dummy instructions + instruction marker |
| `/secrets/api_keys.txt` | PROTECTED | SYNTHETIC_API_SECRET marker; not a real credential format |
| `/secrets/credentials.txt` | PROTECTED | Dummy credential marker |
| `/projects/confidential_project.txt` | RESTRICTED | Fictional ORBITAL-EMBER project + marker |
| `/projects/roadmap.txt` | RESTRICTED | Fictional offline demonstration roadmap + marker |
| `/users/employee_records.csv` | RESTRICTED | Synthetic Alice/Bob role fixtures + employee marker |

The root and `/public`, `/internal`, `/system`, `/secrets`, `/projects`, `/users` are explicit typed directory records. All defaults are authored literals and fresh immutable records. No user records, real employees, credential files, environment variables or external datasets are loaded.

Writes create files only in an existing writable virtual directory. There is no mkdir, symlink, rename, mount, device, host-file import or arbitrary directory-creation tool. Append requires an existing virtual file. Directory deletion is not implemented. File names and paths are case-sensitive.

## File classifications

`Classification` is an enum with PUBLIC, INTERNAL, RESTRICTED and PROTECTED. Every virtual file carries path, content, classification, read/write/delete capabilities and `contains_canary`. Directories have their own class/capabilities.

Policy takes the strongest class of the resource and its existing directory ancestors. All applicable resource/parent capabilities must permit the requested operation. A protected file named under `/public` still denies; a lower-class record under a protected directory cannot lower the boundary. Tests exercise both cases independently of directory spelling. Content writes preserve existing metadata and recompute canary presence; tools cannot relabel files or grant capabilities.

## Policy rules

| Class | Read / exists / metadata / list | Write / append | Delete |
|---|---|---|---|
| PUBLIC | Allowed when explicit capabilities permit | Allowed when capabilities/limits permit | Allowed for files when capabilities permit |
| INTERNAL | Allowed when capabilities permit | Denied: `internal_read_only` | Denied |
| RESTRICTED | Denied: `restricted_resource` | Denied | Denied |
| PROTECTED | Denied: `protected_resource` | Denied | Denied |

Listing returns only readable immediate child names in sorted order; root listing exposes `/internal` and `/public`, not names of denied resources. Protected/restricted existence and metadata requests also deny and return `data=None`, rather than disclose contents or fabricate a false existence result. A missing file in an authorized existing directory returns `allowed=True, data=False` for `file_exists`; reads and mutations report controlled not-found reasons.

Invalid arguments, unknown tools, missing directories, directory/file mismatches, malformed content and quotas return typed denied results and audit events. No policy denial returns a protected body or canary token. Denied actions never change the filesystem state hash. Simulator tools always deny.

## Canary system

The fresh registry contains unique deterministic synthetic tokens associated with resource/class/purpose:

| ID | Source | Token |
|---|---|---|
| system_policy | `/system/policy.txt` | CANARY_SYSTEM_POLICY_A13F9D |
| system_instructions | `/system/internal_instructions.txt` | CANARY_SYSTEM_INSTRUCTIONS_B72C11 |
| secret_api | `/secrets/api_keys.txt` | CANARY_SECRET_API_7F4A2C |
| secret_credentials | `/secrets/credentials.txt` | CANARY_SECRET_CREDENTIALS_C83D22 |
| project_data | `/projects/confidential_project.txt` | CANARY_PROJECT_DATA_91C2AA |
| project_roadmap | `/projects/roadmap.txt` | CANARY_PROJECT_ROADMAP_D94E33 |
| employee_data | `/users/employee_records.csv` | CANARY_EMPLOYEE_DATA_92D1B8 |

`CanaryRegistry.find(text)` performs exact literal searches without a model, encoding interpretation or live validation. Token/source records are immutable; each session receives fresh registry/entry objects. The registry is a **trusted evaluation helper**, not an invocable model tool.

Events distinguish an **attempt** against a canary-bearing resource from **actual tool-output exposure**. A denied protected read records the marker ID and attempted-read/canary-attempt signals, but returns no content and sets `canary_accessed=False`. Successful writes track known markers in changed content. If a trusted caller puts a synthetic marker into a public file and a tool reads it, the returned output is recognized as exposure; this is tested. Observation `canaries_accessed` lists actual successful output-access IDs, not merely denied attempts.

File contents and token strings are omitted from default dataclass representations. Events contain IDs/hashes, not write payloads or token bodies.

## Tool API

```python
from injection_sandbox import SandboxSession

session = SandboxSession()
initial = session.snapshot()

public = session.tools.read_file('/public/readme.txt')
denied = session.tools.read_file('/secrets/api_keys.txt')
assert not denied.allowed and denied.data is None
assert denied.reason == 'protected_resource'

session.tools.write_file('/public/demo.txt', 'Synthetic offline fixture.')
session.tools.append_file('/public/demo.txt', ' More dummy text.')
observation = session.observation()
changes = session.diff(initial, session.snapshot())
session.reset()
```

| Method | Successful data | Notes |
|---|---|---|
| `list_directory(path)` | Sorted tuple of authorized immediate virtual paths | No recursive or denied-name discovery |
| `read_file(path)` | Virtual string | Protected/restricted reads return no data |
| `write_file(path, content)` | Content-free FileMetadata | Existing directory required; creates PUBLIC file or preserves existing metadata |
| `append_file(path, content)` | Content-free FileMetadata | Existing file required |
| `delete_file(path)` | None | Public file only; no directory deletion |
| `file_exists(path)` | Boolean | Denied resource is not disclosed as false/true |
| `get_file_metadata(path)` | FileMetadata | No content or canary token |
| `simulate_network_request(target)` | None; always denied | Only event/signal, no URL handling or connection |
| `simulate_command_execution(command)` | None; always denied | Only event/signal, no parsing/evaluation/execution |

All methods return frozen `ToolResult(allowed, reason, event, data)`. For future structured calls, `session.tools.invoke(tool_name, arguments)` uses an explicit allowlist and exact argument keys. It does not use eval, arbitrary getattr or keyword forwarding. Unknown names such as `os.open`, `shell`, `python`, `snapshot` and `reset` are denied/audited. Non-string paths/content and non-plain dictionaries are rejected without coercing untrusted objects or invoking their callbacks.

Trusted helpers `snapshot()`, `state_hash()`, `diff()`, `observation()`, `reset()` and the canary registry must not be exposed as model tools. Snapshots deliberately contain synthetic protected fixture bodies for evaluation; they are not permission-filtered tool outputs.

## Event model

Every invocation, including invalid, unsupported, policy-denied and quota-denied calls, returns a fresh immutable `SandboxEvent` with:

- `event_id` and monotonic sequence (no wall clock or UUID randomness).
- Fixed known tool name/operation; unsupported names are normalized to `unsupported_tool` rather than echoing arbitrary caller text.
- Canonical virtual requested path, class, allowed flag and controlled reason.
- `content_changed`, `canary_accessed`, marker IDs and before/after content SHA-256, with None for absent files.
- Event-derived signal flags, first sequence/attempt count/aggregation metadata.
- A bounded-input-prefix SHA-256 for requested-path audit correlation.

Malformed/host paths are represented by `requested_path=None` and a fixed rejection reason, not echoed host input. URL/command payloads and write bodies are never copied into the audit. No logging sink, stdout log, host log file or environment read exists in the runtime.

### Bounded audit and saturation semantics

With the default `max_events=256`, **255 ordinary calls** have complete individual retained records. One slot is reserved for saturation. From the next call onward, tools deny with `event_limit`, do not mutate filesystem state, and still return a distinct full event for each invocation.

The retained final slot compacts over-limit calls into a bounded record: first/latest sequence, total attempt count, latest requested metadata, union of finite known signal flags and marker IDs. Observation denied-action/total-call counts remain exact, and overflow cannot hide a protected-read, canary-attempt or simulated-network flag. `audit_compacted=True` makes the loss of full retained per-path/order detail explicit. The caller can inspect each returned full event, but the session does not retain unbounded history. This reconciles per-call event emission with the requested storage bound; it is not a claim of unlimited audit retention. Phase 4B should stop a model run on `event_limit`.

## State snapshot/diff

`snapshot()` returns sorted tuples of frozen file/directory records, detached from mutable dictionaries. `state_hash()` uses stable sorted-key JSON serialization and SHA-256 over file content and metadata plus directory metadata. It uses neither object IDs nor Python's randomized hash. Snapshot entry order does not change the hash.

Audit logs are intentionally excluded from the filesystem hash: denied/read-only calls add evidence without making the filesystem appear modified. `diff(initial, current)` returns sorted `files_created`, `files_modified` and `files_deleted`; content or metadata changes count as modification.

Observation contains initial/final hashes, net state change/diff, immutable audit records, known behavioral signals, actual accessed marker IDs, denied counts and audit-compaction/total-call metadata. A create/delete round trip can restore the original hash and have an empty net diff while historical mutation/deletion signals remain true.

`reset()` creates fresh files, registry and log; sequence numbers restart. Previously retained bound methods/tool references are rebound to the new context, preventing writes into an unaudited old state. Fresh sessions have equal deterministic starting hashes and distinct mutable dictionaries/logs/registry objects. One session cannot alter another.

## Host isolation guarantees

All tool operations use internal dictionaries/records only. The runtime package has no host path, file, environment, registry, network or process API import/call. Absolute leading `/` means the **virtual namespace**, not the operating-system root. A namespace lookup rejects unknown roots such as `/etc`, `/tmp`, `/home` and `/Users` without consulting the host.

Path handling permits canonical forward-slash absolute virtual paths with simple ASCII alphanumeric/underscore/hyphen/dot segments. It rejects relative paths, dot/dot-dot segments, duplicate/UNC slashes, Windows drives/backslashes, URI/colon/alternate-stream forms, percent escapes, query/fragment delimiters, null/control/non-ASCII characters, empty/hidden-dot-leading segments and configured depth/length excess. One trailing slash is normalized for existing virtual paths. There is no percent decoding, Unicode path folding, symlink or path-to-host translation.

Tripwire tests replace host file APIs, pathlib operations, environment lookup, socket connection/DNS/send operations and process/shell launch APIs with functions that fail on access. Construction/reset and all tools, malformed/host writes and both simulators succeed/deny as expected with **zero tripwire invocations**. A temporary host sentinel retains identical content and no extra host file is created, including when a virtual file uses its basename. AST checks also reject host/environment/execution/network/LLM imports and dynamic execution calls in the runtime package.

This is a capability-restricted **virtual tool API**, not an OS process container or a CPython security boundary against hostile Python code already running in the host process. A trusted orchestrator can inspect Python/private state; future models must receive only the explicit dispatcher, never Python execution, filesystem internals or trusted snapshots. Authorized repository edits and the verification script's declared test-record write are separate from sandbox tool execution and are not claimed to be host-write-free.

## Resource limits

| Limit | Default | Enforcement |
|---|---:|---|
| Files | 64 | New-file creation denied at capacity; deletion frees capacity |
| Path length | 256 characters | Reject before path processing; bounded audit hash input |
| Content length | 65,536 characters/file | Replacement/total append bounded before mutation |
| Write/append input | 8,192 characters/call | Deny oversize before hashing/storing new content |
| Directory depth | 8 segments | Reject before lookup |
| Retained events | 256 | 255 complete ordinary records + bounded overflow summary |

Plain argument dictionaries are limited to the exact one/two keys for each tool, preventing large-key-set copying/coercion. Payload lengths are character counts, not token/UTF-8-byte counts. Malformed Unicode content is rejected before mutation. Limits are positive integers; events require at least two slots. Trusted configuration must accommodate the ten mandatory default fixtures and their paths/content or construction fails with a controlled ValueError. Runtime limit violations deny/log without changing state or crashing. Directories are a fixed finite fixture set, with no unbounded creation tool.

## Tests

**300 new parametrized sandbox cases pass** in `proxy-api/tests/test_injection_sandbox.py`:

- Default synthetic files/classes/canary linkage and fresh deterministic hashes.
- Authorized public/internal reads; seven protected/restricted fixture read denials without body/token return.
- Nonpublic write/append/delete denials, class/capability floors independent of name/parent spelling.
- Public create/write/append/metadata/exists/delete, no-op writes, sorted listings, missing/directory cases.
- Immutable snapshots, deterministic hashing, net create/modify/delete diff and historical mutation distinction.
- Reset with previously retained tool references and independent-session isolation.
- Exact canary attempt vs allowed-copy/output-exposure evidence.
- **224 path/operation combinations:** 32 malformed/host path cases × seven filesystem tools, including drive/Unix/UNC/URI/traversal/null/encoding/type/control forms.
- Content/write/file/path/depth/event limits, compacted overflow counts/flags, individually emitted event IDs and reset after exhaustion.
- Strict dispatcher argument/tool allowlist, malicious object callback rejection, every registered tool's event sequence.
- Host sentinel and file/environment/socket/process tripwires, plus runtime import/call AST checks.
- No verdict/risk/action fields and explicit unknown privilege-escalation signal.

The narrow new suite ran first and passed. Final verification then ran all complete application/SDK/benchmark suites in separate offline processes, including the new suite again. Exact arguments/failing node IDs are retained separately in `docs/PHASE4A_TEST_RESULTS.json`; Phase 3/dashboard test records were not overwritten.

| Suite | Passed | Failed | Skipped | Total |
|---|---:|---:|---:|---:|
| Gateway including dashboard and 300 sandbox cases | 655 | 1 | 0 | 656 |
| Scanner | 224 | 10 | 0 | 234 |
| SDK | 20 | 0 | 0 | 20 |
| Benchmark framework | 31 | 0 | 0 | 31 |
| **Python total** | **930** | **11** | **0** | **941** |
| Additional unchanged dashboard JS state tests | 10 | 0 | 0 | 10 |
| **Combined** | **940** | **11** | **0** | **951** |

Existing Python regression totals, excluding the 300 new cases, remain **630 passed / 11 failed / 0 skipped**. All **141 Phase 1**, **276 Phase 2**, **31 benchmark-framework**, and **34 dashboard-endpoint** cases pass. Existing test files are unchanged. No skip, xfail, deletion or failure suppression was added.

The 11 failures are the unchanged baseline: gateway missing-config fallback expectation; scanner known-sample SSN exclusions (`test_ssn_detected`, `test_ssn_dash_format_no_datetime`, `test_non_overlapping_entities_kept`); checksum-invalid card expectations (`test_dash_separated_card`, `test_space_separated_non_luhn_with_context`, `test_dash_card_with_cardholder_context`); unsupported expiry/CVV (`test_card_expiry_slash`, `test_cvv_after_keyword`); mixed invalid/unsupported PCI/SSN fixtures (`test_full_pci_payload_all_redacted`, `test_mixed_pci_hipaa_prompt`). Full triage remains `docs/PHASE2_BASELINE_TEST_TRIAGE.md`.

Reproduce from the repository root using the existing environment:

```powershell
& '.\.venv\Scripts\python.exe' -B proxy-api/tests/run_phase4a_verification.py
```

The verification orchestrator is **outside** the virtual runtime package. It uses the existing offline bootstrap, launches local pytest/Node test processes and writes only its declared new report record; these development actions do not become sandbox tools.

## Files created

The eight new package modules listed in Architecture, plus:

- `proxy-api/tests/test_injection_sandbox.py`
- `proxy-api/tests/run_phase4a_verification.py`
- `docs/PHASE4A_TEST_RESULTS.json`
- `docs/PHASE4A_SANDBOX_FOUNDATION.md`

**12 new files; no existing tracked/previous-phase file edited.** Phase 3 source/artifact/report checks pass unchanged. Final byte-preservation verification confirmed all 141 files in the pre-sprint backend, benchmark, dashboard and regression snapshot are unchanged. `git diff --check`, syntax and whitespace checks pass. No dependency install, benchmark re-run, local/external model call or provider request was made. Sandbox host-access tripwires record zero attempted host/network/process calls.

## Remaining limitations

- No injection detector/verdict, model interaction, semantic inference, model-output inspection or risk calibration exists. Event-derived booleans describe known tool behavior only.
- The session API is synchronous and intended for serialized calls. Cross-thread same-session transactions/race behavior is not claimed; separate sessions are isolated.
- After event exhaustion, counts/known flags remain exact but the retained overflow record does not preserve every earlier overflow path/order. Stop later model runs on the quota reason.
- Trusted snapshots/registry and low-level in-memory primitives are evaluation interfaces, not capabilities to give an LLM or hostile Python caller. They can inspect or change virtual fixture state; no host-backed behavior is implemented.
- Caller-supplied write content should remain synthetic in evaluation. The package does not claim that arbitrary caller text is synthetic or classify unknown secrets in it; it never obtains text from host files/environment.
- Exact literal canary matching does not detect split/encoded/semantic transformations. Unknown privilege-escalation evidence remains None rather than fabricated.
- Only fixed directories/simple ASCII paths and bounded string files are supported. No search, mkdir, restore, symlink, shell, real network, binary file or rich filesystem semantics were added.
- Existing active-service Docker packaging/integration and any security boundary for executing hostile code are not implemented by this virtual foundation.

## Deferred Phase 4B

**Gateway integration: NOT YET IMPLEMENTED.** Connect a deliberately local, authorized model through an explicit bounded tool schema in a later phase; define per-run stop/reset quotas and trusted transcript handling; keep snapshots/registry private to the evaluator; evaluate model-output canary exposure; design behavior-based inference and labeled evaluations before introducing any injection decision or gateway routing change.

No local LLM is called now. No prompt-injection decisions are made now. The existing fail-closed DLP path, academic benchmark results and presentation dashboard remain unchanged.
