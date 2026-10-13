# Offline academic benchmark

This evaluates the unchanged Phase 2 system using authored synthetic fixtures. It does not validate live credentials or production traffic. No external network, providers, environment credentials, downloaded models, or new dependencies are used.

From the repository root, use the existing environment:

```powershell
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_all
```

The runner archives an existing `results/latest` under a timestamped run directory before running again. It validates the frozen dataset and production hashes, runs detection and two baselines, sanitization and mocked-provider block checks, application/framework tests, sequential latency and throughput experiments, and generates the report. Baseline application failures are retained, not suppressed. The Python scripts import application packages only after removing credential environment variables, disabling dotenv values/loading, installing an external socket/DNS guard, and supplying explicit `_env_file=None` gateway settings. In-memory HTTP transports never connect to a service. Use the existing installed English spaCy model; a missing model fails rather than downloads.

Individual stages (run from the root):

```powershell
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.validate_dataset
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.split_dataset
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_detection_benchmark
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_baselines
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_sanitization_benchmark
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_tests
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_latency_benchmark
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.run_throughput_benchmark
& '.\.venv\Scripts\python.exe' -B -m benchmarks.scripts.generate_report
```

`generate_dataset` reproduces the authored corpus; it refuses different content under the same frozen version. Detection refuses to overwrite a completed `metrics.json`; use the archive-producing full runner for another run. Individual later stages write their own current artifacts; archive those before rerunning if comparing them. Do not use Python `-O` (validation assertions are intentional). Run performance stages sequentially without simultaneous tests or benchmark workloads. Background OS load is not controlled.

The dataset contains 1,000 prompts (400 safe, 600 sensitive), split into 300 development and 700 test prompts by fixed seed 20261013 and whole template/topic families. Test labels are authored insertion spans, not model predictions. The corpus was constructed with knowledge of supported formats, then frozen before any detector results; no production recognizer was tuned against the test set. Values/format families are shared between splits; this is a limited holdout, not an unseen-domain study. Public names/dates/documentation IPs and conceptual attack quotations are deliberate benign controls even though the policy can protect them. Their false positives measure this task/policy conflict, not necessarily an invalid regex.

One canonical entity type is labeled per inserted value. Nested taxonomy alternatives such as IP_ADDRESS on a PRIVATE_IP, incidental NER inside an address/secret, and partial assignment matches can count as extra span predictions or taxonomy confusion. This annotation choice is frozen and explicitly limits span interpretation. Tool/schema-like records are textual prompt renderings, not a benchmark of every outbound JSON field; existing Phase 2 regressions cover that boundary.

Headline metrics are prompt classification and typed strict exact-span precision/recall/F1, separately. Relaxed matching requires >=50% coverage of the gold span and uses maximum-cardinality one-to-one matching. A very broad predicted span can satisfy that relaxed rule, so strict scores remain primary. Span TN/FPR are `null` because arbitrary character spans have no defensible finite negative universe; prompt occurrence provides FPR overall and per entity. Zero-denominator metrics are `null` (NOT VERIFIED/not applicable), never artificially perfect scores.

Sanitization is evaluated using gold exact substrings, coverage of gold offsets by replacements, a post-sanitization rescan, and a secondary unchanged-character alignment metric. Report both changed-sensitive-only leakage and leakage for **all non-block sensitive outputs**, including missed/allow prompts. Blocking is tested at real gateway routes in both streaming modes with mocked provider functions. Three deliberate fault probes are reported separately from natural processing failures.

Human evaluation is **PENDING HUMAN EVALUATION**. `human_evaluation_template.csv` contains up to 150 deterministically selected synthetic original/sanitized pairs and blank ratings. Ask reviewers to score task understandability and information preserved from 1 (poor) to 5 (excellent), meaning damage from 1 (none) to 5 (severe), and intended-task usability yes/no. Keep reviewers independent of detector development when possible, use two raters, record disagreements and agreement statistics, and retain individual ratings. Automated preservation ratios are not semantic judgments.

Latency uses 8 warmup prompts per stage, a deterministic size/label-stratified subset, 3 repetitions, high-resolution monotonic timing, and no provider calls. Startup/loading is excluded. Scanner timing covers the actual in-process `/process` logic without anonymization; gateway timing includes actual egress inspection, JSON MockTransport, anonymization/verification when applicable and risk decisions. TCP/server middleware is excluded. Throughput is a finite batch of actual scanner calls in a thread pool at 1/2/4/8 workers, 3 repeats; queue wait is included in P95. This is not steady-state service capacity or production scalability.

Machine-readable outputs, model/dependency/hardware versions, source/dataset hashes, false positives/negatives, confusion matrices, test logs, and reproduction metadata are in `results/latest`. A failed initial helper run is retained in `results/initial_helper_failure`. The faculty report is `docs/PHASE3_ACADEMIC_EVALUATION_REPORT.md`. Optional PNG charts are omitted when matplotlib is not already installed.
