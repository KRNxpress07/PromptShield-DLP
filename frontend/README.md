# PromptShield research dashboard

From `C:\CNS\PromptShield-DLP`, run:

```powershell
& '.\.venv\Scripts\python.exe' -B frontend/server.py
```

Open **http://127.0.0.1:8787**. This loopback-only host serves the five named frontend assets and `GET /v1/benchmark/summary`. It never serves the repository root or benchmark directory. `--port 8788` selects another unprivileged port if needed. Port 8080 is reserved/unavailable in the evaluated Windows environment.

The UI remains static HTML/CSS/JavaScript, with zero frontend dependencies, local system fonts and CSS/SVG charts. Seven sections cover overview, live scanning, benchmarks, detection, sanitization, performance and methodology. Presentation mode enlarges metrics/chart text, simplifies navigation and hides connection controls; it affects only browser state. Data is fetched at startup and on the reload button, with unavailable values displayed as “Not available.”

The summary endpoint reads the actual `benchmarks/results/latest/metrics.json` and the existing per-entity, false-positive and sanitization CSVs. It projects finite typed metrics, selected known entity categories and narrowly verified synthetic/benign fragments into controlled JSON. It does not expose environment variables, raw prompts/predictions, manifests, filesystem paths, arbitrary files or full CSVs. Query parameters and write methods are rejected; missing/malformed primary data returns a generic 503. Optional absent CSVs yield empty sections and a warning. No benchmark result is regenerated, copied, tuned or rewritten by the dashboard. Recorded Phase 3 regression counts are labeled as historical, not this sprint's test totals.

The live scanner still calls the existing gateway (default `http://localhost:8000`): `/v1/scan`, `/v1/documents/scan`, and `/v1/chat/completions`. Configure the gateway URL/key/provider/model before a live demonstration. The separate dashboard server does not start or mock the scanner/LLM gateway. Gateway and local scanner startup remain the existing project workflows. The gateway key is password-masked, held only in the form's memory, and never persisted by the frontend. No provider credential is entered into this dashboard.

Editing the input/file/connection invalidates the assessment; stale results cannot be used for forwarding. A block has no send action. Mask/warn exposes sanitized forwarding only. Allow forwards scanned text, or the returned extracted text for a document; no binary file is sent to an LLM. Every chat request is still inspected by the existing gateway. Timeouts and scan errors remove send controls. Assistant text, code blocks, benchmark values and file names are escaped before display. The live risk display is a deterministic heuristic: none=0, low=1–49, medium=50–69, high=70–89, critical≥90. Injection and configured severity floors can force a stricter action; the server action remains authoritative.

Charts start from zero, display numerical values, and retain the worse false-positive result alongside recall/F1. Prompt classification and strict/relaxed span metrics remain separate. Exact leakage is shown for changed outputs **and** all non-block sensitive outputs, including misses. Partial-removal failures are called out. Human utility remains **PENDING HUMAN EVALUATION**. Timing is labeled local in-process and excludes startup, server/TCP middleware and external LLM latency; throughput is a finite batch, not production scalability.

To run the isolated endpoint checks with the existing offline test bootstrap:

```powershell
& '.\.venv\Scripts\python.exe' -B frontend/tests/run_validation.py
```

This executes gateway, scanner, SDK and benchmark framework suites in separate offline processes, writes its new test record to `docs/PRESENTATION_DASHBOARD_TEST_RESULTS.json`, checks JavaScript syntax and protected hashes, and never writes to `benchmarks/results`. The detailed handoff is `docs/PRESENTATION_DASHBOARD_REPORT.md`.

The dashboard is designed for 1920×1080 and 1366×768, with responsive layouts for narrower widths. Live rendering/screenshot verification requires an enabled browser; the current computer-use inventory contains no available browser, so screenshots are not provided and visual viewport verification is NOT VERIFIED. Direct `file://` viewing cannot load the endpoint: use the loopback host. Docker packaging for this additional dashboard host and multi-user/production deployment are not part of this UI sprint.
