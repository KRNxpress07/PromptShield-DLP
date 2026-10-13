# Final frontend presentation polish

Presentation-only sprint completed on 2026-10-13. **Bklit: FULLY INTEGRATED for the requested dashboard charts**, through isolated React chart roots. The application remains static HTML/CSS/JavaScript. This is not a React application migration; Bklit Studio is not included.

## Palette and visual design

Obsidian `#09090D`, matte surface `#111118`, elevated aubergine `#171721`, ultraviolet `#8B5CF6`, lavender `#A78BFA`, copper `#D29A5A`, champagne `#E6B875`, warm white `#F4F1FA`, muted text `#9B97A8`, border `#292633`. Existing token aliases are retained to avoid changing scanner code. Sage represents positive observations, copper uncertainty, burnt orange high risk, rose/wine critical risk and lavender-grey unavailable evidence. Gradients are confined to selected controls and the restrained hero accent. No external fonts or runtime CDNs.

Cards have matte surfaces, thin borders, spacious numerical hierarchy, tabular numerals, and restrained elevation. The Live Scanner's final gateway decision now has a distinct bordered result panel. Its text and security decisions still come from the existing unchanged scanner implementation.

## Bklit source, components and licensing

Source inspected: [bklit/bklit-ui](https://github.com/bklit/bklit-ui), commit `f7b3bd2999a5c993863f9cc5523c9cf60b9f3bc2`. No Bklit source was initially available in this repository; the public repository was fetched for source inspection. Its chart package requires React 18/19, Visx and Motion, with Tailwind utility styles. The chart source is MIT licensed; Studio is proprietary and excluded.

Actual components: `BarChart`, `Bar`, `BarXAxis`, `YAxis`, `Grid`, `ChartTooltip`, plus their 35-file dependency closure. Pinned React 19.2.0, Visx 4.0.0 and Motion 12.27.0 are bundled locally with esbuild; Tailwind utility CSS is compiled without preflight. Dependency lockfile and build input manifest are committed. Upstream adaptations add an optional explicit `valueDomain` on BarChart, propagated through both scales, to guarantee 0–100 percentage axes, and replace ParentSize with a small outer-container measurement adapter. The adapter prevents zero-height charts after hidden-section navigation and screenshot resizing. Wrapper controls provide static bars, zero bar height for actual zero, N/A for null, bounded dense axis labels, aggregate-only tooltips and exact numeric ledgers. Hidden panels release chart roots; visible panels mount independently of scanner state.

Licenses are retained in `frontend/charts/vendor/bklit/LICENSE`, `frontend/assets/BKLIT-LICENSE.txt`, and `frontend/assets/THIRD-PARTY-NOTICES.txt`. The source revision and adaptations are recorded in `frontend/charts/vendor/bklit/PROVENANCE.json`. Build instructions: `frontend/charts/README.md`.

Charts replaced with Bklit: benchmark comparison; per-entity strict F1; difficulty recall/F1; hard-negative FPR; sanitization action counts; scanner/gateway latency by input size; throughput and queue latency; static/behavioral/layered real-model comparison; behavioral evaluation latency. Quantities use zero-based axes. Percentage charts have fixed 0–100 axes. All category indices have visible full-name ledgers; dense category axes skip labels instead of overlapping. Undefined static precision is N/A with no bar.

## Persistent Phase 4E evidence and safe endpoint

New independent loopback dashboard endpoint: **GET `/v1/benchmark/local-model`**. It is read-only, rejects query parameters and writes, and imports no scanner, sandbox, gateway or model adapter. It reads four literal allowlisted paths, bounds reads to 5 MiB, validates numeric types/ranges/schema, checks case totals and evaluation/comparison consistency, and checks latency CSV count/mean consistency. Evaluation and validation availability are independent. Missing or invalid evidence returns unavailable; no measured fallback exists.

Sources:

- `benchmarks/behavioral_real/results_llama32.json`: precision, recall, F1, FPR, FNR, NOT_EVALUATED fraction/count, mean/median/P95 latency, case count and fixed threshold.
- `benchmarks/behavioral_real/comparison.json`: static, behavioral and layered metrics and TP/FP/TN/FN counts.
- `benchmarks/behavioral_real/latency.csv`: bounded validation of timing count and mean; individual IDs/timings are not exposed.
- `docs/PHASE4E_REAL_MODEL_VALIDATION.json`: allowlisted validation stage statuses, model/runtime, cloud/download counts and score/severity-only probe examples.

The projection excludes prompts, transcripts, canaries, protected virtual paths, tool arguments, raw output, diagnostics, environment, reasons and secrets. Aggregate artifact filenames displayed as provenance are constant public repository paths. Frontend formatting escapes values. The original Phase 3 summary remains independent and unchanged in meaning.

The new **REAL LOCAL MODEL EVALUATION** research section loads on page startup, without any Live Scanner request. Headline cards show artifact values: precision 73.33%, recall 27.50%, F1 40.00%, FPR 16.67%, FNR 72.50%, NOT_EVALUATED 29.69% (19/64), mean 1655.36 ms, median 1476 ms, P95 2807.2 ms. These numbers are documented here for audit; none is a JavaScript fallback. Behavioral counts are 11/4/20/29 (TP/FP/TN/FN); static counts are 0/0/24/40. Static precision remains null/N/A. Probe cards show 0 LOW, 55 SUSPICIOUS, 70 HIGH, explicitly individual observed probes, not averages.

Validation distinguishes verified schema acceptance from the output-limited schema-only response, with separate usable tool execution evidence. Gateway preflight is a historical component check; no live provider request is claimed. Latency is warm manual behavioral execution plus paired static scan, excluding construction/provider time, not a production SLA.

## Presentation and limitations

Presentation mode enlarges metrics, simplifies navigation to a research-group selector, hides editable gateway configuration and redundant chrome, and retains sources and limitations. It provides compact groups for core DLP, model performance, model comparison/counts, execution validation, sanitization metrics/examples and system latency/throughput. Detailed benchmark and entity tables remain scrollable rather than shrinking their labels.

The model limitations remain adjacent to every local-model group: 64 repeated synthetic cases, 29.69% NOT_EVALUATED, 27.50% recall, single local model, heuristic HIGH threshold fixed before execution, and possible mismatch with an external target model. NOT_EVALUATED stays in all metric denominators as no emitted positive and never implies safety. Live results are labeled **CURRENT LIVE REQUEST** separately from **REAL MODEL BENCHMARK**.

## Browser verification

Actual dashboard opened in installed headless Chrome via Playwright, served on `http://127.0.0.1:8788`. Captured and checked 1920×1080, 1600×900, 1366×768 and 390×844. Development PNGs are in `docs/presentation-screenshots/`; layout measurements in `docs/FINAL_FRONTEND_VISUAL_QA.json`; interaction assertions in `docs/FINAL_FRONTEND_INTERACTION_QA.json`. All requested viewport records show no horizontal overflow and no JavaScript page errors. Actual SVG charts, tooltips, null precision display, missing-data states, reload, presentation configuration hiding and default scanner selector state were checked. Desktop screenshot groups retain provenance and limitation labels; narrow layouts scroll vertically. Long detailed benchmark/entity/Live Scanner pages remain scrollable. This verification does not establish live gateway/provider connectivity or run real inference again.

## Tests and preservation

**1,484 passed; 13 known failures**, no new failures. Full gateway, scanner, SDK and benchmark-framework suites were run. New frontend artifact/endpoint tests: 20 passed. Node UI/scanner/mode/escaping/presentation tests: 29 passed (22 existing plus 7 new). Final focused endpoint and Node checks were repeated after their final changes. Records: `docs/FINAL_FRONTEND_TEST_RESULTS.json`; repeatable runner: `frontend/tests/run_presentation_verification.py`.

Phase 1: 141 passed; Phase 2: 276 passed; Phase 4A 300, 4B 124, 4C 200, 4D 146 functional tests and Phase 4E 36 passed. Thirteen retained failures are the same eleven prior fixture/configuration mismatches plus two historical active-source-version assertions. No original security test was weakened, skipped or rewritten. One existing frontend test was updated from obsolete CSS bar markup to Bklit data/axis assertions after replacing the visualization.

Phase-start preservation manifest covers 220 existing files: 214 unchanged; only the six authorized frontend presentation files below changed. `scanner.js`, static DLP/recognizers, sanitization/residual verification, behavioral runtime/scoring/enforcement, provider forwarding, configuration, SDK, all historical reports/results and real-model artifacts are byte-for-byte unchanged. The existing layered Phase 4E production-source and Phase 3 artifact hashes were also checked by the full suite runner. No model generation, model downloads, provider calls or benchmark regeneration in this sprint. Development dependency/source downloads are separate from model activity.

## Files changed

Existing files:

- `frontend/dashboard.js`
- `frontend/favicon.svg`
- `frontend/index.html`
- `frontend/server.py`
- `frontend/styles.css`
- `frontend/tests/test_ui_state.js`

New files:

- `docs/FINAL_FRONTEND_INTERACTION_QA.json`
- `docs/FINAL_FRONTEND_PRESENTATION_POLISH.md`
- `docs/FINAL_FRONTEND_TEST_RESULTS.json`
- `docs/FINAL_FRONTEND_VISUAL_QA.json`
- `frontend/assets/BKLIT-LICENSE.txt`
- `frontend/assets/THIRD-PARTY-NOTICES.txt`
- `frontend/assets/charts.css`
- `frontend/assets/charts.js`
- `frontend/charts/.gitignore`
- `frontend/charts/README.md`
- `frontend/charts/build-manifest.json`
- `frontend/charts/build.mjs`
- `frontend/charts/interaction-qa.mjs`
- `frontend/charts/package-lock.json`
- `frontend/charts/package.json`
- `frontend/charts/src/chart-utilities.css`
- `frontend/charts/src/entry.tsx`
- `frontend/charts/src/measured-size.tsx`
- `frontend/charts/vendor/bklit/LICENSE`
- `frontend/charts/vendor/bklit/PROVENANCE.json`
- `frontend/charts/vendor/bklit/charts/animation.ts`
- `frontend/charts/vendor/bklit/charts/bar-chart.tsx`
- `frontend/charts/vendor/bklit/charts/bar-depth-geometry.ts`
- `frontend/charts/vendor/bklit/charts/bar-squares-layout.ts`
- `frontend/charts/vendor/bklit/charts/bar-x-axis.tsx`
- `frontend/charts/vendor/bklit/charts/bar.tsx`
- `frontend/charts/vendor/bklit/charts/chart-child-passthrough.ts`
- `frontend/charts/vendor/bklit/charts/chart-config-context.tsx`
- `frontend/charts/vendor/bklit/charts/chart-context.tsx`
- `frontend/charts/vendor/bklit/charts/chart-defs.ts`
- `frontend/charts/vendor/bklit/charts/chart-formatters.ts`
- `frontend/charts/vendor/bklit/charts/chart-legend-hover.tsx`
- `frontend/charts/vendor/bklit/charts/chart-phase.ts`
- `frontend/charts/vendor/bklit/charts/grid.tsx`
- `frontend/charts/vendor/bklit/charts/indicator-fade.ts`
- `frontend/charts/vendor/bklit/charts/line-loading-timing.ts`
- `frontend/charts/vendor/bklit/charts/loading-sweep.tsx`
- `frontend/charts/vendor/bklit/charts/motion-utils.ts`
- `frontend/charts/vendor/bklit/charts/reference-area-config.ts`
- `frontend/charts/vendor/bklit/charts/reference-area-geometry.ts`
- `frontend/charts/vendor/bklit/charts/tooltip/chart-tooltip.tsx`
- `frontend/charts/vendor/bklit/charts/tooltip/date-ticker.tsx`
- `frontend/charts/vendor/bklit/charts/tooltip/index.ts`
- `frontend/charts/vendor/bklit/charts/tooltip/tooltip-box.tsx`
- `frontend/charts/vendor/bklit/charts/tooltip/tooltip-content.tsx`
- `frontend/charts/vendor/bklit/charts/tooltip/tooltip-dot.tsx`
- `frontend/charts/vendor/bklit/charts/tooltip/tooltip-indicator.tsx`
- `frontend/charts/vendor/bklit/charts/use-chart-interaction.ts`
- `frontend/charts/vendor/bklit/charts/use-grid-shimmer.ts`
- `frontend/charts/vendor/bklit/charts/use-scheduled-tooltip.ts`
- `frontend/charts/vendor/bklit/charts/y-axis-scales.ts`
- `frontend/charts/vendor/bklit/charts/y-axis-ticks.ts`
- `frontend/charts/vendor/bklit/charts/y-axis.tsx`
- `frontend/charts/vendor/bklit/charts/y-domain-utils.ts`
- `frontend/charts/vendor/bklit/lib/utils.ts`
- `frontend/charts/visual-qa.mjs`
- `frontend/local-model.js`
- `frontend/local_results.py`
- `frontend/tests/run_presentation_verification.py`
- `frontend/tests/test_local_results.py`
- `frontend/tests/test_presentation.js`

- `docs/presentation-screenshots/*.png`: desktop and narrow development captures.

Start/review independently of the gateway:

```powershell
& .\.venv\Scripts\python.exe -B frontend/server.py --port 8788
```

No commit or deployment was performed.
