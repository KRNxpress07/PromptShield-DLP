"""Generate faculty methodology/results directly from recorded observations."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from .common import DATA, ENTITY_TYPES, ROOT, RESULTS, digest, production_hashes, records, write_json


def load(name):
    path = RESULTS / name
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


def table(headers, rows):
    def escape(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |'] + ['| ' + ' | '.join(escape(v) for v in row) + ' |' for row in rows])


def pct(value):
    return f'{100 * value:.2f}%' if value is not None else 'NOT VERIFIED / undefined'


def num(value):
    return f'{value:.3f}' if value is not None else 'NOT VERIFIED'


def csv_rows(name):
    path = RESULTS / name
    return list(csv.DictReader(path.open(encoding='utf-8'))) if path.exists() else []


def failure_reason(node):
    if 'test_missing_file_returns_empty' in node:
        return 'Existing config fallback returns repository YAML; test expects empty without isolating fallback.'
    if any(s in node for s in ['test_ssn_detected', 'test_ssn_dash_format_no_datetime', 'test_non_overlapping_entities_kept']):
        return 'Known sample 123-45-6789 is deliberately excluded by Presidio; invalid benchmark expectation.'
    if any(s in node for s in ['test_card_expiry_slash', 'test_cvv_after_keyword']):
        return 'Expiry/CVV expected as CREDIT_CARD; separate unsupported PCI category.'
    if any(s in node for s in ['test_full_pci_payload_all_redacted', 'test_mixed_pci_hipaa_prompt']):
        return 'Mixed checksum-invalid card, unsupported expiry/CVV and/or invalid SSN fixtures.'
    return 'Checksum-invalid card fixture; Luhn validation intentionally retained.'


def main():
    metrics = load('metrics.json')
    if metrics is None:
        raise RuntimeError('Detection results NOT VERIFIED: metrics.json absent')
    sanitization, latency, throughput, tests = [load(name) for name in ['sanitization_metrics.json', 'latency_metrics.json', 'throughput_metrics.json', 'test_results.json']]
    frozen = json.loads((DATA / 'production_freeze.json').read_text())
    assert production_hashes() == frozen, 'Production source/policy changed'
    # Keep initial detector observations separate from the combined report file.
    if not (RESULTS / 'detection_metrics.json').exists():
        write_json(RESULTS / 'detection_metrics.json', metrics)
    combined = {**metrics, 'sanitization': sanitization or 'NOT VERIFIED', 'latency': latency or 'NOT VERIFIED', 'throughput': throughput or 'NOT VERIFIED', 'tests': tests or 'NOT VERIFIED'}
    write_json(RESULTS / 'metrics.json', combined)
    dataset, detectors = metrics['dataset'], metrics['detectors']
    test_rows = records('test')
    dev_rows = records('dev')
    per_entity = csv_rows('per_entity_metrics.csv')
    fp, fn = csv_rows('false_positives.csv'), csv_rows('false_negatives.csv')
    chunks = ['# Phase 3 Academic Evaluation',
              f'\nRecorded local experiment started **{metrics["run_started_utc"]}**. Dataset `{metrics["environment"]["dataset_version"]}`, seed `{metrics["environment"]["seed"]}`, SHA-256 `{metrics["dataset_sha256"]}`. Production source/policy hashes match the pre-result freeze. Phase 3 changes are isolated to `benchmarks/` and this report; no detector, application policy, SDK, frontend or regression test was changed.',
              '## Research questions',
              'RQ1: How accurately does the system detect protected sensitive data in LLM prompts?\n\nRQ2: How effectively does sanitization remove sensitive information while preserving prompt utility?\n\nRQ3: What runtime overhead does local DLP inspection introduce?\n\nRQ4: How does the project compare with simpler baselines?',
              '## Dataset',
              table(['Property', 'Recorded count'], [['Total prompts', dataset['total']], ['Safe / sensitive', f'{dataset["labels"]["safe"]} / {dataset["labels"]["sensitive"]}'], ['Development / test', f'{dataset["dev"]} / {dataset["test"]}'], ['Held-out test safe / sensitive', f'{sum(r["label"]=="safe" for r in test_rows)} / {sum(r["label"]=="sensitive" for r in test_rows)}'], ['Ordinary safe / hard negatives (whole corpus)', '160 / 240'], ['Labeled spans (whole corpus / test)', f'{sum(dataset["entities"].values())} / {sum(len(r["entities"]) for r in test_rows)}']]),
              'All values are authored synthetic/hypothetical fixtures: repeated SYNTHETIC key bodies, dummy PEM payloads, unsigned dummy JWT signatures, example-domain emails, documentation IPs, test-card/sample-IBAN shapes and fictional identity fields. No environment file, credential value, production record, external dataset, live secret-validation endpoint or external LLM is used. Structural PII validity does not establish that a number is unassigned; no linkage to a real person is asserted. `validate_dataset` verifies exact regeneration from this authored source and hashes; that provenance check is not a universal real-secret detector.',
              'Sensitive records include 520 single-value records and 80 multi-value records, spanning short/prose/code/log/config/CSV/tool/schema/nested/markdown/JSON/long contexts. Twenty insertion/context families vary wording and structure; values vary by entity, and some repeat. The 400 safe records use 40 ordinary topic families and 60 hard-negative families, with four presentation variants each. This is a manageable template-based corpus, not 1,000 independent real-world scenarios.',
              table(['Category', 'Prompts'], sorted(dataset['categories'].items())),
              table(['Category', 'Dev prompts', 'Test prompts'], [[category, sum(r['category'] == category for r in dev_rows), sum(r['category'] == category for r in test_rows)] for category in sorted(dataset['categories'])]),
              table(['Difficulty (all labels)', 'Prompts'], sorted(dataset['difficulty'].items())),
              'Each sensitive span has type, Python Unicode character start/end (half-open), exact source text, difficulty and synthetic-source metadata. Easy means canonical/short; medium means embedded structured/prose contexts; hard means unusual boundaries, multi-value or longer/nested records. Safe difficulty is recorded but sensitive-only difficulty metrics are reported separately.',
              'The split holds whole template/topic families together: 30% development and 70% test within each family stratum, with seed 20261013 and persisted IDs. Test content was frozen before detector observations, and recognizers were not tuned afterward. Developers authored the formats with detector knowledge; this is not a blind externally annotated holdout. Both splits share entity/value families, so leakage of familiar formats remains a threat.',
              'Grouping entire context families means some structures (notably the single-value CSV/config families) occur only in development. Their presence in the corpus does not establish final-test coverage for those structures. The per-split category table makes this visible; no final-test result is substituted with a development score.',
              'One canonical type is annotated per inserted value. Secondary nested labels, e.g. IP_ADDRESS inside PRIVATE_IP or LOCATION inside an address, may count as extra span predictions. This penalizes some taxonomically defensible overlaps. Partial assignment spans can also fail exact matching. The annotation policy was frozen, not revised to improve scores. Public/documentation names, dates, IPs and attack quotations are task-benign safe controls even when the current policy protects their shape; false positives in this group expose a policy/intent conflict.',
              '## Metrics',
              'Let TP, FP, FN, TN refer to the stated unit. Precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2TP/(2TP+FP+FN); FPR = FP/(FP+TN); FNR = FN/(FN+TP). Zero denominators are JSON null and reported as undefined/NOT VERIFIED; no artificially perfect defaults.',
              '**Prompt-level:** sensitive if any gold protected entity exists; predicted sensitive if any configured protected finding exists. A wrong-type detection still classifies the prompt as sensitive. Processing errors emit no predictions, remain in denominators and count as FN on sensitive prompts; they are also reported separately, not described as safe forwarding.',
              '**Headline span-level:** same entity type and exact start/end. Matching is maximum-cardinality one-to-one, not greedy or many-to-one. Unmatched predictions are FP and unmatched gold spans FN. **Secondary relaxed:** same type and intersection/gold-span length >=0.5, with the same one-to-one matching. A broad span can meet this rule, so it does not prove precise removal. Span TN/FPR are undefined: no finite natural universe of negative character spans was invented. Per-entity prompt occurrence has legitimate TN/FPR and is exported alongside strict/relaxed span metrics.',
              'Entity confusion uses type-agnostic relaxed matching, prefers same-type candidates and retains MISSED/SPURIOUS counts. It distinguishes taxonomy disagreement from no overlapping detection; it is descriptive, not a replacement for strict scores.',
              'Sanitization success = successful actually-sanitized sensitive prompts / actually-sanitized sensitive prompts, requiring full gold offset coverage by replacement spans, no exact gold substring in outgoing text and no protected post-rescan finding. Exact residual leakage is any surviving full gold substring. Denominators are reported for actually sanitized prompts and for ALL non-block sensitive outputs including detector misses. Full-value absence alone misses partial content; gold replacement coverage is reported separately. Block verification failure rate = failed no-provider/status checks / representative checked requests. Processing error rate excludes expected policy blocks.',
              'Local latency is elapsed perf_counter_ns converted to milliseconds. Mean, median, min, max, population SD and linearly interpolated P95/P99 are computed over successful measurements; failures are counted and raw failure durations retained. Throughput = successful completions / timed batch wall seconds; error rate = failed attempts / total attempts. Structural preservation = ordered unchanged non-sensitive source characters aligned into output / non-sensitive source characters, with [REDACTED] removed from the alignment. It is not semantic utility.',
              '## Baselines',
              'Baseline A (`regex_simple`) is a small independent regex set for email, marked phone, card-shaped numbers, dotted IP, SSN shape, legacy sk keys and AKIA IDs. It imports no project recognizer patterns and has no checksum/NER/context/postprocessing. Baseline B (`presidio_builtin`) is a fresh installed AnalyzerEngine using the same NLP engine and confidence threshold 0.4, restricted to nine common protected built-in types: EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, PERSON, LOCATION, IP_ADDRESS, DATE_TIME and IBAN_CODE. It does not register project additions, custom SSN validation or project post-processing.',
              'Unsupported custom labels are counted as misses in full-scope baseline scores because coverage is part of RQ4. `supported_label_strict_span` also provides a secondary within-supported-label score in metrics.json; do not present full-scope improvement as superiority of all common PII recognizers. No optional ablation was introduced. Project detection uses the actual /process analyzer and postprocessor with the frozen default 26-entity policy; no risk decisions are treated as ground-truth detections.',
              '## Detection results']
    comparison = []
    for detector, data in detectors.items():
        for level in ['prompt', 'strict_span', 'relaxed_span']:
            m = data[level]
            comparison.append([detector, level, m['tp'], m['fp'], m['fn'], m['tn'] if m['tn'] is not None else 'undefined', pct(m['precision']), pct(m['recall']), pct(m['f1']), pct(m['fpr']), pct(m['fnr'])])
    chunks.append(table(['Detector', 'Unit', 'TP', 'FP', 'FN', 'TN', 'Precision', 'Recall', 'F1', 'FPR', 'FNR'], comparison))
    chunks.append('The project detects more protected categories on this frozen synthetic corpus. Its higher recall/F1 coexists with a higher prompt FPR than both baselines; this is an observed tradeoff, not a universal superiority claim. No confidence intervals or significance tests were computed; template clustering and small per-entity support limit inference.')
    chunks.append('## Per-entity results')
    entity_table = []
    for entity in ENTITY_TYPES:
        strict = next(r for r in per_entity if r['entity'] == entity and r['level'] == 'strict')
        relaxed = next(r for r in per_entity if r['entity'] == entity and r['level'] == 'relaxed')
        occurrence = next(r for r in per_entity if r['entity'] == entity and r['level'] == 'prompt')
        entity_table.append([entity, dataset['entities'][entity], int(strict['tp']) + int(strict['fn']), pct(float(strict['precision'])) if strict['precision'] else 'undefined', pct(float(strict['recall'])) if strict['recall'] else 'undefined', pct(float(strict['f1'])) if strict['f1'] else 'undefined', pct(float(relaxed['f1'])) if relaxed['f1'] else 'undefined', pct(float(occurrence['fpr'])) if occurrence['fpr'] else 'undefined'])
    chunks.append(table(['Type', 'Whole-corpus spans', 'Test spans', 'Strict P', 'Strict R', 'Strict F1', 'Relaxed F1', 'Prompt occurrence FPR'], entity_table))
    chunks.append('## Difficulty results')
    chunks.append(table(['Sensitive difficulty', 'Test prompts', 'Prompt recall', 'Strict span F1', 'Relaxed span F1'], [[d, g['prompts'], pct(g['prompt']['recall']), pct(g['strict_span']['f1']), pct(g['relaxed_span']['f1'])] for d, g in detectors['project']['difficulty'].items()]))
    chunks.append('## Hard-negative results')
    chunks.append(table(['Detector', 'Safe subset', 'FP', 'TN', 'FPR'], [[name, kind, m['fp'], m['tn'], pct(m['fpr'])] for name, data in detectors.items() for kind, m in data['safe_subsets'].items()]))
    chunks.append('A safe subset has no positive gold records: recall/FNR are undefined, not evidence of perfect detection. Prompt FPR and FP/TN counts are the meaningful statistics here. Check public names/dates/IPs and conceptual attack quotations separately from invalid key/card/phone negatives when interpreting the 51 project safe-prompt detections.')
    chunks.append('## Sanitization results')
    if sanitization:
        chunks.append(table(['Measurement', 'Observed value'], [[k, pct(sanitization[k]) if 'rate' in k or k.startswith('mean_non_sensitive') else sanitization[k]] for k in ['sensitive_prompts', 'actually_sanitized_sensitive', 'sensitive_outgoing', 'sanitization_success_rate', 'residual_leakage_rate_sanitized', 'residual_leakage_rate_all_nonblock_sensitive', 'gold_span_replacement_coverage_rate', 'post_rescan_residual_prompts', 'mean_non_sensitive_char_preservation', 'block_subset_prompts', 'block_subset_requests', 'block_check_failures']]))
        chunks.append('Zero full-value leakage among changed prompts does not establish zero egress leakage. Five missed sensitive prompts are allowed unchanged; two changed prompts have incomplete gold-span coverage even though the full original substring is absent and the same detector rescans clean. Exact-substring leakage is insensitive to partial/encoded/semantic remnants. Representative ASGI gateway block checks use the actual scanner and two mocked forwarders in both stream modes; safe false-positive controls are included. Three additional deliberate fault probes verify unsupported image, unavailable scanner and retained-value sanitization rejection, with no provider call.')
    else:
        chunks.append('NOT VERIFIED: sanitization metrics absent.')
    chunks += ['## Information preservation', '**PENDING HUMAN EVALUATION.** No human scores or external LLM ratings are invented. The template contains ' + str(sanitization['human_template_count'] if sanitization else 'NOT VERIFIED') + ' deterministically selected synthetic original/sanitized pairs with exact spans, blank 1–5 task-understandability/information-preservation/meaning-damage fields, yes/no usability, rater ID and comments. Use two independent raters and retain disagreements. Automated character alignment, placeholder counts and conditional JSON validity are secondary structural measures; they cannot establish intended-task success or semantic preservation.', '## Latency results']
    if latency:
        overall = [r for r in latency['groups'] if r['stratum'] == 'all']
        chunks.append(table(['Stage', 'Successful n', 'Errors', 'Mean ms', 'Median ms', 'P95 ms', 'P99 ms', 'Min ms', 'Max ms', 'SD ms'], [[r['stage'], r['count'], r['errors']] + [num(r[k]) for k in ['mean_ms', 'median_ms', 'p95_ms', 'p99_ms', 'min_ms', 'max_ms', 'stddev_ms']] for r in overall]))
        chunks.append(table(['Stage', 'Size bucket', 'n', 'Mean ms', 'P95 ms'], [[r['stage'], r['group'], r['count'], num(r['mean_ms']), num(r['p95_ms'])] for r in latency['groups'] if r['stratum'] == 'size_bucket']))
        chunks.append(table(['Stage', 'Label', 'n', 'Mean ms', 'P95 ms'], [[r['stage'], r['group'], r['count'], num(r['mean_ms']), num(r['p95_ms'])] for r in latency['groups'] if r['stratum'] == 'label']))
        chunks.append(f'Warmup: {latency["warmup_prompts"]} prompts per stage. Repetitions: {latency["repeats"]}. Fixed stratified subset: {len(latency["subset_ids"])} prompts. Size buckets: <=100, 101–500, 501–2000, >=2001 characters. Some label/bucket combinations do not exist in this corpus; absent groups are not imputed. NLP-heavy/structured grouping is also exported. ' + latency['boundary'])
    else:
        chunks.append('NOT VERIFIED: latency metrics absent.')
    chunks.append('## Throughput results')
    if throughput:
        chunks.append(table(['Scanner workers', 'Completed', 'Errors', 'Error rate', 'Prompts/s', 'Queued P95 ms'], [[r['concurrency'], r['completed'], r['errors'], pct(r['error_rate']), num(r['prompts_per_second']), num(r['p95_ms'])] for r in throughput['aggregates']]))
        chunks.append('Each concurrency uses the same fixed ' + str(len(throughput['subset_ids'])) + '-prompt subset and three repetitions, preceded by 2×worker-count warmup tasks. ' + throughput['concurrency_implementation'] + ' ' + throughput['p95_boundary'] + ' Submission and completion overhead are included in batch wall time; initialization/thread creation is excluded. Increased worker count can increase queued latency or reduce throughput on this CPU-bound workload. This measures a finite in-process batch, not TCP serving capacity or production scalability.')
    else:
        chunks.append('NOT VERIFIED: throughput metrics absent.')
    chunks.append('## Environment and reproducibility')
    env = metrics['environment']
    chunks.append(table(['Property', 'Recorded value'], [[k, env[k]] for k in ['os', 'python', 'cpu', 'logical_cpus', 'ram_bytes', 'network']]))
    chunks.append(table(['Installed dependency/model', 'Version'], sorted(env['dependencies'].items())))
    chunks.append('The evaluated NLP model is installed `en_core_web_lg` 3.8.0, selected by the actual AnalyzerEngine default. Dependency distribution versions are recorded, not newly installed or pinned by this phase. Source, corpus, split, benchmark-code and output hashes plus the complete installed-package version map are retained in `run_manifest.json`. Exact detector predictions and counters should reproduce in this environment; timing varies with OS background load, thermal state, thread scheduling and other hardware. Performance stages ran sequentially without overlapping application tests or other benchmark processes; unrelated OS load was not controlled.')
    chunks.append('Run `python -B -m benchmarks.scripts.run_all` from the repository root in the existing .venv. It archives an existing latest run before repeating. See `benchmarks/README.md` for individual commands, human-rating instructions and units. No external request is needed. Missing model/dependency/metric fails or is explicitly NOT VERIFIED. No heavy plotting dependency was added; matplotlib is not installed, so optional PNG charts were omitted.')
    chunks.append('## Error analysis')
    chunks.append(table(['Synthetic false-positive example', 'Predicted type', 'Record'], [[r['matched_text'], r['entity_type'], r['id']] for r in [r for r in fp if r['label'] == 'safe'][:10]]))
    chunks.append(table(['Synthetic strict-span miss', 'Gold type', 'Record'], [[r['ground_truth'], r['entity_type'], r['id']] for r in fn[:10]]))
    chunks.append('Strict-span misses include correct-type detections with punctuation/quote boundary extensions and genuine sensitivity misses. Prompt misses include trailing-period JWT/internal-hostname contexts and NER misses in terse JSON/markup. The five unchanged outputs are `s-jwt_token-09`, `s-internal_hostname-09`, `s-person-17`, `s-location-17`, and `s-location-19`. Partial-removal failures include `s-person-19` (surname survives) and `s-date_time-19` (leading day survives). Full false-positive/false-negative prompts and entity-confusion counts are inspectable in CSV/JSON. These findings are reported without changing production rules.')
    if sanitization:
        chunks.append(table(['Observed natural event', 'Count'], [[k, sanitization['error_counts'].get(k, 0)] for k in ['scanner_processing_error', 'security_processing_error', 'unsupported_dlp_content', 'pii_policy_violation', 'sanitization_verification_failed']]))
        chunks.append(f'Natural gateway processing-error rate: {pct(sanitization["processing_error_rate"])}. Expected policy blocks: {sanitization["actions"].get("block", 0)}; these are not accuracy-processing errors. Fault-probe outcomes are separate in block_effectiveness.csv. A zero natural error rate does not measure fault tolerance under arbitrary system failures.')
    chunks.append('An initial sanitization helper run failed while selecting a blocked safe record with no ground-truth spans. Its partial raw observations and failure description are preserved under `benchmarks/results/initial_helper_failure/`. Only evaluation selection/counting logic was fixed; the scanner, policy, labels and frozen detection results were unchanged. The completed sanitization run replaced no detector result. This is distinct from a production scanner failure.')
    chunks.append('The first valid throughput measurement is retained under `benchmarks/results/throughput_initial/`. The final run additionally compares every concurrent type/span/score output with its frozen serial prediction to check shared-engine stability; comparison overhead is included. Both timing runs remain inspectable, with no recognizer or corpus changes.')
    chunks.append('## Regression verification')
    if tests:
        valid = [v for v in tests.values() if 'passed' in v]
        totals = {k: sum(v[k] for v in valid) for k in ['passed', 'failed', 'skipped']}
        chunks.append(table(['Suite', 'Passed', 'Failed', 'Skipped', 'Exit'], [[name, v.get('passed', 'NOT VERIFIED'), v.get('failed', 'NOT VERIFIED'), v.get('skipped', 'NOT VERIFIED'), v.get('exit_code')] for name, v in tests.items()] + [['TOTAL', totals['passed'], totals['failed'], totals['skipped'], '—']]))
        chunks.append(f'Phase 1 regression cases: {sum(v.get("phase1_passed", 0) for v in valid)} passed. Phase 2 cases: {sum(v.get("phase2_passed", 0) for v in valid)} passed. No existing test was edited, skipped, xfailed or deleted. Application-only totals remain 565 passed / 11 failed / 0 skipped; framework tests are additional. Full test logs, exact pytest arguments and node IDs are retained.')
        failures = [[name, node, failure_reason(node)] for name, v in tests.items() for node in v.get('failures', [])]
        chunks.append(table(['Suite', 'Every remaining failure', 'Reason'], failures))
    else:
        chunks.append('NOT VERIFIED: test results absent.')
    chunks += ['## Limitations',
               'This evaluation does not establish live credential validity, general multilingual/organization confidentiality accuracy, every provider-forwarded field, attachment/OCR coverage, fragmented/encoded secrets, numeric JSON PII, output DLP, production traffic behavior, networking overhead or external LLM latency. Tool/schema records are text renderings, while real nested-field enforcement remains covered by Phase 2 regressions. Exact-value leakage does not detect every partial remnant. Only a representative block subset was checked at actual gateway routes. No semantic score exists before human ratings. Per-entity support is small, and the canonical taxonomy can over-penalize legitimate secondary labels.',
               '## Threats to validity',
               '- **Synthetic/template bias:** Repeated value/context families differ from natural traffic and can favor deterministic patterns. Synthetic key body artifacts can also confuse NER.\n- **Detector-aware construction:** Categories and formats were authored with knowledge of supported rules; freezing and a family split prevent tuning this run but do not eliminate design bias.\n- **Annotation/policy bias:** One canonical label per insertion and benign public-control labels can count valid protected-shape detections as false positives. No independent annotation adjudication occurred.\n- **English-heavy data:** NLP contexts and addresses predominantly English; no claim across languages/geographies.\n- **No live secret validation:** Shapes are not evidence of issued/usable credentials or identifiers.\n- **Hardware dependence:** One laptop CPU/environment, finite threaded in-process batches, uncontrollable background load, no steady-state/production network study.\n- **Limited human evaluation:** Ratings pending; automated preservation does not measure semantics.\n- **No production traffic or external LLM latency:** Provider boundary is mocked; accuracy and latency apply only to this corpus and local inspection.\n- **Statistical uncertainty:** No confidence intervals/significance tests; correlated templates and small entity counts restrict generalization.',
               '## Changed and created files',
               'All Phase 3 files are listed in `benchmarks/results/latest/phase3_changed_files.txt`, with hash provenance in `run_manifest.json`. They consist of benchmark dataset/splits/freeze metadata, isolated scripts, framework tests, reproducibility README, raw JSON/CSV/test logs, the retained failed-helper observations and this generated report. Pre-existing Phase 1/2 working-tree edits remain uncommitted and preserved.',
               '## Conclusions',
               'RQ1: On this frozen synthetic holdout, the project has high prompt recall but measurable hard-negative false positives and lower exact-span accuracy. RQ2: Actually changed outputs remove complete labeled values in this run, yet missed prompts leak unchanged values and two changed outputs retain partial span content; utility ratings remain pending. RQ3: Local inspection overhead and finite-batch throughput are measured for this environment, with server/network/provider latency excluded. RQ4: The custom integration has higher full-scope recall/F1 than the chosen simpler baselines on this corpus, with a higher prompt FPR; no universal PII superiority, novelty or production-readiness claim follows.',
               '**VERIFIED:** Frozen corpus, machine-readable detection/span/sanitization/performance outputs, baseline comparison and preservation of existing security regressions. **PENDING HUMAN EVALUATION:** Intent/utility ratings. **NOT VERIFIED:** Deployment scalability, live adapters/credential validity, real-world generalization, statistical significance and semantic preservation.']
    report = ROOT / 'docs/PHASE3_ACADEMIC_EVALUATION_REPORT.md'
    report.write_text('\n\n'.join(chunks) + '\n', encoding='utf-8')
    changed = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / 'benchmarks').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    changed.append(report.relative_to(ROOT).as_posix())
    # Include the generated inventory/manifest themselves in the file list.
    changed = sorted(set(changed) | {'benchmarks/results/latest/phase3_changed_files.txt', 'benchmarks/results/latest/run_manifest.json'})
    (RESULTS / 'phase3_changed_files.txt').write_text('\n'.join(changed) + '\n', encoding='utf-8')
    import importlib.metadata
    distributions = {d.metadata['Name']: d.version for d in importlib.metadata.distributions() if d.metadata['Name']}
    provenance = {'dataset_sha256': digest(DATA / 'dlp_benchmark.jsonl'), 'source_preserved': production_hashes() == frozen,
                  'benchmark_code_hashes': {p.relative_to(ROOT).as_posix(): digest(p) for p in (ROOT / 'benchmarks').rglob('*.py')},
                  'installed_distributions': dict(sorted(distributions.items())), 'output_hashes': {p.relative_to(ROOT).as_posix(): digest(p) for p in RESULTS.iterdir() if p.is_file() and p.name != 'run_manifest.json'}, 'report_sha256': digest(report)}
    write_json(RESULTS / 'run_manifest.json', provenance)
    print('\nDataset:', dataset['total'], 'safe:', dataset['labels']['safe'], 'sensitive:', dataset['labels']['sensitive'], 'dev/test:', dataset['dev'], '/', dataset['test'])
    print('Detection (prompt):', {k: detectors['project']['prompt'][k] for k in ['precision', 'recall', 'f1', 'fpr', 'fnr']})
    print('Detection (strict span):', detectors['project']['strict_span'])
    print('Sanitization:', {k: sanitization[k] for k in ['sanitization_success_rate', 'residual_leakage_rate_sanitized', 'residual_leakage_rate_all_nonblock_sensitive']} if sanitization else 'NOT VERIFIED')
    print('Latency:', [{k: r[k] for k in ['stage', 'mean_ms', 'median_ms', 'p95_ms']} for r in latency['groups'] if r['stratum'] == 'all'] if latency else 'NOT VERIFIED')
    print('Throughput:', [{k: r[k] for k in ['concurrency', 'prompts_per_second', 'error_rate']} for r in throughput['aggregates']] if throughput else 'NOT VERIFIED')
    print('Baseline prompt F1:', {name: data['prompt']['f1'] for name, data in detectors.items()})
    print('Tests:', totals if tests else 'NOT VERIFIED')
    print('Report:', report)
    print('Changed/created files:')
    print('\n'.join(changed))
    return combined


if __name__ == '__main__':
    main()
