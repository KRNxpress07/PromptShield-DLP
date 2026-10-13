"""Local wall-clock timing with warmup, size strata and real thread concurrency."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import time
from .common import RESULTS, SEED, records, write_csv, write_json
from .metrics import latency_stats, ratio, size_bucket
from .runtime import Runtime


def subset(max_per_group=12):
    import random
    groups = defaultdict(list)
    for row in records('test'):
        groups[(size_bucket(len(row['text'])), row['label'])].append(row)
    rng = random.Random(SEED)
    selected = []
    for key in sorted(groups):
        rng.shuffle(groups[key])
        selected.extend(groups[key][:max_per_group])
    return selected


async def latency():
    rt = Runtime()
    selected, samples = subset(), []
    try:
        for row in selected[:8]:
            await rt.process(row['text'])
            await rt.inspect(row['text'])
        for repeat in range(3):
            for stage in ['scanner_only', 'gateway_dlp']:
                for row in selected:
                    error, action = None, None
                    start = time.perf_counter_ns()
                    try:
                        if stage == 'scanner_only':
                            await rt.process(row['text'])
                        else:
                            action = (await rt.inspect(row['text'])).assessment.action.value
                    except Exception as exc:
                        error = getattr(exc, 'code', type(exc).__name__)
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    nlp_heavy = any(e['entity_type'] in {'PERSON', 'LOCATION', 'DATE_TIME'} for e in row['entities'])
                    samples.append({'stage': stage, 'repeat': repeat + 1, 'id': row['id'], 'chars': len(row['text']), 'size_bucket': size_bucket(len(row['text'])), 'label': row['label'], 'entity_mix': 'nlp_pii' if nlp_heavy else 'structured_or_safe', 'latency_ms': elapsed, 'error': error, 'action': action})
        groups = []
        for stage in ['scanner_only', 'gateway_dlp']:
            base = [r for r in samples if r['stage'] == stage]
            for stratum in ['all', 'size_bucket', 'label', 'entity_mix']:
                values = ['all'] if stratum == 'all' else sorted({r[stratum] for r in base})
                for group in values:
                    entries = base if stratum == 'all' else [r for r in base if r[stratum] == group]
                    successful = [r['latency_ms'] for r in entries if not r['error']]
                    groups.append({'stage': stage, 'stratum': stratum, 'group': group, 'attempts': len(entries), 'errors': sum(bool(r['error']) for r in entries), **latency_stats(successful)})
        write_csv(RESULTS / 'latency_results.csv', samples)
        write_csv(RESULTS / 'latency_summary.csv', groups)
        summary = {'warmup_prompts': 8, 'repeats': 3, 'subset_ids': [r['id'] for r in selected], 'measurements': len(samples), 'groups': groups,
                   'boundary': 'scanner_only: actual ProcessRequest validation + project /process analyze/postprocess, anonymize=False, direct in-process call. gateway_dlp: actual inspect_outbound_payload including scanner JSON serialization/contract/risk/conditional anonymization/rescan through MockTransport. Excludes app startup, HTTP server/middleware/TCP, provider calls and disk artifacts. Logging disabled. Errors excluded from successful latency statistics, raw failure durations retained.',
                   'percentiles': 'Linear interpolation between adjacent sorted samples (index=(n-1)*q); population standard deviation.', 'production_scalability': 'NOT VERIFIED'}
        write_json(RESULTS / 'latency_metrics.json', summary)
        print('Latency samples:', len(samples), 'errors:', sum(bool(r['error']) for r in samples))
    finally:
        await rt.close()
    return summary


def throughput():
    import json
    rt = Runtime()
    selected = subset(6)
    samples, output = [], []
    reference = json.loads((RESULTS / 'project_predictions.json').read_text(encoding='utf-8'))

    def signature(predictions):
        return sorted((p['entity_type'], p['start'], p['end'], p['score']) for p in predictions)
    # Startup and thread-pool construction excluded; submissions, queued work,
    # event-loop setup and all completions included in timed batch wall time.
    def task(row, submitted):
        error = None
        start = time.perf_counter_ns()
        try:
            response = asyncio.run(rt.process(row['text']))
            actual = [r.model_dump() for r in response.results]
            if signature(actual) != signature(reference[row['id']]):
                raise RuntimeError('Concurrent prediction differs from frozen serial result')
        except Exception as exc:
            error = getattr(exc, 'code', type(exc).__name__)
        finish = time.perf_counter_ns()
        return {'id': row['id'], 'service_ms': (finish - start) / 1e6, 'latency_ms': (finish - submitted) / 1e6, 'error': error}

    try:
        for concurrency in [1, 2, 4, 8]:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                # Warm all workers, then submit an identical deterministic batch.
                for future in [executor.submit(task, selected[i % len(selected)], time.perf_counter_ns()) for i in range(concurrency * 2)]:
                    future.result()
                for repeat in range(3):
                    start = time.perf_counter_ns()
                    futures = [executor.submit(task, row, time.perf_counter_ns()) for row in selected]
                    batch = [future.result() for future in as_completed(futures)]
                    seconds = (time.perf_counter_ns() - start) / 1e9
                    for sample in batch:
                        samples.append({'concurrency': concurrency, 'repeat': repeat + 1, **sample})
                    successful = [r['latency_ms'] for r in batch if not r['error']]
                    completed = len(successful)
                    output.append({'concurrency': concurrency, 'repeat': repeat + 1, 'attempted': len(batch), 'completed': completed, 'errors': len(batch) - completed, 'error_rate': ratio(len(batch) - completed, len(batch)), 'wall_seconds': seconds, 'prompts_per_second': completed / seconds, **latency_stats(successful)})
        aggregates = []
        for concurrency in [1, 2, 4, 8]:
            entries = [r for r in output if r['concurrency'] == concurrency]
            corresponding = [r for r in samples if r['concurrency'] == concurrency]
            complete = sum(r['completed'] for r in entries)
            errors = sum(r['errors'] for r in entries)
            seconds = sum(r['wall_seconds'] for r in entries)
            aggregates.append({'concurrency': concurrency, 'completed': complete, 'errors': errors, 'error_rate': errors / (complete + errors), 'wall_seconds': seconds, 'prompts_per_second': complete / seconds, **latency_stats([r['latency_ms'] for r in corresponding if not r['error']])})
        write_csv(RESULTS / 'throughput_results.csv', output)
        write_csv(RESULTS / 'throughput_samples.csv', samples)
        write_json(RESULTS / 'throughput_metrics.json', {'stage': 'scanner_only', 'concurrency_implementation': 'ThreadPoolExecutor; shared read-only analyzer/NLP engine and request-local state; no custom registry mutation. Each worker runs actual /process coroutine. No provider/network. Every completion is checked against its frozen serial type/span/score predictions; mismatch is an error. This comparison overhead is included in timings.', 'repeats': 3, 'subset_ids': [r['id'] for r in selected], 'p95_boundary': 'Submission to finish (includes queue wait), finite closed batch; not steady-state arrival load.', 'aggregates': aggregates, 'production_scalability': 'NOT VERIFIED'})
        for row in aggregates:
            print('Throughput:', row)
    finally:
        asyncio.run(rt.close())
    return aggregates
