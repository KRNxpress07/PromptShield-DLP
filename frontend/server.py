"""Loopback-only dashboard host and read-only, allowlisted research summary.

Independent of the DLP gateway: imports no gateway, scanner or benchmark code.
Run from the repository root: .venv/Scripts/python.exe -B frontend/server.py
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
from pathlib import Path
import re

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

FRONTEND_DIR = Path(__file__).resolve().parent
RESULTS_DIR = FRONTEND_DIR.parent / 'benchmarks' / 'results' / 'latest'
MAX_FILE_BYTES = 5 * 1024 * 1024
ENTITY_TYPES = frozenset('API_KEY AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SESSION_TOKEN PRIVATE_KEY GITHUB_TOKEN SLACK_WEBHOOK JWT_TOKEN BEARER_TOKEN DB_CONNECTION_STRING GENERIC_SECRET_ASSIGNMENT PRIVATE_IP INTERNAL_HOSTNAME EMAIL_ADDRESS PHONE_NUMBER US_SSN MASKED_US_SSN CREDIT_CARD PERSON LOCATION STREET_ADDRESS POSTAL_CODE IP_ADDRESS DATE_TIME IBAN_CODE PROMPT_INJECTION'.split())
DETECTORS = ('regex_simple', 'presidio_builtin', 'project')
COUNTERS = ('tp', 'fp', 'fn', 'tn')
RATES = ('precision', 'recall', 'f1', 'fpr', 'fnr')
TIMINGS = ('mean_ms', 'median_ms', 'p95_ms', 'p99_ms', 'min_ms', 'max_ms', 'stddev_ms')
SANITIZATION_COUNTS = ('test_prompts', 'sensitive_prompts', 'actually_sanitized_sensitive', 'sensitive_outgoing', 'post_rescan_residual_prompts', 'block_subset_prompts', 'block_subset_requests', 'block_check_failures', 'fault_probes', 'human_template_count')
SANITIZATION_RATES = ('sanitization_success_rate', 'residual_leakage_rate_sanitized', 'residual_leakage_rate_all_nonblock_sensitive', 'gold_span_replacement_coverage_rate', 'mean_non_sensitive_char_preservation', 'processing_error_rate')
ASSETS = {'/': 'index.html', '/index.html': 'index.html', '/styles.css': 'styles.css', '/dashboard.js': 'dashboard.js', '/scanner.js': 'scanner.js', '/favicon.svg': 'favicon.svg'}


class InvalidArtifact(ValueError):
    pass


def number(value, *, rate=False, integer=False, nullable=True):
    if value is None and nullable:
        return None
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise InvalidArtifact()
    if rate and value > 1 or integer and type(value) is not int:
        raise InvalidArtifact()
    return value


def mapping(value):
    if not isinstance(value, dict):
        raise InvalidArtifact()
    return value


def metric(value):
    value = mapping(value)
    return {**{k: number(value.get(k), integer=True) for k in COUNTERS}, **{k: number(value.get(k), rate=True) for k in RATES}}


def read_artifact(name):
    # Every caller supplies a literal allowlisted name, never a request/path value.
    if name not in {'metrics.json', 'per_entity_metrics.csv', 'false_positives.csv', 'sanitization_results.csv'}:
        raise InvalidArtifact()
    path = RESULTS_DIR / name
    if path.stat().st_size > MAX_FILE_BYTES:
        raise InvalidArtifact()
    return path.read_text(encoding='utf-8')


def summary():
    raw = mapping(json.loads(read_artifact('metrics.json')))
    dataset = mapping(raw.get('dataset'))
    labels = mapping(dataset.get('labels'))
    output = {
        'available': True, 'source': 'Phase 3 · frozen synthetic test set',
        'dataset': {**{k: number(dataset.get(k), integer=True, nullable=False) for k in ('total', 'dev', 'test')}, 'safe': number(labels.get('safe'), integer=True, nullable=False), 'sensitive': number(labels.get('sensitive'), integer=True, nullable=False)},
        'detection': {}, 'per_entity': [], 'sanitization': None, 'latency': [], 'throughput': [], 'tests': {}, 'false_positive_examples': [], 'sanitization_example': None, 'warnings': [],
    }
    started = raw.get('run_started_utc')
    output['run_started_utc'] = started if isinstance(started, str) and re.fullmatch(r'[0-9T:.+Z-]{10,40}', started) else None
    sha = raw.get('dataset_sha256')
    output['dataset_sha256'] = sha if isinstance(sha, str) and re.fullmatch(r'[a-f0-9]{64}', sha) else None
    detectors = mapping(raw.get('detectors'))
    for name in DETECTORS:
        detector = mapping(detectors.get(name))
        output['detection'][name] = {k: metric(detector.get(k)) for k in ('prompt', 'strict_span', 'relaxed_span')}
        subsets = mapping(detector.get('safe_subsets'))
        output['detection'][name]['safe_subsets'] = {k: metric(subsets.get(k)) for k in ('ordinary', 'hard_negative')}
        difficulty = mapping(detector.get('difficulty'))
        output['detection'][name]['difficulty'] = {k: {'prompts': number(mapping(difficulty.get(k)).get('prompts'), integer=True), **{level: metric(mapping(difficulty.get(k)).get(level)) for level in ('prompt', 'strict_span', 'relaxed_span')}} for k in ('easy', 'medium', 'hard')}
    if isinstance(raw.get('sanitization'), dict):
        value = raw['sanitization']
        output['sanitization'] = {**{k: number(value.get(k), integer=True) for k in SANITIZATION_COUNTS}, **{k: number(value.get(k), rate=True) for k in SANITIZATION_RATES}, 'actions': {k: number(mapping(value.get('actions')).get(k), integer=True) for k in ('block', 'warn', 'mask', 'allow')}, 'human_ratings': 'PENDING HUMAN EVALUATION'}
    if isinstance(raw.get('latency'), dict):
        groups = raw['latency'].get('groups')
        if not isinstance(groups, list):
            raise InvalidArtifact()
        for group in groups:
            mapping(group)
            if group.get('stage') not in {'scanner_only', 'gateway_dlp'} or group.get('stratum') not in {'all', 'size_bucket', 'label', 'entity_mix'}:
                continue
            if group.get('group') not in {'all', 'small', 'medium', 'large', 'very_large', 'safe', 'sensitive', 'nlp_pii', 'structured_or_safe'}:
                continue
            output['latency'].append({k: group[k] for k in ('stage', 'stratum', 'group')} | {'count': number(group.get('count'), integer=True), 'errors': number(group.get('errors'), integer=True)} | {k: number(group.get(k)) for k in TIMINGS})
    if isinstance(raw.get('throughput'), dict):
        groups = raw['throughput'].get('aggregates')
        if not isinstance(groups, list):
            raise InvalidArtifact()
        for group in groups:
            mapping(group)
            if group.get('concurrency') not in (1, 2, 4, 8):
                continue
            output['throughput'].append({'workers': group['concurrency'], 'completed': number(group.get('completed'), integer=True), 'errors': number(group.get('errors'), integer=True), 'error_rate': number(group.get('error_rate'), rate=True), 'prompts_per_second': number(group.get('prompts_per_second')), 'p95_ms': number(group.get('p95_ms'))})
    if isinstance(raw.get('tests'), dict):
        for name in ('gateway', 'scanner', 'sdk', 'framework'):
            if isinstance(raw['tests'].get(name), dict):
                output['tests'][name] = {k: number(raw['tests'][name].get(k), integer=True) for k in ('passed', 'failed', 'skipped', 'phase1_passed', 'phase2_passed')}
    try:
        rows = csv.DictReader(io.StringIO(read_artifact('per_entity_metrics.csv')))
        entities = {}
        for row in rows:
            if row.get('detector') != 'project' or row.get('entity') not in ENTITY_TYPES or row.get('level') not in {'strict', 'relaxed', 'prompt'}:
                continue
            level = row['level']
            item = entities.setdefault(row['entity'], {'entity': row['entity']})
            values = metric({k: (int(row[k]) if k in COUNTERS else float(row[k])) if row.get(k) else None for k in (*COUNTERS, *RATES)})
            item[level] = values
        output['per_entity'] = [value for _, value in sorted(entities.items()) if all(k in value for k in ('strict', 'relaxed', 'prompt'))]
    except FileNotFoundError:
        output['warnings'].append('Per-entity data not available.')
    # Only public/benign matched fragments are exposed. Never return raw CSV
    # prompts, credentials, predictions, paths, environment or manifest contents.
    public_fragments = {'1.2.3', '192.0.2.1', '203.0.113.7', 'January 15, 2025', 'January 15', '2024-05-21'}
    try:
        seen = set()
        for row in csv.DictReader(io.StringIO(read_artifact('false_positives.csv'))):
            pair = (row.get('matched_text'), row.get('entity_type'))
            if row.get('label') == 'safe' and pair[0] in public_fragments and pair[1] in {'DATE_TIME', 'IP_ADDRESS'} and pair not in seen:
                seen.add(pair)
                output['false_positive_examples'].append({'text': pair[0], 'entity': pair[1]})
    except FileNotFoundError:
        output['warnings'].append('False-positive examples not available.')
    try:
        for row in csv.DictReader(io.StringIO(read_artifact('sanitization_results.csv'))):
            original, sanitized = row.get('original_prompt', ''), row.get('sanitized_prompt', '')
            if row.get('id') == 's-email_address-03' and re.fullmatch(r'Help redact the following demonstration record before sharing: synthetic\d+@example\.com', original):
                if sanitized == re.sub(r'synthetic\d+@example\.com', '[REDACTED]', original):
                    output['sanitization_example'] = {'original': original, 'sanitized': sanitized}
                    break
    except FileNotFoundError:
        output['warnings'].append('Sanitization example not available.')
    return output


app = FastAPI(title='PromptShield Research Dashboard', docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware('http')
async def secure_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http: https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response


@app.get('/v1/benchmark/summary')
def benchmark_summary(request: Request):
    if request.query_params:
        return JSONResponse(status_code=422, content={'available': False, 'error': 'unsupported_query', 'message': 'This endpoint accepts no parameters.'})
    try:
        return summary()
    except FileNotFoundError:
        return JSONResponse(status_code=503, content={'available': False, 'error': 'benchmark_unavailable', 'message': 'Benchmark results not available.'})
    except (OSError, ValueError, TypeError, KeyError, csv.Error, OverflowError):
        return JSONResponse(status_code=503, content={'available': False, 'error': 'benchmark_invalid', 'message': 'Benchmark results could not be validated.'})


@app.get('/{asset:path}')
def frontend_asset(asset: str):
    filename = ASSETS.get('/' + asset)
    if filename is None:
        return JSONResponse(status_code=404, content={'error': 'not_found'})
    return FileResponse(FRONTEND_DIR / filename)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Serve the dashboard on loopback only; DLP gateway stays separate.')
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('port must be between 1024 and 65535')
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=args.port, log_level='warning')
