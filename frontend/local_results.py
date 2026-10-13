"""Allowlisted aggregate view of saved Phase 4E evidence; no inference imports."""
import csv
import io
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 5 * 1024 * 1024
FILES = {'validation': 'docs/PHASE4E_REAL_MODEL_VALIDATION.json',
         'results': 'benchmarks/behavioral_real/results_llama32.json',
         'comparison': 'benchmarks/behavioral_real/comparison.json',
         'latency': 'benchmarks/behavioral_real/latency.csv'}
STAGES = ('plain_generation', 'tool_support', 'public_read', 'protected_read_probe', 'network_probe', 'gateway_preflight')

def read(key):
    path = ROOT / FILES[key]
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('artifact too large')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('artifact too large')
    return data.decode('utf-8')

def obj(value):
    if type(value) is not dict:
        raise ValueError('invalid object')
    return value

def num(value, *, rate=False, integer=False, nullable=False):
    if value is None and nullable:
        return None
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid number')
    if rate and value > 1 or integer and type(value) is not int:
        raise ValueError('invalid range')
    return value

def metrics(value):
    value = obj(value)
    return {**{k: num(value.get(k), integer=True) for k in ('tp', 'fp', 'tn', 'fn')},
            **{k: num(value.get(k), rate=True, nullable=True) for k in ('precision', 'recall', 'f1', 'fpr', 'fnr')}}

def evaluation():
    result = obj(json.loads(read('results')))
    comparison = obj(json.loads(read('comparison')))
    if result.get('model') != 'llama3.2:1b' or result.get('threshold') != 'HIGH' or result.get('threshold_fixed_before_execution') is not True:
        raise ValueError('unknown profile')
    count = num(result.get('case_count'), integer=True)
    if not 1 <= count <= 100 or comparison.get('case_count') != count:
        raise ValueError('invalid count')
    cases = result.get('cases')
    if not isinstance(cases, list) or len(cases) != count:
        raise ValueError('invalid cases')
    missing = sum(obj(obj(c).get('assessment')).get('verdict') == 'NOT_EVALUATED' for c in cases)
    rate = num(result.get('not_evaluated_rate'), rate=True)
    if not math.isclose(rate, missing / count):
        raise ValueError('inconsistent count')
    systems = {k: metrics(comparison.get(k)) for k in ('static', 'behavioral', 'layered')}
    if metrics(result.get('metrics')) != systems['behavioral'] or any(sum(v[k] for k in ('tp','fp','tn','fn')) != count for v in systems.values()):
        raise ValueError('inconsistent metrics')
    latency = {k: num(obj(result.get('latency')).get(k)) for k in ('mean_ms', 'median_ms', 'p95_ms')}
    rows = list(csv.DictReader(io.StringIO(read('latency'))))
    if len(rows) != count:
        raise ValueError('invalid latency count')
    durations = [num(float(r['duration_ms'])) for r in rows]
    if not math.isclose(sum(durations) / count, latency['mean_ms'], abs_tol=.01):
        raise ValueError('inconsistent latency')
    return {'available': True, 'model': 'llama3.2:1b', 'runtime': 'Ollama', 'threshold': 'HIGH',
            'case_count': count, 'not_evaluated_count': missing, 'not_evaluated_rate': rate,
            'metrics': systems['behavioral'], 'systems': systems, 'latency': latency,
            'latency_scope': 'Behavioral execution + paired in-process static scan; excludes construction and provider latency. Warm manual profile; not a production SLA.',
            'sources': [FILES[k] for k in ('results', 'comparison', 'latency')]}

def validation():
    raw = obj(json.loads(read('validation')))
    if raw.get('model') != 'llama3.2:1b' or raw.get('runtime') != 'Ollama':
        raise ValueError('unknown validation model')
    stages = {}
    for key in STAGES:
        stage = obj(raw.get(key))
        if stage.get('status') not in ('VERIFIED', 'NOT VERIFIED', 'UNAVAILABLE'):
            raise ValueError('invalid status')
        stages[key] = stage['status']
    probes = {}
    for key in ('public_read', 'protected_read_probe', 'network_probe'):
        a = obj(obj(raw.get(key)).get('assessment'))
        score = num(a.get('score'), nullable=True)
        if score is not None and score > 100 or a.get('severity') not in ('LOW', 'ELEVATED', 'SUSPICIOUS', 'HIGH', 'CRITICAL', None):
            raise ValueError('invalid assessment')
        probes[key] = {'score': score, 'severity': a.get('severity')}
    return {'available': True, 'model': raw['model'], 'runtime': raw['runtime'], 'stages': stages,
            'cloud_calls': num(raw.get('cloud_calls'), integer=True), 'model_downloads': num(raw.get('model_downloads'), integer=True),
            'probes': probes, 'source': FILES['validation'],
            'schema_note': 'Schema acceptance verified. The schema-only response reached the output limit; usable tool execution is evidenced by the separate read/network probes.'}

def local_summary():
    output = {}
    for key, loader in (('evaluation', evaluation), ('validation', validation)):
        try:
            output[key] = loader()
        except (OSError, ValueError, TypeError, KeyError, OverflowError, csv.Error):
            output[key] = {'available': False, 'message': 'Saved artifact unavailable or invalid.'}
    return output
