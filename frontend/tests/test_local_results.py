"""Saved-artifact validation and endpoint privacy; no model or gateway calls."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

FRONTEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRONTEND))
import local_results as local
spec = importlib.util.spec_from_file_location('presentation_server', FRONTEND / 'server.py')
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

@pytest.fixture
def artifacts():
    return {k: local.read(k) for k in local.FILES}

def test_real_aggregate_provenance():
    result = local.local_summary()
    raw = json.loads(local.read('results'))
    comparison = json.loads(local.read('comparison'))
    assert result['evaluation']['metrics'] == raw['metrics']
    assert result['evaluation']['latency'] == raw['latency']
    assert result['evaluation']['systems']['static'] == comparison['static']
    assert result['evaluation']['systems']['static']['precision'] is None
    assert result['evaluation']['not_evaluated_count'] == sum(c['assessment']['verdict'] == 'NOT_EVALUATED' for c in raw['cases'])
    validation = json.loads(local.read('validation'))
    for name, probe in result['validation']['probes'].items():
        assert probe == {k: validation[name]['assessment'][k] for k in ('score', 'severity')}

@pytest.mark.parametrize('missing', list(local.FILES))
def test_missing_artifact_has_no_fallback(monkeypatch, artifacts, missing):
    def read(key):
        if key == missing:
            raise FileNotFoundError()
        return artifacts[key]
    monkeypatch.setattr(local, 'read', read)
    result = local.local_summary()
    key = 'validation' if missing == 'validation' else 'evaluation'
    assert result[key] == {'available': False, 'message': 'Saved artifact unavailable or invalid.'}
    assert result['evaluation' if key == 'validation' else 'validation']['available']

@pytest.mark.parametrize('value', [-1, True, '0.4', float('nan'), float('inf'), 1.5])
def test_invalid_metric_unavailable(monkeypatch, artifacts, value):
    result = json.loads(artifacts['results'])
    result['metrics']['recall'] = value
    artifacts['results'] = json.dumps(result)
    monkeypatch.setattr(local, 'read', artifacts.__getitem__)
    assert local.local_summary()['evaluation']['available'] is False

@pytest.mark.parametrize('change', ['model', 'count', 'rate', 'csv', 'threshold', 'cases'])
def test_invalid_schema_unavailable(monkeypatch, artifacts, change):
    result = json.loads(artifacts['results'])
    if change == 'model': result['model'] = 'private-model-data'
    if change == 'count': result['case_count'] += 1
    if change == 'rate': result['not_evaluated_rate'] = 0
    if change == 'threshold': result['threshold_fixed_before_execution'] = False
    if change == 'cases': result['cases'] = []
    if change == 'csv': artifacts['latency'] = 'id,duration_ms\nx,NaN\n'
    artifacts['results'] = json.dumps(result)
    monkeypatch.setattr(local, 'read', artifacts.__getitem__)
    assert local.local_summary()['evaluation']['available'] is False

def test_private_fields_are_not_exposed(monkeypatch, artifacts):
    sentinel = 'PRIVATE_TEST_SENTINEL'
    for key in ('results', 'comparison', 'validation'):
        raw = json.loads(artifacts[key])
        raw.update(dict.fromkeys(('prompt', 'transcript', 'canary', 'protected_path', 'tool_arguments', 'raw_model_output', 'environment', 'secret'), sentinel))
        if key == 'validation': raw['public_read']['assessment']['reasons'] = [sentinel]
        artifacts[key] = json.dumps(raw)
    monkeypatch.setattr(local, 'read', artifacts.__getitem__)
    output = json.dumps(local.local_summary())
    assert sentinel not in output
    assert 'cases' not in output and 'diagnostic' not in output

def test_size_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(local, 'ROOT', tmp_path)
    path = tmp_path / local.FILES['results']
    path.parent.mkdir(parents=True)
    path.write_bytes(b' ' * (local.MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError): local.read('results')

def test_endpoint_is_read_only_and_assets_allowlisted():
    with TestClient(server.app) as client:
        response = client.get('/v1/benchmark/local-model')
        assert response.status_code == 200 and response.json()['evaluation']['available']
        assert response.headers['Cache-Control'] == 'no-store'
        assert client.get('/v1/benchmark/local-model?path=anything').status_code == 422
        assert client.post('/v1/benchmark/local-model').status_code == 405
        assert client.get('/benchmarks/behavioral_real/results_llama32.json').status_code == 404
        assert client.get('/local_results.py').status_code == 404
        assert client.get('/assets/charts.js').status_code == 200
        assert client.get('/assets/BKLIT-LICENSE.txt').status_code == 200
        assert client.get('/assets/THIRD-PARTY-NOTICES.txt').status_code == 200
