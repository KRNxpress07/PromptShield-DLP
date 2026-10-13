"""Isolated read-only dashboard endpoint; no DLP source/policy modification."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dashboard_server_tests', ROOT / 'frontend/server.py')
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


@pytest.fixture
def host(tmp_path, monkeypatch):
    source = ROOT / 'benchmarks/results/latest'
    for name in ('metrics.json', 'per_entity_metrics.csv', 'false_positives.csv', 'sanitization_results.csv'):
        (tmp_path / name).write_bytes((source / name).read_bytes())
    monkeypatch.setattr(dashboard, 'RESULTS_DIR', tmp_path)
    with TestClient(dashboard.app) as client:
        yield client, tmp_path


def test_valid_summary_matches_recorded_metrics_and_csv(host):
    client, directory = host
    response = client.get('/v1/benchmark/summary')
    assert response.status_code == 200
    summary = response.json()
    original = json.loads((directory / 'metrics.json').read_text())
    assert summary['detection']['project']['prompt'] == original['detectors']['project']['prompt']
    assert summary['dataset']['total'] == original['dataset']['total']
    assert len(summary['per_entity']) == 26
    assert len(summary['latency']) == len(original['latency']['groups'])
    assert summary['throughput'][-1]['prompts_per_second'] == original['throughput']['aggregates'][-1]['prompts_per_second']
    assert summary['sanitization']['human_ratings'] == 'PENDING HUMAN EVALUATION'
    assert summary['false_positive_examples']
    assert summary['sanitization_example']['sanitized'].endswith('[REDACTED]')
    assert response.headers['cache-control'] == 'no-store'


def test_missing_metrics_is_controlled(host):
    client, directory = host
    (directory / 'metrics.json').unlink()
    response = client.get('/v1/benchmark/summary')
    assert response.status_code == 503
    assert response.json()['error'] == 'benchmark_unavailable'
    assert str(directory) not in response.text


@pytest.mark.parametrize('content', ['{', '[]', '{}', 'null', '{"dataset":42}', '{"private_key":"dummy-sensitive-canary"}'])
def test_malformed_metrics_no_content_or_path_echo(host, content):
    client, directory = host
    (directory / 'metrics.json').write_text(content)
    response = client.get('/v1/benchmark/summary')
    assert response.status_code == 503
    assert response.json()['error'] == 'benchmark_invalid'
    assert 'dummy-sensitive-canary' not in response.text and str(directory) not in response.text


@pytest.mark.parametrize('value', [True, -1, 1.01, 'sk-proj-dummy-sensitive-canary', float('nan'), float('inf')])
def test_invalid_numeric_metrics_reject_without_echo(host, value):
    client, directory = host
    path = directory / 'metrics.json'
    raw = json.loads(path.read_text())
    raw['detectors']['project']['prompt']['recall'] = value
    path.write_text(json.dumps(raw))
    response = client.get('/v1/benchmark/summary')
    assert response.status_code == 503
    assert 'dummy-sensitive-canary' not in response.text


def test_unknown_environment_prompt_secrets_and_manifest_not_exposed(host, monkeypatch):
    client, directory = host
    canary = 'opaque-environment-canary-do-not-expose'
    monkeypatch.setenv('GROQ_API_KEY', canary)
    path = directory / 'metrics.json'
    raw = json.loads(path.read_text())
    raw.update({'environment': {'api_key': canary}, 'raw_prompt': canary, '.env': canary, 'production_hashes': {canary: canary}})
    raw['sanitization']['provider_secret'] = canary
    path.write_text(json.dumps(raw))
    # Optional example CSV contains poisoned arbitrary raw content: ignored.
    (directory / 'false_positives.csv').write_text('label,matched_text,entity_type,prompt\nsafe,' + canary + ',EMAIL_ADDRESS,' + canary)
    response = client.get('/v1/benchmark/summary')
    assert response.status_code == 200
    assert canary not in response.text
    assert not {'environment', 'production_hashes', 'raw_prompt', '.env'} & set(response.json())


@pytest.mark.parametrize('url', ['/v1/benchmark/summary?path=C:/private/.env', '/v1/benchmark/summary?file=../../.env', '/.env', '/server.py', '/benchmarks/results/latest/metrics.json', '/%2e%2e/.env', '/docs/PHASE1_SECURITY_HARDENING_REPORT.md'])
def test_no_arbitrary_path_access(host, url):
    client, directory = host
    response = client.get(url)
    assert response.status_code in {404, 422}
    assert str(directory) not in response.text


@pytest.mark.parametrize('method', ['POST', 'PUT', 'DELETE', 'PATCH'])
def test_summary_read_only(host, method):
    client, _ = host
    assert client.request(method, '/v1/benchmark/summary').status_code == 405


def test_optional_csv_unavailable_cleanly(host):
    client, directory = host
    for name in ('per_entity_metrics.csv', 'false_positives.csv', 'sanitization_results.csv'):
        (directory / name).unlink()
    response = client.get('/v1/benchmark/summary')
    assert response.status_code == 200
    assert len(response.json()['warnings']) == 3
    assert response.json()['per_entity'] == []


def test_invalid_csv_numbers_cleanly(host):
    client, directory = host
    (directory / 'per_entity_metrics.csv').write_text('detector,entity,level,precision\nproject,API_KEY,strict,not-a-number')
    assert client.get('/v1/benchmark/summary').status_code == 503


def test_oversized_result_rejected(host, monkeypatch):
    client, _ = host
    monkeypatch.setattr(dashboard, 'MAX_FILE_BYTES', 10)
    assert client.get('/v1/benchmark/summary').status_code == 503


@pytest.mark.parametrize('asset', ['/', '/styles.css', '/dashboard.js', '/scanner.js', '/favicon.svg'])
def test_only_public_frontend_assets_are_served(host, asset):
    client, _ = host
    response = client.get(asset)
    assert response.status_code == 200
    assert 'nosniff' == response.headers['x-content-type-options']
    assert "script-src 'self'" in response.headers['content-security-policy']
