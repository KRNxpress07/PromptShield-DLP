"""Offline bootstrap and artifact/provenance utilities. No .env reads."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'benchmarks/dataset'
RESULTS = ROOT / 'benchmarks/results/latest'
SEED = 20261013
VERSION = 'synthetic-v1'
ENTITY_TYPES = tuple('API_KEY AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SESSION_TOKEN PRIVATE_KEY GITHUB_TOKEN SLACK_WEBHOOK JWT_TOKEN BEARER_TOKEN DB_CONNECTION_STRING GENERIC_SECRET_ASSIGNMENT PRIVATE_IP INTERNAL_HOSTNAME EMAIL_ADDRESS PHONE_NUMBER US_SSN MASKED_US_SSN CREDIT_CARD PERSON LOCATION STREET_ADDRESS POSTAL_CODE IP_ADDRESS DATE_TIME IBAN_CODE PROMPT_INJECTION'.split())
_BOOTSTRAPPED = False


def offline():
    """Remove credential-bearing environment before application imports; deny egress."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    allowed = {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'}
    keep = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    os.environ.clear()
    os.environ.update(keep)
    os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
    os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    import dotenv
    dotenv.load_dotenv = lambda *a, **k: False
    dotenv.dotenv_values = lambda *a, **k: {}
    connect, connect_ex, resolve = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def local(address):
        return not isinstance(address, tuple) or address[0] in ('127.0.0.1', '::1', 'localhost')

    def guarded(fn):
        def call(sock, address):
            if not local(address):
                raise RuntimeError('External network disabled by benchmark')
            return fn(sock, address)
        return call

    def dns(host, *a, **k):
        if host not in (None, 'localhost', '127.0.0.1', '::1', b'localhost', b'127.0.0.1', b'::1'):
            raise RuntimeError('External DNS disabled by benchmark')
        return resolve(host, *a, **k)

    socket.socket.connect = guarded(connect)
    socket.socket.connect_ex = guarded(connect_ex)
    socket.getaddrinfo = dns
    _BOOTSTRAPPED = True


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def production_hashes():
    paths = []
    for directory in ('proxy-api/app', 'presidio/app', 'sdk/python/aisg'):
        paths.extend(sorted((ROOT / directory).rglob('*.py')))
    paths.extend(ROOT / name for name in ('config/gateway.yaml', 'presidio/recognizers.yaml'))
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in paths}


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')


def write_csv(path, rows, fields=None):
    import csv
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields or list(rows[0]) if rows else fields or ['id'])
        writer.writeheader()
        writer.writerows(rows)


def records(split='test'):
    corpus = [json.loads(line) for line in (DATA / 'dlp_benchmark.jsonl').read_text(encoding='utf-8').splitlines()]
    if split == 'all':
        return corpus
    ids = set((DATA / f'{split}_ids.txt').read_text().splitlines())
    return [r for r in corpus if r['id'] in ids]


def environment():
    versions = {}
    for name in ('presidio-analyzer', 'presidio-anonymizer', 'spacy', 'en-core-web-lg', 'en-core-web-sm', 'httpx', 'fastapi', 'pydantic', 'litellm', 'phonenumbers', 'numpy', 'pytest'):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = 'NOT INSTALLED'
    cpu, ram = platform.processor(), None
    if sys.platform == 'win32':
        command = 'Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name; (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory'
        result = subprocess.run(['powershell', '-NoProfile', '-Command', command], capture_output=True, text=True, check=False)
        lines = result.stdout.strip().splitlines()
        if len(lines) >= 2:
            cpu = lines[0].strip()
            try:
                ram = int(lines[-1])
            except ValueError:
                pass
    return {'os': platform.platform(), 'python': sys.version, 'cpu': cpu or 'NOT VERIFIED', 'logical_cpus': os.cpu_count(), 'ram_bytes': ram, 'dependencies': versions, 'network': 'external TCP/DNS denied; in-memory transports only', 'seed': SEED, 'dataset_version': VERSION}
