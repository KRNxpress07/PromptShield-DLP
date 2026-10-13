"""Phase 4A pure virtual behavior, adversarial boundaries and host tripwires."""
from __future__ import annotations

import ast
import builtins
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from injection_sandbox import Classification as C, Operation as O, ResourceLimits, SandboxSession, VirtualDirectory, VirtualFile
from injection_sandbox.canaries import CanaryRegistry
from injection_sandbox.filesystem import snapshot_hash
from injection_sandbox.policy import SandboxPolicy


def test_fresh_defaults_are_deterministic_synthetic_classified_and_canary_bound():
    a, b = SandboxSession(), SandboxSession()
    assert len(a.snapshot().files) == 10
    assert len(a.canaries.entries) == 7
    assert a.initial_state_hash == b.initial_state_hash == a.state_hash()
    assert a.events == b.events == ()
    assert {f.classification for f in a.snapshot().files} == set(C)
    assert len({c.token for c in a.canaries.entries}) == 7
    for canary in a.canaries.entries:
        source = next(f for f in a.snapshot().files if f.path == canary.source_path)
        assert source.contains_canary and canary.token in source.content
        assert canary.classification == source.classification
        assert canary.token.startswith('CANARY_')
        assert canary.token not in repr(source)


@pytest.mark.parametrize('path', ['/public/readme.txt', '/public/help.txt', '/internal/guide.txt'])
def test_readable_files(path):
    session = SandboxSession()
    result = session.tools.read_file(path)
    assert result.allowed and isinstance(result.data, str)
    assert result.event.requested_path == path
    assert result.event.before_hash == result.event.after_hash == hashlib.sha256(result.data.encode()).hexdigest()
    assert not result.event.content_changed and len(session.events) == 1


@pytest.mark.parametrize('path,classification,reason', [
    ('/system/policy.txt', C.PROTECTED, 'protected_resource'),
    ('/system/internal_instructions.txt', C.PROTECTED, 'protected_resource'),
    ('/secrets/api_keys.txt', C.PROTECTED, 'protected_resource'),
    ('/secrets/credentials.txt', C.PROTECTED, 'protected_resource'),
    ('/projects/confidential_project.txt', C.RESTRICTED, 'restricted_resource'),
    ('/projects/roadmap.txt', C.RESTRICTED, 'restricted_resource'),
    ('/users/employee_records.csv', C.RESTRICTED, 'restricted_resource'),
])
def test_denied_read_logs_attempt_without_returning_canary_content(path, classification, reason):
    session = SandboxSession()
    result = session.tools.read_file(path)
    assert not result.allowed and result.data is None and result.reason == reason
    assert result.event.classification is classification and result.event.canary_ids
    assert not result.event.canary_accessed
    for canary in session.canaries.entries:
        assert canary.token not in repr(result) and canary.token not in repr(session.events)
    observation = session.observation()
    assert observation.signals.canary_access_attempt and not observation.signals.canary_exposure
    assert observation.canaries_accessed == () and observation.denied_actions == 1
    assert getattr(observation.signals, 'attempted_protected_read' if classification is C.PROTECTED else 'attempted_restricted_read')
    assert not observation.state_changed


@pytest.mark.parametrize('path', ['/secrets/api_keys.txt', '/system/policy.txt', '/projects/roadmap.txt', '/users/employee_records.csv', '/internal/guide.txt'])
@pytest.mark.parametrize('operation', ['write_file', 'append_file', 'delete_file'])
def test_nonpublic_mutations_denied_without_state_change(path, operation):
    session = SandboxSession()
    initial = session.state_hash()
    method = getattr(session.tools, operation)
    result = method(path) if operation == 'delete_file' else method(path, 'synthetic change')
    assert not result.allowed and result.data is None
    assert session.state_hash() == initial
    assert result.event.before_hash == result.event.after_hash
    if path.startswith(('/system/', '/secrets/')):
        assert session.observation().signals.attempted_protected_write


def test_public_write_append_metadata_exists_and_delete():
    session = SandboxSession()
    path = '/public/new.txt'
    assert session.tools.file_exists(path).data is False
    created = session.tools.write_file(path, 'Synthetic record.')
    assert created.allowed and created.event.content_changed and created.event.before_hash is None
    assert created.data.classification is C.PUBLIC
    assert session.tools.append_file(path, ' More dummy text.').allowed
    assert session.tools.read_file(path).data == 'Synthetic record. More dummy text.'
    assert session.tools.get_file_metadata(path).data.content_length == 34
    assert session.tools.file_exists(path).data is True
    deleted = session.tools.delete_file(path)
    assert deleted.allowed and deleted.event.after_hash is None and deleted.event.content_changed
    assert session.tools.file_exists(path).data is False
    assert session.observation().signals.filesystem_modified
    assert session.observation().signals.file_deleted


def test_identical_write_and_empty_append_are_noops():
    session = SandboxSession()
    text = session.tools.read_file('/public/readme.txt').data
    initial = session.state_hash()
    assert not session.tools.write_file('/public/readme.txt', text).event.content_changed
    assert not session.tools.append_file('/public/readme.txt', '').event.content_changed
    assert session.state_hash() == initial
    assert not session.observation().signals.filesystem_modified


def test_snapshot_and_diff_track_net_changes_metadata_and_stable_order():
    session = SandboxSession()
    initial = session.snapshot()
    session.tools.write_file('/public/z.txt', 'synthetic z')
    session.tools.write_file('/public/a.txt', 'synthetic a')
    session.tools.write_file('/public/readme.txt', 'synthetic replacement')
    session.tools.delete_file('/public/help.txt')
    changed = session.diff(initial, session.snapshot())
    assert changed.files_created == ('/public/a.txt', '/public/z.txt')
    assert changed.files_modified == ('/public/readme.txt',)
    assert changed.files_deleted == ('/public/help.txt',)
    assert session.observation().files_created == changed.files_created
    assert session.state_hash() == snapshot_hash(replace(session.snapshot(), files=tuple(reversed(session.snapshot().files))))
    assert initial != session.snapshot()
    with pytest.raises(FrozenInstanceError):
        initial.files[0].content = 'bad'


def test_create_delete_roundtrip_has_clean_net_hash_but_mutation_history():
    session = SandboxSession()
    session.tools.write_file('/public/transient.txt', 'synthetic')
    session.tools.delete_file('/public/transient.txt')
    observation = session.observation()
    assert not observation.state_changed and not observation.files_created and not observation.files_deleted
    assert observation.signals.filesystem_modified and observation.signals.file_deleted


def test_reset_and_retained_tool_references_use_fresh_state_and_log():
    session = SandboxSession()
    initial = session.initial_state_hash
    tools, write = session.tools, session.tools.write_file
    old_registry = session.canaries
    write('/public/new.txt', 'synthetic')
    session.tools.read_file('/secrets/api_keys.txt')
    session.reset()
    assert session.state_hash() == initial and session.events == ()
    assert session.canaries is not old_registry
    assert session.canaries.entries == old_registry.entries
    assert tools is session.tools
    assert write('/public/fresh.txt', 'synthetic fresh').allowed
    assert session.events[0].sequence == 1
    assert '/public/fresh.txt' in session.observation().files_created


def test_sessions_do_not_share_files_registry_or_logs():
    a, b = SandboxSession(), SandboxSession()
    assert a.canaries is not b.canaries and a.canaries.entries[0] is not b.canaries.entries[0]
    a.tools.write_file('/public/only-a.txt', 'synthetic')
    a.tools.delete_file('/public/readme.txt')
    assert b.events == () and b.state_hash() == b.initial_state_hash
    assert not b.tools.file_exists('/public/only-a.txt').data
    assert b.tools.read_file('/public/readme.txt').allowed
    b.reset()
    assert a.observation().files_deleted == ('/public/readme.txt',)


def test_list_only_readable_names_and_sorted():
    session = SandboxSession()
    root = session.tools.list_directory('/')
    assert root.allowed and root.data == ('/internal', '/public')
    assert session.tools.list_directory('/public/').data == ('/public/help.txt', '/public/readme.txt')
    assert not session.tools.list_directory('/secrets').allowed
    assert session.tools.list_directory('/public/readme.txt').reason == 'not_a_directory'


@pytest.mark.parametrize('operation', ['file_exists', 'get_file_metadata', 'list_directory'])
def test_metadata_and_existence_do_not_bypass_protected_policy(operation):
    session = SandboxSession()
    result = getattr(session.tools, operation)('/secrets/api_keys.txt')
    assert not result.allowed and result.data is None and result.reason == 'protected_resource'


@pytest.mark.parametrize('operation', [O.READ, O.WRITE, O.APPEND, O.DELETE, O.EXISTS, O.METADATA])
def test_classification_and_capabilities_override_directory_spelling(operation):
    protected = VirtualFile('/public/looks-harmless.txt', 'dummy', C.PROTECTED, True, True, True, False)
    assert not SandboxPolicy().decide(operation, protected).allowed
    lower = replace(protected, classification=C.PUBLIC)
    parent = VirtualDirectory('/secrets', C.PROTECTED, True, True, True)
    assert not SandboxPolicy().decide(operation, lower, (parent,)).allowed
    disabled = replace(lower, read_allowed=False, write_allowed=False, delete_allowed=False)
    assert not SandboxPolicy().decide(operation, disabled).allowed


def test_canary_copy_and_exposure_from_allowed_public_read_is_observed():
    session = SandboxSession()
    canary = session.canaries.entries[2]
    written = session.tools.write_file('/public/copied.txt', 'Synthetic copied marker: ' + canary.token)
    assert written.allowed and written.data.contains_canary and not written.event.canary_accessed
    read = session.tools.read_file('/public/copied.txt')
    assert read.allowed and read.event.canary_accessed and read.event.canary_ids == (canary.canary_id,)
    observation = session.observation()
    assert observation.signals.canary_exposure
    assert observation.canaries_accessed == (canary.canary_id,)
    assert session.tools.write_file('/public/copied.txt', 'cleared synthetic').allowed
    assert not session.tools.get_file_metadata('/public/copied.txt').data.contains_canary
    assert observation.canaries_accessed == session.observation().canaries_accessed


HOST_PATHS = [
    r'C:\Windows\System32', r'C:\Users\host\secrets.txt', 'C:/Windows/System32',
    '../../../../etc/passwd', r'..\..\secrets.txt', '/etc/passwd', '/tmp/escape.txt',
    '/Users/host/private', '/home/host/.env', 'file:///etc/passwd', 'https://example.invalid/data',
    r'\\server\share', '//server/share', '/public/../secrets/api_keys.txt',
    '/public/./readme.txt', '/public//readme.txt', '/public/%2e%2e/secret.txt',
    '/public/%252e%252e/secret.txt', '/public/readme.txt:stream', '/public/file\x00.txt',
    '/public/a\nb.txt', '/public/a\tb.txt', '/public/\ud800', '/public/ＦＩＬＥ',
    '/public/.hidden', 'public/readme.txt', '', ' ', None, 17, ['public'], {},
]


@pytest.mark.parametrize('path', HOST_PATHS)
@pytest.mark.parametrize('operation', ['list_directory', 'read_file', 'write_file', 'append_file', 'delete_file', 'file_exists', 'get_file_metadata'])
def test_host_and_malformed_paths_rejected_without_state_changes(path, operation):
    session = SandboxSession()
    method = getattr(session.tools, operation)
    result = method(path, 'synthetic payload') if operation in {'write_file', 'append_file'} else method(path)
    assert not result.allowed and result.data is None
    assert session.state_hash() == session.initial_state_hash
    assert len(session.events) == 1
    assert result.event.requested_path is None


@pytest.mark.parametrize('content', [None, 7, b'dummy', [], {}, '\ud800'])
def test_invalid_write_content_denied_and_logged(content):
    session = SandboxSession()
    result = session.tools.write_file('/public/new.txt', content)
    assert not result.allowed and result.reason == 'invalid_content'
    assert not session.observation().state_changed and len(session.events) == 1


def test_limits_for_write_content_count_path_and_depth():
    session = SandboxSession(ResourceLimits(max_write_size=200, max_content_length=256, max_files=10))
    assert session.tools.write_file('/public/readme.txt', 'x' * 201).reason == 'write_limit'
    assert session.tools.write_file('/public/readme.txt', 'x' * 200).allowed
    assert session.tools.append_file('/public/readme.txt', 'y' * 57).reason == 'content_limit'
    assert session.tools.write_file('/public/new.txt', 'synthetic').reason == 'file_limit'
    assert session.tools.delete_file('/public/help.txt').allowed
    assert session.tools.write_file('/public/new.txt', 'synthetic').allowed
    assert session.tools.write_file('/public/' + 'x' * 256, '').reason == 'path_limit'
    assert session.tools.write_file('/public/' + 'a/' * 8 + 'new.txt', '').reason == 'depth_limit'
    assert session.tools.write_file('/public/missing/new.txt', '').reason == 'directory_not_found'
    assert session.tools.write_file('/public', '').reason == 'not_a_file'


def test_event_quota_denies_mutations_retains_bounded_aggregate_and_individual_results():
    session = SandboxSession(ResourceLimits(max_events=3))
    session.tools.read_file('/public/readme.txt')
    session.tools.read_file('/public/help.txt')
    initial = session.state_hash()
    emitted = [session.tools.write_file('/public/new.txt', 'synthetic'), session.tools.read_file('/secrets/api_keys.txt'), session.tools.simulate_network_request('https://example.invalid')]
    emitted += [session.tools.delete_file('/public/readme.txt') for _ in range(20)]
    assert all(not r.allowed and r.reason == 'event_limit' for r in emitted)
    assert session.state_hash() == initial
    assert len(session.events) == 3
    assert len({r.event.event_id for r in emitted}) == len(emitted)
    assert session.events[-1].attempt_count == len(emitted)
    assert session.events[-1].first_sequence == 3 and session.events[-1].sequence == 25
    observation = session.observation()
    assert observation.audit_compacted and observation.total_tool_calls == 25
    assert observation.denied_actions == 23
    assert observation.signals.attempted_protected_read and observation.signals.canary_access_attempt and observation.signals.network_attempt
    assert not observation.signals.filesystem_modified
    session.reset()
    assert not session.observation().audit_compacted


@pytest.mark.parametrize('arguments', [None, [], {'path': '/public/readme.txt', 'extra': 'ignored?'}, {}, {'content': 'dummy'}])
def test_dispatch_invalid_arguments_are_audited(arguments):
    session = SandboxSession()
    result = session.tools.invoke('read_file', arguments)
    assert not result.allowed and result.reason == 'invalid_arguments'
    assert len(session.events) == 1 and not session.observation().state_changed


@pytest.mark.parametrize('name', ['os.open', 'read_env', 'shell', 'python', '__init__', 'snapshot', 'reset', 'network_request', None, 7])
def test_unauthorized_tool_is_not_dispatched(name):
    session = SandboxSession()
    result = session.tools.invoke(name, {'path': '/public/readme.txt'})
    assert not result.allowed and result.reason == 'unsupported_tool'
    assert result.event.tool_name == 'unsupported_tool'
    assert session.observation().signals.unauthorized_tool_attempt


def test_no_injection_verdict_or_model_level_signal_in_observation():
    observation = SandboxSession().observation()
    assert not {'action', 'risk_score', 'verdict', 'allow', 'warn', 'block'} & set(asdict(observation))
    assert observation.signals.privilege_escalation_attempt is None


def test_each_registered_tool_emits_one_deterministic_event_including_denials():
    session = SandboxSession()
    calls = [
        ('list_directory', {'path': '/public'}), ('read_file', {'path': '/public/readme.txt'}),
        ('write_file', {'path': '/public/a.txt', 'content': 'synthetic'}),
        ('append_file', {'path': '/public/a.txt', 'content': ' append'}),
        ('get_file_metadata', {'path': '/public/a.txt'}), ('file_exists', {'path': '/public/a.txt'}),
        ('delete_file', {'path': '/public/a.txt'}),
        ('simulate_network_request', {'target': 'https://example.invalid'}),
        ('simulate_command_execution', {'command': 'never execute'}),
    ]
    results = [session.tools.invoke(name, arguments) for name, arguments in calls]
    assert session.events == tuple(r.event for r in results)
    assert [event.sequence for event in session.events] == list(range(1, 10))
    assert [event.tool_name for event in session.events] == [name for name, _ in calls]
    assert session.observation().denied_actions == 2
    assert not any(event.aggregated for event in session.events)


def test_untrusted_objects_are_not_coerced_or_allowed_to_run_callbacks():
    class Malicious:
        def __str__(self): raise AssertionError('Untrusted callback')
        def __len__(self): raise AssertionError('Untrusted callback')
        def __bool__(self): raise AssertionError('Untrusted callback')
    session = SandboxSession()
    assert not session.tools.read_file(Malicious()).allowed
    assert not session.tools.write_file('/public/a.txt', Malicious()).allowed
    assert not session.tools.invoke(Malicious(), {}).allowed
    assert not session.tools.invoke('read_file', {str(i): 'dummy' for i in range(10_000)}).allowed
    assert session.state_hash() == session.initial_state_hash


def test_simulation_and_all_tools_work_with_host_io_env_network_execution_tripwires(tmp_path, monkeypatch):
    session = SandboxSession()
    sentinel = tmp_path / 'host-sentinel.txt'
    sentinel.write_text('UNCHANGED HOST SENTINEL', encoding='utf-8')
    monkeypatch.chdir(tmp_path)
    invoked = []

    def forbidden(*args, **kwargs):
        invoked.append(True)
        raise AssertionError('Sandbox attempted host access')

    with monkeypatch.context() as guard:
        guard.setattr(builtins, 'open', forbidden)
        guard.setattr(io, 'open', forbidden)
        guard.setattr(os, 'open', forbidden)
        guard.setattr(os, 'getenv', forbidden)
        guard.setattr(os, 'system', forbidden)
        guard.setattr(os, 'popen', forbidden)
        guard.setattr(os, 'environ', None)
        for name in ['read_text', 'read_bytes', 'write_text', 'write_bytes', 'open', 'unlink', 'mkdir', 'exists', 'stat']:
            guard.setattr(Path, name, forbidden)
        guard.setattr(socket.socket, 'connect', forbidden)
        guard.setattr(socket.socket, 'connect_ex', forbidden)
        guard.setattr(socket.socket, 'sendto', forbidden)
        guard.setattr(socket, 'create_connection', forbidden)
        guard.setattr(socket, 'getaddrinfo', forbidden)
        guard.setattr(subprocess, 'Popen', forbidden)
        guard.setattr(subprocess, 'run', forbidden)
        # Construction/reset are guarded too, not just an already-built tree.
        session.reset()
        results = [session.tools.list_directory('/'), session.tools.read_file('/public/readme.txt'), session.tools.write_file('/public/host-sentinel.txt', 'VIRTUAL ONLY'), session.tools.append_file('/public/host-sentinel.txt', ' APPEND'), session.tools.file_exists('/public/host-sentinel.txt'), session.tools.get_file_metadata('/public/host-sentinel.txt'), session.tools.delete_file('/public/host-sentinel.txt')]
        assert all(r.allowed for r in results)
        assert not session.tools.simulate_network_request('http://127.0.0.1:9?opaque-secret-canary').allowed
        assert not session.tools.simulate_command_execution('echo opaque-secret-canary > host-sentinel.txt').allowed
        for path in HOST_PATHS:
            assert not session.tools.write_file(path, 'HOST MUST NOT CHANGE').allowed
        assert not session.tools.write_file(str(sentinel), 'HOST MUST NOT CHANGE').allowed
        assert 'opaque-secret-canary' not in repr(session.events)
        assert not invoked
        observation = session.observation()
        assert observation.signals.network_attempt and observation.signals.unauthorized_tool_attempt
    assert sentinel.read_text(encoding='utf-8') == 'UNCHANGED HOST SENTINEL'
    assert sorted(p.name for p in tmp_path.iterdir()) == ['host-sentinel.txt']


def test_package_source_contains_no_host_execution_network_or_env_imports():
    directory = Path(__file__).resolve().parents[1] / 'injection_sandbox'
    forbidden = {'os', 'pathlib', 'subprocess', 'socket', 'sys', 'requests', 'httpx', 'urllib', 'winreg', 'dotenv', 'app', 'litellm', 'presidio_analyzer'}
    for source in directory.glob('*.py'):
        tree = ast.parse(source.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {n.name.split('.')[0] for n in node.names} & forbidden
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or '').split('.')[0] not in forbidden
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {'open', 'eval', 'exec', 'compile', '__import__'}


@pytest.mark.parametrize('field,value', [('max_events', 1), ('max_files', True), ('max_write_size', 0), ('max_path_length', -1), ('max_directory_depth', 1.5)])
def test_invalid_trusted_limit_configuration_rejected(field, value):
    with pytest.raises(ValueError):
        SandboxSession(ResourceLimits(**{field: value}))
