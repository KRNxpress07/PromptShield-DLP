"""Strict virtual tool dispatcher. No eval, dynamic getattr, IO or execution."""
from __future__ import annotations

import json

from .canaries import CanaryRegistry
from .events import EventLog
from .filesystem import PathRejected, VirtualFilesystem, content_hash
from .models import Classification, Operation, ResourceLimits, Signal, ToolResult
from .policy import MUTATIONS, READ_OPERATIONS, SandboxPolicy

_TOOLS = (
    ('list_directory', Operation.LIST, ('path',)),
    ('read_file', Operation.READ, ('path',)),
    ('write_file', Operation.WRITE, ('path', 'content')),
    ('append_file', Operation.APPEND, ('path', 'content')),
    ('delete_file', Operation.DELETE, ('path',)),
    ('file_exists', Operation.EXISTS, ('path',)),
    ('get_file_metadata', Operation.METADATA, ('path',)),
    ('simulate_network_request', Operation.NETWORK, ('target',)),
    ('simulate_command_execution', Operation.COMMAND, ('command',)),
)


class VirtualTools:
    def __init__(self, filesystem: VirtualFilesystem, policy: SandboxPolicy, canaries: CanaryRegistry, events: EventLog, limits: ResourceLimits):
        self._fs, self._policy, self._canaries, self._events, self._limits = filesystem, policy, canaries, events, limits

    def invoke(self, tool_name, arguments) -> ToolResult:
        definition = next((d for d in _TOOLS if type(tool_name) is str and d[0] == tool_name), None)
        name, operation, keys = definition or ('unsupported_tool', Operation.UNKNOWN, ())
        valid = type(arguments) is dict and len(arguments) == len(keys) and all(type(k) is str for k in arguments) and set(arguments) == set(keys)
        arguments = arguments if type(arguments) is dict and len(arguments) <= 2 and all(type(k) is str for k in arguments) else {}
        requested = arguments.get('path')
        path, reason, classification, before = None, None, None, None
        flags = set()
        ids: tuple[str, ...] = ()
        exposed = False
        data = None
        allowed = changed = False
        # Keep invalid arguments out of logs. A bounded-prefix hash identifies
        # repeated rejected inputs without recording host paths or payload text.
        request_hash = content_hash(json.dumps(requested[:self._limits.max_path_length], ensure_ascii=True)) if type(requested) is str else None
        if operation in (Operation.NETWORK, Operation.COMMAND):
            requested = None
            if operation is Operation.NETWORK:
                flags.add(Signal.NETWORK)
            else:
                flags.add(Signal.UNAUTHORIZED)
        elif operation is Operation.UNKNOWN:
            flags.add(Signal.UNAUTHORIZED)
        elif requested is not None:
            try:
                path = self._fs.normalize(requested)
            except PathRejected as exc:
                reason = exc.reason
        else:
            reason = 'invalid_arguments'
        file = self._fs.get_file(path) if path is not None else None
        directory = self._fs.get_directory(path) if path is not None else None
        parent = self._fs.parent(path) if path is not None else None
        resource = file or directory or parent
        parents = self._fs.parents(path) if path is not None else ()
        decision = self._policy.decide(operation, resource, parents) if resource and operation not in (Operation.NETWORK, Operation.COMMAND, Operation.UNKNOWN) else None
        if file:
            before = content_hash(file.content)
            ids = tuple(sorted(set(self._canaries.for_source(path)) | set(self._canaries.find(file.content))))
        if decision:
            classification = decision.classification
            if operation in READ_OPERATIONS:
                if classification is Classification.PROTECTED:
                    flags.add(Signal.PROTECTED_READ)
                if classification is Classification.RESTRICTED:
                    flags.add(Signal.RESTRICTED_READ)
            elif operation in MUTATIONS and classification is Classification.PROTECTED:
                flags.add(Signal.PROTECTED_WRITE)
        if ids:
            flags.add(Signal.CANARY_ATTEMPT)
        if self._events.exhausted:
            reason = 'event_limit'
        elif definition is None:
            reason = 'unsupported_tool'
        elif not valid:
            reason = 'invalid_arguments'
        elif operation is Operation.NETWORK:
            reason = 'network_denied'
        elif operation is Operation.COMMAND:
            reason = 'execution_denied'
        elif reason:
            pass
        elif decision is None:
            reason = 'directory_not_found'
        elif not decision.allowed:
            reason = decision.reason
        elif operation is Operation.LIST:
            if directory is None:
                reason = 'not_a_directory'
            else:
                # Names of denied child resources are not exposed via listing.
                children = []
                for child in self._fs.list_children(path):
                    child_resource = self._fs.get_file(child) or self._fs.get_directory(child)
                    if self._policy.decide(Operation.METADATA, child_resource, self._fs.parents(child)).allowed:
                        children.append(child)
                allowed, data = True, tuple(children)
        elif operation is Operation.EXISTS:
            allowed, data = True, file is not None or directory is not None
        elif operation in (Operation.READ, Operation.METADATA, Operation.DELETE, Operation.APPEND) and file is None:
            reason = 'not_a_file' if directory else 'file_not_found'
        elif operation in (Operation.WRITE, Operation.APPEND):
            content = arguments['content']
            if directory:
                reason = 'not_a_file'
            elif parent is None:
                reason = 'directory_not_found'
            elif type(content) is not str:
                reason = 'invalid_content'
            elif len(content) > self._limits.max_write_size:
                reason = 'write_limit'
            elif len(content) + (len(file.content) if operation is Operation.APPEND else 0) > self._limits.max_content_length:
                reason = 'content_limit'
            elif file is None and self._fs.file_count >= self._limits.max_files:
                reason = 'file_limit'
            else:
                text = file.content + content if operation is Operation.APPEND else content
                # Surrogates are malformed Unicode; validate before mutation/hash.
                try:
                    text.encode('utf-8')
                except UnicodeEncodeError:
                    reason = 'invalid_content'
                else:
                    self._fs.store(path, text)
                    changed, allowed, data = file is None or text != file.content, True, self._fs.metadata(path)
        elif operation is Operation.READ:
            allowed, data = True, file.content
            exposed = bool(self._canaries.find(file.content))
            if exposed:
                flags.add(Signal.CANARY_EXPOSURE)
        elif operation is Operation.METADATA:
            allowed, data = True, self._fs.metadata(path)
        elif operation is Operation.DELETE:
            self._fs.remove(path)
            allowed, changed = True, True
            flags.add(Signal.DELETED)
        reason = reason or 'allowed'
        if changed:
            flags.add(Signal.MODIFIED)
        after_file = self._fs.get_file(path) if path is not None else None
        after = content_hash(after_file.content) if after_file else None
        if changed and after_file:
            ids = tuple(sorted(set(ids) | set(self._canaries.find(after_file.content))))
            if ids:
                flags.add(Signal.CANARY_ATTEMPT)
        event = self._events.record(tool_name=name, requested_path=path, operation=operation, allowed=allowed, classification=classification, reason=reason, content_changed=changed, canary_accessed=exposed, canary_ids=ids, before_hash=before, after_hash=after, signal_flags=frozenset(flags), request_hash=request_hash)
        return ToolResult(allowed, reason, event, data)

    def list_directory(self, path):
        return self.invoke('list_directory', {'path': path})

    def read_file(self, path):
        return self.invoke('read_file', {'path': path})

    def write_file(self, path, content):
        return self.invoke('write_file', {'path': path, 'content': content})

    def append_file(self, path, content):
        return self.invoke('append_file', {'path': path, 'content': content})

    def delete_file(self, path):
        return self.invoke('delete_file', {'path': path})

    def file_exists(self, path):
        return self.invoke('file_exists', {'path': path})

    def get_file_metadata(self, path):
        return self.invoke('get_file_metadata', {'path': path})

    def simulate_network_request(self, target):
        return self.invoke('simulate_network_request', {'target': target})

    def simulate_command_execution(self, command):
        return self.invoke('simulate_command_execution', {'command': command})
