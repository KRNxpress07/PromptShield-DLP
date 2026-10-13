"""Immutable, standard-library-only records; no injection verdict or risk score."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Classification(str, Enum):
    PUBLIC = 'PUBLIC'
    INTERNAL = 'INTERNAL'
    RESTRICTED = 'RESTRICTED'
    PROTECTED = 'PROTECTED'


class Operation(str, Enum):
    LIST = 'list'
    READ = 'read'
    WRITE = 'write'
    APPEND = 'append'
    DELETE = 'delete'
    EXISTS = 'exists'
    METADATA = 'metadata'
    NETWORK = 'network'
    COMMAND = 'command'
    UNKNOWN = 'unknown'


class Signal(str, Enum):
    PROTECTED_READ = 'attempted_protected_read'
    RESTRICTED_READ = 'attempted_restricted_read'
    PROTECTED_WRITE = 'attempted_protected_write'
    MODIFIED = 'filesystem_modified'
    DELETED = 'file_deleted'
    CANARY_ATTEMPT = 'canary_access_attempt'
    CANARY_EXPOSURE = 'canary_exposure'
    UNAUTHORIZED = 'unauthorized_tool_attempt'
    NETWORK = 'network_attempt'


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_files: int = 64
    max_path_length: int = 256
    max_content_length: int = 65_536
    max_events: int = 256
    max_write_size: int = 8_192
    max_directory_depth: int = 8

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError('Resource limits must be positive integers')
        if self.max_events < 2:
            raise ValueError('At least two event slots are required')


@dataclass(frozen=True, slots=True)
class VirtualFile:
    path: str
    content: str = field(repr=False)
    classification: Classification
    read_allowed: bool
    write_allowed: bool
    delete_allowed: bool
    contains_canary: bool


@dataclass(frozen=True, slots=True)
class VirtualDirectory:
    path: str
    classification: Classification
    read_allowed: bool
    write_allowed: bool
    delete_allowed: bool = False


@dataclass(frozen=True, slots=True)
class FileMetadata:
    path: str
    classification: Classification
    read_allowed: bool
    write_allowed: bool
    delete_allowed: bool
    contains_canary: bool
    content_length: int


@dataclass(frozen=True, slots=True)
class Canary:
    canary_id: str
    token: str = field(repr=False)
    source_path: str
    classification: Classification
    purpose: str


@dataclass(frozen=True, slots=True)
class SandboxEvent:
    event_id: str
    sequence: int
    tool_name: str
    requested_path: str | None
    operation: Operation
    allowed: bool
    classification: Classification | None
    reason: str
    content_changed: bool
    canary_accessed: bool
    canary_ids: tuple[str, ...]
    before_hash: str | None
    after_hash: str | None
    signal_flags: frozenset[Signal] = frozenset()
    request_hash: str | None = None
    first_sequence: int = 0
    attempt_count: int = 1
    aggregated: bool = False


@dataclass(frozen=True, slots=True)
class ToolResult:
    allowed: bool
    reason: str
    event: SandboxEvent
    data: str | bool | FileMetadata | tuple[str, ...] | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class SandboxSnapshot:
    files: tuple[VirtualFile, ...]
    directories: tuple[VirtualDirectory, ...]


@dataclass(frozen=True, slots=True)
class FilesystemDiff:
    files_created: tuple[str, ...]
    files_modified: tuple[str, ...]
    files_deleted: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BehaviorSignals:
    attempted_protected_read: bool = False
    attempted_restricted_read: bool = False
    attempted_protected_write: bool = False
    filesystem_modified: bool = False
    file_deleted: bool = False
    canary_access_attempt: bool = False
    canary_exposure: bool = False
    unauthorized_tool_attempt: bool = False
    network_attempt: bool = False
    # No privilege tool/model evaluation exists in 4A; unknown, not fabricated.
    privilege_escalation_attempt: bool | None = None


@dataclass(frozen=True, slots=True)
class SandboxObservation:
    initial_state_hash: str
    final_state_hash: str
    state_changed: bool
    events: tuple[SandboxEvent, ...]
    signals: BehaviorSignals
    canaries_accessed: tuple[str, ...]
    denied_actions: int
    files_modified: tuple[str, ...]
    files_deleted: tuple[str, ...]
    files_created: tuple[str, ...]
    audit_compacted: bool
    total_tool_calls: int
