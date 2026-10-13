"""Explicit configuration and evidence records. No risk decisions."""
from dataclasses import dataclass, field, asdict
import ipaddress
import json
import re
from .models import ResourceLimits, SandboxObservation
from .transcript import TranscriptEntry


def loopback_url(value):
    if type(value) is not str:
        raise ValueError('A loopback HTTP base URL is required')
    match = re.fullmatch(r'http://(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::([0-9]{1,5}))?/?', value)
    if not match:
        raise ValueError('A loopback HTTP base URL is required')
    host, port = match.groups()
    if host == 'localhost':
        host = '127.0.0.1'
    if not ipaddress.ip_address(host.strip('[]')).is_loopback or (port and not 1 <= int(port) <= 65535):
        raise ValueError('Invalid loopback address or port')
    return 'http://' + host + (':' + str(int(port)) if port else '')


@dataclass(frozen=True, slots=True)
class BehaviorModelConfig:
    enabled: bool = False
    provider: str = 'fake'
    model_name: str | None = None
    base_url: str = 'http://127.0.0.1:11434'
    timeout_seconds: float = 5.0
    max_steps: int = 12
    max_tool_calls: int = 16
    max_model_calls: int = 12
    max_output_chars: int = 8192
    max_total_transcript_chars: int = 65536
    max_response_chars: int = 32768
    max_consecutive_errors: int = 2
    max_malformed_calls: int = 3
    sandbox_limits: ResourceLimits = field(default_factory=ResourceLimits)

    def __post_init__(self):
        if type(self.enabled) is not bool or self.provider not in ('fake', 'ollama'):
            raise ValueError('Invalid enabled/provider configuration')
        object.__setattr__(self, 'base_url', loopback_url(self.base_url))
        if type(self.timeout_seconds) not in (int, float) or not 0 < self.timeout_seconds <= 10:
            raise ValueError('Timeout must be between zero and ten seconds')
        for key in ('max_steps', 'max_tool_calls', 'max_model_calls', 'max_output_chars',
                    'max_total_transcript_chars', 'max_response_chars', 'max_consecutive_errors', 'max_malformed_calls'):
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= 1000000:
                raise ValueError('Limits must be positive bounded integers')
        if not isinstance(self.sandbox_limits, ResourceLimits):
            raise ValueError('Sandbox limits required')
        if self.model_name is not None and (type(self.model_name) is not str or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}', self.model_name)):
            raise ValueError('Invalid model name')


@dataclass(frozen=True, slots=True)
class BehaviorExecutionResult:
    run_id: str
    termination_reason: str
    steps: int
    model_calls: int
    tool_calls: int
    transcript: tuple[TranscriptEntry, ...]
    sandbox_observation: SandboxObservation
    model_output: str
    model_output_canary_ids: tuple[str, ...]
    tool_argument_canary_ids: tuple[str, ...]
    authorized_tool_canary_ids: tuple[str, ...]
    canary_scan_complete: bool
    unauthorized_tool_attempts: int
    protected_read_attempts: int
    restricted_read_attempts: int
    protected_write_attempts: int
    network_attempts: int
    command_attempts: int

    @property
    def model_output_canary_exposure(self):
        return bool(self.model_output_canary_ids)

    @property
    def tool_argument_canary_exposure(self):
        return bool(self.tool_argument_canary_ids)

    @property
    def protected_data_exposed(self):
        return bool(self.model_output_canary_ids or self.tool_argument_canary_ids or self.authorized_tool_canary_ids)

    @property
    def state_changed(self):
        return self.sandbox_observation.state_changed

    def to_dict(self):
        result = asdict(self)
        for key in ('model_output_canary_exposure', 'tool_argument_canary_exposure', 'protected_data_exposed', 'state_changed'):
            result[key] = getattr(self, key)
        return result

    def to_json(self):
        return json.dumps(self.to_dict(), default=lambda v: sorted(v), sort_keys=True)
