"""Literal opt-in gateway policy; no environment or credential discovery."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from injection_sandbox.behavior import BehaviorModelConfig


class BehavioralConfigurationError(ValueError):
    """Controlled configuration error with no untrusted values."""


class BehavioralInjectionConfig(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    mode: Literal['off', 'audit', 'enforce'] = 'off'
    allow_request_mode_override: bool = False
    provider: Literal['ollama'] = 'ollama'
    model: str | None = None
    base_url: str = 'http://127.0.0.1:11434'
    timeout_seconds: float = Field(default=10, gt=0, le=10, allow_inf_nan=False)
    block_severity: Literal['LOW', 'ELEVATED', 'SUSPICIOUS', 'HIGH', 'CRITICAL'] = 'HIGH'
    fail_closed_on_not_evaluated: bool = True
    fail_closed_on_partial: bool = False
    max_steps: int = Field(default=12, ge=1, le=64)
    max_model_calls: int = Field(default=12, ge=1, le=64)
    max_tool_calls: int = Field(default=16, ge=1, le=128)
    max_output_chars: int = Field(default=8192, ge=1, le=65536)
    max_total_transcript_chars: int = Field(default=65536, ge=1024, le=262144)
    max_response_chars: int = Field(default=32768, ge=256, le=262144)
    max_behavior_input_chars: int = Field(default=12000, ge=1, le=65536)
    max_concurrent: int = Field(default=2, ge=1, le=16)
    max_queue: int = Field(default=16, ge=0, le=128)
    queue_timeout_seconds: float = Field(default=2, gt=0, le=10, allow_inf_nan=False)

    @model_validator(mode='after')
    def valid_runtime(self):
        if (self.mode != 'off' or self.allow_request_mode_override) and not self.model:
            raise ValueError('Explicit local model required')
        self.execution_config()  # Validate model/address even when mode is off.
        if self.max_behavior_input_chars > self.max_total_transcript_chars:
            raise ValueError('Input limit must fit transcript budget')
        return self

    def execution_config(self):
        return BehaviorModelConfig(enabled=self.mode != 'off' or self.allow_request_mode_override, provider=self.provider,
            model_name=self.model, base_url=self.base_url, timeout_seconds=self.timeout_seconds,
            max_steps=self.max_steps, max_model_calls=self.max_model_calls, max_tool_calls=self.max_tool_calls,
            max_output_chars=self.max_output_chars, max_total_transcript_chars=self.max_total_transcript_chars,
            max_response_chars=self.max_response_chars)


def validate_behavioral_config(value):
    try:
        return BehavioralInjectionConfig.model_validate(value)
    except (ValueError, TypeError):
        raise BehavioralConfigurationError('Invalid behavioral injection configuration') from None
