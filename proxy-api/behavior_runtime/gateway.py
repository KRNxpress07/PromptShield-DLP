"""Gateway-only policy composition, bounded capacity, and safe telemetry."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import time

from injection_sandbox.behavior_risk import assess_behavior, KNOWN_TERMINATIONS
from injection_sandbox.behavior_verdict import (BehaviorRiskAssessment, Completeness,
    Verdict, SEVERITY_FLOORS, REASON_PHRASES, ASSESSMENT_VERSION)
from injection_sandbox.executor import LocalBehaviorExecutor
from .ollama import OptionalOllamaAdapter

FAILURES = {
    'input_too_large': 'BEHAVIOR_INPUT_TOO_LARGE',
    'capacity_unavailable': 'BEHAVIOR_CAPACITY_UNAVAILABLE',
    'runtime_error': 'BEHAVIOR_RUNTIME_ERROR',
    'runtime_missing': 'BEHAVIOR_RUNTIME_MISSING',
}


def unavailable(reason):
    code = FAILURES[reason]
    return BehaviorRiskAssessment(None, None, Verdict.NOT_EVALUATED, Completeness.FAILED,
        (code, 'EVIDENCE_INCOMPLETE'), (), (), None, (), reason,
        'Behavioral analysis could not be completed.', 'UNAVAILABLE')


def canonical_input(payload, trusted_model, limit):
    # Import lazily: only the gateway owns forwarding inventory and validation.
    from app.egress import provider_text_inventory
    _, paths, texts = provider_text_inventory(payload, trusted_model=trusted_model)
    if sum(len(text.content) for text in texts) > limit:
        return None
    entries = [{'path': list(path), 'kind': 'key' if key else 'value', 'text': text.content}
               for (path, key), text in zip(paths, texts)]
    entries.sort(key=lambda entry: json.dumps([entry['path'], entry['kind']], ensure_ascii=True))
    # Check progressively, including structural labels and JSON escaping. Never
    # silently truncate or pass only the message-content subset to the model.
    encoder = json.JSONEncoder(ensure_ascii=True, separators=(',', ':'), sort_keys=True)
    chunks, size = [], 0
    for chunk in encoder.iterencode({'format': 'provider-text-v1', 'leaves': entries}):
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return ''.join(chunks)


def safe_metadata(assessment):
    allowed_reasons = set(REASON_PHRASES) | set(FAILURES.values())
    return {'score': assessment.score, 'severity': assessment.severity.value if assessment.severity else None,
            'verdict': assessment.verdict.value,
            'reasons': [code for code in assessment.reason_codes if code in allowed_reasons],
            'completeness': assessment.evidence_completeness.value,
            'assessment_version': ASSESSMENT_VERSION}


@dataclass(frozen=True)
class PreflightOutcome:
    assessment: BehaviorRiskAssessment
    duration_ms: int
    attempted: bool
    blocked: bool
    status_code: int | None
    error_code: str | None

    def metadata(self):
        return safe_metadata(self.assessment)

    def telemetry(self, mode):
        termination = self.assessment.execution_termination
        return {'mode': mode, 'execution_attempted': self.attempted, 'duration_ms': self.duration_ms,
                'termination_reason': termination if termination in KNOWN_TERMINATIONS or termination in FAILURES else 'unknown',
                'assessment_completeness': self.assessment.evidence_completeness.value,
                'severity': self.metadata()['severity'], 'score': self.assessment.score,
                'verdict': self.assessment.verdict.value, 'reason_codes': self.metadata()['reasons'],
                'blocked': self.blocked}


def policy_outcome(config, assessment, start, attempted=False):
    blocked = False
    status = code = None
    if config.mode == 'enforce':
        if assessment.severity and SEVERITY_FLOORS[assessment.severity] >= SEVERITY_FLOORS[config.block_severity]:
            blocked, status, code = True, 422, 'behavioral_injection_blocked'
        elif ((assessment.verdict == Verdict.NOT_EVALUATED and config.fail_closed_on_not_evaluated)
              or (assessment.evidence_completeness == Completeness.PARTIAL and config.fail_closed_on_partial)
              or assessment.execution_termination == 'capacity_unavailable'):
            blocked, status, code = True, 503, 'behavioral_security_unavailable'
    return PreflightOutcome(assessment, max(0, int((time.monotonic() - start) * 1000)), attempted,
                            blocked, status, code)


class ModeOverrideError(ValueError):
    def __init__(self, code, status):
        self.code, self.status = code, status


def effective_mode(config, override=None):
    if override is None:
        return config.mode
    if type(override) is not str or override not in ('off', 'audit', 'enforce'):
        raise ModeOverrideError('invalid_behavioral_mode_override', 400)
    if not config.allow_request_mode_override:
        raise ModeOverrideError('behavioral_mode_override_disabled', 403)
    return override


class BehavioralPreflight:
    """One runtime per application lifespan; no verdict cache, fresh sessions."""
    def __init__(self, config, *, adapter_factory=None):
        self.config = config
        self.closed = False
        self.waiting = self.active = 0
        self.slots = asyncio.Semaphore(config.max_concurrent)
        self.pool = None
        self.adapter_factory = adapter_factory
        self.availability_adapter = None
        self.status_cache = None
        self.status_lock = asyncio.Lock()
        if config.mode != 'off' or config.allow_request_mode_override:
            if adapter_factory is None:
                adapter = OptionalOllamaAdapter(config.execution_config())
                self.adapter_factory = lambda: adapter
                self.availability_adapter = adapter
            self.pool = ThreadPoolExecutor(max_workers=config.max_concurrent, thread_name_prefix='behavioral')

    def _execute(self, text, config):
        try:
            result = LocalBehaviorExecutor(self.adapter_factory(), config.execution_config()).run(text)
            return assess_behavior(result)
        except Exception:
            return unavailable('runtime_error')

    async def evaluate(self, payload, *, trusted_model=False, mode=None):
        selected = self.config.mode if mode is None else effective_mode(self.config, mode)
        config = self.config if selected == self.config.mode else self.config.model_copy(update={'mode': selected})
        if config.mode == 'off':
            return None
        start = time.monotonic()
        if self.closed:
            return policy_outcome(config, unavailable('runtime_missing'), start)
        try:
            text = canonical_input(payload, trusted_model, self.config.max_behavior_input_chars)
        except Exception:
            return policy_outcome(config, unavailable('runtime_error'), start)
        if text is None:
            return policy_outcome(config, unavailable('input_too_large'), start)
        # Single-event-loop admission accounting caps running + waiting requests.
        if self.waiting + self.active >= self.config.max_concurrent + self.config.max_queue:
            return policy_outcome(config, unavailable('capacity_unavailable'), start)
        self.waiting += 1
        try:
            await asyncio.wait_for(self.slots.acquire(), self.config.queue_timeout_seconds)
        except asyncio.TimeoutError:
            return policy_outcome(config, unavailable('capacity_unavailable'), start)
        finally:
            self.waiting -= 1
        self.active += 1
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(self.pool, self._execute, text, config)
        except Exception:
            self.active -= 1
            self.slots.release()
            return policy_outcome(config, unavailable('runtime_error'), start)

        def release(_):
            self.active -= 1
            self.slots.release()
        future.add_done_callback(release)
        # Cancellation must not free a slot while its synchronous worker runs.
        assessment = await asyncio.shield(future)
        return policy_outcome(config, assessment, start, attempted=True)

    async def status(self):
        configured = bool(self.config.model)
        active = self.config.mode != 'off' or self.config.allow_request_mode_override
        available = False
        if active and not self.closed:
            async with self.status_lock:
                if self.status_cache is None or time.monotonic() - self.status_cache[0] > 5:
                    try:
                        value = await asyncio.to_thread(self.availability_adapter.available) if self.availability_adapter else False
                    except Exception:
                        value = False
                    self.status_cache = (time.monotonic(), bool(value))
                available = self.status_cache[1]
        return {'configured': configured, 'enabled': active, 'runtime_available': available,
            'model_name': self.config.model, 'mode': self.config.mode,
            'allow_request_mode_override': self.config.allow_request_mode_override,
            'assessment_version': ASSESSMENT_VERSION}

    def close(self):
        self.closed = True
        if self.pool is not None:
            self.pool.shutdown(wait=False, cancel_futures=True)
