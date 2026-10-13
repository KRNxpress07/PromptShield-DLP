"""Deterministic bounded audit: individual results, compacted overflow counters."""
from dataclasses import replace
from .models import BehaviorSignals, SandboxEvent, Signal


class EventLog:
    def __init__(self, max_events: int):
        self._limit = max_events
        self._events: list[SandboxEvent] = []
        self._sequence = 0

    @property
    def exhausted(self) -> bool:
        # Reserve one slot for all denied calls after normal logging capacity.
        return self._sequence >= self._limit - 1

    @property
    def total_calls(self) -> int:
        return self._sequence

    @property
    def events(self) -> tuple[SandboxEvent, ...]:
        return tuple(self._events)

    def record(self, **fields) -> SandboxEvent:
        self._sequence += 1
        emitted = SandboxEvent(event_id=f'event-{self._sequence:06d}', sequence=self._sequence, first_sequence=self._sequence, **fields)
        if not self._events or not self._events[-1].aggregated:
            stored = replace(emitted, aggregated=True) if emitted.reason == 'event_limit' else emitted
            self._events.append(stored)
        else:
            prior = self._events[-1]
            # Overflow calls cannot mutate state; preserve total counts, the
            # latest requested metadata and all known signal/canary evidence.
            self._events[-1] = replace(emitted, aggregated=True, first_sequence=prior.first_sequence, attempt_count=prior.attempt_count + 1, signal_flags=prior.signal_flags | emitted.signal_flags, canary_ids=tuple(sorted(set(prior.canary_ids) | set(emitted.canary_ids))))
        return emitted


def derive_signals(events: tuple[SandboxEvent, ...]) -> BehaviorSignals:
    flags = set().union(*(event.signal_flags for event in events))
    return BehaviorSignals(**{signal.value: signal in flags for signal in Signal})
