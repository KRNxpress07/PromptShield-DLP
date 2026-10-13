"""Fresh deterministic session state, trusted snapshots, event observations."""
from .canaries import CanaryRegistry
from .events import EventLog, derive_signals
from .filesystem import VirtualFilesystem, diff, snapshot_hash
from .models import ResourceLimits, SandboxObservation, SandboxSnapshot
from .policy import SandboxPolicy
from .tools import VirtualTools


class SandboxSession:
    def __init__(self, limits: ResourceLimits | None = None):
        if limits is not None and type(limits) is not ResourceLimits:
            raise ValueError('Expected ResourceLimits')
        self._limits = limits or ResourceLimits()
        self.reset()

    def reset(self):
        self._canaries = CanaryRegistry()
        self._filesystem = VirtualFilesystem(self._canaries, self._limits)
        self._events = EventLog(self._limits.max_events)
        # Rebind the same facade on reset. Previously held bound tool methods
        # then address the new state/log, rather than an unaudited stale session.
        tools = getattr(self, '_tools', None)
        if tools is None:
            self._tools = VirtualTools(self._filesystem, SandboxPolicy(), self._canaries, self._events, self._limits)
        else:
            tools.__init__(self._filesystem, SandboxPolicy(), self._canaries, self._events, self._limits)
        self._initial = self._filesystem.snapshot()

    @property
    def tools(self) -> VirtualTools:
        return self._tools

    @property
    def canaries(self) -> CanaryRegistry:
        # Trusted evaluation API, not a dispatched tool exposed to a model.
        return self._canaries

    @property
    def events(self):
        return self._events.events

    @property
    def initial_state_hash(self) -> str:
        return snapshot_hash(self._initial)

    def snapshot(self) -> SandboxSnapshot:
        return self._filesystem.snapshot()

    def state_hash(self) -> str:
        return snapshot_hash(self.snapshot())

    @staticmethod
    def diff(initial: SandboxSnapshot, current: SandboxSnapshot):
        return diff(initial, current)

    def observation(self) -> SandboxObservation:
        events, final = self.events, self.state_hash()
        changed = self.diff(self._initial, self.snapshot())
        return SandboxObservation(self.initial_state_hash, final, final != self.initial_state_hash, events, derive_signals(events), tuple(sorted({c for event in events if event.canary_accessed for c in event.canary_ids})), sum(event.attempt_count for event in events if not event.allowed), changed.files_modified, changed.files_deleted, changed.files_created, any(event.aggregated for event in events), self._events.total_calls)
