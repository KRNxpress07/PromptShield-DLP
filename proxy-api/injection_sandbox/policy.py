"""Class floors and per-resource capabilities, independent of filename spelling."""
from dataclasses import dataclass
from .models import Classification, Operation, VirtualDirectory, VirtualFile

_RANK = {Classification.PUBLIC: 0, Classification.INTERNAL: 1, Classification.RESTRICTED: 2, Classification.PROTECTED: 3}
READ_OPERATIONS = frozenset({Operation.LIST, Operation.READ, Operation.EXISTS, Operation.METADATA})
MUTATIONS = frozenset({Operation.WRITE, Operation.APPEND, Operation.DELETE})


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    classification: Classification


class SandboxPolicy:
    def decide(self, operation: Operation, resource: VirtualFile | VirtualDirectory, parents: tuple[VirtualDirectory, ...] = ()) -> PolicyDecision:
        classification = max((r.classification for r in (resource, *parents)), key=_RANK.__getitem__)
        if classification is Classification.PROTECTED:
            return PolicyDecision(False, 'protected_resource', classification)
        if classification is Classification.RESTRICTED:
            return PolicyDecision(False, 'restricted_resource', classification)
        if classification is Classification.INTERNAL and operation in MUTATIONS:
            return PolicyDecision(False, 'internal_read_only', classification)
        capability = 'read_allowed' if operation in READ_OPERATIONS else 'delete_allowed' if operation is Operation.DELETE else 'write_allowed'
        allowed = all(getattr(r, capability) for r in (resource, *parents))
        return PolicyDecision(allowed, 'allowed' if allowed else 'capability_denied', classification)
