"""Phase 4A virtual tool environment. Not registered with gateway or any LLM."""
from .models import (
    BehaviorSignals, Canary, Classification, FileMetadata, FilesystemDiff,
    Operation, ResourceLimits, SandboxEvent, SandboxObservation,
    SandboxSnapshot, ToolResult, VirtualDirectory, VirtualFile,
)
from .sandbox import SandboxSession

__all__ = [
    'SandboxSession', 'ResourceLimits', 'Classification', 'Operation',
    'VirtualFile', 'VirtualDirectory', 'FileMetadata', 'Canary', 'SandboxEvent',
    'ToolResult', 'SandboxSnapshot', 'FilesystemDiff', 'BehaviorSignals',
    'SandboxObservation',
]
