"""JSON-only trusted adapter contract and deterministic offline implementation."""
from typing import Protocol
import json


class LocalModelAdapter(Protocol):
    def generate(self, request_json: str) -> str:
        """Return JSON {text: string, tool_calls: [{id, name, arguments}]}."""


class ModelUnavailable(Exception):
    """Configured local service/model is unavailable; no fallback permitted."""


class FakeLocalModelAdapter:
    """Scripted JSON responses, exceptions, or trusted request-to-response functions.

    Callables are test fixtures, never supplied by a model. Only JSON crosses
    this boundary. Create a new adapter to replay a script from its beginning.
    """
    def __init__(self, responses=(), *, repeat_last=False):
        self.responses = tuple(responses)
        self.repeat_last = repeat_last
        self.calls = 0

    def generate(self, request_json):
        index = self.calls
        self.calls += 1
        if index >= len(self.responses):
            if not self.repeat_last or not self.responses:
                return json.dumps({'text': 'Done.', 'tool_calls': []})
            index = len(self.responses) - 1
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        if callable(response):
            response = response(request_json)
        return response if isinstance(response, str) else json.dumps(response)
