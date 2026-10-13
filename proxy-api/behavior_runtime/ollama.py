"""Explicit loopback-only Ollama transport. No environment credentials or pulls."""
import json
import re
import time
import httpx
from injection_sandbox.behavior import loopback_url
from injection_sandbox.model_adapter import ModelUnavailable


class OptionalOllamaAdapter:
    def __init__(self, config, *, transport=None, manual_timeout_seconds=None, manual_prediction_tokens=128):
        if not config.enabled or config.provider != 'ollama' or not config.model_name:
            raise ValueError('Explicit enabled Ollama model configuration required')
        self.config = config
        self.base_url = loopback_url(config.base_url)
        self.transport = transport
        if manual_timeout_seconds is not None and (type(manual_timeout_seconds) not in (int, float) or not 0 < manual_timeout_seconds <= 30):
            raise ValueError('Manual timeout must be between zero and thirty seconds')
        if type(manual_prediction_tokens) is not int or not 16 <= manual_prediction_tokens <= 512:
            raise ValueError('Invalid manual prediction budget')
        self.timeout = manual_timeout_seconds if manual_timeout_seconds is not None else config.timeout_seconds
        self.manual = manual_timeout_seconds is not None
        self.prediction_tokens = manual_prediction_tokens if self.manual else 1024
        self.last_diagnostic = {}

    def _request(self, method, path, payload=None):
        start = time.monotonic()
        self.last_diagnostic = {'http_status': None, 'condition': 'request_started'}
        try:
            with httpx.Client(trust_env=False, follow_redirects=False,
                              timeout=self.timeout, transport=self.transport) as client:
                with client.stream(method, self.base_url + path, json=payload) as response:
                    self.last_diagnostic['http_status'] = response.status_code
                    if response.status_code != 200:
                        self.last_diagnostic['condition'] = 'http_error'
                        raise ModelUnavailable('Local service unavailable')
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > self.config.max_response_chars * 4:
                            raise ValueError('Local response exceeds byte limit')
                        chunks.append(chunk)
                    result = json.loads(b''.join(chunks))
                    self.last_diagnostic['condition'] = 'completed'
                    if type(result) is dict:
                        for key in ('load_duration', 'prompt_eval_duration', 'eval_duration', 'eval_count', 'prompt_eval_count'):
                            if type(result.get(key)) is int and result[key] >= 0:
                                self.last_diagnostic[key] = result[key]
                        if result.get('done_reason') in ('stop', 'length', 'load'):
                            self.last_diagnostic['done_reason'] = result['done_reason']
                        message = result.get('message', {})
                        if type(message) is dict and type(message.get('tool_calls', [])) is list:
                            self.last_diagnostic['tool_calls'] = len(message.get('tool_calls', []))
                            self.last_diagnostic['argument_shapes'] = []
                            for call in message.get('tool_calls', [])[:16]:
                                function = call.get('function', {}) if type(call) is dict else {}
                                arguments = function.get('arguments') if type(function) is dict else None
                                self.last_diagnostic['argument_shapes'].append({'type': type(arguments).__name__,
                                    'known_keys': sorted(key for key in arguments if key in ('path','content','target','command')) if type(arguments) is dict else [],
                                    'extra_keys': bool(set(arguments)-{'path','content','target','command'}) if type(arguments) is dict else False})
                    return result
        except ModelUnavailable:
            raise
        except httpx.TimeoutException:
            self.last_diagnostic['condition'] = 'timeout'
            raise ModelUnavailable('Local request timed out') from None
        except (httpx.HTTPError, OSError, ValueError, TypeError, RecursionError):
            self.last_diagnostic['condition'] = 'transport_or_response_error'
            raise ModelUnavailable('Local service unavailable') from None
        finally:
            self.last_diagnostic['duration_ms'] = int((time.monotonic() - start) * 1000)

    def available(self):
        """Verify an already-installed local model; never request a download."""
        if 'cloud' in self.config.model_name.lower():
            return False
        try:
            result = self._request('GET', '/api/tags')
            if type(result) is not dict or type(result.get('models')) is not list:
                return False
            for model in result['models']:
                if (type(model) is dict and model.get('name') == self.config.model_name
                        and type(model.get('size')) is int and model['size'] > 0
                        and type(model.get('digest')) is str
                        and re.fullmatch(r'(?:sha256:)?[a-fA-F0-9]{64}', model['digest'])
                        and not _remote_metadata(model)):
                    return True
        except (ModelUnavailable, RecursionError):
            pass
        return False

    def generate(self, request_json):
        # Recheck each call: no reliance on stale model availability or cloud aliases.
        if not self.available():
            raise ModelUnavailable('Configured local model not available')
        request = json.loads(request_json)
        messages = []
        for entry in request['messages']:
            message = dict(entry)
            if 'tool_calls' in message:
                message['tool_calls'] = [{'function': {'name': call['name'], 'arguments': call['arguments']}}
                                         for call in message['tool_calls']]
            if message['role'] == 'tool':
                # Ollama uses tool_name, rather than OpenAI tool_call_id.
                prior = messages[-1]['tool_calls'][0]['function']['name']
                message['tool_name'] = prior
                message.pop('tool_call_id', None)
            messages.append(message)
        options = {'temperature': 0, 'seed': 0, 'num_predict': max(1, min(self.prediction_tokens, request['max_output_chars']))}
        if self.manual:
            options['num_ctx'] = 4096
        response = self._request('POST', '/api/chat', {
            'model': self.config.model_name, 'messages': messages, 'tools': request['tools'],
            'stream': False, 'options': options,
        })
        if type(response) is not dict or type(response.get('message')) is not dict:
            raise ValueError('Malformed local model response')
        message = response['message']
        calls = []
        for index, call in enumerate(message.get('tool_calls', [])):
            function = call['function']
            arguments = function['arguments']
            # Observed local legacy parser envelope. Translate only this exact
            # matching wrapper; executor still validates every inner key/type.
            if (type(arguments) is dict and set(arguments) == {'type', 'function', 'parameters'}
                    and arguments['type'] == 'function' and arguments['function'] == function['name']
                    and type(arguments['parameters']) is dict):
                arguments = arguments['parameters']
                self.last_diagnostic['legacy_envelopes_normalized'] = self.last_diagnostic.get('legacy_envelopes_normalized', 0) + 1
            calls.append({'id': 'local_' + str(index), 'name': function['name'], 'arguments': arguments})
        return json.dumps({'text': message.get('content', ''), 'tool_calls': calls,
                           'output_truncated': response.get('done_reason') == 'length' or response.get('done') is False})

    def plain_probe(self):
        """Manual diagnostic only: harmless text, no tools or user prompt."""
        if not self.manual:
            raise ValueError('Explicit manual transport required')
        if not self.available():
            raise ModelUnavailable('Configured local model not available')
        result = self._request('POST', '/api/chat', {'model': self.config.model_name, 'stream': False,
            'messages': [{'role': 'user', 'content': 'Respond with only the word READY.'}],
            'options': {'temperature': 0, 'seed': 0, 'num_predict': 16, 'num_ctx': 4096}})
        message = result.get('message', {})
        return {'completed': result.get('done') is True and result.get('done_reason') != 'length',
                'nonempty_output': type(message.get('content')) is str and bool(message['content'].strip()),
                'output_chars': len(message.get('content', ''))}


def _remote_metadata(value):
    if type(value) is dict:
        return any('remote' in key.lower() or 'cloud' in key.lower() or _remote_metadata(item)
                   for key, item in value.items())
    if type(value) is list:
        return any(_remote_metadata(item) for item in value)
    return type(value) is str and 'cloud' in value.lower()
