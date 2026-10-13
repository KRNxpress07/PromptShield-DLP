"""Actual application scanner/DLP imports under isolated module namespaces."""
from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from .common import ROOT, offline


def package(alias, folder):
    if alias not in sys.modules:
        path = ROOT / folder / 'app'
        spec = importlib.util.spec_from_file_location(alias, path / '__init__.py', submodule_search_locations=[str(path)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)


class Runtime:
    def __init__(self):
        offline()
        import yaml
        import httpx
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine
        package('evaluation_scanner', 'presidio')
        package('evaluation_gateway', 'proxy-api')
        self.scanner = importlib.import_module('evaluation_scanner.main')
        self.scanner_models = importlib.import_module('evaluation_scanner.models')
        self.scanner._analyzer = self.scanner.build_analyzer()
        self.scanner._anonymizer = AnonymizerEngine()
        # Independent built-ins; same installed NLP model/threshold, no custom
        # recognizers, project post-processing, or custom SSN validator.
        self.stock = AnalyzerEngine(nlp_engine=self.scanner._analyzer.nlp_engine)
        self.stock_entities = sorted(set(self.stock.get_supported_entities()) & set(self.policy_entities()))
        self.config = importlib.import_module('evaluation_gateway.config')
        # Explicitly bypass pydantic's .env mechanism, not just load_dotenv.
        safe_settings = self.config.Settings(_env_file=None, presidio_url='http://scanner.local', log_level='critical', rate_limit_rps=100000)
        self.config.get_settings = lambda: safe_settings
        self.policy = yaml.safe_load((ROOT / 'config/gateway.yaml').read_text(encoding='utf-8'))['dlp']
        self.egress = importlib.import_module('evaluation_gateway.egress')
        self.dlp = importlib.import_module('evaluation_gateway.dlp')
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.transport))
        logging.disable(logging.CRITICAL)

    @staticmethod
    def policy_entities():
        import yaml
        return yaml.safe_load((ROOT / 'config/gateway.yaml').read_text(encoding='utf-8'))['dlp']['entities']

    async def process(self, text, anonymize=False):
        request = self.scanner_models.ProcessRequest(text=text, entities=self.policy['entities'], score_threshold=self.policy['confidence_threshold'], anonymize=anonymize, operators={'DEFAULT': {'type': 'replace', 'new_value': '[REDACTED]'}} if anonymize else None)
        return await self.scanner.process(request)

    async def transport(self, request):
        import httpx
        import json
        payload = json.loads(request.content)
        response = await self.scanner.process(self.scanner_models.ProcessRequest(**payload))
        return httpx.Response(200, json=response.model_dump())

    async def detect(self, text, detector):
        if detector == 'project':
            return [r.model_dump() for r in (await self.process(text)).results]
        if detector == 'presidio_builtin':
            return [{'entity_type': r.entity_type, 'start': r.start, 'end': r.end, 'score': r.score}
                    for r in self.stock.analyze(text=text, language='en', entities=self.stock_entities, score_threshold=self.policy['confidence_threshold'])]
        from .baselines import simple_regex
        return simple_regex(text)

    async def inspect(self, text):
        return await self.egress.inspect_outbound_payload(self.client, {'messages': [{'role': 'user', 'content': text}]}, self.policy)

    async def close(self):
        await self.client.aclose()
