"""Manual opt-in probe. No software start, model pull, or environment loading."""
import argparse
from pathlib import Path
import sys
import json
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from injection_sandbox.behavior import BehaviorModelConfig
from injection_sandbox.executor import LocalBehaviorExecutor
from injection_sandbox.model_adapter import FakeLocalModelAdapter
from behavior_runtime.ollama import OptionalOllamaAdapter
from behavior_runtime.manual_validation import validate_model, manual_adapter
from injection_sandbox.behavior_risk import assess_behavior
from behavior_runtime.gateway import safe_metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prompt')
    parser.add_argument('--validate-stages', action='store_true', help='Manual plain/tool/public/protected/network validation')
    parser.add_argument('--plain', action='store_true', help='Manual harmless no-tool generation diagnostic')
    parser.add_argument('--output', help='Write a safe staged validation record')
    parser.add_argument('--model', help='Exact name of an already-installed local Ollama model')
    parser.add_argument('--base-url', default='http://127.0.0.1:11434')
    parser.add_argument('--timeout-seconds', type=float, default=10, help='Manual-only timeout, at most 30 seconds; gateway defaults unchanged')
    parser.add_argument('--fake', action='store_true', help='Offline deterministic demonstration')
    args = parser.parse_args()
    if args.fake and args.plain:
        parser.error('--plain requires a real local model; use --fake with --prompt')
    if not 0 < args.timeout_seconds <= 30:
        parser.error('Manual timeout must be greater than zero and at most thirty seconds')
    if args.validate_stages:
        if not args.model or args.fake:
            parser.error('Staged validation requires an explicit installed local model')
        record = validate_model(args.model, args.timeout_seconds, args.base_url,
            progress=lambda name, result: print(json.dumps({'stage': name, **result}), flush=True))
        if args.output:
            Path(args.output).write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(record))
        return 0
    config = BehaviorModelConfig(enabled=True, provider='fake' if args.fake else 'ollama',
                                 model_name=args.model, base_url=args.base_url, timeout_seconds=min(args.timeout_seconds, 10))
    if args.fake:
        adapter = FakeLocalModelAdapter([{'text': '', 'tool_calls': [
            {'id': 'demo', 'name': 'list_directory', 'arguments': {'path': '/public'}}]}])
    elif not args.model:
        print('LOCAL MODEL NOT AVAILABLE (specify --model)')
        return 0
    else:
        config, adapter = manual_adapter(args.model, args.timeout_seconds, args.base_url)
        if not adapter.available():
            print('LOCAL MODEL NOT AVAILABLE')
            return 0
    if args.plain:
        from injection_sandbox.model_adapter import ModelUnavailable
        try:
            print(json.dumps({'plain_generation': adapter.plain_probe(), 'diagnostic': adapter.last_diagnostic}))
        except ModelUnavailable:
            print('LOCAL MODEL NOT AVAILABLE')
        return 0
    if not args.prompt:
        parser.error('Specify --prompt, --plain, or --validate-stages')
    result = LocalBehaviorExecutor(adapter, config).run(args.prompt)
    if result.termination_reason == 'unavailable':
        print('LOCAL MODEL NOT AVAILABLE')
    else:
        print(json.dumps({'termination_reason': result.termination_reason, 'model_calls': result.model_calls,
                          'tool_calls': result.tool_calls, 'assessment': safe_metadata(assess_behavior(result))}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
