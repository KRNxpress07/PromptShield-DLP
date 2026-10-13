"""Ground-truth leakage and structural preservation on actual gateway DLP."""
from __future__ import annotations

import asyncio
from collections import Counter
import difflib
import importlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from .common import RESULTS, records, write_csv, write_json
from .metrics import ratio
from .runtime import Runtime


def structural(original, sanitized, gold):
    """Ordered character alignment, secondary proxy only, not semantic utility."""
    protected = {i for g in gold for i in range(g['start'], g['end'])}
    clean = sanitized.replace('[REDACTED]', '')
    equal_positions = set()
    for block in difflib.SequenceMatcher(None, original, clean, autojunk=False).get_matching_blocks():
        equal_positions.update(range(block.a, block.a + block.size))
    benign = set(range(len(original))) - protected
    preservation = ratio(len(equal_positions & benign), len(benign))
    original_valid_json = False
    sanitized_valid_json = None
    try:
        json.loads(original)
        original_valid_json = True
        try:
            json.loads(sanitized)
            sanitized_valid_json = True
        except (ValueError, TypeError):
            sanitized_valid_json = False
    except (ValueError, TypeError):
        pass
    return {'non_sensitive_char_preservation': preservation, 'placeholder_count': sanitized.count('[REDACTED]'),
            'original_valid_json': original_valid_json, 'sanitized_valid_json': sanitized_valid_json}


async def block_checks(rt, blocked):
    """Real gateway ASGI route + real scanner + two mocked provider boundaries."""
    import httpx
    gateway = importlib.import_module('evaluation_gateway.main')
    providers = importlib.import_module('evaluation_gateway.providers')
    rt.config._gateway_config = {'api_keys': [{'key': 'benchmark-dummy-gateway', 'name': 'synthetic'}], 'providers': {'groq': {'api_key': 'synthetic-no-live-key'}}, 'dlp': rt.policy}
    gateway._http_client = rt.client
    upstream = AsyncMock(return_value=SimpleNamespace(usage=None, model_dump=lambda: {'choices': [{'message': {'content': 'mock'}}]}))

    async def chunks():
        yield {'choices': [{'delta': {'content': 'mock'}}]}

    streaming = AsyncMock(side_effect=lambda *a, **k: chunks())
    providers.forward_chat_completion = upstream
    providers.forward_chat_completion_stream = streaming
    checks = []
    # At most two per ground-truth primary entity, deterministic; include mixed.
    selected = block_subset(blocked)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app), base_url='http://gateway.local') as client:
        for row in selected:
            for stream in [False, True]:
                upstream.reset_mock()
                streaming.reset_mock()
                gateway._rate_buckets.clear()
                response = await client.post('/v1/chat/completions', headers={'Authorization': 'Bearer benchmark-dummy-gateway'}, json={'messages': [{'role': 'user', 'content': row['text']}], 'stream': stream})
                code = response.json().get('error')
                called = upstream.call_count + streaming.call_count
                passed = response.status_code == 422 and code == 'pii_policy_violation' and called == 0
                checks.append({'id': row['id'], 'stream': stream, 'status': response.status_code, 'code': code, 'provider_calls': called, 'pass': passed})
        # Error behavior measured separately from legitimate policy blocks.
        transport_original = rt.client
        probes = [
            ('unsupported_image', {'messages': [{'role': 'user', 'content': [{'type': 'image_url', 'image_url': {'url': 'https://example.invalid/dummy.png'}}]}]}, 'unsupported_dlp_content', None),
            ('scanner_unavailable', {'messages': [{'role': 'user', 'content': 'Email synthetic@example.com'}]}, 'security_processing_error', 'unavailable'),
            ('retained_value', {'messages': [{'role': 'user', 'content': 'synthetic@example.com'}]}, 'sanitization_verification_failed', 'retained'),
        ]
        for name, payload, expected, fault in probes:
            upstream.reset_mock()
            streaming.reset_mock()
            gateway._rate_buckets.clear()
            if fault:
                def broken(request, fault=fault):
                    if fault == 'unavailable':
                        return httpx.Response(503, json={'error': 'synthetic_fault'})
                    text = json.loads(request.content)['text']
                    return httpx.Response(200, json={'results': [{'entity_type': 'EMAIL_ADDRESS', 'start': 0, 'end': len(text), 'score': .9}], 'anonymized_text': text})
                gateway._http_client = httpx.AsyncClient(transport=httpx.MockTransport(broken))
            response = await client.post('/v1/chat/completions', headers={'Authorization': 'Bearer benchmark-dummy-gateway'}, json=payload)
            called = upstream.call_count + streaming.call_count
            code = response.json().get('error')
            checks.append({'id': name, 'stream': False, 'status': response.status_code, 'code': code, 'provider_calls': called, 'pass': code == expected and called == 0})
            if fault:
                await gateway._http_client.aclose()
            gateway._http_client = transport_original
    return checks


def block_subset(blocked):
    selected, counts = [], Counter()
    for row in blocked:
        kind = row['entities'][0]['entity_type'] if row['entities'] else 'SAFE_CONTROL'
        if counts[kind] < 2:
            selected.append(row)
            counts[kind] += 1
    return selected


async def run():
    rt = Runtime()
    rows, output, human_candidates, blocked = records('test'), [], [], []
    counts = Counter()
    try:
        for row in rows:
            action, sanitized, error = None, None, None
            predictions = []
            try:
                decision = await rt.inspect(row['text'])
                action = decision.assessment.action.value
                predictions = [v.model_dump() for v in decision.scan.violations]
                if action == 'block':
                    blocked.append(row)
                    counts['pii_policy_violation'] += 1
                else:
                    sanitized = decision.payload['messages'][0]['content']
            except Exception as exc:
                error = getattr(exc, 'code', 'scanner_processing_error')
                counts[error] += 1
            sensitive = bool(row['entities'])
            actual_sanitized = sanitized is not None and sanitized != row['text']
            surviving = [e['text'] for e in row['entities'] if sanitized is not None and e['text'] in sanitized]
            residual_predictions, rescan_error = None, None
            if actual_sanitized:
                try:
                    raw = await rt.detect(sanitized, 'project')
                    # Same documented placeholder exception as gateway.
                    offsets = [i for i in range(len(sanitized)) if sanitized.startswith('[REDACTED]', i)]
                    residual_predictions = [p for p in raw if not any(i <= p['start'] < p['end'] <= i + len('[REDACTED]') for i in offsets)]
                except Exception as exc:
                    rescan_error = type(exc).__name__
                    counts['rescan_processing_error'] += 1
            covered = []
            for g in row['entities']:
                covered.append(all(any(p['start'] <= i < p['end'] for p in predictions) for i in range(g['start'], g['end'])))
            shape = structural(row['text'], sanitized, row['entities']) if sanitized is not None else {k: None for k in ['non_sensitive_char_preservation', 'placeholder_count', 'original_valid_json', 'sanitized_valid_json']}
            success = sensitive and actual_sanitized and not surviving and residual_predictions == [] and all(covered)
            item = {'id': row['id'], 'label': row['label'], 'action': action, 'error': error, 'outgoing_available': sanitized is not None, 'actually_sanitized': actual_sanitized, 'all_gold_spans_covered_by_replacements': all(covered) if covered else None, 'exact_gold_survives': bool(surviving), 'surviving_values': json.dumps(surviving), 'post_rescan_findings': len(residual_predictions) if residual_predictions is not None else None, 'post_rescan_error': rescan_error, 'sanitization_success': success if sensitive and actual_sanitized else None, **shape, 'original_prompt': row['text'], 'sanitized_prompt': sanitized}
            output.append(item)
            if actual_sanitized and sensitive:
                human_candidates.append({'id': row['id'], 'original_prompt': row['text'], 'sanitized_prompt': sanitized, 'sensitive_spans': json.dumps(row['entities']), 'task_understandable_1_to_5': '', 'non_sensitive_information_preserved_1_to_5': '', 'meaning_damage_1_to_5': '', 'usable_yes_no': '', 'rater_id': '', 'comments': ''})
        selected = sorted(human_candidates, key=lambda r: r['id'])
        import random
        random.Random(20261013).shuffle(selected)
        selected = selected[:150]
        write_csv(RESULTS / 'human_evaluation_template.csv', selected)
        write_csv(RESULTS / 'sanitization_results.csv', output)
        actual = [r for r in output if r['label'] == 'sensitive' and r['actually_sanitized']]
        outgoing = [r for r in output if r['label'] == 'sensitive' and r['outgoing_available']]
        checks = await block_checks(rt, blocked)
        benchmark_checks = [c for c in checks if c['id'] in {r['id'] for r in rows}]
        write_csv(RESULTS / 'block_effectiveness.csv', checks)
        preserved = [r['non_sensitive_char_preservation'] for r in actual if r['non_sensitive_char_preservation'] is not None]
        summary = {'test_prompts': len(rows), 'sensitive_prompts': sum(r['label'] == 'sensitive' for r in output), 'actually_sanitized_sensitive': len(actual), 'sensitive_outgoing': len(outgoing),
                   'sanitization_success_rate': ratio(sum(r['sanitization_success'] for r in actual), len(actual)),
                   'residual_leakage_rate_sanitized': ratio(sum(r['exact_gold_survives'] for r in actual), len(actual)),
                   'residual_leakage_rate_all_nonblock_sensitive': ratio(sum(r['exact_gold_survives'] for r in outgoing), len(outgoing)),
                   'post_rescan_residual_prompts': sum(bool(r['post_rescan_findings']) for r in actual),
                   'gold_span_replacement_coverage_rate': ratio(sum(r['all_gold_spans_covered_by_replacements'] for r in actual), len(actual)),
                   'mean_non_sensitive_char_preservation': ratio(sum(preserved), len(preserved)),
                   'actions': dict(Counter(r['action'] or r['error'] for r in output)), 'error_counts': dict(counts),
                   'processing_error_rate': ratio(sum(r['error'] is not None for r in output), len(output)), 'fail_closed_rejections_including_policy_blocks': sum(r['error'] is not None or r['action'] == 'block' for r in output),
                   'block_subset_prompts': len({r['id'] for r in benchmark_checks}), 'block_subset_requests': len(benchmark_checks), 'block_check_failures': sum(not r['pass'] for r in checks), 'fault_probes': 3,
                   'human_template_count': len(selected), 'human_ratings': 'PENDING HUMAN EVALUATION',
                   'definitions': {'success': 'Among sensitive prompts actually changed and non-block: all gold characters covered by replacement spans, no exact gold text survives, and no protected rescan finding.', 'leakage': 'Any exact original gold substring survives. Denominators reported for actually sanitized and ALL non-block sensitive prompts (including missed/allow).', 'coverage': 'Ground-truth offsets checked against union of original replacement spans, independent of entity label. Secondary to exact-substring leakage; not encoded/semantic leakage.', 'structural': 'SequenceMatcher ordered unchanged non-sensitive character alignment, placeholder text excluded; not semantic utility.'}}
        write_json(RESULTS / 'sanitization_metrics.json', summary)
        print(json.dumps(summary, indent=2))
    finally:
        await rt.close()
    return summary


def main():
    asyncio.run(run())


if __name__ == '__main__':
    main()
