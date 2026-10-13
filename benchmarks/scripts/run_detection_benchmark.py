"""Run project and independent baselines on frozen holdout, retain predictions."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
from .common import DATA, ENTITY_TYPES, RESULTS, digest, environment, production_hashes, records, write_csv, write_json
from .metrics import confusion, matches, prompt_metrics, span_metrics
from .runtime import Runtime
from .validate_dataset import main as validate


def evaluate(rows, predictions):
    output = {'prompt': prompt_metrics(rows, predictions), 'strict_span': span_metrics(rows, predictions, 'strict'), 'relaxed_span': span_metrics(rows, predictions, 'relaxed')}
    output['safe_subsets'] = {kind: prompt_metrics([r for r in rows if r['negative_kind'] == kind], predictions) for kind in ['ordinary', 'hard_negative']}
    output['difficulty'] = {}
    for difficulty in ['easy', 'medium', 'hard']:
        subset = [r for r in rows if r['label'] == 'sensitive' and r['difficulty'] == difficulty]
        output['difficulty'][difficulty] = {'prompts': len(subset), 'prompt': prompt_metrics(subset, predictions), 'strict_span': span_metrics(subset, predictions, 'strict'), 'relaxed_span': span_metrics(subset, predictions, 'relaxed')}
    return output


async def run(split='test'):
    summary = validate()
    frozen = json.loads((DATA / 'production_freeze.json').read_text())
    assert production_hashes() == frozen, 'Production policy/source changed since freeze'
    rows = records(split)
    rt = Runtime()
    output_dir = RESULTS if split == 'test' else RESULTS.parent / 'development'
    if (output_dir / 'metrics.json').exists():
        raise RuntimeError('Existing run must be archived/versioned, not overwritten. Use run_all.py.')
    detectors = ['regex_simple', 'presidio_builtin', 'project']
    result = {'run_started_utc': datetime.now(timezone.utc).isoformat(), 'split': split, 'dataset_sha256': digest(DATA / 'dlp_benchmark.jsonl'), 'dataset': summary, 'environment': environment(), 'production_hashes': frozen,
              'matching': {'headline': 'prompt classification and strict typed exact-span reported separately', 'relaxed': 'one-to-one maximum cardinality, same type, intersection / gold length >= 0.5', 'span_tn_fpr': 'undefined (null): no finite span-negative universe; use prompt occurrence FPR'}, 'detectors': {}}
    try:
        for detector in detectors:
            predictions, errors = {}, []
            for row in rows:
                try:
                    predictions[row['id']] = await rt.detect(row['text'], detector)
                except Exception as exc:
                    predictions[row['id']] = []
                    errors.append({'id': row['id'], 'error_type': type(exc).__name__})
            metrics = evaluate(rows, predictions)
            metrics['errors'] = errors
            metrics['error_rate'] = len(errors) / len(rows)
            # Error cases remain in the denominator with no emitted detections;
            # this counts sensitive errors as FN, not evidence of safe forwarding.
            metrics['supported_types'] = sorted(rt.stock_entities) if detector == 'presidio_builtin' else sorted(__import__('benchmarks.scripts.baselines', fromlist=['PATTERNS']).PATTERNS) if detector == 'regex_simple' else list(ENTITY_TYPES)
            supported = set(metrics['supported_types'])
            # Secondary apples-to-apples entity comparison, not the headline.
            comparable = [{**row, 'entities': [e for e in row['entities'] if e['entity_type'] in supported]} for row in rows]
            metrics['supported_label_strict_span'] = span_metrics(comparable, predictions, 'strict')
            result['detectors'][detector] = metrics
            write_json(output_dir / f'{detector}_predictions.json', predictions)
            write_csv(output_dir / f'{detector}_entity_confusion.csv', confusion(rows, predictions), ['gold', 'predicted', 'count'])
            per_entity, difficulties, fp_rows, fn_rows = [], [], [], []
            for entity in ENTITY_TYPES:
                for level in ['prompt', 'strict', 'relaxed']:
                    m = prompt_metrics(rows, predictions, entity) if level == 'prompt' else span_metrics(rows, predictions, level, entity)
                    per_entity.append({'detector': detector, 'entity': entity, 'level': level, **m})
            for difficulty, group in metrics['difficulty'].items():
                for level in ['prompt', 'strict_span', 'relaxed_span']:
                    difficulties.append({'detector': detector, 'difficulty': difficulty, 'level': level, 'prompts': group['prompts'], **group[level]})
            for row in rows:
                pred = predictions[row['id']]
                pairs = matches(row['entities'], pred)
                used_g, used_p = {g for g, _ in pairs}, {p for _, p in pairs}
                for pi, p in enumerate(pred):
                    if pi not in used_p:
                        fp_rows.append({'id': row['id'], 'label': row['label'], 'negative_kind': row['negative_kind'], 'entity_type': p['entity_type'], 'start': p['start'], 'end': p['end'], 'matched_text': row['text'][p['start']:p['end']], 'prompt': row['text']})
                for gi, g in enumerate(row['entities']):
                    if gi not in used_g:
                        fn_rows.append({'id': row['id'], 'entity_type': g['entity_type'], 'start': g['start'], 'end': g['end'], 'ground_truth': g['text'], 'difficulty': row['difficulty'], 'prompt': row['text']})
            write_csv(output_dir / f'{detector}_per_entity_metrics.csv', per_entity)
            write_csv(output_dir / f'{detector}_difficulty_metrics.csv', difficulties)
            write_csv(output_dir / f'{detector}_false_positives.csv', fp_rows, ['id', 'label', 'negative_kind', 'entity_type', 'start', 'end', 'matched_text', 'prompt'])
            write_csv(output_dir / f'{detector}_false_negatives.csv', fn_rows, ['id', 'entity_type', 'start', 'end', 'ground_truth', 'difficulty', 'prompt'])
            print(detector, json.dumps(metrics['prompt']), 'strict span:', json.dumps(metrics['strict_span']))
        write_json(output_dir / 'metrics.json', result)
        # Convenient headline project artifacts in addition to named comparators.
        import shutil
        for name in ['per_entity_metrics', 'difficulty_metrics', 'false_positives', 'false_negatives', 'entity_confusion']:
            shutil.copyfile(output_dir / f'project_{name}.csv', output_dir / f'{name}.csv')
        write_csv(output_dir / 'confusion_matrix.csv', [{'detector': k, **v['prompt']} for k, v in result['detectors'].items()])
        assert production_hashes() == frozen
    finally:
        await rt.close()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--split', choices=['dev', 'test'], default='test')
    asyncio.run(run(parser.parse_args().split))


if __name__ == '__main__':
    main()
