"""Reject malformed labels/spans/splits and verify frozen synthetic provenance."""
import json
from collections import Counter
from .common import DATA, ENTITY_TYPES, VERSION, digest, records
from .generate_dataset import build, split

CATEGORIES = {'short', 'prose', 'code', 'log', 'config', 'csv', 'tool', 'nested', 'boundary', 'markdown', 'long', 'schema', 'json', 'multi_entity', 'ordinary_safe', 'hard_negative'}


def validate(rows, dev_ids, test_ids):
    seen, texts = set(), set()
    for row in rows:
        assert isinstance(row, dict)
        assert isinstance(row['id'], str) and row['id'] and row['id'] not in seen, 'Duplicate/invalid ID'
        seen.add(row['id'])
        assert isinstance(row['text'], str) and row['text'].strip() and row['text'] not in texts, 'Duplicate/empty prompt'
        texts.add(row['text'])
        assert row['label'] in {'safe', 'sensitive'} and row['category'] in CATEGORIES
        assert row['difficulty'] in {'easy', 'medium', 'hard'}
        assert row['synthetic'] is True and row['version'] == VERSION
        assert isinstance(row['entities'], list)
        assert (row['label'] == 'sensitive') == bool(row['entities']), 'Label/entity inconsistency'
        previous_end = 0
        for entity in sorted(row['entities'], key=lambda x: x['start']):
            assert entity['entity_type'] in ENTITY_TYPES, 'Unknown entity type'
            assert type(entity['start']) is int and type(entity['end']) is int
            assert 0 <= entity['start'] < entity['end'] <= len(row['text'])
            assert entity['text'] == row['text'][entity['start']:entity['end']], 'Span text mismatch'
            assert entity['start'] >= previous_end, 'Unintentional overlapping ground truth'
            previous_end = entity['end']
    assert len(dev_ids) == len(set(dev_ids)) and len(test_ids) == len(set(test_ids))
    assert not set(dev_ids) & set(test_ids), 'Split overlap'
    assert set(dev_ids) | set(test_ids) == seen, 'Missing/foreign split IDs'
    dev_families = {r['template_family'] for r in rows if r['id'] in set(dev_ids)}
    test_families = {r['template_family'] for r in rows if r['id'] in set(test_ids)}
    assert not dev_families & test_families, 'Template leakage between splits'
    return {'total': len(rows), 'labels': dict(Counter(r['label'] for r in rows)), 'categories': dict(Counter(r['category'] for r in rows)), 'difficulty': dict(Counter(r['difficulty'] for r in rows)), 'entities': dict(Counter(e['entity_type'] for r in rows for e in r['entities'])), 'dev': len(dev_ids), 'test': len(test_ids)}


def main():
    rows = records('all')
    dev, test = [(DATA / f'{name}_ids.txt').read_text().splitlines() for name in ('dev', 'test')]
    summary = validate(rows, dev, test)
    assert rows == build(), 'Corpus differs from authored synthetic generator; no external data accepted'
    assert (dev, test) == split(rows), 'Splits differ from deterministic freeze'
    manifest = json.loads((DATA / 'freeze_manifest.json').read_text())
    for field, file in [('sha256', 'dlp_benchmark.jsonl'), ('dev_sha256', 'dev_ids.txt'), ('test_sha256', 'test_ids.txt')]:
        assert digest(DATA / file) == manifest[field], 'Frozen artifact hash mismatch'
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == '__main__':
    main()
