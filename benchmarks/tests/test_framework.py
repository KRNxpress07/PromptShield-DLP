"""Known-answer metrics, malformed corpus and deterministic provenance checks."""
import copy
import json
import pytest
from benchmarks.scripts.common import DATA, production_hashes, records
from benchmarks.scripts.generate_dataset import build, split
from benchmarks.scripts.validate_dataset import validate
from benchmarks.scripts.metrics import matches, measures, prompt_metrics, span_metrics, confusion, percentile, size_bucket
from benchmarks.scripts.run_sanitization_benchmark import structural, block_subset


def span(entity='A', start=0, end=4):
    return {'entity_type': entity, 'start': start, 'end': end}


def test_known_prompt_confusion():
    rows = [{'id': str(i), 'entities': [span()] if i < 2 else []} for i in range(4)]
    pred = {'0': [span()], '1': [], '2': [span()], '3': []}
    assert prompt_metrics(rows, pred) == {'tp': 1, 'fp': 1, 'fn': 1, 'tn': 1, 'precision': .5, 'recall': .5, 'f1': .5, 'fpr': .5, 'fnr': .5}


def test_exact_and_relaxed_boundary():
    gold = [span()]
    assert not matches(gold, [span(start=1, end=4)])
    assert matches(gold, [span(start=2, end=5)], 'relaxed') == [(0, 0)]
    assert not matches(gold, [span(start=3, end=5)], 'relaxed')
    assert not matches(gold, [span('B')], 'relaxed')


def test_duplicate_predictions_do_not_double_count():
    rows = [{'id': 'a', 'entities': [span()]}]
    result = span_metrics(rows, {'a': [span(), span()]}, 'strict')
    assert result['tp'] == 1 and result['fp'] == 1 and result['fn'] == 0
    assert result['tn'] is None and result['fpr'] is None


def test_augmenting_path_not_greedy_matching():
    # First gold can use either prediction, second can only use first.
    gold = [span(start=0, end=4), span(start=2, end=6)]
    pred = [span(start=2, end=4), span(start=0, end=2)]
    assert len(matches(gold, pred, 'relaxed')) == 2


def test_taxonomy_confusion_distinguished_from_miss():
    rows = [{'id': 'a', 'entities': [span('MASKED_US_SSN')]}]
    pred = {'a': [span('US_SSN')]}
    assert confusion(rows, pred) == [{'gold': 'MASKED_US_SSN', 'predicted': 'US_SSN', 'count': 1}]
    assert span_metrics(rows, pred, 'strict')['fn'] == 1
    assert prompt_metrics(rows, pred)['tp'] == 1


def test_zero_denominators_are_null():
    m = measures(0, 0, 0, 0)
    assert all(m[k] is None for k in ['precision', 'recall', 'f1', 'fpr', 'fnr'])
    assert measures(0, 1, 1, 0)['f1'] == 0


def test_secondary_preservation_excludes_gold():
    result = structural('Email demo@example.com now', 'Email [REDACTED] now', [{'start': 6, 'end': 22}])
    assert result['non_sensitive_char_preservation'] == 1
    assert result['placeholder_count'] == 1


def test_block_sample_includes_false_positive_safe_controls():
    rows = [{'id': 'safe-' + str(i), 'entities': []} for i in range(3)]
    rows += [{'id': 'secret', 'entities': [span('API_KEY')]}]
    assert [r['id'] for r in block_subset(rows)] == ['safe-0', 'safe-1', 'secret']


@pytest.mark.parametrize('size,expected', [(100, 'small'), (101, 'medium'), (500, 'medium'), (501, 'large'), (2000, 'large'), (2001, 'very_large')])
def test_size_boundaries(size, expected):
    assert size_bucket(size) == expected


def test_percentile_interpolation():
    assert percentile([0, 10], .95) == 9.5
    assert percentile([], .95) is None


def test_frozen_dataset_and_source_unchanged():
    rows = records('all')
    assert rows == build()
    dev, test = split(rows)
    assert len(dev) == 300 and len(test) == 700
    assert validate(rows, dev, test)['total'] == 1000
    assert production_hashes() == json.loads((DATA / 'production_freeze.json').read_text())


@pytest.mark.parametrize('fault', ['duplicate_id', 'duplicate_text', 'wrong_span_text', 'out_of_bounds', 'unknown_entity', 'safe_with_entity', 'sensitive_empty', 'invalid_difficulty', 'invalid_category', 'non_synthetic', 'overlap', 'bool_offset', 'split_overlap', 'missing_split', 'family_overlap'])
def test_reject_malformed_dataset(fault):
    rows = copy.deepcopy(build())
    dev, test = split(rows)
    if fault == 'duplicate_id': rows[1]['id'] = rows[0]['id']
    elif fault == 'duplicate_text': rows[1]['text'] = rows[0]['text']
    elif fault == 'wrong_span_text': rows[0]['entities'][0]['text'] = 'wrong'
    elif fault == 'out_of_bounds': rows[0]['entities'][0]['end'] = 100000
    elif fault == 'unknown_entity': rows[0]['entities'][0]['entity_type'] = 'UNKNOWN'
    elif fault == 'safe_with_entity': rows[0]['label'] = 'safe'
    elif fault == 'sensitive_empty': rows[0]['entities'] = []
    elif fault == 'invalid_difficulty': rows[0]['difficulty'] = 'ultra'
    elif fault == 'invalid_category': rows[0]['category'] = 'unknown'
    elif fault == 'non_synthetic': rows[0]['synthetic'] = False
    elif fault == 'overlap': rows[0]['entities'].append(rows[0]['entities'][0].copy())
    elif fault == 'bool_offset': rows[0]['entities'][0]['start'] = True
    elif fault == 'split_overlap': test.append(dev[0])
    elif fault == 'missing_split': test.pop()
    elif fault == 'family_overlap':
        dev_id, test_id = dev[0], test[0]
        next(r for r in rows if r['id'] == test_id)['template_family'] = next(r for r in rows if r['id'] == dev_id)['template_family']
    with pytest.raises(AssertionError):
        validate(rows, dev, test)
