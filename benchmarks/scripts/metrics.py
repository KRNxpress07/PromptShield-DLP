"""Prompt confusion and maximum-cardinality one-to-one span matching."""
from collections import Counter
import math
import statistics


def ratio(a, b):
    return a / b if b else None


def measures(tp, fp, fn, tn=None):
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'precision': precision, 'recall': recall,
            'f1': ratio(2 * tp, 2 * tp + fp + fn), 'fpr': ratio(fp, fp + tn) if tn is not None else None, 'fnr': ratio(fn, fn + tp)}


def overlap(g, p):
    return max(0, min(g['end'], p['end']) - max(g['start'], p['start'])) / (g['end'] - g['start'])


def matches(gold, pred, method='strict', typed=True):
    """Maximum cardinality matching, deterministic ordering; no double-counting."""
    assert method in {'strict', 'relaxed'}
    adjacency = {}
    for gi, g in enumerate(gold):
        adjacency[gi] = [pi for pi, p in enumerate(pred)
                         if (not typed or g['entity_type'] == p['entity_type']) and
                         ((g['start'], g['end']) == (p['start'], p['end']) if method == 'strict' else overlap(g, p) >= .5)]
        adjacency[gi].sort(key=lambda pi: (gold[gi]['entity_type'] != pred[pi]['entity_type'], -overlap(gold[gi], pred[pi]), pi))
    owners = {}

    def augment(gi, seen):
        for pi in adjacency[gi]:
            if pi in seen:
                continue
            seen.add(pi)
            if pi not in owners or augment(owners[pi], seen):
                owners[pi] = gi
                return True
        return False

    for gi in range(len(gold)):
        augment(gi, set())
    return sorted((gi, pi) for pi, gi in owners.items())


def prompt_metrics(rows, predictions, entity=None):
    counts = Counter()
    for row in rows:
        expected = any(e['entity_type'] == entity for e in row['entities']) if entity else bool(row['entities'])
        predicted = any(e['entity_type'] == entity for e in predictions[row['id']]) if entity else bool(predictions[row['id']])
        counts['tp' if expected and predicted else 'fn' if expected else 'fp' if predicted else 'tn'] += 1
    return measures(counts['tp'], counts['fp'], counts['fn'], counts['tn'])


def span_metrics(rows, predictions, method, entity=None):
    tp, fp, fn = 0, 0, 0
    for row in rows:
        gold = [e for e in row['entities'] if not entity or e['entity_type'] == entity]
        pred = [e for e in predictions[row['id']] if not entity or e['entity_type'] == entity]
        count = len(matches(gold, pred, method))
        tp += count
        fp += len(pred) - count
        fn += len(gold) - count
    # A span has no finite natural negative universe. FPR/TN are undefined here;
    # per-entity prompt occurrence supplies a defensible negative unit instead.
    return measures(tp, fp, fn)


def confusion(rows, predictions):
    result = Counter()
    for row in rows:
        gold, pred = row['entities'], predictions[row['id']]
        pairs = matches(gold, pred, 'relaxed', typed=False)
        used_g, used_p = {g for g, _ in pairs}, {p for _, p in pairs}
        for gi, pi in pairs:
            result[(gold[gi]['entity_type'], pred[pi]['entity_type'])] += 1
        for gi, g in enumerate(gold):
            if gi not in used_g:
                result[(g['entity_type'], 'MISSED')] += 1
        for pi, p in enumerate(pred):
            if pi not in used_p:
                result[('SPURIOUS', p['entity_type'])] += 1
    return [{'gold': g, 'predicted': p, 'count': n} for (g, p), n in sorted(result.items())]


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    low, high = math.floor(index), math.ceil(index)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def latency_stats(values):
    return {'count': len(values), 'mean_ms': statistics.mean(values) if values else None,
            'median_ms': statistics.median(values) if values else None, 'p95_ms': percentile(values, .95), 'p99_ms': percentile(values, .99),
            'min_ms': min(values) if values else None, 'max_ms': max(values) if values else None,
            'stddev_ms': statistics.pstdev(values) if values else None}


def size_bucket(size):
    return 'small' if size <= 100 else 'medium' if size <= 500 else 'large' if size <= 2000 else 'very_large'
