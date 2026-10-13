"""Reproduce and verify saved group-stratified split IDs, never silently re-split."""
from .common import DATA, records
from .generate_dataset import split

if __name__ == '__main__':
    dev, test = split(records('all'))
    for name, ids in [('dev', dev), ('test', test)]:
        path = DATA / f'{name}_ids.txt'
        content = '\n'.join(ids) + '\n'
        if path.exists() and path.read_text() != content:
            raise RuntimeError('Frozen split differs; create a new dataset version')
        path.write_text(content, encoding='utf-8')
    print(f'Deterministic family split verified: {len(dev)} dev / {len(test)} test')
