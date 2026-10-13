"""Baselines run with detection in one versioned experiment, or inspect results."""
import json
from .common import RESULTS


def main():
    path = RESULTS / 'metrics.json'
    if not path.exists():
        from .run_detection_benchmark import main as detection
        detection()
    result = json.loads(path.read_text())
    for detector, data in result['detectors'].items():
        print(detector, 'prompt F1:', data['prompt']['f1'], 'strict span F1:', data['strict_span']['f1'])


if __name__ == '__main__':
    main()
