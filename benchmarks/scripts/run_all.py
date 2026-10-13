"""Full versioned offline experiment, with sequential timing and no score tuning."""
from datetime import datetime, timezone
import shutil
from .common import DATA, RESULTS, offline, production_hashes, write_json


def main():
    offline()
    base = RESULTS.parent.resolve()
    source = RESULTS.resolve()
    if source.exists() and any(source.iterdir()):
        target = (base / ('run_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))).resolve()
        # Resolved recursive move endpoints must remain inside benchmark results.
        assert source.parent == base and target.parent == base and source != base
        shutil.move(str(source), str(target))
    RESULTS.mkdir(parents=True, exist_ok=True)
    from .validate_dataset import main as validate
    from .run_detection_benchmark import run as detection
    from .run_sanitization_benchmark import run as sanitization
    from .run_tests import main as tests
    from .performance import latency, throughput
    from .generate_report import main as report
    import asyncio
    import json
    try:
        validate()
        assert production_hashes() == json.loads((DATA / 'production_freeze.json').read_text())
        asyncio.run(detection())
        asyncio.run(sanitization())
        tests()
        asyncio.run(latency())
        throughput()
        report()
    except Exception as exc:
        write_json(RESULTS / 'run_failure.json', {'status': 'INCOMPLETE: uncomputed metrics NOT VERIFIED', 'error_type': type(exc).__name__})
        raise


if __name__ == '__main__':
    main()
