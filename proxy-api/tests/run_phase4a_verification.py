"""Offline verification orchestrator, not part of the virtual runtime package."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from benchmarks.scripts.common import digest, offline, production_hashes


def main():
    offline()
    results = {}
    for suite, directory, arguments in [
        ('gateway', 'proxy-api', ['tests', '-q', '-p', 'no:cacheprovider', '-p', 'pytest_asyncio.plugin', '--tb=short', '--show-capture=no']),
        ('scanner', 'presidio', ['tests', '-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']),
        ('sdk', 'sdk/python', ['tests', '-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']),
        ('framework', '.', ['benchmarks/tests', '-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']),
    ]:
        source = f'''import sys,os,json
sys.path.insert(0,{str(ROOT)!r})
from benchmarks.scripts.common import offline
offline()
sys.path.insert(0,os.getcwd())
import pytest
class Recorder:
 def pytest_sessionfinish(self,session,exitstatus):
  t=session.config.pluginmanager.getplugin('terminalreporter')
  result={{k:len(t.stats.get(k,[])) for k in ['passed','failed','skipped','error','xfailed','xpassed']}}
  result['exit_code']=int(exitstatus)
  result['phase1_passed']=sum('test_phase1_security.py' in r.nodeid or 'test_phase1_dlp_block_preserves_422_and_typed_exception' in r.nodeid for r in t.stats.get('passed',[]))
  result['phase2_passed']=sum('test_phase2_' in r.nodeid for r in t.stats.get('passed',[]))
  result['sandbox_passed']=sum('test_injection_sandbox.py' in r.nodeid for r in t.stats.get('passed',[]))
  result['failures']=[r.nodeid for r in t.stats.get('failed',[])+t.stats.get('error',[])]
  print('PHASE4A_TEST_JSON='+json.dumps(result))
sys.exit(pytest.main({arguments!r},plugins=[Recorder()]))
'''
        process = subprocess.run([sys.executable, '-B', '-c', source], cwd=ROOT / directory, capture_output=True, text=True, encoding='utf-8', errors='replace')
        lines = [line.split('PHASE4A_TEST_JSON=', 1)[1] for line in process.stdout.splitlines() if 'PHASE4A_TEST_JSON=' in line]
        results[suite] = json.loads(lines[-1]) if lines else {'status': 'NOT VERIFIED', 'exit_code': process.returncode}
        results[suite]['arguments'] = arguments
        print(suite, json.dumps(results[suite]), flush=True)
    ui = subprocess.run(['node', '--test', str(ROOT / 'frontend/tests/test_ui_state.js')], capture_output=True, text=True)
    results['dashboard_state_tests'] = {'exit_code': ui.returncode, 'output': ui.stdout}
    print(ui.stdout, flush=True)
    frozen = json.loads((ROOT / 'benchmarks/dataset/production_freeze.json').read_text())
    if production_hashes() != frozen:
        raise RuntimeError('Frozen active backend source changed')
    manifest = json.loads((ROOT / 'benchmarks/results/latest/run_manifest.json').read_text())
    for name, sha in {**manifest['benchmark_code_hashes'], **manifest['output_hashes']}.items():
        if digest(ROOT / name) != sha:
            raise RuntimeError('Protected benchmark artifact changed')
    if digest(ROOT / 'docs/PHASE3_ACADEMIC_EVALUATION_REPORT.md') != manifest['report_sha256']:
        raise RuntimeError('Phase 3 report changed')
    results['phase3_preservation'] = 'PASS: frozen active backend, benchmark code, results and report unchanged'
    target = ROOT / 'docs/PHASE4A_TEST_RESULTS.json'
    target.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print('Test record:', target, flush=True)
    if ui.returncode or results['gateway'].get('sandbox_passed') != 300:
        raise RuntimeError('New sandbox/dashboard state checks failed')
    return results


if __name__ == '__main__':
    main()
