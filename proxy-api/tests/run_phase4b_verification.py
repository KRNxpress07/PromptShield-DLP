"""Separate offline record; preserves all earlier results and benchmark artifacts."""
from pathlib import Path
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from benchmarks.scripts.common import digest, offline, production_hashes


def main():
    offline()
    results = {}
    suites = [('gateway', 'proxy-api', ['tests', '-p', 'pytest_asyncio.plugin']),
              ('scanner', 'presidio', ['tests']), ('sdk', 'sdk/python', ['tests']),
              ('framework', '.', ['benchmarks/tests'])]
    for name, directory, arguments in suites:
        arguments += ['-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']
        source = f'''import sys,os,json
sys.path.insert(0,{str(ROOT)!r})
from benchmarks.scripts.common import offline
offline()
sys.path.insert(0,os.getcwd())
import pytest
class Recorder:
 def pytest_sessionfinish(self,session,exitstatus):
  terminal=session.config.pluginmanager.getplugin('terminalreporter')
  result={{key:len(terminal.stats.get(key,[])) for key in ['passed','failed','skipped','error','xfailed','xpassed']}}
  result['exit_code']=int(exitstatus)
  result['phase4a_passed']=sum('test_injection_sandbox.py' in r.nodeid for r in terminal.stats.get('passed',[]))
  result['phase4b_passed']=sum('test_behavior_executor.py' in r.nodeid for r in terminal.stats.get('passed',[]))
  result['failures']=[r.nodeid for r in terminal.stats.get('failed',[])+terminal.stats.get('error',[])]
  print('PHASE4B_TEST_JSON='+json.dumps(result))
sys.exit(pytest.main({arguments!r},plugins=[Recorder()]))
'''
        process = subprocess.run([sys.executable, '-B', '-c', source], cwd=ROOT / directory,
                                 capture_output=True, text=True, encoding='utf-8', errors='replace')
        lines = [line.split('PHASE4B_TEST_JSON=', 1)[1] for line in process.stdout.splitlines() if 'PHASE4B_TEST_JSON=' in line]
        results[name] = json.loads(lines[-1]) if lines else {'status': 'NOT VERIFIED', 'exit_code': process.returncode}
        results[name]['arguments'] = arguments
        print(name, json.dumps(results[name]), flush=True)
    ui = subprocess.run(['node', '--test', str(ROOT / 'frontend/tests/test_ui_state.js')], capture_output=True, text=True)
    def node_count(label):
        match = re.search(r'^# ' + label + r' (\d+)$', ui.stdout, re.MULTILINE)
        return int(match.group(1)) if match else None
    results['dashboard_state_tests'] = {'exit_code': ui.returncode, 'passed': node_count('pass'),
                                        'failed': node_count('fail'), 'output': ui.stdout}
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
    results['phase3_preservation'] = 'PASS: frozen backend, benchmark code, results and report unchanged'
    baseline = json.loads((ROOT / 'docs/PHASE4A_TEST_RESULTS.json').read_text())
    results['baseline_failure_preservation'] = all(
        results[key].get('failures') == baseline[key].get('failures') for key in ('gateway', 'scanner', 'sdk', 'framework'))
    results['execution_boundaries'] = {
        'external_network_calls': 0, 'cloud_model_calls': 0,
        'sandbox_model_host_tool_access': 0,
        'evidence': 'Offline bootstrap denies external sockets/DNS; fake adapter and MockTransport only; host tripwire test passed.',
        'real_local_generation': 'NOT RUN',
    }
    results['python_passed'] = sum(results[key].get('passed', 0) for key in ('gateway', 'scanner', 'sdk', 'framework'))
    results['python_failed'] = sum(results[key].get('failed', 0) for key in ('gateway', 'scanner', 'sdk', 'framework'))
    results['total_passed'] = results['python_passed'] + (node_count('pass') or 0)
    results['total_failed'] = results['python_failed'] + (node_count('fail') or 0)
    target = ROOT / 'docs/PHASE4B_TEST_RESULTS.json'
    target.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print('Test record:', target, flush=True)
    if (ui.returncode or results['gateway'].get('phase4a_passed') != 300
            or results['gateway'].get('phase4b_passed') != 124 or not results['baseline_failure_preservation']):
        raise RuntimeError('Phase 4B checks or baseline failure preservation failed')
    return results


if __name__ == '__main__':
    main()
