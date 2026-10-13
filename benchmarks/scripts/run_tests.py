"""Execute all suites separately, retaining exact offline counts and failures."""
import json
import subprocess
import sys
from .common import ROOT, RESULTS, offline, write_json


def main():
    offline()
    summaries = {}
    for suite, folder, args in [
        ('gateway', 'proxy-api', ['tests', '-q', '-p', 'no:cacheprovider', '-p', 'pytest_asyncio.plugin', '--tb=short', '--show-capture=no']),
        ('scanner', 'presidio', ['tests', '-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']),
        ('sdk', 'sdk/python', ['tests', '-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']),
        ('framework', '.', ['benchmarks/tests', '-q', '-p', 'no:cacheprovider', '--tb=short', '--show-capture=no']),
    ]:
        destination = RESULTS / f'test_{suite}.json'
        source = f'''import sys,os,json
sys.path.insert(0,{str(ROOT)!r})
from benchmarks.scripts.common import offline
offline()
sys.path.insert(0,os.getcwd())
import pytest
class Recorder:
 def pytest_sessionfinish(self,session,exitstatus):
  terminal=session.config.pluginmanager.getplugin('terminalreporter')
  result={{k:len(terminal.stats.get(k,[])) for k in ['passed','failed','skipped','error','xfailed','xpassed']}}
  result['exit_code']=int(exitstatus)
  result['phase1_passed']=sum('test_phase1_security.py' in r.nodeid or 'test_phase1_dlp_block_preserves_422_and_typed_exception' in r.nodeid for r in terminal.stats.get('passed',[]))
  result['phase2_passed']=sum('test_phase2_' in r.nodeid for r in terminal.stats.get('passed',[]))
  result['failures']=[r.nodeid for r in terminal.stats.get('failed',[])+terminal.stats.get('error',[])]
  result['arguments']={args!r}
  open({str(destination)!r},'w',encoding='utf-8').write(json.dumps(result,indent=2)+'\\n')
sys.exit(pytest.main({args!r},plugins=[Recorder()]))
'''
        RESULTS.mkdir(parents=True, exist_ok=True)
        result = subprocess.run([sys.executable, '-B', '-c', source], cwd=ROOT / folder, capture_output=True, text=True, encoding='utf-8', errors='replace')
        (RESULTS / f'test_{suite}.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        if destination.exists():
            summaries[suite] = json.loads(destination.read_text())
        else:
            summaries[suite] = {'status': 'NOT VERIFIED', 'exit_code': result.returncode}
        print(suite, json.dumps(summaries[suite]), flush=True)
    write_json(RESULTS / 'test_results.json', summaries)
    return summaries


if __name__ == '__main__':
    main()
