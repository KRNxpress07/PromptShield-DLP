const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const ui=require('../local-model.js');
const root=path.resolve(__dirname,'../..');
const summary=JSON.parse(execFileSync(path.join(root,'.venv/Scripts/python.exe'),['-c',"import sys,json;sys.path.insert(0,'frontend');import local_results;print(json.dumps(local_results.local_summary()))"],{cwd:root,encoding:'utf8'}));
test('All headline measurements come from saved Phase 4E artifacts',()=>{
 const raw=JSON.parse(fs.readFileSync(path.join(root,'benchmarks/behavioral_real/results_llama32.json')));
 const r=ui.render(summary);
 for(const k of ['precision','recall','f1','fpr','fnr'])assert.ok(r.metricHTML.includes(ui.pct(raw.metrics[k])));
 for(const k of ['mean_ms','median_ms','p95_ms'])assert.ok(r.metricHTML.includes(ui.ms(raw.latency[k])));
 assert.ok(r.metricHTML.includes(`${summary.evaluation.not_evaluated_count} / ${raw.case_count}`));
});
test('Undefined static precision is N/A and comparison chart uses source values',()=>{
 const r=ui.render(summary);assert.match(r.countsHTML,/<td>N\/A<\/td>/);
 for(const k of ['precision','recall','f1','fpr'])for(const system of ['static','behavioral','layered'])assert.ok(r.countsHTML.includes(ui.pct(summary.evaluation.systems[system][k])));
 assert.match(r.comparisonHTML,/bklit-chart/);
 assert.match(r.comparisonHTML,/zero to 100 percent axis/);
});
test('Classification counts match saved comparison artifact',()=>{
 const r=ui.render(summary);for(const value of Object.values(summary.evaluation.systems))for(const k of ['tp','fp','tn','fn'])assert.ok(r.countsHTML.includes(`<td>${value[k]}</td>`));
});
test('Probe examples use validation evidence and never averages',()=>{
 const r=ui.render(summary);for(const probe of Object.values(summary.validation.probes)){assert.ok(r.probesHTML.includes(String(probe.score)));assert.ok(r.probesHTML.includes(probe.severity));}
 assert.ok(r.validationHTML.includes(summary.validation.schema_note));
});
test('Missing artifacts show N/A with no measured fallback',()=>{
 const r=ui.render(null);assert.ok(r.metricHTML.includes('N/A'));assert.ok(r.comparisonHTML.includes('N/A'));assert.ok(r.validationHTML.includes('UNAVAILABLE'));
 assert.doesNotMatch(r.metricHTML,/73\.33|27\.50|1655|29\.69/);
 const source=fs.readFileSync(path.join(root,'frontend/local-model.js'),'utf8');assert.doesNotMatch(source,/73\.33|27\.50|1655\.36|2807\.2|0\.7333|0\.296875/);
});
test('Private fields never render and HTML metacharacters are escaped',()=>{
 const data=structuredClone(summary);data.transcript='PRIVATE_SENTINEL';data.validation.canary='PRIVATE_SENTINEL';data.evaluation.metrics.prompt='PRIVATE_SENTINEL';
 assert.ok(!JSON.stringify(ui.render(data)).includes('PRIVATE_SENTINEL'));
 const markup=ui.chart([{label:'<script>oops</script>"',value:1}]);assert.doesNotMatch(markup,/<script>/);assert.match(markup,/&lt;script&gt;/);
});
test('Presentation mode hides configuration and retains source/limitation labels',()=>{
 const css=fs.readFileSync(path.join(root,'frontend/styles.css'),'utf8'), html=fs.readFileSync(path.join(root,'frontend/index.html'),'utf8');
 assert.match(css,/body\.presentation \.connection-panel[^}]*display:none/);
 assert.match(html,/id="local-limitations"/);assert.match(html,/id="local-sources"/);
 assert.match(html,/CURRENT LIVE REQUEST/);assert.match(html,/REAL MODEL BENCHMARK/);
});
