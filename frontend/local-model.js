/* Saved research evidence only. Independent of scanner.js and gateway state. */
'use strict';
(() => {
  const finite = n => typeof n === 'number' && Number.isFinite(n);
  const escape = v => String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const pct = n => finite(n) ? `${(100*n).toFixed(2)}%` : 'N/A';
  const ms = n => finite(n) ? `${n.toLocaleString('en-US',{maximumFractionDigits:2,minimumFractionDigits:0})} ms` : 'N/A';
  function card(label,value,note='',tone='') {return `<article class="metric-card ${tone}"><div class="metric-top">${escape(label)}</div><div class="metric-value">${escape(value)}</div><p class="metric-note">${escape(note)}</p></article>`;}
  function chart(items,unit='%') {
    const spec=escape(JSON.stringify({items,unit}));
    return `<div class="bklit-chart" data-chart="${spec}" role="img" aria-label="Measured ${escape(unit)} values. Axis starts at zero."></div><div class="chart-ledger">${items.map((i,index)=>`<div><span><small>${String(index+1).padStart(2,'0')}</small> ${escape(i.label)}</span><strong>${finite(i.value)?escape(i.value.toFixed(2)+unit):'N/A'}</strong></div>`).join('')}</div>`;
  }
  function render(data) {
    const e=data?.evaluation?.available?data.evaluation:null, v=data?.validation?.available?data.validation:null;
    const m=e?.metrics;
    const metricHTML=[['Precision',pct(m?.precision)],['Recall',pct(m?.recall),'Missed positives remain in the denominator','caution'],['F1',pct(m?.f1)],['False positive rate',pct(m?.fpr)],['False negative rate',pct(m?.fnr),'Lower is better','danger'],['NOT_EVALUATED',pct(e?.not_evaluated_rate),e?`${e.not_evaluated_count} / ${e.case_count} · never implies safety`:'Unavailable','caution'],['Mean latency',ms(e?.latency?.mean_ms)],['Median latency',ms(e?.latency?.median_ms)],['P95 latency',ms(e?.latency?.p95_ms)]].map(args=>card(...args)).join('');
    const systems=[['static','Static injection detector'],['behavioral','Behavioral local model'],['layered','Layered']];
    const comparisonItems=['precision','recall','f1','fpr'].map(key=>({label:{precision:'Precision',recall:'Recall',f1:'F1',fpr:'FPR'}[key],...Object.fromEntries(systems.map(([id])=>[id,finite(e?.systems?.[id]?.[key])?e.systems[id][key]*100:null]))}));
    const series=systems.map(([key,label],i)=>({key,label,color:['#D29A5A','#A78BFA','#A9CBB8'][i]}));
    const comparisonHTML=`<article class="panel"><div class="panel-heading"><h3>Static vs behavioral vs layered</h3><span class="annotation">0–100% · HIGH threshold</span></div><div class="comparison-legend">${series.map(s=>`<span style="--series-color:${s.color}">${escape(s.label)}</span>`).join('')}</div><div class="bklit-chart" data-chart="${escape(JSON.stringify({items:comparisonItems,series,unit:'%'}))}" role="img" aria-label="Static versus behavioral comparison, fixed zero to 100 percent axis"></div></article>`;
    const countsHTML=`<table class="compact-table comparison-values"><thead><tr><th>System</th>${['Precision','Recall','F1','FPR','TP','FP','TN','FN'].map(k=>`<th>${k}</th>`).join('')}</tr></thead><tbody>${systems.map(([id,label])=>`<tr><td>${label}</td>${['precision','recall','f1','fpr'].map(k=>`<td>${pct(e?.systems?.[id]?.[k])}</td>`).join('')}${['tp','fp','tn','fn'].map(k=>`<td>${finite(e?.systems?.[id]?.[k])?escape(e.systems[id][k]):'N/A'}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
    const stageNames={plain_generation:'Plain generation',tool_support:'Tool schema acceptance',public_read:'Public virtual read',protected_read_probe:'Protected read observation',network_probe:'Network simulator observation',gateway_preflight:'Gateway preflight'};
    const validationHTML=`<div class="validation-heading"><strong>${escape(v?.model||'Unavailable')}</strong><span>${escape(v?.runtime||'Unavailable')}</span></div><div class="validation-stages">${Object.entries(stageNames).map(([key,label])=>`<div><span>${label}</span><strong class="${v?.stages?.[key]==='VERIFIED'?'verified':'unavailable'}">${escape(v?.stages?.[key]||'UNAVAILABLE')}</strong></div>`).join('')}</div><div class="validation-foot"><span>Cloud calls <strong>${finite(v?.cloud_calls)?escape(v.cloud_calls):'N/A'}</strong></span><span>Model downloads <strong>${finite(v?.model_downloads)?escape(v.model_downloads):'N/A'}</strong></span></div><p class="panel-note">${escape(v?.schema_note||'Validation artifact unavailable.')}</p>`;
    const probesHTML=[['public_read','PUBLIC READ'],['protected_read_probe','PROTECTED READ'],['network_probe','NETWORK ATTEMPT']].map(([key,label])=>card(label,finite(v?.probes?.[key]?.score)?String(v.probes[key].score):'N/A',v?.probes?.[key]?.severity||'Unavailable',key==='network_probe'?'danger':'')).join('');
    const latencyHTML=chart(['mean_ms','median_ms','p95_ms'].map(key=>({label:{mean_ms:'Mean',median_ms:'Median',p95_ms:'P95'}[key],value:e?.latency?.[key]})),' ms');
    const limitations=e?`${e.case_count}-case real-model corpus · ${pct(e.not_evaluated_rate)} NOT_EVALUATED · ${pct(m?.recall)} recall. Single local model, repeated synthetic templates, heuristic HIGH threshold fixed before execution. Local behavior may differ from the external target model. NOT_EVALUATED remains in metric denominators as no emitted positive; gateway fail-closed decisions are separate.`:'Saved real-model evaluation unavailable. No substitute measurements are shown. Single-model synthetic research does not establish production protection.';
    return {metricHTML,comparisonHTML:e?comparisonHTML:'<div class="no-data">Comparison unavailable · N/A</div>',countsHTML,validationHTML,probesHTML,latencyHTML,limitations,latencyScope:e?.latency_scope||'Latency unavailable.',sources:[...(e?.sources||[]),...(v?.source?[v.source]:[])]};
  }
  if(typeof module!=='undefined')module.exports={render,chart,pct,ms};
  if(typeof document==='undefined')return;
  const $=id=>document.getElementById(id);
  let version=0;
  function apply(data){const r=render(data);for(const [id,key] of Object.entries({'local-model-metrics':'metricHTML','local-comparison-charts':'comparisonHTML','local-counts':'countsHTML','local-validation':'validationHTML','local-probes':'probesHTML','local-latency-chart':'latencyHTML'}))$(id).innerHTML=r[key];$('local-limitations').textContent=r.limitations;$('local-latency-scope').textContent=r.latencyScope;$('local-sources').textContent=r.sources.length?r.sources.join(' · '):'Artifact sources unavailable.';}
  async function load(){const current=++version;const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),12000);try{const response=await fetch('/v1/benchmark/local-model',{signal:controller.signal,cache:'no-store'});if(!response.ok)throw Error();const body=await response.json();if(current===version)apply(body);}catch{if(current===version)apply(null);}finally{clearTimeout(timer);}}
  document.querySelectorAll('[data-local-page]').forEach(button=>button.addEventListener('click',()=>{const page=button.dataset.localPage;document.querySelectorAll('.local-page').forEach(p=>{p.hidden=p.id!==`local-page-${page}`;});document.querySelectorAll('[data-local-page]').forEach(b=>{b.classList.toggle('active',b===button);b.setAttribute('aria-pressed',String(b===button));});}));
  $('reload-data').addEventListener('click',load);
  apply(null);load();
})();
