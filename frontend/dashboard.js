'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => { const node = document.createElement('span'); node.textContent = String(value ?? ''); return node.innerHTML; };
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const pct = value => finite(value) ? `${(value * 100).toFixed(2)}%` : 'Not available';
  const dec = (value, digits = 2) => finite(value) ? value.toFixed(digits) : 'Not available';
  const count = value => finite(value) ? value.toLocaleString('en-US') : 'Not available';
  const names = { regex_simple: 'Regex baseline', presidio_builtin: 'Presidio built-in', project: 'PromptShield project' };
  const colors = { regex_simple: 'baseline', presidio_builtin: 'builtin', project: '' };
  const views = ['overview', 'scanner', 'benchmarks', 'detection', 'sanitization', 'performance', 'methodology', 'local-model'];
  let data = null, sortKey = 'f1', sortDirection = 1, loadVersion = 0;
  const na = '<div class="no-data">Not available</div>';

  function activate(view) {
    if (!views.includes(view)) view = 'overview';
    views.forEach(name => { $(`view-${name}`).hidden = name !== view; });
    document.querySelectorAll('[data-view]').forEach(button => {
      const active = button.dataset.view === view;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    $('current-section').textContent = view === 'scanner' ? 'LIVE SCANNER' : view.toUpperCase();
    $('presentation-section').value = view;
    history.replaceState(null, '', `#${view}`);
    window.scrollTo({ top: 0, behavior: 'instant' });
  }
  document.querySelectorAll('[data-view],[data-go]').forEach(button => button.addEventListener('click', () => activate(button.dataset.view || button.dataset.go)));
  $('presentation-section').addEventListener('change', () => activate($('presentation-section').value));
  document.querySelectorAll('[data-research-group]').forEach(button => button.addEventListener('click', () => {
    const group = button.dataset.researchGroup, page = button.dataset.researchPage;
    document.querySelectorAll(`[id^="${group}-page-"]`).forEach(panel => { panel.hidden = panel.id !== `${group}-page-${page}`; });
    document.querySelectorAll(`[data-research-group="${group}"]`).forEach(b => { b.classList.toggle('active', b === button); b.setAttribute('aria-pressed', String(b === button)); });
  }));
  window.addEventListener('hashchange', () => activate(location.hash.slice(1)));
  $('presentation-toggle').addEventListener('click', () => {
    const enabled = document.body.classList.toggle('presentation');
    $('presentation-toggle').setAttribute('aria-pressed', String(enabled));
    $('presentation-toggle').innerHTML = `<span aria-hidden="true">▣</span> ${enabled ? 'Exit presentation' : 'Presentation mode'}`;
  });

  function metricCard(label, value, note, tone = '', unit = '') {
    const available = value !== 'Not available';
    return `<article class="metric-card ${tone}"><div class="metric-top"><span>${esc(label)}</span><span class="metric-indicator" aria-hidden="true"></span></div><div class="metric-value ${available ? '' : 'na'}">${esc(value)}${available && unit ? `<span class="unit">${esc(unit)}</span>` : ''}</div><p class="metric-note">${esc(note)}</p></article>`;
  }
  function axis(max, unit) { return `<div class="chart-axis"><span>0${esc(unit)}</span><span>${esc(dec(max, unit === '%' ? 0 : 1))}${esc(unit)}</span></div>`; }
  function bars(items, max = 100, unit = '%', digits = 2) {
    if (!items.length || items.every(item => !finite(item.value))) return na;
    const spec = esc(JSON.stringify({items, unit})).replace(/"/g, '&quot;');
    return `<div class="bklit-chart" data-chart="${spec}" role="img" aria-label="Measured values; zero-based axis"></div><div class="chart-ledger">${items.map((item, index) => `<div><span><small>${String(index + 1).padStart(2, '0')}</small> ${esc(item.label)}</span><strong>${finite(item.value) ? esc(item.value.toFixed(digits) + unit) : 'N/A'}</strong></div>`).join('')}</div>`;
  }
  function comparison(metric, subset = null) {
    return Object.keys(names).map(name => {
      const value = subset ? data?.detection?.[name]?.safe_subsets?.[subset]?.[metric] : data?.detection?.[name]?.prompt?.[metric];
      return { label: names[name], value: finite(value) ? value * 100 : null, color: metric === 'fpr' && name === 'project' ? 'bad' : colors[name] };
    });
  }
  function quality(value) {
    if (!finite(value)) return ['na', 'Not available'];
    if (value >= .95) return ['excellent', 'Excellent'];
    if (value >= .90) return ['strong', 'Strong'];
    if (value >= .75) return ['moderate', 'Moderate'];
    return ['needs', 'Needs improvement'];
  }
  function overall(stage) { return data?.latency?.find(row => row.stage === stage && row.stratum === 'all'); }

  function renderHeadlines() {
    const p = data?.detection?.project?.prompt;
    const s = data?.sanitization;
    const latency = overall('gateway_dlp');
    const rates = (data?.throughput || []).map(row => row.prompts_per_second).filter(finite);
    const peak = rates.length ? Math.max(...rates) : null;
    const entries = [
      ['Prompt precision', pct(p?.precision), 'Detected prompts that are labeled sensitive'],
      ['Prompt recall', pct(p?.recall), 'Sensitive test prompts detected'],
      ['Prompt F1', pct(p?.f1), 'Balance of prompt precision and recall'],
      ['Prompt FPR', pct(p?.fpr), 'Safe test prompts flagged · lower is better', 'caution'],
      ['Strict span F1', pct(data?.detection?.project?.strict_span?.f1), 'Entity type + exact boundary match'],
      ['Sanitization success', pct(s?.sanitization_success_rate), 'Changed sensitive outputs · gold + rescan'],
      ['Residual leakage', pct(s?.residual_leakage_rate_all_nonblock_sensitive), 'All non-block sensitive outputs · exact value', 'danger'],
      ['Median gateway DLP', dec(latency?.median_ms), 'Local inspection · excludes provider latency', '', 'ms'],
      ['P95 gateway DLP', dec(latency?.p95_ms), 'Local inspection · 95th percentile', '', 'ms'],
      ['Peak tested throughput', dec(peak), 'Finite local scanner batches · tested workers', '', 'prompts/s'],
    ];
    $('headline-metrics').innerHTML = entries.map(args => metricCard(...args)).join('');
    $('scope-prompts').textContent = count(data?.dataset?.total);
    $('scope-split').textContent = data ? `${count(data.dataset.dev)} / ${count(data.dataset.test)}` : 'Not available';
    $('overview-comparison').innerHTML = bars(comparison('f1'));
    const missed = finite(s?.sensitive_outgoing) && finite(s?.actually_sanitized_sensitive) ? s.sensitive_outgoing - s.actually_sanitized_sensitive : null;
    $('overview-missed').textContent = count(missed);
  }

  function renderBenchmarks() {
    const d = data?.dataset;
    $('dataset-strip').innerHTML = [['Total prompts', count(d?.total)], ['Safe / sensitive', d ? `${count(d.safe)} / ${count(d.sensitive)}` : 'Not available'], ['Development / test', d ? `${count(d.dev)} / ${count(d.test)}` : 'Not available'], ['Protected categories', '26']].map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');
    ['f1', 'fpr', 'precision', 'recall'].forEach(metric => { $(`baseline-${metric}`).innerHTML = bars(comparison(metric)); });
    $('ordinary-fpr').innerHTML = bars(comparison('fpr', 'ordinary'));
    $('hard-fpr').innerHTML = bars(comparison('fpr', 'hard_negative'));
    $('difficulty-cards').innerHTML = ['easy', 'medium', 'hard'].map(level => {
      const group = data?.detection?.project?.difficulty?.[level];
      return `<article class="panel"><h3>${level[0].toUpperCase() + level.slice(1)}</h3><div class="difficulty-support">${count(group?.prompts)} sensitive test prompts</div>${bars([{ label: 'Prompt recall', value: finite(group?.prompt?.recall) ? group.prompt.recall * 100 : null }, { label: 'Strict span F1', value: finite(group?.strict_span?.f1) ? group.strict_span.f1 * 100 : null, color: 'builtin' }, { label: 'Relaxed span F1', value: finite(group?.relaxed_span?.f1) ? group.relaxed_span.f1 * 100 : null, color: 'baseline' }])}</article>`;
    }).join('');
    $('false-positive-examples').innerHTML = (data?.false_positive_examples || []).map(row => `<div class="example-item"><code>${esc(row.text)}</code><span>→ ${esc(row.entity)}</span></div>`).join('') || na;
  }

  function entityValue(row, key) {
    if (key === 'entity') return row.entity;
    if (key === 'support') return finite(row.strict?.tp) && finite(row.strict?.fn) ? row.strict.tp + row.strict.fn : null;
    if (key === 'relaxed') return row.relaxed?.f1;
    if (key === 'fpr') return row.prompt?.fpr;
    return row.strict?.[key];
  }
  function renderEntities() {
    const search = $('entity-search').value.trim().toUpperCase(), status = $('entity-status').value;
    const rows = (data?.per_entity || []).filter(row => row.entity.includes(search) && (status === 'all' || quality(row.strict?.f1)[0] === status));
    rows.sort((a, b) => {
      const av = entityValue(a, sortKey), bv = entityValue(b, sortKey);
      if (av == null) return 1; if (bv == null) return -1;
      return (typeof av === 'string' ? av.localeCompare(bv) : av - bv) * sortDirection;
    });
    $('entity-table-body').innerHTML = rows.map(row => {
      const [className, label] = quality(row.strict?.f1);
      return `<tr><td data-label="Entity"><div class="entity-name">${esc(row.entity)}<span class="quality ${className}">${label}</span></div></td>${[['precision', 'Precision'], ['recall', 'Recall'], ['f1', 'Strict F1'], ['relaxed', 'Relaxed F1'], ['fpr', 'Occurrence FPR'], ['support', 'Test support']].map(([key, title]) => `<td data-label="${title}" class="${key === 'f1' ? 'cell-f1' : ''}">${key === 'support' ? count(entityValue(row, key)) : pct(entityValue(row, key))}</td>`).join('')}</tr>`;
    }).join('') || '<tr><td colspan="7" class="no-data">No matching entity data available.</td></tr>';
    document.querySelectorAll('[data-sort]').forEach(button => {
      const active = button.dataset.sort === sortKey;
      button.closest('th').setAttribute('aria-sort', active ? sortDirection === 1 ? 'ascending' : 'descending' : 'none');
      const label = button.textContent.replace(/[↕↑↓]/g, '').trim();
      button.textContent = `${label} ${active ? sortDirection === 1 ? '↑' : '↓' : '↕'}`;
    });
    const all = [...(data?.per_entity || [])].sort((a, b) => (a.strict?.f1 ?? -1) - (b.strict?.f1 ?? -1));
    $('entity-f1-chart').innerHTML = bars(rows.map(row => ({label:row.entity, value:finite(row.strict?.f1)?row.strict.f1*100:null})));
  }
  $('entity-search').addEventListener('input', renderEntities);
  $('entity-status').addEventListener('change', renderEntities);
  document.querySelectorAll('[data-sort]').forEach(button => button.addEventListener('click', () => { const key = button.dataset.sort; sortDirection = sortKey === key ? -sortDirection : 1; sortKey = key; renderEntities(); }));

  function renderSanitization() {
    const s = data?.sanitization;
    $('sanitization-metrics').innerHTML = [
      ['Sanitization success', pct(s?.sanitization_success_rate), 'Actually changed sensitive prompts · gold + rescan'],
      ['Gold span replacement coverage', pct(s?.gold_span_replacement_coverage_rate), 'Changed sensitive prompts with full labeled-span coverage'],
      ['Residual leakage • sanitized', pct(s?.residual_leakage_rate_sanitized), 'Exact values in changed outputs · partial remnants excluded'],
      ['Residual leakage • all non-block', pct(s?.residual_leakage_rate_all_nonblock_sensitive), 'Includes missed sensitive prompts allowed unchanged', 'danger'],
      ['Post-rescan residual prompts', count(s?.post_rescan_residual_prompts), 'Same-detector rescan · cannot expose every systematic miss'],
      ['Non-sensitive char preservation', pct(s?.mean_non_sensitive_char_preservation), 'Ordered character alignment · not semantic utility'],
    ].map(args => metricCard(...args)).join('');
    const partial = finite(s?.gold_span_replacement_coverage_rate) && finite(s?.actually_sanitized_sensitive) ? Math.round((1 - s.gold_span_replacement_coverage_rate) * s.actually_sanitized_sensitive) : null;
    const missed = finite(s?.sensitive_outgoing) && finite(s?.actually_sanitized_sensitive) ? s.sensitive_outgoing - s.actually_sanitized_sensitive : null;
    $('residual-explanation').textContent = s ? `${count(missed)} sensitive prompts were missed and allowed unchanged. ${count(partial)} changed prompts retain partial labeled-span content, despite clean rescans. Complete-value absence does not prove complete removal.` : 'Benchmark data not available.';
    const example = data?.sanitization_example;
    $('before-after').innerHTML = example ? `<label>BEFORE / SYNTHETIC</label><pre>${esc(example.original)}</pre><label>AFTER / ACTUAL SANITIZED OUTPUT</label><pre class="after">${esc(example.sanitized)}</pre>` : na;
    const actions = s?.actions;
    const totals = actions && ['block', 'warn', 'mask', 'allow'].every(key => finite(actions[key])) ? Object.values(actions).reduce((sum, value) => sum + value, 0) : null;
    $('action-counts').innerHTML = totals ? bars(['block', 'warn', 'mask', 'allow'].map(key => ({label: {block:'Blocked',warn:'Warn / sanitize',mask:'Mask',allow:'Allow'}[key],value:actions[key]})), null, ' prompts', 0) : na;
    $('human-pairs').textContent = count(s?.human_template_count);
  }

  function lineChart(rows, key, color, unit) {
    return bars([...rows].sort((a,b) => a.workers - b.workers).map(row => ({label: `${row.workers} workers`, value: row[key]})), null, ` ${unit}`, 2);
  }
  function renderPerformance() {
    $('latency-stages').innerHTML = ['scanner_only', 'gateway_dlp'].map(stage => {
      const value = overall(stage);
      return `<article class="panel performance-stage"><div class="panel-heading"><h3>${stage === 'scanner_only' ? 'Scanner-only' : 'Gateway DLP'}</h3><span class="annotation">${count(value?.count)} successful timings</span></div><div class="stage-metrics">${[['mean_ms', 'Mean'], ['median_ms', 'Median'], ['p95_ms', 'P95'], ['p99_ms', 'P99']].map(([key, label]) => `<div><label>${label}</label><strong>${dec(value?.[key])}</strong><small>milliseconds</small></div>`).join('')}</div></article>`;
    }).join('');
    const stat = $('latency-stat').value;
    const groups = data?.latency?.filter(row => row.stratum === 'size_bucket') || [];
    const values = groups.map(row => row[stat]).filter(finite), max = Math.ceil((values.length ? Math.max(...values) : 1) / 20) * 20;
    ['scanner_only', 'gateway_dlp'].forEach(stage => {
      const items = ['small', 'medium', 'large', 'very_large'].map(bucket => ({ label: bucket === 'very_large' ? 'Very large' : bucket[0].toUpperCase() + bucket.slice(1), value: groups.find(row => row.stage === stage && row.group === bucket)?.[stat], color: stage === 'scanner_only' ? 'builtin' : '' }));
      $(stage === 'scanner_only' ? 'scanner-size-chart' : 'gateway-size-chart').innerHTML = bars(items, max, ' ms');
    });
    const throughput = data?.throughput || [];
    $('throughput-chart').innerHTML = lineChart(throughput, 'prompts_per_second', '#A78BFA', 'prompts/s');
    $('queue-chart').innerHTML = lineChart(throughput, 'p95_ms', '#D29A5A', 'ms');
    $('throughput-table').innerHTML = throughput.length ? `<table class="compact-table"><thead><tr><th>Workers</th><th>Prompts/s</th><th>P95 queued ms</th><th>Completed</th><th>Error rate</th></tr></thead><tbody>${[...throughput].sort((a, b) => a.workers - b.workers).map(row => `<tr><td>${row.workers}</td><td>${dec(row.prompts_per_second, 3)}</td><td>${dec(row.p95_ms, 3)}</td><td>${count(row.completed)}</td><td>${pct(row.error_rate)}</td></tr>`).join('')}</tbody></table>` : na;
  }
  $('latency-stat').addEventListener('change', renderPerformance);

  function renderMethodology() {
    $('method-corpus').textContent = data ? `${count(data.dataset.total)} synthetic prompts · ${count(data.dataset.safe)} safe / ${count(data.dataset.sensitive)} sensitive` : 'Not available';
    $('method-split').textContent = data ? `${count(data.dataset.dev)} development / ${count(data.dataset.test)} test` : 'Not available';
    const groups = {
      'IDENTITY / PII': 'EMAIL_ADDRESS PHONE_NUMBER PERSON LOCATION US_SSN MASKED_US_SSN STREET_ADDRESS POSTAL_CODE DATE_TIME IBAN_CODE CREDIT_CARD IP_ADDRESS',
      'CREDENTIALS': 'API_KEY AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SESSION_TOKEN PRIVATE_KEY GITHUB_TOKEN SLACK_WEBHOOK JWT_TOKEN BEARER_TOKEN DB_CONNECTION_STRING GENERIC_SECRET_ASSIGNMENT',
      'INFRASTRUCTURE': 'PRIVATE_IP INTERNAL_HOSTNAME', 'SECURITY': 'PROMPT_INJECTION',
    };
    $('protected-entities').innerHTML = Object.entries(groups).map(([label, entities]) => `<article class="panel entity-group"><h3>${label}</h3><div class="entity-chip-list">${entities.split(' ').map(entity => `<span>${entity}</span>`).join('')}</div></article>`).join('');
    const tests = Object.entries(data?.tests || {});
    $('research-tests').innerHTML = tests.length ? `<table class="compact-table"><thead><tr><th>Suite</th><th>Passed</th><th>Failed</th><th>Skipped</th></tr></thead><tbody>${tests.map(([name, value]) => `<tr><td>${esc(name)}</td><td>${count(value.passed)}</td><td class="${value.failed ? 'red-text' : ''}">${count(value.failed)}</td><td>${count(value.skipped)}</td></tr>`).join('')}</tbody></table>` : na;
    $('run-started').textContent = data?.run_started_utc || 'Not available';
    $('dataset-hash').textContent = data?.dataset_sha256 || 'Not available';
  }
  function renderAll() { renderHeadlines(); renderBenchmarks(); renderEntities(); renderSanitization(); renderPerformance(); renderMethodology(); }
  async function loadData() {
    const version = ++loadVersion;
    data = null; renderAll();
    $('data-status').className = 'status-chip pending'; $('data-status').textContent = 'Loading benchmark';
    $('data-notice').hidden = true; $('reload-data').disabled = true;
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch('/v1/benchmark/summary', { cache: 'no-store', signal: controller.signal });
      const body = await response.json();
      if (!response.ok || !body.available || !body.dataset || !body.detection?.project) throw new Error('Unavailable');
      if (version !== loadVersion) return;
      data = body; renderAll();
      $('data-status').className = 'status-chip'; $('data-status').textContent = 'Frozen results loaded';
      if (body.warnings?.length) { $('data-notice').hidden = false; $('data-notice').textContent = body.warnings.join(' '); }
    } catch {
      if (version !== loadVersion) return;
      $('data-status').className = 'status-chip error'; $('data-status').textContent = 'Data not available';
      $('data-notice').hidden = false;
      $('data-notice').textContent = 'Benchmark data not available. Open this dashboard through frontend/server.py and verify that the Phase 3 result files are present. No substitute values are shown.';
    } finally { clearTimeout(timer); if (version === loadVersion) $('reload-data').disabled = false; }
  }
  $('reload-data').addEventListener('click', loadData);
  activate(location.hash.slice(1));
  loadData();
})();
