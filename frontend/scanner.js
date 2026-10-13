'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => { const node = document.createElement('span'); node.textContent = String(value ?? ''); return node.innerHTML; };
  const color = action => ({ allow: '#00e5c3', mask: '#4c8dff', warn: '#f5b942', block: '#ff5a67' }[action] || '#aab3c2');
  const critical = new Set('PRIVATE_KEY AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SESSION_TOKEN API_KEY GITHUB_TOKEN DB_CONNECTION_STRING SLACK_WEBHOOK PROMPT_INJECTION'.split(' '));
  let activeSource = 'text', selectedFile = null, lastScan = null, originalText = null, revision = 0, busy = false;

  function status(text, kind = 'pending') { $('gateway-status').textContent = text; $('gateway-status').className = `status-chip ${kind}`; }
  function chars() { $('char-count').textContent = `${$('text-input').value.length.toLocaleString()} chars`; }
  function invalidate() {
    revision += 1;
    if (lastScan) {
      lastScan = null; originalText = null;
      $('readout-empty').hidden = true; $('readout-body').hidden = false;
      $('readout-body').innerHTML = '<div class="data-notice">Input or connection changed. Analyze again before forwarding.</div>';
      $('scanner-details').hidden = true; $('response-pane').hidden = true;
      status('Analysis out of date');
    }
  }
  $('text-input').addEventListener('input', () => { chars(); invalidate(); });
  ['api-base', 'api-key', 'provider', 'model'].forEach(id => $(id).addEventListener('input', invalidate));
  function switchSource(source) {
    if (source === activeSource) return;
    invalidate(); activeSource = source;
    ['text', 'file'].forEach(name => { $(`tab-${name}`).classList.toggle('active', name === source); $(`tab-${name}`).setAttribute('aria-pressed', String(name === source)); });
    $('text-input').hidden = source !== 'text'; $('dropzone').hidden = source !== 'file';
    $('char-count').hidden = source !== 'text';
  }
  $('tab-text').addEventListener('click', () => switchSource('text'));
  $('tab-file').addEventListener('click', () => switchSource('file'));
  $('choose-file').addEventListener('click', () => $('file-input').click());
  function setFile(file) {
    invalidate(); selectedFile = file;
    $('file-chip-wrap').textContent = '';
    const chip = document.createElement('div'); chip.className = 'file-chip';
    const name = document.createElement('span'); name.textContent = file.name;
    const clear = document.createElement('button'); clear.type = 'button'; clear.textContent = 'Remove'; clear.setAttribute('aria-label', 'Remove selected file');
    clear.addEventListener('click', () => { invalidate(); selectedFile = null; $('file-input').value = ''; chip.remove(); });
    chip.append(name, clear); $('file-chip-wrap').append(chip);
  }
  $('file-input').addEventListener('change', event => { if (event.target.files.length) setFile(event.target.files[0]); });
  $('dropzone').addEventListener('dragover', event => { event.preventDefault(); $('dropzone').classList.add('dragover'); });
  $('dropzone').addEventListener('dragleave', () => $('dropzone').classList.remove('dragover'));
  $('dropzone').addEventListener('drop', event => { event.preventDefault(); $('dropzone').classList.remove('dragover'); if (event.dataTransfer.files.length) setFile(event.dataTransfer.files[0]); });
  function gateway() {
    const url = new URL($('api-base').value.trim());
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Enter an HTTP(S) gateway URL without embedded credentials, query parameters, or fragments.');
    return url.href.replace(/\/$/, '');
  }
  function responseMessage(data, fallback) {
    if (typeof data?.detail === 'string') return data.detail;
    if (typeof data?.detail?.message === 'string') return data.detail.message;
    if (typeof data?.message === 'string') return data.message;
    return fallback;
  }
  function showError(message, isNetwork = false) {
    lastScan = null; originalText = null;
    $('readout-empty').hidden = true; $('readout-body').hidden = false; $('scanner-details').hidden = true;
    $('readout-body').innerHTML = `<div class="block-banner">${esc(message)}<p class="panel-note">${isNetwork ? 'Check the gateway URL and local services. No request was sent to an LLM.' : 'Analysis did not complete. Resolve the issue and analyze again.'}</p></div>`;
    status(isNetwork ? 'Gateway unavailable' : 'Analysis rejected', 'error');
  }
  function validScan(data) {
    return data && ['allow', 'mask', 'warn', 'block'].includes(data.action) && ['none', 'low', 'medium', 'high', 'critical'].includes(data.risk_level) && Number.isInteger(data.risk_score) && data.risk_score >= 0 && data.risk_score <= 100 && typeof data.reason === 'string' && Array.isArray(data.violations) && data.violations.every(v => /^[A-Z][A-Z0-9_]*$/.test(v.entity_type) && Number.isInteger(v.start) && Number.isInteger(v.end) && v.start >= 0 && v.end > v.start && typeof v.score === 'number' && Number.isFinite(v.score) && v.score >= 0 && v.score <= 1) && (data.redacted_text === null || typeof data.redacted_text === 'string');
  }
  function render(data) {
    const action = data.action;
    $('readout-empty').hidden = true; $('readout-body').hidden = false;
    const types = new Set(data.violations.map(v => v.entity_type));
    $('readout-body').innerHTML = `<div class="risk-summary"><div class="risk-number" style="color:${color(action)}">${data.risk_score}<small> / 100</small></div><span class="policy-action" style="color:${color(action)}">${action.toUpperCase()}</span></div><div class="risk-meta"><span>Risk level <strong>${esc(data.risk_level.toUpperCase())}</strong></span><span>Findings <strong>${data.violations.length}</strong></span><span>Types <strong>${types.size}</strong></span></div><div class="risk-track" role="meter" aria-label="Policy risk score, deterministic heuristic" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${data.risk_score}"><span class="risk-marker" style="left:${data.risk_score}%"></span></div><div class="risk-ticks">${[0, 1, 50, 70, 90, 100].filter(v => v !== 1).map(v => `<span style="left:${v}%">${v}</span>`).join('')}</div><p class="risk-caption">Policy risk score — deterministic heuristic, not a calibrated probability.<br>1–49 low · 50–69 medium · 70–89 high · ≥90 critical</p><div class="action-legend">${['allow', 'mask', 'warn', 'block'].map(name => `<span class="${name}" style="${name === action ? `border-color:${color(action)};background:${color(action)}12` : ''}">${name.toUpperCase()}</span>`).join('')}</div><p class="risk-reason">${esc(data.reason)}</p>${action === 'block' ? '<div class="block-banner">BLOCKED — provider forwarding is unavailable. Edit the input and analyze again.</div>' : '<div class="risk-action-row" id="risk-action-row"></div>'}`;
    if (action !== 'block') {
      const canSend = action === 'allow' ? typeof originalText === 'string' || typeof data.redacted_text === 'string' : typeof data.redacted_text === 'string' && data.redacted_text.trim().length > 0;
      const row = $('risk-action-row');
      const button = document.createElement('button'); button.className = `button ${action === 'warn' ? 'amber-button' : 'primary'}`;
      button.textContent = action === 'allow' ? 'Send to LLM' : 'Send sanitized text'; button.disabled = !canSend;
      button.addEventListener('click', send);
      const note = document.createElement('p'); note.textContent = action === 'allow' ? 'The gateway re-inspects before forwarding.' : 'Mask and warn actions require sanitization. No raw override.';
      row.append(button, note);
    }
    $('scanner-details').hidden = false;
    $('findings-list').innerHTML = data.violations.length ? data.violations.map(v => `<div class="finding ${critical.has(v.entity_type) ? 'critical' : ''}"><span class="entity-badge" aria-hidden="true"></span><span class="finding-type">${esc(v.entity_type)}</span><small>${v.start}–${v.end}</small><span class="finding-score" title="Detector confidence score">${v.score.toFixed(2)}</span></div>`).join('') : '<p class="panel-note">No configured protected entities detected. This is not a universal sensitivity guarantee.</p>';
    $('preview-heading').textContent = action === 'allow' ? 'Scanned text preview' : 'Sanitized preview';
    const preview = data.redacted_text ?? originalText;
    $('sanitized-preview').innerHTML = typeof preview === 'string' ? esc(preview).replaceAll('[REDACTED]', '<mark>[REDACTED]</mark>') : 'Sanitized preview not available.';
  }
  async function runScan() {
    if (busy) return;
    if (activeSource === 'text' && !$('text-input').value.trim()) { showError('Enter text to analyze.'); return; }
    if (activeSource === 'file' && !selectedFile) { showError('Choose a supported file to analyze.'); return; }
    if (activeSource === 'file' && selectedFile.size > 15 * 1024 * 1024) { showError('The selected file exceeds the 15 MB document limit.'); return; }
    const currentRevision = revision, source = activeSource, input = source === 'text' ? $('text-input').value : null;
    lastScan = null; originalText = null; busy = true;
    $('scan-btn').disabled = true; $('scan-btn-label').innerHTML = '<span class="spinner"></span>Analyzing';
    $('response-pane').hidden = true; $('scanner-details').hidden = true; $('readout-empty').hidden = true; $('readout-body').hidden = false;
    $('readout-body').innerHTML = '<div class="empty-state"><span class="spinner"></span><h3>Inspecting locally</h3><p>Detection, risk assessment, and sanitization.</p></div>';
    status('Scanning locally');
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 60000);
    try {
      const base = gateway(); let response;
      if (source === 'text') response = await fetch(`${base}/v1/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: input, source: 'prompt' }), signal: controller.signal });
      else { const form = new FormData(); form.append('file', selectedFile); response = await fetch(`${base}/v1/documents/scan`, { method: 'POST', body: form, signal: controller.signal }); }
      const body = await response.json();
      if (currentRevision !== revision) { showError('Input changed during inspection. Analyze the current input again.'); return; }
      if (!response.ok) { showError(responseMessage(body, `Scan rejected (${response.status}).`)); return; }
      if (!validScan(body)) { showError('The gateway returned an incomplete assessment. Forwarding is disabled.'); return; }
      lastScan = body; originalText = input; render(body); status('Gateway connected', '');
    } catch (error) { showError(error.name === 'AbortError' ? 'Local inspection timed out. Analyze again when services are ready.' : error instanceof TypeError ? 'Could not reach the gateway.' : error.message, error instanceof TypeError); }
    finally { clearTimeout(timer); busy = false; $('scan-btn').disabled = false; $('scan-btn-label').textContent = 'Analyze input'; }
  }
  $('scan-btn').addEventListener('click', runScan);
  async function send() {
    if (!lastScan || busy || lastScan.action === 'block') return;
    const scan = lastScan, currentRevision = revision;
    const sanitized = scan.action !== 'allow';
    const text = sanitized ? scan.redacted_text : originalText ?? scan.redacted_text;
    if (typeof text !== 'string' || !text.trim()) return;
    busy = true; $('scan-btn').disabled = true;
    $('risk-action-row')?.querySelector('button')?.setAttribute('disabled', '');
    $('response-pane').hidden = false; $('response-card').innerHTML = '<div class="resp-meta"><span><span class="spinner"></span> Gateway inspection and provider request in progress</span></div>';
    status('Gateway forwarding');
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 90000);
    try {
      const provider = $('provider').value.trim(), model = $('model').value.trim(), key = $('api-key').value.trim();
      const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` };
      if (provider) headers['x-provider'] = provider;
      if (model) headers['x-model'] = model;
      const response = await fetch(`${gateway()}/v1/chat/completions`, { method: 'POST', headers, body: JSON.stringify({ ...(model ? { model } : {}), messages: [{ role: 'user', content: text }] }), signal: controller.signal });
      const body = await response.json();
      if (currentRevision !== revision) return;
      if (!response.ok || body.error) { $('response-card').innerHTML = `<div class="resp-error">${esc(responseMessage(body, `Gateway rejected the request (${response.status}).`))}</div>`; status('Request rejected', 'error'); return; }
      const content = body.choices?.[0]?.message?.content;
      if (typeof content !== 'string') { $('response-card').innerHTML = '<div class="resp-error">No text completion returned.</div>'; return; }
      const meta = body.aisg_metadata || {};
      const latency = typeof meta.latency_ms === 'number' && Number.isFinite(meta.latency_ms) ? `${meta.latency_ms} ms` : 'Not available';
      $('response-card').innerHTML = `<div class="resp-meta"><span><b>Provider</b> ${esc(provider || 'Server default')}</span><span><b>Model</b> ${esc(model || 'Server default')}</span><span><b>Request latency</b> ${esc(latency)}</span><span><b>Submitted</b> ${sanitized ? 'sanitized text' : 'scanned text'}</span></div><div class="conversation"><div class="message-row"><div class="speaker">USER</div><div class="message user">${esc(text.slice(0, 2200)).replaceAll('\n', '<br>')}${text.length > 2200 ? '…' : ''}</div></div><div class="message-row"><div class="speaker">ASSISTANT</div><div class="message assistant-content">${assistant(content)}</div></div></div>`;
      $('response-card').querySelectorAll('.copy-code-btn').forEach(button => button.addEventListener('click', async () => {
        const code = button.closest('.code-block').querySelector('code');
        try { await navigator.clipboard.writeText(code.textContent); button.textContent = 'Copied'; }
        catch { const selection = window.getSelection(), range = document.createRange(); range.selectNodeContents(code); selection.removeAllRanges(); selection.addRange(range); button.textContent = 'Selected'; }
        setTimeout(() => { button.textContent = 'Copy'; }, 1400);
      }));
      status('Gateway connected', '');
    } catch (error) { if (currentRevision === revision) { $('response-card').innerHTML = `<div class="resp-error">${error.name === 'AbortError' ? 'The request timed out.' : 'Could not complete the gateway request. Check the local service and connection settings.'}</div>`; status('Gateway request failed', 'error'); } }
    finally { clearTimeout(timer); busy = false; $('scan-btn').disabled = false; if (lastScan) $('risk-action-row')?.querySelector('button')?.removeAttribute('disabled'); }
  }
  function inline(text) { return esc(text).replace(/`([^`]+)`/g, '<span class="inline-code">$1</span>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/\*([^*]+)\*/g, '<em>$1</em>'); }
  function prose(text) {
    const lines = text.replace(/\r\n/g, '\n').split('\n'), output = [];
    let paragraph = [], list = [], kind = null;
    function flush() { if (paragraph.length) { output.push(`<p>${inline(paragraph.join(' '))}</p>`); paragraph = []; } if (list.length) { output.push(`<${kind}>${list.map(item => `<li>${inline(item)}</li>`).join('')}</${kind}>`); list = []; kind = null; } }
    lines.forEach(line => { const trimmed = line.trim(), bullet = trimmed.match(/^[-*]\s+(.+)/), ordered = trimmed.match(/^\d+\.\s+(.+)/); if (!trimmed) { flush(); return; } if (bullet || ordered) { const nextKind = bullet ? 'ul' : 'ol'; if (paragraph.length || kind && kind !== nextKind) flush(); kind = nextKind; list.push((bullet || ordered)[1]); } else { if (list.length) flush(); paragraph.push(trimmed.replace(/^#{1,6}\s+/, '')); } });
    flush(); return output.join('');
  }
  function assistant(text) {
    const regex = /```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g; let match, position = 0; const output = [];
    while ((match = regex.exec(text)) !== null) { if (match.index > position) output.push(prose(text.slice(position, match.index))); output.push(`<div class="code-block"><div class="code-label"><span>${esc(match[1] || 'code')}</span><button class="copy-code-btn" type="button">Copy</button></div><pre><code>${esc(match[2].trim())}</code></pre></div>`); position = regex.lastIndex; }
    if (position < text.length) output.push(prose(text.slice(position)));
    return output.join('') || '<p>No text returned.</p>';
  }
  chars();
})();
