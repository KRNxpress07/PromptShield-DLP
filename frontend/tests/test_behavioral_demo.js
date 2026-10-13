/* State/payload tests with a minimal DOM test double. No browser or network.
 * These exercise event handlers, not CSS/layout; visual verification is separate.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const escape = value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function fixture(script, fetcher) {
  const elements = new Map(), requests = [];
  class Element {
    constructor() { this.listeners = {}; this.attributes = {}; this.children = []; this._html = ''; this._text = ''; this.hidden = false; this.value = ''; this.dataset = {}; this.disabled = false; this.className = ''; this.classes = new Set(); this.classList = { add: v => this.classes.add(v), remove: v => this.classes.delete(v), toggle: (v, force) => { const enabled = force ?? !this.classes.has(v); if (enabled) this.classes.add(v); else this.classes.delete(v); return enabled; } }; }
    set innerHTML(value) { this._html = value; this.children = []; for (const match of value.matchAll(/id="([^"]+)"/g)) elements.set(match[1], new Element()); }
    get innerHTML() { return this._html || escape(this._text); }
    set textContent(value) { this._text = String(value); this._html = ''; }
    get textContent() { return this._text; }
    addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
    setAttribute(name, value) { this.attributes[name] = value; if (name === 'disabled') this.disabled = true; }
    removeAttribute(name) { delete this.attributes[name]; if (name === 'disabled') this.disabled = false; }
    append(...children) { this.children.push(...children); }
    remove() { this.removed = true; }
    querySelector(selector) { return selector === 'button' ? this.children.find(c => c.tag === 'button') || null : null; }
    querySelectorAll() { return []; }
    closest() { return new Element(); }
    async emit(name, values = {}) { for (const fn of this.listeners[name] || []) await fn({ target: this, preventDefault() {}, ...values }); }
  }
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  for (const match of html.matchAll(/id="([^"]+)"/g)) elements.set(match[1], new Element());
  const $ = id => elements.get(id);
  $('api-base').value = 'http://local.test'; $('api-key').value = 'synthetic-dummy-gateway'; $('provider').value = 'groq'; $('model').value = 'dummy-model'; $('text-input').value = 'Email synthetic7@example.com'; $('entity-status').value = 'all'; $('latency-stat').value = 'mean_ms';
  const nav = [...html.matchAll(/data-view="([^"]+)"/g)].map(match => { const e = new Element(); e.dataset.view = match[1]; return e; });
  const go = [...html.matchAll(/data-go="([^"]+)"/g)].map(match => { const e = new Element(); e.dataset.go = match[1]; return e; });
  const sorted = [...html.matchAll(/data-sort="([^"]+)"/g)].map(match => { const e = new Element(); e.dataset.sort = match[1]; e.textContent = match[1]; return e; });
  const body = new Element();
  const document = { body, getElementById: $, createElement: tag => { const e = new Element(); e.tag = tag; return e; }, querySelectorAll: selector => selector === '[data-view]' ? nav : selector === '[data-sort]' ? sorted : selector === '[data-view],[data-go]' ? [...nav, ...go] : [] };
  const context = vm.createContext({ document, history: { replaceState() {} }, location: { hash: '' }, window: { scrollTo() {}, addEventListener() {} }, URL, AbortController, setTimeout: () => 1, clearTimeout() {}, FormData: class { constructor() { this.fields = []; } append(k, v) { this.fields.push([k, v]); } }, fetch: async (url, options) => { requests.push({ url, options }); return fetcher(url, options); }, navigator: {} });
  vm.runInContext(fs.readFileSync(path.join(root, script), 'utf8'), context);
  return { $, requests, nav, sorted, body, Element };
}
const scan = (action = 'mask', score = 40) => ({ action, risk_level: score >= 90 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score ? 'low' : 'none', risk_score: score, reason: 'Synthetic local assessment', violations: action === 'allow' ? [] : [{ entity_type: 'EMAIL_ADDRESS', start: 6, end: 28, score: .9 }], redacted_text: action === 'allow' ? 'Explain sorting.' : 'Email [REDACTED]' });
const response = body => ({ ok: true, json: async () => body });


const server = (overrides = true) => ({ mode: 'off', enabled: true, runtime_available: true, allow_request_mode_override: overrides });
const behavioral = (severity = 'HIGH') => ({score: 70, severity, verdict: 'LIKELY_INJECTION_BEHAVIOR', completeness: 'COMPLETE', reasons: ['NETWORK_ATTEMPT'], assessment_version: 'behavior-risk-v1'});

for (const mode of ['off', 'audit', 'enforce']) {
  test('Demo sends only supported request mode ' + mode, async () => {
    const f = fixture('scanner.js', async url => response(url.endsWith('/status') ? server() : url.endsWith('/scan') ? scan() : {choices:[{message:{content:'done'}}], aisg_metadata:{behavioral:behavioral(),behavioral_mode:mode,behavioral_duration_ms:25,behavioral_would_block:true}}));
    await f.$('behavioral-status-check').emit('click');
    await f.$('behavior-mode-' + mode).emit('click');
    await f.$('scan-btn').emit('click');
    await f.$('risk-action-row').querySelector('button').emit('click');
    const sent = f.requests.find(row => row.url.endsWith('/chat/completions'));
    assert.equal(sent.options.headers['X-AISG-Behavioral-Mode'], mode);
    assert.equal(JSON.parse(sent.options.body).messages[0].content, 'Email [REDACTED]');
    if (mode === 'audit') assert.match(f.$('behavioral-result-card').innerHTML, /Would block in enforce mode/);
    assert.match(f.$('behavioral-final-decision').textContent, /FORWARD/);
  });
}

test('No unsupported mode header or auto-polling', async () => {
  const f=fixture('scanner.js',async url=>response(url.endsWith('/scan')?scan():{choices:[{message:{content:'done'}}]}));
  assert.equal(f.requests.length,0);
  await f.$('scan-btn').emit('click'); await f.$('risk-action-row').querySelector('button').emit('click');
  assert.equal(f.requests[1].options.headers['X-AISG-Behavioral-Mode'],undefined);
});

test('Permission-disabled selector cannot weaken server mode', async () => {
  const f=fixture('scanner.js',async()=>response({...server(false), mode:'enforce'}));
  await f.$('behavioral-status-check').emit('click');
  await f.$('behavior-mode-off').emit('click');
  assert.equal(f.$('behavior-mode-enforce').attributes['aria-pressed'],'true');
  assert.match(f.$('behavioral-override-note').textContent,/disabled by server/);
});

for (const code of ['behavioral_injection_blocked','behavioral_security_unavailable']) {
  test('Behavioral block hides provider panel and private data: '+code,async()=>{
    const token='CANARY_SECRET_API_7F4A2C';
    const f=fixture('scanner.js',async url=>url.endsWith('/scan')?response(scan()):({ok:false,status:code.endsWith('blocked')?422:503,json:async()=>({error:code,message:'exception '+token,transcript:token,behavioral:{...behavioral(),transcript:token,tool_arguments:token,reasons:['NETWORK_ATTEMPT',token]},behavioral_mode:'enforce',behavioral_duration_ms:3})}));
    await f.$('scan-btn').emit('click');await f.$('risk-action-row').querySelector('button').emit('click');
    assert.equal(f.$('response-pane').hidden,true);
    assert.doesNotMatch(f.$('behavioral-result-card').innerHTML,new RegExp(token));
    assert.doesNotMatch(f.$('behavioral-final-decision').textContent,new RegExp(token));
    assert.match(f.$('behavioral-final-decision').textContent,/BLOCK/);
  });
}

test('NOT_EVALUATED audit shows unavailable but forwards',async()=>{
  const f=fixture('scanner.js',async url=>response(url.endsWith('/scan')?scan():{choices:[{message:{content:'done'}}],aisg_metadata:{behavioral:{score:null,severity:null,verdict:'NOT_EVALUATED',completeness:'FAILED',reasons:['MODEL_UNAVAILABLE'],assessment_version:'behavior-risk-v1'},behavioral_mode:'audit'}}));
  await f.$('scan-btn').emit('click');await f.$('risk-action-row').querySelector('button').emit('click');
  assert.match(f.$('behavioral-result-card').innerHTML,/Behavioral analysis unavailable/);
  assert.match(f.$('behavioral-final-decision').textContent,/FORWARD/);
});

test('Mode changes invalidate old scan/send handler',async()=>{
  const f=fixture('scanner.js',async url=>response(url.endsWith('/status')?server():scan()));
  await f.$('behavioral-status-check').emit('click');await f.$('scan-btn').emit('click');
  const old=f.$('risk-action-row').querySelector('button');await f.$('behavior-mode-audit').emit('click');await old.emit('click');
  assert.equal(f.requests.length,2);
  assert.match(f.$('behavioral-static-card').textContent,/current input/);
});

test('Status failures do not show exception or send override',async()=>{
  const f=fixture('scanner.js',async()=>({ok:false,json:async()=>({message:'private CANARY_SECRET_API_7F4A2C'})}));
  await f.$('behavioral-status-check').emit('click');
  assert.match(f.$('behavioral-local-status').textContent,/UNAVAILABLE/);
  assert.doesNotMatch(f.$('behavioral-override-note').textContent,/CANARY_SECRET/);
});

test('Server override rejection is clear and never shown as provider response',async()=>{
  const f=fixture('scanner.js',async url=>url.endsWith('/scan')?response(scan()):({ok:false,status:403,json:async()=>({error:'behavioral_mode_override_disabled'})}));
  await f.$('scan-btn').emit('click');await f.$('risk-action-row').querySelector('button').emit('click');
  assert.equal(f.$('response-pane').hidden,true);assert.match(f.$('behavioral-override-note').textContent,/Server rejected/);
});

test('Credential edits clear capability and restore the OFF result',async()=>{
  const f=fixture('scanner.js',async()=>response(server()));
  await f.$('behavioral-status-check').emit('click');await f.$('behavior-mode-enforce').emit('click');
  f.$('api-key').value='new key';await f.$('api-key').emit('input');
  assert.equal(f.$('behavior-mode-off').attributes['aria-pressed'],'true');
  assert.match(f.$('behavioral-result-card').innerHTML,/OFF/);
});
