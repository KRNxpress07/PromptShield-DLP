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

test('Mask sends only sanitized text; assistant markup remains escaped', async () => {
  const f = fixture('scanner.js', async url => response(url.endsWith('/scan') ? scan() : { choices: [{ message: { content: '<script>unsafe()</script>\n\n```js\nconst a = 1;\n```' } }] }));
  await f.$('scan-btn').emit('click');
  const send = f.$('risk-action-row').querySelector('button');
  assert.equal(send.textContent, 'Send sanitized text');
  await send.emit('click');
  const payload = JSON.parse(f.requests[1].options.body);
  assert.equal(payload.messages[0].content, 'Email [REDACTED]');
  assert.match(f.$('response-card').innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(f.$('response-card').innerHTML, /<script>/);
});
test('Warn provides no raw override', async () => {
  const f = fixture('scanner.js', async () => response(scan('warn', 78)));
  await f.$('scan-btn').emit('click');
  assert.equal(f.$('risk-action-row').children.filter(e => e.tag === 'button').length, 1);
  assert.equal(f.$('risk-action-row').querySelector('button').textContent, 'Send sanitized text');
});
test('Block exposes no send action and displays critical score', async () => {
  const f = fixture('scanner.js', async () => response(scan('block', 95)));
  await f.$('scan-btn').emit('click');
  assert.equal(f.$('risk-action-row'), undefined);
  assert.match(f.$('readout-body').innerHTML, /BLOCKED/);
  assert.match(f.$('readout-body').innerHTML, /aria-valuenow="95"/);
});
test('Editing input invalidates assessment and prevents stale forwarding', async () => {
  const f = fixture('scanner.js', async () => response(scan()));
  await f.$('scan-btn').emit('click');
  const oldSend = f.$('risk-action-row').querySelector('button');
  f.$('text-input').value = 'Changed input'; await f.$('text-input').emit('input');
  await oldSend.emit('click');
  assert.equal(f.requests.length, 1);
  assert.match(f.$('readout-body').innerHTML, /Analyze again/);
});
test('Malformed scan response fails closed in UI', async () => {
  const f = fixture('scanner.js', async () => response({ action: 'mask', redacted_text: null }));
  await f.$('scan-btn').emit('click');
  assert.equal(f.$('risk-action-row'), undefined);
  assert.match(f.$('readout-body').innerHTML, /incomplete assessment/);
});
test('A changed prompt during a pending scan cannot adopt the stale result', async () => {
  let resolve;
  const f = fixture('scanner.js', () => new Promise(done => { resolve = done; }));
  const pending = f.$('scan-btn').emit('click');
  f.$('text-input').value = 'New text'; await f.$('text-input').emit('input');
  resolve(response(scan())); await pending;
  assert.equal(f.$('risk-action-row'), undefined);
  assert.match(f.$('readout-body').innerHTML, /Input changed/);
});
test('File upload uses document route; only returned text is forwarded', async () => {
  const f = fixture('scanner.js', async url => response(url.endsWith('/scan') ? scan() : { choices: [{ message: { content: 'Mock completion' } }] }));
  await f.$('tab-file').emit('click');
  f.$('file-input').files = [{ name: 'synthetic.txt', size: 35 }]; await f.$('file-input').emit('change');
  await f.$('scan-btn').emit('click');
  assert.match(f.requests[0].url, /documents\/scan$/);
  assert.equal(f.requests[0].options.body.fields[0][0], 'file');
  await f.$('risk-action-row').querySelector('button').emit('click');
  assert.equal(JSON.parse(f.requests[1].options.body).messages[0].content, 'Email [REDACTED]');
});
test('Missing benchmark data never substitutes measured values', async () => {
  const f = fixture('dashboard.js', async () => ({ ok: false, json: async () => ({ available: false }) }));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(f.$('headline-metrics').innerHTML, /Not available/);
  assert.equal(f.$('data-status').textContent, 'Data not available');
  assert.equal(f.$('data-notice').hidden, false);
});
test('Navigation and presentation mode alter only frontend state', async () => {
  const f = fixture('dashboard.js', async () => ({ ok: false, json: async () => ({ available: false }) }));
  await f.nav.find(e => e.dataset.view === 'performance').emit('click');
  assert.equal(f.$('view-overview').hidden, true);
  assert.equal(f.$('view-performance').hidden, false);
  await f.$('presentation-toggle').emit('click');
  assert.equal(f.body.classes.has('presentation'), true);
  assert.equal(f.$('presentation-toggle').attributes['aria-pressed'], 'true');
  assert.equal(f.requests.length, 1); // Benchmark GET only; no DLP/policy requests.
});
test('Dashboard presents actual recorded metrics and both leakage denominators', async () => {
  const recorded = JSON.parse(fs.readFileSync(path.resolve(root, '../benchmarks/results/latest/metrics.json'), 'utf8'));
  const body = { available: true, dataset: { ...recorded.dataset, safe: recorded.dataset.labels.safe, sensitive: recorded.dataset.labels.sensitive }, detection: recorded.detectors, sanitization: recorded.sanitization, latency: recorded.latency.groups, throughput: recorded.throughput.aggregates.map(row => ({ ...row, workers: row.concurrency })), tests: recorded.tests, per_entity: [] };
  const f = fixture('dashboard.js', async () => response(body));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.$('data-status').textContent, 'Frozen results loaded');
  const f1 = (recorded.detectors.project.prompt.f1 * 100).toFixed(2) + '%';
  assert.match(f.$('headline-metrics').innerHTML, new RegExp(f1.replace('.', '\\.')));
  assert.match(f.$('sanitization-metrics').innerHTML, /Residual leakage • sanitized/);
  assert.match(f.$('sanitization-metrics').innerHTML, /Residual leakage • all non-block/);
  assert.match(f.$('baseline-fpr').innerHTML, /bar-fill bad/);
  assert.match(f.$('throughput-chart').innerHTML, /Zero-based vertical axis/);
  assert.doesNotMatch(f.$('headline-metrics').innerHTML, /accuracy|secure|protection/);
});
