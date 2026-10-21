// Deterministic DOM/HTTP substitutes, not browser or visual qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const source = await readFile(new URL('../../../assets/reactive-queries.js', import.meta.url), 'utf8');
const {mountQueryForm, installQueryForms} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const tick = () => new Promise(resolve => setImmediate(resolve));

class Node extends EventTarget {
  constructor(localName, id = '') {
    super(); Object.assign(this, {localName, id, dataset: {}, attributes: new Map(), childNodes: [], value: '', name: '', disabled: false});
    this.style = {setProperty: (name, value) => this.attributes.set(`style:${name}`, value)};
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  getAttributeNames() { return [...this.attributes.keys()]; }
  hasAttribute(name) { return this.attributes.has(name); }
  removeAttribute(name) { this.attributes.delete(name); }
  querySelector() { return null; }
  contains(node) { return node === this || this.childNodes.includes(node); }
  replaceChildren(...nodes) { this.childNodes = nodes; }
  matches(selector) { return selector.startsWith('input[type="range"]') && this.localName === 'input' && this.type === 'range'; }
  closest(selector) { return selector.startsWith('button[') && this.localName === 'button' ? this : null; }
}
function fixture(kind = 'calculator', values = {}, revision = '0') {
  const document = {baseURI: 'https://example.test/', body: new Node('body'), nodes: new Map(), activeElement: null};
  const form = new Node('form', kind === 'calculator' ? 'calculator-draft' : 'report-search');
  const resultIDs = kind === 'calculator' ? ['calculator-values', 'calculator-scenarios'] : ['report-search-results'];
  form.dataset = {page: kind, queryOn: 'input', queryResults: resultIDs.join(' '), queryStatus: `${kind}-status`, queryDebounce: '150'};
  if (kind === 'calculator') Object.assign(form.dataset, {queryRevision: 'draft_revision', queryCommitField: 'commit_valuation', queryCommitInput: 'valuation'});
  Object.assign(form, {action: `https://example.test/${kind}`, method: 'get', ownerDocument: document, isConnected: true});
  const entries = kind === 'calculator' ? {valuation: '$550M', strike: '$3.25', options: '20,000', total_shares: '18100000',
    commit_valuation: 'false', ...values, draft_revision: revision} : {term: '', ...values};
  form.elements = Object.entries(entries).map(([name, value]) => Object.assign(new Node('input', `field-${name}`), {name, value, form, ownerDocument: document}));
  form.elements.namedItem = name => form.elements.find(control => control.name === name);
  const status = new Node('p', form.dataset.queryStatus);
  const regions = resultIDs.map(id => Object.assign(new Node('section', id), {childNodes: [`initial:${id}`]}));
  const range = Object.assign(new Node('input', 'valuation-slider'), {type: 'range', min: '500000000', max: '60000000000',
    value: '550000000', form, dataset: {queryInput: 'valuation', queryLabels: 'valuation-labels'}});
  const choices = [['550000000', '$550M'], ['14000000000', '$14B'], ['10300000000', '$10.30B'], ['10400000000', '$10.40B']];
  const list = new Node('datalist', 'valuation-labels');
  list.querySelectorAll = () => choices.map(([value, label]) => ({value, label}));
  const preset = Object.assign(new Node('button', 'scenario-14b'), {form, dataset: {queryInput: 'valuation', queryValue: '14000000000', queryLabel: '$14B'}});
  const children = [...form.elements, status, ...regions, ...(kind === 'calculator' ? [range, list, preset] : [])];
  for (const node of [form, ...children]) { node.ownerDocument = document; document.nodes.set(node.id, node); }
  form.contains = node => children.includes(node);
  document.getElementById = id => document.nodes.get(id);
  document.importNode = node => Object.assign(new Node(node.localName, node.id), {childNodes: [...node.childNodes], attributes: new Map(node.attributes)});
  form.querySelectorAll = selector => kind === 'calculator' ? selector.startsWith('input[type="range"]') ? [range] : selector.startsWith('button[') ? [preset] : [] : [];
  const listeners = new Map();
  form.addEventListener = (name, listener) => listeners.set(name, listener);
  form.removeEventListener = name => listeners.delete(name);
  form.emit = (name, target = form, properties = {}) => {
    const event = {target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopImmediatePropagation() {}, ...properties};
    listeners.get(name)?.(event); return event;
  };
  for (const control of form.elements) control.blur = () => { document.activeElement = document.body; form.emit('blur', control); };
  form.reportValidity = () => true;
  document.defaultView = {
    CustomEvent: class extends Event { constructor(name, options) { super(name, options); this.detail = options.detail; } },
    FormData: class { constructor(owner) { this.values = owner.elements.filter(control => control.name && !control.disabled && ['input', 'textarea'].includes(control.localName)).map(control => [control.name, control.value]); } entries() { return this.values.values(); } },
  };
  document.activeElement = document.body;
  return {form, document, regions, status, range, preset, control: name => form.elements.namedItem(name), listeners};
}
function mount(kind = 'calculator', reply, revision = '0') {
  const ui = fixture(kind, {}, revision), requests = [], timers = new Map();
  let token = 0, result;
  const stop = mountQueryForm(ui.form, {
    schedule(callback, delay) { const key = ++token; timers.set(key, {callback, delay}); return key; },
    cancelSchedule(key) { timers.delete(key); },
    async fetch(url, options) {
      const values = Object.fromEntries(new URL(url).searchParams);
      requests.push({url, values, options});
      const response = await reply?.(values, ui);
      if (response) { if (response.canonical) result = response.canonical; return response; }
      result = fixture(kind, values, values.draft_revision);
      for (const region of result.regions) region.childNodes = [`accepted:${values.draft_revision ?? values.term}:${region.id}`];
      if (kind === 'calculator') {
        const raw = new Map([['$14B', '14000000000'], ['$10.30B', '10300000000'], ['$10.40B', '10400000000']]);
        result.range.value = raw.get(values.valuation) ?? '550000000';
      }
      return {ok: true, status: 200, headers: {get: () => 'text/html'}, text: async () => 'canonical HTML'};
    },
    parseHTML() { return result.document; },
  });
  const fire = () => { const [key, timer] = [...timers].find(([, value]) => value.delay === 150); timers.delete(key); timer.callback(); };
  return {...ui, requests, timers, stop, fire};
}

test('an exhausted revision is a visible stale-state error rather than an uncaught event failure', t => {
  const ui = mount('calculator', undefined, '18446744073709551615'); t.after(ui.stop);
  assert.doesNotThrow(() => ui.form.emit('input', ui.control('valuation')));
  assert.equal(ui.form.dataset.queryState, 'error');
  assert.equal(ui.regions[0].dataset.queryStale, 'true');
  assert.match(ui.status.textContent, /Reload the page/);
  assert.equal(ui.requests.length, 0);
  assert.doesNotThrow(ui.stop.suspend);
});

test('named presentation outputs are not query input or draft state', async t => {
  const ui = mount(); t.after(ui.stop);
  ui.form.elements.push(Object.assign(new Node('output', 'derived'), {name: 'derived', value: 'Server result'}));
  ui.form.emit('input', ui.control('valuation')); ui.fire(); await tick();
  assert.equal(ui.form.dataset.queryState, 'ready');
  assert.equal(ui.requests[0].values.derived, undefined);
  assert.equal(ui.requests[0].options.cache, 'no-store');
});

for (const name of ['options', 'strike', 'valuation']) test(`Enter commits ${name} through the shared form contract`, async t => {
  const ui = mount(); t.after(ui.stop);
  ui.control(name).value = {options: '9,000', strike: '$4.00', valuation: '$14B'}[name];
  ui.document.activeElement = ui.control(name);
  ui.form.emit('input', ui.control(name));
  const event = ui.form.emit('keydown', ui.control(name), {key: 'Enter'});
  await tick();
  assert.equal(event.defaultPrevented, true);
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.requests[0].values.commit_valuation, String(name === 'valuation'));
  assert.equal(ui.requests[0].values.draft_revision, '2');
  assert.equal(ui.form.dataset.queryState, 'ready');
  assert.equal(ui.regions[0].dataset.queryStale, 'false');
});

test('range preview selects a server label immediately and debounces the shared read', async t => {
  const ui = mount(); t.after(ui.stop);
  ui.document.activeElement = ui.range; ui.range.value = '10300000000';
  ui.form.emit('input', ui.range);
  assert.equal(ui.control('valuation').value, '$10.30B');
  assert.equal(ui.range.attributes.get('aria-valuetext'), '$10.30B');
  assert.equal(ui.requests.length, 0);
  assert.equal(ui.regions[0].dataset.queryStale, 'true');
  ui.fire(); await tick();
  assert.equal(ui.requests[0].values.valuation, '$10.30B');
  assert.equal(ui.form.dataset.queryState, 'ready');
});

test('preset uses the same request and mirrors the native range without app callbacks', async t => {
  const ui = mount(); t.after(ui.stop);
  ui.form.emit('click', ui.preset); await tick();
  assert.equal(ui.control('valuation').value, '$14B');
  assert.equal(ui.range.value, '14000000000');
  assert.equal(ui.preset.attributes.get('aria-pressed'), 'true');
  assert.equal(ui.requests.length, 1);
});

test('Roc rejection preserves draft until noncommit blur restores its last accepted value', async t => {
  const ui = mount('calculator', values => values.strike === '4.999'
    ? {ok: false, status: 422} : undefined); t.after(ui.stop);
  ui.control('strike').value = '4.999'; ui.document.activeElement = ui.control('strike');
  ui.form.emit('submit'); await tick();
  assert.equal(ui.form.dataset.queryState, 'invalid');
  assert.equal(ui.control('strike').value, '4.999');
  ui.control('strike').blur(); ui.form.emit('click', ui.preset); await tick();
  assert.equal(ui.requests.at(-1).values.strike, '$3.25');
  assert.equal(ui.form.dataset.queryState, 'ready');
});

test('operational fault does not silently restore a possibly valid edited field', async t => {
  const ui = mount('calculator', () => { throw new Error('offline'); }); t.after(ui.stop);
  ui.control('strike').value = '$4.00'; ui.form.emit('submit'); await tick();
  ui.control('strike').blur(); await tick();
  assert.equal(ui.control('strike').value, '$4.00');
  assert.equal(ui.requests.at(-1).values.strike, '$4.00');
  assert.equal(ui.form.dataset.queryState, 'error');
});

test('a response cannot overwrite the focused raw draft while normalizing other fields', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', {...values, options: '9,000', strike: '$4.00'}, values.draft_revision);
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'normalized', canonical};
  }); t.after(ui.stop);
  ui.control('options').value = '9000'; ui.control('strike').value = '4';
  ui.document.activeElement = ui.control('options');
  ui.form.emit('submit'); await tick();
  assert.equal(ui.control('options').value, '9000');
  assert.equal(ui.control('strike').value, '$4.00');
  assert.equal(ui.document.activeElement, ui.control('options'));
});

test('all region identities validate before any result is published', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', values, values.draft_revision);
    canonical.document.nodes.delete('calculator-scenarios');
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'wrong identity', canonical};
  }); t.after(ui.stop);
  ui.form.emit('submit'); await tick();
  assert.deepEqual(ui.regions[0].childNodes, ['initial:calculator-values']);
  assert.deepEqual(ui.regions[1].childNodes, ['initial:calculator-scenarios']);
  assert.equal(ui.form.dataset.queryState, 'error');
});

test('patch events expose only current/incoming DOM regions for reviewed enhancement retention', async t => {
  const ui = mount(); t.after(ui.stop);
  const patches = [];
  for (const region of ui.regions) region.addEventListener('cui:before-patch', event => patches.push(event.detail));
  ui.form.emit('submit'); await tick();
  assert.equal(patches.length, 2);
  assert.equal(patches[0].current, ui.regions[0]);
  assert.equal(patches[0].incoming.id, 'calculator-values');
  assert.deepEqual(ui.regions[1].childNodes, ['accepted:1:calculator-scenarios']);
});

test('Reports search uses the same coordinator without revision/commit/finance fields', async t => {
  const ui = mount('search'); t.after(ui.stop);
  ui.control('term').value = 'Quarterly'; ui.document.activeElement = ui.control('term');
  ui.form.emit('input', ui.control('term')); ui.fire(); await tick();
  assert.deepEqual(ui.requests[0].values, {term: 'Quarterly'});
  assert.equal(ui.control('term').value, 'Quarterly');
  assert.deepEqual(ui.regions[0].childNodes, ['accepted:Quarterly:report-search-results']);
  assert.equal(ui.form.dataset.queryState, 'ready');
  assert.equal(ui.requests[0].options.credentials, 'same-origin');
  assert.equal(ui.requests[0].options.redirect, 'error');
});

test('a mismatched echoed revision cannot publish or normalize fields', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', {...values, strike: '$999.00'}, '999');
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'wrong revision', canonical};
  }); t.after(ui.stop);
  ui.form.emit('submit'); await tick();
  assert.equal(ui.control('strike').value, '$3.25');
  assert.deepEqual(ui.regions[0].childNodes, ['initial:calculator-values']);
  assert.equal(ui.form.dataset.queryState, 'error');
});

test('valuation blur commits the rejected raw draft instead of restoring it first', async t => {
  let calls = 0;
  const ui = mount('calculator', values => {
    if (++calls === 1) return {ok: false, status: 422};
    const canonical = fixture('calculator', {...values, valuation: '$60B'}, values.draft_revision);
    canonical.range.value = '60000000000';
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'clamped by Roc', canonical};
  }); t.after(ui.stop);
  ui.control('valuation').value = '$60.10B'; ui.form.emit('submit'); await tick();
  assert.equal(ui.form.dataset.queryState, 'invalid');
  ui.control('valuation').blur(); await tick();
  assert.equal(ui.requests.at(-1).values.valuation, '$60.10B');
  assert.equal(ui.requests.at(-1).values.commit_valuation, 'true');
  assert.equal(ui.control('valuation').value, '$60B');
  assert.equal(ui.range.value, '60000000000');
});

test('teardown removes handlers, aborts pending work, and prevents detached publication', async () => {
  let reply;
  const pending = new Promise(resolve => { reply = resolve; });
  const ui = mount('calculator', () => pending);
  ui.form.emit('submit');
  ui.form.isConnected = false; ui.stop();
  assert.equal(ui.requests[0].options.signal.aborted, true);
  assert.equal(ui.listeners.size, 0);
  assert.equal(ui.timers.size, 0);
  reply(undefined); await tick();
  assert.deepEqual(ui.regions[0].childNodes, ['initial:calculator-values']);
});

test('canonical root attributes update while host status attributes retain their authority', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', values, values.draft_revision);
    canonical.regions[0].setAttribute('aria-label', 'New canonical label');
    canonical.regions[0].setAttribute('class', 'new-style');
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'new attributes', canonical};
  }); t.after(ui.stop);
  ui.regions[0].setAttribute('class', 'old-style');
  ui.regions[0].setAttribute('data-obsolete', 'old');
  ui.form.emit('submit'); await tick();
  assert.equal(ui.regions[0].getAttribute('aria-label'), 'New canonical label');
  assert.equal(ui.regions[0].getAttribute('class'), 'new-style');
  assert.equal(ui.regions[0].hasAttribute('data-obsolete'), false);
  assert.equal(ui.regions[0].getAttribute('aria-busy'), 'false');
});

test('root installation and cleanup are idempotent across reinstallations', () => {
  let disconnected = 0;
  const root = {querySelectorAll: () => [], contains: () => true};
  root.defaultView = {
    MutationObserver: class { observe() {} disconnect() { disconnected += 1; } },
    addEventListener() {}, removeEventListener() {},
  };
  const first = installQueryForms(root);
  assert.equal(installQueryForms(root), first);
  first(); first();
  assert.equal(disconnected, 1);
  const second = installQueryForms(root);
  assert.notEqual(second, first);
  first();
  assert.equal(installQueryForms(root), second);
  second();
});
