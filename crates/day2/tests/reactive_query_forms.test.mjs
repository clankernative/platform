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
  get firstElementChild() { return this.childNodes.find(child => child instanceof Node) ?? null; }
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
// Like native forms and documents ([LegacyOverrideBuiltIns]), builtins live on the
// prototype and every named control or element is an own property that hides them.
const S = Symbol('substitute state');
function shadowed(object, named) {
  const own = key => typeof key === 'string' ? named(key) : undefined;
  return new Proxy(object, {
    get: (target, key, receiver) => own(key) ?? Reflect.get(target, key, receiver),
    has: (target, key) => own(key) !== undefined || Reflect.has(target, key),
    getOwnPropertyDescriptor: (target, key) => own(key) === undefined ? Reflect.getOwnPropertyDescriptor(target, key)
      : {value: own(key), writable: false, enumerable: false, configurable: true},
  });
}
class Controls extends Array {
  static get [Symbol.species]() { return Array; }
  namedItem(name) { return this.find(control => control.name === name) ?? null; }
}
class Form {
  constructor(state) { this[S] = state; }
  get ownerDocument() { return this[S].document; }
  get localName() { return 'form'; }
  get id() { return this[S].id; }
  get dataset() { return this[S].dataset; }
  get action() { return this[S].action; }
  get method() { return 'get'; }
  get elements() { return this[S].elements; }
  get isConnected() { return this[S].connected; }
  set isConnected(value) { this[S].connected = value; }
  contains(node) { return this[S].children.includes(node); }
  querySelectorAll(selector) { return this[S].select(selector); }
  setAttribute(name, value) { this[S].attributes.set(name, value); }
  addEventListener(name, listener) { this[S].listeners.set(name, listener); }
  removeEventListener(name) { this[S].listeners.delete(name); }
  reportValidity() { return true; }
}
class Document {
  constructor(state) { this[S] = state; }
  get ownerDocument() { return null; }
  get baseURI() { return 'https://example.test/'; }
  get body() { return this[S].body; }
  get activeElement() { return this[S].active; }
  set activeElement(node) { this[S].active = node; }
  get defaultView() { return this[S].view; }
  getElementById(id) { return this[S].nodes.get(id) ?? null; }
  importNode(node) { return Object.assign(new Node(node.localName, node.id), {childNodes: [...node.childNodes], attributes: new Map(node.attributes)}); }
}
function fixture(kind = 'calculator', values = {}, revision = '0', {documentNames = []} = {}) {
  const nodes = new Map(), body = new Node('body');
  const named = new Map(documentNames.map(name => [name, Object.assign(new Node('img', ''), {name})]));
  const document = shadowed(new Document({nodes, body, active: body, view: null}), name => named.get(name));
  const resultIDs = kind === 'calculator' ? ['calculator-values', 'calculator-scenarios'] : ['report-search-results'];
  const dataset = {page: kind, queryOn: 'input', queryResults: resultIDs.join(' '), queryStatus: `${kind}-status`, queryDebounce: '150'};
  if (kind === 'calculator') Object.assign(dataset, {queryRevision: 'draft_revision', queryCommitField: 'commit_valuation', queryCommitInput: 'valuation'});
  const state = {document, dataset, id: kind === 'calculator' ? 'calculator-draft' : 'report-search', action: `https://example.test/${kind}`,
    elements: new Controls(), children: [], connected: true, attributes: new Map(), listeners: new Map(), select: () => []};
  const form = shadowed(new Form(state), name => state.elements.namedItem(name) ?? undefined);
  const entries = kind === 'calculator' ? {valuation: '$550M', strike: '$3.25', options: '20,000', total_shares: '18100000',
    commit_valuation: 'false', ...values, draft_revision: revision} : {term: '', ...values};
  state.elements.push(...Object.entries(entries).map(([name, value]) => Object.assign(new Node('input', `field-${name}`), {name, value, form, ownerDocument: document})));
  const status = new Node('p', dataset.queryStatus);
  const regions = resultIDs.map(id => Object.assign(new Node('section', id), {childNodes: [`initial:${id}`]}));
  const range = Object.assign(new Node('input', 'valuation-slider'), {type: 'range', min: '500000000', max: '60000000000',
    value: '550000000', form, dataset: {queryInput: 'valuation', queryLabels: 'valuation-labels'}});
  const choices = [['550000000', '$550M'], ['14000000000', '$14B'], ['10300000000', '$10.30B'], ['10400000000', '$10.40B'], ['60000000000', '$60B']];
  const list = new Node('datalist', 'valuation-labels');
  list.querySelectorAll = () => choices.map(([value, label]) => ({value, label}));
  const preset = Object.assign(new Node('button', 'scenario-14b'), {form, dataset: {queryInput: 'valuation', queryValue: '14000000000', queryLabel: '$14B'}});
  state.children = [...state.elements, status, ...regions, ...(kind === 'calculator' ? [range, list, preset] : [])];
  nodes.set(state.id, form);
  for (const node of state.children) { node.ownerDocument = document; nodes.set(node.id, node); }
  state.select = selector => kind === 'calculator' ? selector.startsWith('input[type="range"]') ? [range] : selector.startsWith('button[') ? [preset] : [] : [];
  const emit = (name, target = form, properties = {}) => {
    const event = {target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopImmediatePropagation() {}, ...properties};
    state.listeners.get(name)?.(event); return event;
  };
  for (const control of state.elements) control.blur = () => { document.activeElement = document.body; emit('blur', control); };
  document[S].view = {
    CustomEvent: class extends Event { constructor(name, options) { super(name, options); this.detail = options.detail; } },
    // Native FormData reads the form's internal control list, never its named properties.
    FormData: class { constructor(owner) { this.values = owner[S].elements.filter(control => control.name && !control.disabled && ['input', 'textarea'].includes(control.localName)).map(control => [control.name, control.value]); } entries() { return this.values.values(); } },
  };
  return {form, document, nodes, dataset, emit, regions, status, range, preset, control: name => state.elements.namedItem(name), listeners: state.listeners};
}
function mount(kind = 'calculator', reply, revision = '0', {values = {}, documentNames = []} = {}) {
  const ui = fixture(kind, values, revision, {documentNames}), requests = [], timers = new Map();
  let token = 0, result;
  const stop = mountQueryForm(ui.form, {
    schedule(callback, delay) { const key = ++token; timers.set(key, {callback, delay}); return key; },
    cancelSchedule(key) { timers.delete(key); },
    async fetch(url, options) {
      const values = Object.fromEntries(new URL(url).searchParams);
      requests.push({url, values, options});
      const response = await reply?.(values, ui);
      if (response) { if (response.canonical) result = response.canonical; return response; }
      result = fixture(kind, values, values.draft_revision, {documentNames});
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
  assert.doesNotThrow(() => ui.emit('input', ui.control('valuation')));
  assert.equal(ui.dataset.queryState, 'error');
  assert.equal(ui.regions[0].dataset.queryStale, 'true');
  assert.match(ui.status.textContent, /Reload the page/);
  assert.equal(ui.requests.length, 0);
  assert.doesNotThrow(ui.stop.suspend);
});

test('named presentation outputs are not query input or draft state', async t => {
  const ui = mount(); t.after(ui.stop);
  ui.form.elements.push(Object.assign(new Node('output', 'derived'), {name: 'derived', value: 'Server result'}));
  ui.emit('input', ui.control('valuation')); ui.fire(); await tick();
  assert.equal(ui.dataset.queryState, 'ready');
  assert.equal(ui.requests[0].values.derived, undefined);
  assert.equal(ui.requests[0].options.cache, 'no-store');
});

for (const name of ['options', 'strike', 'valuation']) test(`Enter commits ${name} through the shared form contract`, async t => {
  const ui = mount(); t.after(ui.stop);
  ui.control(name).value = {options: '9,000', strike: '$4.00', valuation: '$14B'}[name];
  ui.document.activeElement = ui.control(name);
  ui.emit('input', ui.control(name));
  const event = ui.emit('keydown', ui.control(name), {key: 'Enter'});
  await tick();
  assert.equal(event.defaultPrevented, true);
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.requests[0].values.commit_valuation, String(name === 'valuation'));
  assert.equal(ui.requests[0].values.draft_revision, '2');
  assert.equal(ui.dataset.queryState, 'ready');
  assert.equal(ui.regions[0].dataset.queryStale, 'false');
});

test('range preview selects a server label immediately and debounces the shared read', async t => {
  const ui = mount(); t.after(ui.stop);
  ui.document.activeElement = ui.range; ui.range.value = '10300000000';
  ui.emit('input', ui.range);
  assert.equal(ui.control('valuation').value, '$10.30B');
  assert.equal(ui.range.attributes.get('aria-valuetext'), '$10.30B');
  assert.equal(ui.requests.length, 0);
  assert.equal(ui.regions[0].dataset.queryStale, 'true');
  ui.fire(); await tick();
  assert.equal(ui.requests[0].values.valuation, '$10.30B');
  assert.equal(ui.dataset.queryState, 'ready');
});

test('preset uses the same request and mirrors the native range without app callbacks', async t => {
  const ui = mount(); t.after(ui.stop);
  ui.emit('click', ui.preset); await tick();
  assert.equal(ui.control('valuation').value, '$14B');
  assert.equal(ui.range.value, '14000000000');
  assert.equal(ui.preset.attributes.get('aria-pressed'), 'true');
  assert.equal(ui.requests.length, 1);
});

test('Roc rejection preserves draft until noncommit blur restores its last accepted value', async t => {
  const ui = mount('calculator', values => values.strike === '4.999'
    ? {ok: false, status: 422} : undefined); t.after(ui.stop);
  ui.control('strike').value = '4.999'; ui.document.activeElement = ui.control('strike');
  ui.emit('submit'); await tick();
  assert.equal(ui.dataset.queryState, 'invalid');
  assert.equal(ui.control('strike').value, '4.999');
  ui.control('strike').blur(); ui.emit('click', ui.preset); await tick();
  assert.equal(ui.requests.at(-1).values.strike, '$3.25');
  assert.equal(ui.dataset.queryState, 'ready');
});

test('operational fault does not silently restore a possibly valid edited field', async t => {
  const ui = mount('calculator', () => { throw new Error('offline'); }); t.after(ui.stop);
  ui.control('strike').value = '$4.00'; ui.emit('submit'); await tick();
  ui.control('strike').blur(); await tick();
  assert.equal(ui.control('strike').value, '$4.00');
  assert.equal(ui.requests.at(-1).values.strike, '$4.00');
  assert.equal(ui.dataset.queryState, 'error');
});

test('a response cannot overwrite the focused raw draft while normalizing other fields', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', {...values, options: '9,000', strike: '$4.00'}, values.draft_revision);
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'normalized', canonical};
  }); t.after(ui.stop);
  ui.control('options').value = '9000'; ui.control('strike').value = '4';
  ui.document.activeElement = ui.control('options');
  ui.emit('submit'); await tick();
  assert.equal(ui.control('options').value, '9000');
  assert.equal(ui.control('strike').value, '$4.00');
  assert.equal(ui.document.activeElement, ui.control('options'));
});

test('all region identities validate before any result is published', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', values, values.draft_revision);
    canonical.nodes.delete('calculator-scenarios');
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'wrong identity', canonical};
  }); t.after(ui.stop);
  ui.emit('submit'); await tick();
  assert.deepEqual(ui.regions[0].childNodes, ['initial:calculator-values']);
  assert.deepEqual(ui.regions[1].childNodes, ['initial:calculator-scenarios']);
  assert.equal(ui.dataset.queryState, 'error');
});

test('patch events expose only current/incoming DOM regions for reviewed enhancement retention', async t => {
  const ui = mount(); t.after(ui.stop);
  const patches = [];
  for (const region of ui.regions) region.addEventListener('cui:before-patch', event => patches.push(event.detail));
  ui.emit('submit'); await tick();
  assert.equal(patches.length, 2);
  assert.equal(patches[0].current, ui.regions[0]);
  assert.equal(patches[0].incoming.id, 'calculator-values');
  assert.deepEqual(ui.regions[1].childNodes, ['accepted:1:calculator-scenarios']);
});

test('Reports search uses the same coordinator without revision/commit/finance fields', async t => {
  const ui = mount('search'); t.after(ui.stop);
  ui.control('term').value = 'Quarterly'; ui.document.activeElement = ui.control('term');
  ui.emit('input', ui.control('term')); ui.fire(); await tick();
  assert.deepEqual(ui.requests[0].values, {term: 'Quarterly'});
  assert.equal(ui.control('term').value, 'Quarterly');
  assert.deepEqual(ui.regions[0].childNodes, ['accepted:Quarterly:report-search-results']);
  assert.equal(ui.dataset.queryState, 'ready');
  assert.equal(ui.requests[0].options.credentials, 'same-origin');
  assert.equal(ui.requests[0].options.redirect, 'error');
});

test('a mismatched echoed revision cannot publish or normalize fields', async t => {
  const ui = mount('calculator', values => {
    const canonical = fixture('calculator', {...values, strike: '$999.00'}, '999');
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'wrong revision', canonical};
  }); t.after(ui.stop);
  ui.emit('submit'); await tick();
  assert.equal(ui.control('strike').value, '$3.25');
  assert.deepEqual(ui.regions[0].childNodes, ['initial:calculator-values']);
  assert.equal(ui.dataset.queryState, 'error');
});

test('valuation blur commits the rejected raw draft instead of restoring it first', async t => {
  let calls = 0;
  const ui = mount('calculator', values => {
    if (++calls === 1) return {ok: false, status: 422};
    const canonical = fixture('calculator', {...values, valuation: '$60B'}, values.draft_revision);
    canonical.range.value = '60000000000';
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'clamped by Roc', canonical};
  }); t.after(ui.stop);
  ui.control('valuation').value = '$60.10B'; ui.emit('submit'); await tick();
  assert.equal(ui.dataset.queryState, 'invalid');
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
  ui.emit('submit');
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
  ui.emit('submit'); await tick();
  assert.equal(ui.regions[0].getAttribute('aria-label'), 'New canonical label');
  assert.equal(ui.regions[0].getAttribute('class'), 'new-style');
  assert.equal(ui.regions[0].hasAttribute('data-obsolete'), false);
  assert.equal(ui.regions[0].getAttribute('aria-busy'), 'false');
});

test('root installation and cleanup are idempotent across reinstallations', () => {
  let disconnected = 0;
  const view = {
    MutationObserver: class { observe() {} disconnect() { disconnected += 1; } },
    addEventListener() {}, removeEventListener() {},
  };
  const root = shadowed(new class {
    get ownerDocument() { return null; }
    get defaultView() { return view; }
    querySelectorAll() { return []; }
    contains() { return true; }
  }(), name => ['querySelectorAll', 'contains', 'defaultView', 'ownerDocument'].includes(name) ? new Node('img') : undefined);
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

const shadowingNames = ['action', 'method', 'elements', 'id', 'dataset', 'localName', 'ownerDocument', 'isConnected',
  'reset', 'submit', 'reportValidity', 'querySelector', 'querySelectorAll', 'contains', 'setAttribute', 'getAttribute',
  'addEventListener', 'removeEventListener', 'closest', 'blur'];
test('admitted field names cannot shadow the form or document members the coordinator uses', async t => {
  const values = Object.fromEntries(shadowingNames.map(name => [name, `raw ${name}`]));
  const ui = mount('search', undefined, '0', {values,
    documentNames: ['getElementById', 'importNode', 'activeElement', 'body', 'baseURI', 'defaultView']});
  t.after(ui.stop);
  // The substitute exposes named controls exactly where native forms do.
  assert.equal(ui.form.action, ui.control('action'));
  assert.equal(ui.form.elements, ui.control('elements'));
  assert.equal(ui.document.getElementById, ui.document.getElementById);
  assert.equal(ui.dataset.queryState, 'idle');
  ui.control('term').value = 'Quarterly'; ui.document[S].active = ui.control('term');
  ui.emit('input', ui.control('term')); ui.fire(); await tick();
  assert.equal(ui.requests.length, 1);
  const url = new URL(ui.requests[0].url);
  assert.equal(url.origin + url.pathname, 'https://example.test/search');
  assert.deepEqual(ui.requests[0].values, {term: 'Quarterly', ...values});
  assert.deepEqual(ui.regions[0].childNodes, ['accepted:Quarterly:report-search-results']);
  assert.equal(ui.dataset.queryState, 'ready');
  assert.equal(ui.form[S].attributes.get('aria-busy'), 'false');
  ui.emit('submit'); await tick();
  assert.equal(ui.requests.length, 2);
  ui.emit('click', ui.form);
  ui.emit('keydown', ui.form, {key: 'Enter'});
  ui.emit('blur', ui.form);
  assert.equal(ui.requests.length, 2);
  ui.stop();
  assert.equal(ui.listeners.size, 0);
});

test('a status that holds a result region is refused before the coordinator mounts', () => {
  const ui = fixture('search');
  ui.status.childNodes = [ui.regions[0]];
  assert.throws(() => mountQueryForm(ui.form, {fetch() {}}), /query_status_identity/);
  assert.equal(ui.listeners.size, 0);
});

function committing(ui) {
  return values => {
    if (values.commit_valuation !== 'true' && values.valuation === '$60.10B') return {ok: false, status: 422};
    const canonical = fixture('calculator', {...values, valuation: values.valuation === '$60.10B' ? '$60B' : values.valuation},
      values.draft_revision);
    canonical.range.value = values.valuation === '$60.10B' ? '60000000000' : ui?.range.value ?? '550000000';
    return {ok: true, headers: {get: () => 'text/html'}, text: async () => 'committed by Roc', canonical};
  };
}

test('a submit that supersedes a pending blur commit carries the commit', async t => {
  const ui = mount('calculator', committing()); t.after(ui.stop);
  ui.control('valuation').value = '$60.10B'; ui.document.activeElement = ui.control('valuation');
  // A mouse submit blurs the focused input first, then submits.
  ui.control('valuation').blur();
  ui.emit('submit'); await tick();
  assert.equal(ui.requests.length, 2);
  assert.equal(ui.requests[0].values.commit_valuation, 'true');
  assert.equal(ui.requests[0].options.signal.aborted, true);
  assert.equal(ui.requests[1].values.commit_valuation, 'true');
  assert.equal(ui.requests[1].values.valuation, '$60.10B');
  assert.equal(ui.dataset.queryState, 'ready');
  assert.equal(ui.control('valuation').value, '$60B');
  // Once Roc has answered the commit, later reads no longer carry it.
  ui.control('strike').value = '$4.00'; ui.emit('input', ui.control('strike')); ui.fire(); await tick();
  assert.equal(ui.requests.at(-1).values.commit_valuation, 'false');
  assert.equal(ui.dataset.queryState, 'ready');
});

test('a debounced edit elsewhere also carries a pending blur commit', async t => {
  const ui = mount('calculator', committing()); t.after(ui.stop);
  ui.control('valuation').value = '$60.10B'; ui.document.activeElement = ui.control('valuation');
  ui.control('valuation').blur();
  ui.document.activeElement = ui.control('strike'); ui.control('strike').value = '$4.00';
  ui.emit('input', ui.control('strike'));
  assert.equal(ui.requests[0].options.signal.aborted, true);
  ui.fire(); await tick();
  assert.equal(ui.requests.at(-1).values.commit_valuation, 'true');
  assert.equal(ui.requests.at(-1).values.strike, '$4.00');
  assert.equal(ui.control('valuation').value, '$60B');
  assert.equal(ui.dataset.queryState, 'ready');
});

test('a pending commit is dropped once the committed value changes', async t => {
  const ui = mount('calculator', committing()); t.after(ui.stop);
  ui.control('valuation').value = '$60.10B'; ui.document.activeElement = ui.control('valuation');
  ui.control('valuation').blur();
  ui.emit('click', ui.preset); await tick();
  assert.equal(ui.requests.length, 2);
  assert.equal(ui.requests[1].values.valuation, '$14B');
  assert.equal(ui.requests[1].values.commit_valuation, 'false');
  assert.equal(ui.dataset.queryState, 'ready');
});

test('a commit interrupted by an operational fault is retried by the next read', async t => {
  let fail = true;
  const answer = committing();
  const ui = mount('calculator', values => {
    if (fail) { fail = false; throw new Error('offline'); }
    return answer(values);
  }); t.after(ui.stop);
  ui.control('valuation').value = '$60.10B'; ui.document.activeElement = ui.control('valuation');
  ui.control('valuation').blur(); await tick();
  assert.equal(ui.dataset.queryState, 'error');
  ui.emit('submit'); await tick();
  assert.equal(ui.requests.at(-1).values.commit_valuation, 'true');
  assert.equal(ui.control('valuation').value, '$60B');
  assert.equal(ui.dataset.queryState, 'ready');
});
