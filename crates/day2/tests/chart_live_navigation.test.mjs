import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
const source = await readFile(new URL('../../../examples/chart-live/ui/chart-navigation.js', import.meta.url), 'utf8');
const {rangeTarget, navigationState, responseRange, installChartNavigation} = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const base = 'https://native.test/chart', start = 1735689600000, end = 1736294400000;
const target = url => rangeTarget(url, base, start, end, 'https://native.test');
const drain = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
function events(node) {
  const listeners = new Map();
  return Object.assign(node, {
    addEventListener(name, fn) { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name).add(fn); },
    removeEventListener(name, fn) { listeners.get(name)?.delete(fn); },
    emit(name, fields = {}) { for (const fn of [...listeners.get(name) ?? []]) fn({preventDefault() {}, ...fields}); },
    listenerCount() { return [...listeners.values()].reduce((n, items) => n + items.size, 0); }
  });
}
// Explicit DOM, network and virtual-timer adapters. No global mutation or real waits.
function harness() {
  const nodes = new Map(), requests = [], historyURLs = [], timers = new Map();
  let now = 0, timerID = 0;
  function node(id, dataset = {}) {
    return events({
      id, dataset, isConnected: true, textContent: '',
      hasAttribute: key => key === 'data-live', querySelector: () => null,
      cloneNode() { return node(id, {...dataset}); },
      remove() { this.isConnected = false; if (nodes.get(id) === this) nodes.delete(id); },
      replaceWith(next) { this.isConnected = false; nodes.set(id, next); }
    });
  }
  const form = node('chart-range', {defaultStart: String(start), defaultEnd: String(end)});
  form.action = base; form.reportValidity = () => true;
  form.elements = {start: {value: String(start)}, end: {value: String(end)}};
  const dialog = node('sample-dialog'); dialog.open = false;
  dialog.close = () => { dialog.open = false; }; dialog.showModal = () => { dialog.open = true; };
  for (const n of [form, node('chart-request-status'), dialog, node('sample-dialog-values'), node('sample-dialog-close'), node('chart-region', {start: String(start), end: String(end)}), node('sample-revisions'), node('day2-live')]) nodes.set(n.id, n);
  const draft = {value: '93', missing: true}; nodes.set('command-draft', draft);
  const document = events({getElementById: id => nodes.get(id), importNode: n => n.cloneNode(), body: {prepend: n => nodes.set(n.id, n)}});
  const view = events({}), location = {href: base, origin: 'https://native.test'};
  const stop = installChartNavigation({
    document, view, location,
    history: {
      pushState(_s, _t, url) { location.href = String(url); historyURLs.push(String(url)); },
      replaceState(_s, _t, url) { location.href = String(url); }
    },
    fetch(url, options) { const headers = deferred(), body = deferred(); requests.push({url: String(url), options, headers, body}); return headers.promise; },
    parseHTML(text) {
      const {start: s, end: e, url} = JSON.parse(text);
      const parsed = new Map([['chart-region', node('chart-region', {start: String(s), end: String(e)})], ['sample-revisions', node('sample-revisions')], ['day2-live', node('day2-live', {liveUrl: '/_live?path=' + encodeURIComponent(new URL(url).pathname + new URL(url).search)})]]);
      return {getElementById: id => parsed.get(id)};
    },
    createAbortController: () => new AbortController(),
    schedule(callback, delay) { const id = ++timerID; timers.set(id, {at: now + delay, callback}); return id; },
    cancelSchedule: id => timers.delete(id)
  });
  return {
    nodes, requests, historyURLs, timers, document, view, stop, draft,
    submit(s, e) { form.elements.start.value = String(s); form.elements.end.value = String(e); form.emit('submit'); },
    async headers(index, status = 200) { const r = requests[index]; r.headers.resolve({ok: status === 200, headers: {get: () => 'text/html'}, text: () => r.body.promise}); await drain(); },
    async body(index, valid = true) { const r = requests[index], url = new URL(r.url); r.body.resolve(JSON.stringify({start: Number(url.searchParams.get('start')) + (valid ? 0 : 1), end: Number(url.searchParams.get('end')), url: r.url})); await drain(); },
    async advance(ms) { now += ms; for (const [id, t] of [...timers]) if (t.at <= now) { timers.delete(id); t.callback(); } await drain(); }
  };
}

test('range routes match Native default omission, identity and field ordering', () => {
  assert.equal(target(base).url.href, base);
  assert.equal(target(base + '?start=' + start + '&end=' + end).url.href, base);
  assert.equal(target(base + '?start=1735862400000&end=1736208000000').url.href, base + '?end=1736208000000&start=1735862400000');
  for (const suffix of ['?start=0&start=1', '?start=0&end=1&x=2', '?start=1e3', '?start=NaN', '?start=9007199254740992', '?start=2&end=1', '?end=-1', '?start=\\d']) assert.equal(target(base + suffix), null, suffix);
  assert.equal(target('http://['), null);
  assert.equal(target('https://other.test/chart'), null);
  assert.equal(target('https://native.test/other'), null);
});

test('response admission rejects wrong ranges and editable or executable children', () => {
  const node = () => ({dataset: {start: String(start), end: String(end)}, hasAttribute: key => key === 'data-live', querySelector: () => null});
  const region = node(), revisions = node(), live = {};
  const document = {getElementById: id => ({'chart-region': region, 'sample-revisions': revisions, 'day2-live': live}[id])};
  assert.ok(responseRange(document, start, end));
  region.dataset.end = String(end - 1); assert.equal(responseRange(document, start, end), null);
  region.dataset.end = String(end); revisions.querySelector = () => ({tagName: 'FORM'}); assert.equal(responseRange(document, start, end), null);
});

test('seeded navigation decisions follow an independent generation model', () => {
  for (let seed = 1; seed <= 64; seed++) {
    const state = navigationState(base); let random = seed, generation = 0, accepted = base;
    const tokens = [];
    for (let step = 0; step < 128; step++) {
      random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
      if (random & 1) { tokens.push(state.begin()); generation++; } else { state.cancel(); generation++; }
      const token = tokens[(random >>> 8) % (tokens.length || 1)] ?? -1;
      const url = base + '?start=' + step, valid = token === generation;
      assert.equal(state.accept(token, url), valid, `seed=${seed} step=${step}`);
      if (valid) accepted = url;
      assert.equal(state.accepted(), accepted, `seed=${seed} step=${step}`);
    }
  }
});

test('an old delayed body cannot disconnect the newest stream or replace drafts', async () => {
  const h = harness();
  try {
    h.submit(start + 1, end - 1); await h.headers(0);
    h.submit(start + 2, end - 2); await h.headers(1); await h.body(1);
    const live = h.nodes.get('day2-live');
    await h.body(0);
    assert.equal(h.nodes.get('day2-live'), live);
    assert.equal(h.nodes.get('chart-region').dataset.start, String(start + 2));
    assert.equal(h.historyURLs.length, 1);
    assert.equal(h.nodes.get('command-draft'), h.draft);
    assert.equal(h.draft.value, '93');
  } finally { h.stop(); }
  assert.equal(h.timers.size, 0);
});

test('seeded body, timeout, rejection and cancellation schedules retain accepted state', async () => {
  async function replay(seed) {
    const h = harness(), transcript = []; let random = seed, accepted = start;
    try {
      for (let step = 0; step < 24; step++) {
        random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
        const mode = (random >>> 8) % 5, s = start + step + 1, e = end - step - 1;
        h.submit(s, e); const index = h.requests.length - 1;
        await h.headers(index, mode === 1 ? 500 : 200);
        if (mode === 2) await h.advance(12000);
        if (mode === 3) h.document.emit('cui-chart:range-cancelled', {target: {id: 'sample-chart'}});
        await h.body(index, mode !== 4);
        if (mode === 0) accepted = s;
        const trace = `seed=${seed} step=${step} mode=${mode}`;
        assert.equal(h.nodes.get('chart-region').dataset.start, String(accepted), trace);
        assert.equal(h.nodes.get('command-draft'), h.draft, trace);
        assert.ok(h.nodes.get('day2-live'), trace);
        transcript.push([accepted, h.historyURLs.length, h.nodes.get('chart-request-status').textContent]);
      }
      h.view.emit('pagehide', {persisted: false});
      assert.equal(h.document.listenerCount(), 0); assert.equal(h.view.listenerCount(), 0); assert.equal(h.timers.size, 0);
    } finally { h.stop(); }
    return transcript;
  }
  for (let seed = 1; seed <= 32; seed++) assert.deepEqual(await replay(seed), await replay(seed), `seed=${seed}`);
});

test('stop aborts pending work and releases timers/listeners before bodies complete', async () => {
  const h = harness(); h.submit(start + 1, end - 1); await h.headers(0);
  h.stop(); h.stop(); assert.equal(h.timers.size, 0); assert.equal(h.requests[0].options.signal.aborted, true);
  await h.body(0);
  assert.equal(h.nodes.get('chart-region').dataset.start, String(start));
  assert.equal(h.document.listenerCount(), 0); assert.equal(h.view.listenerCount(), 0);
});
