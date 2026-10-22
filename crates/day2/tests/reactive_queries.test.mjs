import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source = await readFile(new URL('../../../assets/reactive-queries.js', import.meta.url), 'utf8');
const {createLatestRead} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
function harness(options = {}) {
  const requests = [], published = [], states = [], timers = new Map();
  let nextTimer = 0;
  const query = createLatestRead({
    read(input, revision, signal) {
      const work = deferred(); requests.push({...work, input, revision, signal}); return work.promise;
    },
    publish(value, revision) { published.push({value, revision}); options.onPublish?.(value); },
    status(state, text) { states.push({state, text}); },
    schedule(callback, delay) { const token = ++nextTimer; timers.set(token, {callback, delay}); return token; },
    cancelSchedule(token) { timers.delete(token); },
    initialRevision: options.initialRevision ?? 0n,
  });
  const fire = delay => {
    const match = [...timers].find(([, timer]) => timer.delay === delay);
    assert.ok(match, `Expected a ${delay}ms timer`);
    timers.delete(match[0]); match[1].callback();
  };
  return {query, requests, published, states, timers, fire};
}
const tick = () => new Promise(resolve => setImmediate(resolve));

test('suspension cancels the final U64 revision without overflow or late publication', async () => {
  const h = harness({initialRevision: 18446744073709551614n});
  const work = h.query.update('last revision', true);
  assert.doesNotThrow(h.query.cancel);
  assert.equal(h.requests[0].signal.aborted, true);
  h.requests[0].resolve('obsolete'); await work;
  assert.equal(h.published.length, 0);
  assert.equal(h.timers.size, 0);
  assert.match(h.states.at(-1).text, /Reload the page/);
  h.query.stop();
});

test('a burst shares one debounce and preserves raw input data', async () => {
  const h = harness();
  h.query.update([['valuation', '$1B']]);
  h.query.update([['valuation', 'unfinished text']]);
  assert.equal(h.requests.length, 0);
  assert.equal(h.timers.size, 1);
  h.fire(150);
  assert.deepEqual(h.requests[0].input, [['valuation', 'unfinished text']]);
  assert.equal(h.requests[0].revision, 2n);
  h.requests[0].resolve('accepted HTML'); await tick();
  assert.deepEqual(h.published, [{value: 'accepted HTML', revision: 2n}]);
  assert.equal(h.states.at(-1).state, 'ready');
  assert.equal(h.timers.size, 0);
});

test('input invalidates an in-flight reply before the next debounce fires', async () => {
  const h = harness();
  const first = h.query.update('first', true);
  h.query.update('newer draft');
  assert.equal(h.requests[0].signal.aborted, true);
  h.requests[0].resolve('obsolete'); await first;
  assert.equal(h.published.length, 0);
  assert.equal(h.states.at(-1).state, 'pending');
  h.query.stop();
});

test('latest result wins even when the old producer ignores cancellation', async () => {
  const h = harness();
  const first = h.query.update('first', true), second = h.query.update('second', true);
  h.requests[1].resolve('new'); await second;
  h.requests[0].resolve('old'); await first;
  assert.deepEqual(h.published, [{value: 'new', revision: 2n}]);
  assert.equal(h.states.at(-1).state, 'ready');
});

test('obsolete failures cannot replace a newer ready state', async () => {
  const h = harness();
  const first = h.query.update('first', true), second = h.query.update('second', true);
  h.requests[1].resolve('new'); await second;
  h.requests[0].reject(new Error('old failure')); await first;
  assert.equal(h.states.at(-1).state, 'ready');
  assert.equal(h.states.filter(value => value.state === 'error').length, 0);
});

test('immediate submit supersedes scheduled draft work', async () => {
  const h = harness();
  h.query.update('draft');
  const complete = h.query.update('committed', true);
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].input, 'committed');
  assert.equal([...h.timers.values()].some(timer => timer.delay === 150), false);
  h.requests[0].resolve('HTML'); await complete;
});

test('declared business rejection remains distinct from operational failure', async () => {
  const h = harness();
  const first = h.query.update('invalid', true);
  h.requests[0].reject(Object.assign(new Error('Correct this draft.'), {rejected: true, userMessage: true}));
  await first;
  assert.deepEqual(h.states.at(-1), {state: 'invalid', text: 'Correct this draft.'});
  assert.equal(h.published.length, 0);
  const second = h.query.update('retry', true);
  h.requests[1].reject(new Error('internal credentials must not be surfaced')); await second;
  assert.equal(h.states.at(-1).state, 'error');
  assert.doesNotMatch(h.states.at(-1).text, /credentials/);
});

test('a failed read does not publish or destroy the last accepted result', async () => {
  const h = harness();
  const first = h.query.update('valid', true);
  h.requests[0].resolve('last accepted'); await first;
  const second = h.query.update('unavailable', true);
  h.requests[1].reject(new Error('offline')); await second;
  assert.deepEqual(h.published.map(item => item.value), ['last accepted']);
  assert.equal(h.states.at(-1).state, 'error');
});

test('timeout aborts the read and a late success cannot become current', async () => {
  const h = harness();
  const work = h.query.update('slow', true);
  h.fire(12000);
  assert.equal(h.requests[0].signal.aborted, true);
  assert.match(h.states.at(-1).text, /timed out/);
  h.requests[0].resolve('too late'); await work;
  assert.equal(h.published.length, 0);
  assert.equal(h.states.at(-1).state, 'error');
});

test('teardown cancels pending debounce and in-flight work without new publication', async () => {
  const h = harness();
  const work = h.query.update('running', true);
  h.query.stop(); h.query.stop();
  assert.equal(h.requests[0].signal.aborted, true);
  assert.equal(h.timers.size, 0);
  h.requests[0].resolve('detached'); await work;
  assert.equal(h.published.length, 0);
  assert.throws(() => h.query.update('after stop'), /query_revision_budget/);
});

test('suspending an unaccepted draft never labels the old result current', async () => {
  const h = harness();
  h.query.update('new draft'); h.query.cancel();
  assert.equal(h.timers.size, 0);
  assert.equal(h.states.at(-1).state, 'error');
  assert.match(h.states.at(-1).text, /interrupted/);
  h.query.stop();
});

test('revision ordering remains exact above JavaScript safe integers', async () => {
  const h = harness({initialRevision: '9007199254740992'});
  const work = h.query.update('draft', true);
  assert.equal(h.requests[0].revision, 9007199254740993n);
  h.requests[0].resolve('accepted'); await work;
  assert.equal(h.published[0].revision, 9007199254740993n);
});

test('revision budget fails closed instead of wrapping', () => {
  const h = harness({initialRevision: '18446744073709551615'});
  assert.throws(() => h.query.update('overflow'), /query_revision_budget/);
  assert.equal(h.requests.length, 0);
  assert.equal(h.timers.size, 0);
  assert.throws(() => harness({initialRevision: '-1'}), /query_revision/);
});

test('publication cannot clear a synchronously newer pending draft', async () => {
  let h;
  h = harness({onPublish: () => h.query.update('new input')});
  const work = h.query.update('accepted', true);
  h.requests[0].resolve('HTML'); await work;
  assert.equal(h.states.at(-1).state, 'pending');
  assert.equal(h.query.revision(), 2n);
  h.query.stop();
});
