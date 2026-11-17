import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const source = await readFile(new URL('../../../assets/protected-restore.js', import.meta.url), 'utf8');
const {mount} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const origin = 'https://security.example.test';
const b64 = value => Buffer.from(value).toString('base64url');
const prompt = () => ({purpose: 'day2_restore_approval_v1', origin,
  intent: {archive: 'public archive DATA'}, approver: {email: 'approver@example.test'},
  public_key: {challenge: b64(new Uint8Array(32).fill(7)), rpId: 'security.example.test',
    allowCredentials: [{type: 'public-key', id: b64([1, 2, 3])}], userVerification: 'required'}});

const digest = value => `sha256:${value.repeat(64)}`;
const target = () => ({scope: {installation: 'example', environment: 'sandbox', app: 'calendar'},
  binding_generation: 1, authority: digest('1'), selection: digest('2'), incarnation: digest('3'),
  security_epoch: 2, artifact: digest('4'), schema: digest('5')});
const executionPrompt = () => ({...prompt(), purpose: 'day2_restore_execution_v1',
  approval: {statement: {request: {target: target()}}}, operation: digest('6')});
const installed = () => ({kind: 'protected_restore_installed_metadata_v1', operation: digest('6'),
  target: target(), installed: digest('7'), notice: 'Metadata only; future readiness and delivery are not established.'});

function page(replies = []) {
  const nodes = new Map();
  const root = {dataset: {origin, csrf: 'c'.repeat(43), bound: 'false'}, isConnected: true};
  nodes.set('protected-restore', root);
  for (const name of ['begin', 'approve', 'execution', 'authenticate', 'abandon']) {
    const button = {disabled: false, addEventListener: (type, run) => {assert.equal(type, 'click'); button.click = run;}};
    nodes.set(`restore-${name}`, button);
  }
  for (const name of ['app', 'input', 'review', 'handoff', 'status']) nodes.set(`restore-${name}`, {value: '', textContent: ''});
  nodes.get('restore-app').value = 'calendar';
  nodes.get('restore-input').files = [{size: 3, arrayBuffer: async () => new Uint8Array([7, 8, 9]).buffer}];
  const requests = [], options = [];
  const window = {isSecureContext: true, location: {origin}, fetch: async (url, request) => {
    requests.push({url, request});
    const value = replies.shift();
    if (typeof value === 'function') return value();
    return {ok: true, json: async () => value};
  }};
  window.top = window; window.self = window;
  const navigator = {credentials: {get: async value => {
    options.push(value);
    return {type: 'public-key', rawId: new Uint8Array([1, 2, 3]).buffer,
      response: {clientDataJSON: new Uint8Array([4]).buffer, authenticatorData: new Uint8Array(37).buffer,
        signature: new Uint8Array([5]).buffer, userHandle: null}};
  }}};
  mount({getElementById: id => nodes.get(id)}, window, navigator);
  return {nodes, root, window, navigator, requests, options, click: name => nodes.get(`restore-${name}`).click()};
}

test('actual presentation sends exact one-shot DATA and uses required UV on the checked prompt', async () => {
  const p = page([prompt(), {handoff: 'h'.repeat(43)}]);
  await p.click('begin');
  assert.deepEqual(JSON.parse(p.requests[0].request.body), {action: 'begin', csrf: 'c'.repeat(43), app: 'calendar', input: b64([7, 8, 9])});
  await p.click('approve');
  assert.equal(p.options.length, 1);
  assert.equal(p.options[0].publicKey.userVerification, 'required');
  assert.equal(p.options[0].publicKey.rpId, 'security.example.test');
  assert.deepEqual(p.options[0].publicKey.challenge, new Uint8Array(32).fill(7));
  const assertion = JSON.parse(Buffer.from(JSON.parse(p.requests[1].request.body).assertion, 'base64url'));
  assert.deepEqual(assertion, {format: 'day2_restore_passkey_assertion_v1', credential_id: b64([1, 2, 3]),
    client_data_json: b64([4]), authenticator_data: b64(new Uint8Array(37)), signature: b64([5]), user_handle: null});
  for (const {request} of p.requests) {
    assert.equal(request.method, 'POST'); assert.equal(request.credentials, 'same-origin');
    assert.equal(request.redirect, 'error'); assert.equal(request.headers['Content-Type'], 'application/json');
  }
  assert.equal(p.nodes.get('restore-handoff').value, 'h'.repeat(43));
  assert.match(p.nodes.get('restore-status').textContent, /not a completed restore/);
  await p.click('approve'); assert.equal(p.options.length, 1); assert.equal(p.requests.length, 2);
});

test('double click cannot replace an in-flight command and a lost reply never restarts it', async () => {
  let release;
  const p = page([() => new Promise(resolve => {release = resolve;})]);
  const first = p.click('begin');
  await Promise.resolve(); await Promise.resolve();
  await p.click('begin'); assert.equal(p.requests.length, 1);
  release({ok: false}); await first;
  await p.click('begin'); assert.equal(p.requests.length, 1);
  assert.equal(p.nodes.get('restore-begin').disabled, true);
  assert.match(p.nodes.get('restore-status').textContent, /unknown/);
});

test('a DOM/origin change after the real passkey ceremony cannot publish an assertion', async () => {
  for (const changed of ['csrf', 'origin', 'detached']) {
    const p = page([prompt()]);
    await p.click('begin');
    const get = p.navigator.credentials.get;
    p.navigator.credentials.get = async options => {
      const result = await get(options);
      if (changed === 'csrf') p.root.dataset.csrf = 'replacement';
      if (changed === 'origin') p.window.location.origin = 'https://foreign.example.test';
      if (changed === 'detached') p.root.isConnected = false;
      return result;
    };
    await p.click('approve'); assert.equal(p.requests.length, 1);
    assert.match(p.nodes.get('restore-status').textContent, /unknown/);
  }
});

test('an approval send failure remains spent and never exposes a foreign error', async () => {
  const p = page([prompt(), () => {throw new Error('PRIVATE-FOREIGN-FAILURE');}]);
  await p.click('begin'); await p.click('approve'); await p.click('approve');
  assert.equal(p.requests.length, 2); assert.equal(p.options.length, 1);
  assert.ok(!p.nodes.get('restore-status').textContent.includes('PRIVATE-FOREIGN'));
});

test('executor presentation consumes its handoff without running Authenticate or claiming success', async () => {
  const p = page([executionPrompt()]);
  p.nodes.get('restore-handoff').value = 'h'.repeat(43);
  await p.click('execution'); await p.click('execution');
  assert.equal(p.requests.length, 1); assert.equal(p.options.length, 0);
  assert.equal(p.requests[0].url, '/restore/protected/execution');
  assert.equal(p.nodes.get('restore-handoff').value, '');
  assert.ok(p.requests.every(request => request.url !== '/restore/protected/authenticate'));
});

test('insecure and framed pages refuse before transport or the authenticator', async () => {
  for (const changed of ['insecure', 'framed']) {
    const p = page([prompt()]);
    if (changed === 'insecure') p.window.isSecureContext = false;
    else p.window.top = {};
    await p.click('begin'); assert.equal(p.requests.length, 0); assert.equal(p.options.length, 0);
  }
});

test('executor explicitly uses its distinct UV ceremony and final result is metadata only', async () => {
  const p = page([executionPrompt(), installed()]);
  p.nodes.get('restore-handoff').value = 'h'.repeat(43);
  await p.click('execution');
  assert.equal(p.requests.length, 1); assert.equal(p.options.length, 0);
  assert.equal(p.nodes.get('restore-authenticate').disabled, false);
  await p.click('authenticate');
  assert.equal(p.requests.length, 2); assert.equal(p.options.length, 1);
  assert.equal(p.requests[1].url, '/restore/protected/authenticate');
  const posted = JSON.parse(p.requests[1].request.body);
  assert.deepEqual(Object.keys(posted).sort(), ['action', 'assertion', 'csrf']);
  assert.equal(posted.action, 'authenticate');
  assert.equal(p.options[0].publicKey.userVerification, 'required');
  assert.match(p.nodes.get('restore-status').textContent, /metadata received/);
  assert.match(p.nodes.get('restore-status').textContent, /not established/);
  await p.click('authenticate'); await p.click('execution'); await p.click('abandon');
  assert.equal(p.requests.length, 2);
});

test('terminal send loss and HTTP200 foreign metadata remain permanently spent and unknown', async () => {
  for (const response of [() => {throw new Error('PRIVATE-FOREIGN-TERMINAL');}, {kind: 'unrelated'}, {kind: 'protected_restore_installed_metadata_v1', operation: 'foreign-operation'}]) {
    const p = page([executionPrompt(), response]);
    p.nodes.get('restore-handoff').value = 'h'.repeat(43);
    await p.click('execution'); await p.click('authenticate');
    assert.equal(p.requests.length, 2);
    await p.click('authenticate'); await p.click('execution'); await p.click('abandon');
    assert.equal(p.requests.length, 2);
    assert.match(p.nodes.get('restore-status').textContent, /unknown/);
    assert.ok(!p.nodes.get('restore-status').textContent.includes('PRIVATE-FOREIGN'));
  }
});

test('executor DOM mutation during passkey or wrong prompt purpose cannot send terminal input', async () => {
  for (const changed of ['origin', 'csrf', 'purpose']) {
    const selected = executionPrompt();
    if (changed === 'purpose') selected.purpose = 'day2_restore_approval_v1';
    const p = page([selected]); p.nodes.get('restore-handoff').value = 'h'.repeat(43);
    await p.click('execution');
    const get = p.navigator.credentials.get;
    p.navigator.credentials.get = async options => {
      const result = await get(options);
      if (changed === 'origin') p.window.location.origin = 'https://foreign.example.test';
      if (changed === 'csrf') p.root.dataset.csrf = 'changed';
      return result;
    };
    await p.click('authenticate');
    assert.equal(p.requests.length, 1);
  }
});

test('terminal metadata must contain the exact complete reviewed target and closed digest fields', async () => {
  const cuts = [
    value => {delete value.target;},
    value => {delete value.installed;},
    value => {delete value.notice;},
    value => {value.notice = null;},
    value => {value.notice = 'x'.repeat(513);},
    value => {value.installed = 'unqualified';},
    value => {value.operation = digest('8');},
    value => {value.extra = 'PRIVATE-UNEXPECTED-METADATA';},
    value => {value.target.extra = 'PRIVATE-UNEXPECTED-METADATA';},
    value => {value.target.scope.extra = 'PRIVATE-UNEXPECTED-METADATA';},
    value => {value.target = [];},
    value => {value.target.scope = null;},
  ];
  for (const key of ['binding_generation', 'authority', 'selection', 'incarnation', 'security_epoch', 'artifact', 'schema']) {
    cuts.push(value => {delete value.target[key];});
    cuts.push(value => {value.target[key] = typeof value.target[key] === 'number' ? 3 : digest('9');});
  }
  for (const key of ['installation', 'environment', 'app']) {
    cuts.push(value => {delete value.target.scope[key];});
    cuts.push(value => {value.target.scope[key] = 'other';});
  }
  for (const cut of cuts) {
    const reply = installed(); cut(reply);
    const p = page([executionPrompt(), reply]); p.nodes.get('restore-handoff').value = 'h'.repeat(43);
    await p.click('execution'); await p.click('authenticate');
    assert.equal(p.requests.length, 2);
    assert.match(p.nodes.get('restore-status').textContent, /unknown/);
    assert.ok(!p.nodes.get('restore-review').textContent.includes('PRIVATE-UNEXPECTED'));
    await p.click('authenticate'); await p.click('execution'); await p.click('abandon');
    assert.equal(p.requests.length, 2);
  }
});

test('malformed or imprecise executor review data refuses before a passkey or terminal send', async () => {
  for (const cut of [
    value => {value.operation = 'not-a-digest';},
    value => {delete value.approval.statement.request.target;},
    value => {value.approval.statement.request.target.security_epoch = Number.MAX_SAFE_INTEGER + 1;},
    value => {value.approval.statement.request.target.binding_generation = 0;},
    value => {value.approval.statement.request.target.scope.app = '';},
    value => {value.approval.statement.request.target.scope.extra = 'unknown';},
  ]) {
    const selected = executionPrompt(); cut(selected);
    const p = page([selected]); p.nodes.get('restore-handoff').value = 'h'.repeat(43);
    await p.click('execution'); await p.click('authenticate');
    assert.equal(p.requests.length, 1); assert.equal(p.options.length, 0);
    assert.equal(p.nodes.get('restore-authenticate').disabled, true);
    assert.match(p.nodes.get('restore-status').textContent, /unknown/);
  }
});
