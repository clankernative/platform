// Browser presentation only. The server checks IAP, immutable command/phase,
// CSRF and the genuine native reply. Neither this page nor HTTP status grants
// restore authority. No request retries or terminal-success inference.
const require = ok => { if (!ok) throw new Error('protected_restore_refused'); };
const from64 = value => {
  require(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value));
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
};
const to64 = bytes => btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const digest = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const object = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const targetKeys = ['scope', 'binding_generation', 'authority', 'selection', 'incarnation', 'security_epoch', 'artifact', 'schema'];
const scopeKeys = ['installation', 'environment', 'app'];
const target = value => object(value, targetKeys) && object(value.scope, scopeKeys)
  && scopeKeys.every(key => typeof value.scope[key] === 'string' && value.scope[key].length > 0)
  && ['binding_generation', 'security_epoch'].every(key => Number.isSafeInteger(value[key]) && value[key] > 0)
  && ['authority', 'selection', 'incarnation', 'artifact', 'schema'].every(key => digest(value[key]));
const executionTarget = prompt => {
  const selected = prompt?.approval?.statement?.request?.target;
  require(digest(prompt?.operation) && target(selected));
  return selected;
};
const installedMetadata = (result, saved) => {
  const selected = executionTarget(saved);
  require(object(result, ['kind', 'operation', 'target', 'installed', 'notice'])
    && result.kind === 'protected_restore_installed_metadata_v1'
    && result.operation === saved.operation && digest(result.installed)
    && typeof result.notice === 'string' && result.notice.length <= 512 && target(result.target)
    && scopeKeys.every(key => result.target.scope[key] === selected.scope[key])
    && targetKeys.filter(key => key !== 'scope').every(key => result.target[key] === selected[key]));
};

export function mount(document, window, navigator) {
  const root = document.getElementById('protected-restore');
  if (!root) return;
  const begin = document.getElementById('restore-begin');
  const approve = document.getElementById('restore-approve');
  const execution = document.getElementById('restore-execution');
  const authenticate = document.getElementById('restore-authenticate');
  const abandon = document.getElementById('restore-abandon');
  const app = document.getElementById('restore-app');
  const file = document.getElementById('restore-input');
  const review = document.getElementById('restore-review');
  const handoff = document.getElementById('restore-handoff');
  const status = document.getElementById('restore-status');
  const origin = root.dataset.origin, csrf = root.dataset.csrf;
  let busy = false, prompt = null, executionPrompt = null, terminal = false, spent = root.dataset.bound === 'true';
  const current = () => require(root.isConnected && root.dataset.origin === origin
    && root.dataset.csrf === csrf && window.isSecureContext
    && window.top === window.self && window.location.origin === origin);
  const post = async (action, fields) => {
    current();
    const response = await window.fetch(`/restore/protected/${action}`, {
      method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action, csrf, ...fields}),
    });
    require(response.ok);
    return response;
  };
  const run = async action => {
    if (busy || terminal) return;
    busy = true;
    for (const button of [begin, approve, execution, authenticate, abandon]) button.disabled = true;
    try { current(); await action(); }
    catch { prompt = null; executionPrompt = null; status.textContent = 'Action refused or its result is unknown. No restore completion is proven. Do not retry a sent action.'; }
    finally {
      busy = false; begin.disabled = spent || terminal; approve.disabled = prompt === null || terminal;
      execution.disabled = terminal; authenticate.disabled = executionPrompt === null || terminal; abandon.disabled = terminal;
    }
  };
  begin.addEventListener('click', () => run(async () => {
    require(!spent && file.files.length === 1 && file.files[0].size <= 32768);
    const input = new Uint8Array(await file.files[0].arrayBuffer());
    current();
    require(input.length > 0 && input.length <= 32768);
    // Spend the local UI before the actual send. Reload cannot recover it;
    // the server independently claims the same immutable command first.
    spent = true;
    const response = await post('begin', {app: app.value, input: to64(input)});
    const selected = await response.json();
    current(); require(selected.purpose === 'day2_restore_approval_v1' && selected.origin === origin);
    prompt = selected;
    review.textContent = JSON.stringify({intent: selected.intent, approver: selected.approver}, null, 2);
    status.textContent = 'Review the exact archive, target, epoch, executor and custody before approving.';
  }));
  const assertionFor = async (saved, purpose) => {
    require(saved && saved.purpose === purpose && saved.public_key.userVerification === 'required'
      && saved.public_key.allowCredentials.length === 1 && saved.origin === origin);
    const credential = await navigator.credentials.get({publicKey: {
      challenge: from64(saved.public_key.challenge), rpId: saved.public_key.rpId,
      allowCredentials: saved.public_key.allowCredentials.map(c => ({type: c.type, id: from64(c.id)})),
      userVerification: 'required', timeout: 120000,
    }});
    current();
    require(credential?.type === 'public-key' && credential.response);
    const assertion = new TextEncoder().encode(JSON.stringify({
      format: 'day2_restore_passkey_assertion_v1',
      credential_id: to64(new Uint8Array(credential.rawId)),
      client_data_json: to64(new Uint8Array(credential.response.clientDataJSON)),
      authenticator_data: to64(new Uint8Array(credential.response.authenticatorData)),
      signature: to64(new Uint8Array(credential.response.signature)),
      user_handle: credential.response.userHandle === null ? null : to64(new Uint8Array(credential.response.userHandle)),
    }));
    require(assertion.length <= 16384);
    return assertion;
  };
  approve.addEventListener('click', () => run(async () => {
    const saved = prompt; prompt = null;
    const assertion = await assertionFor(saved, 'day2_restore_approval_v1');
    const response = await post('approve', {assertion: to64(assertion)});
    const result = await response.json(); current();
    require(typeof result.handoff === 'string' && /^[A-Za-z0-9_-]{43}$/.test(result.handoff));
    handoff.value = result.handoff;
    status.textContent = 'Approval recorded. Give this one-use handoff to the selected executor. It is not a completed restore.';
  }));
  execution.addEventListener('click', () => run(async () => {
    const selected = handoff.value; handoff.value = '';
    require(/^[A-Za-z0-9_-]{43}$/.test(selected));
    const response = await post('execution', {handoff: selected});
    const result = await response.json(); current();
    require(result.purpose === 'day2_restore_execution_v1' && result.origin === origin);
    executionTarget(result);
    executionPrompt = result;
    review.textContent = JSON.stringify({approval: result.approval, operation: result.operation}, null, 2);
    status.textContent = 'Review the exact executor request. Authentication requests installation once; a missing result must not be retried.';
  }));
  authenticate.addEventListener('click', () => run(async () => {
    const saved = executionPrompt; executionPrompt = null;
    const assertion = await assertionFor(saved, 'day2_restore_execution_v1');
    // Spend before the actual terminal send. Even rejection, response loss or
    // DOM changes cannot cause another send or a connection adoption.
    terminal = true;
    const response = await post('authenticate', {assertion: to64(assertion)});
    const result = await response.json(); current();
    installedMetadata(result, saved);
    review.textContent = JSON.stringify({operation: result.operation, target: result.target, installed: result.installed}, null, 2);
    status.textContent = 'Native installation metadata received. Future readiness and delivery to any other client are not established.';
  }));
  abandon.addEventListener('click', () => run(async () => {
    prompt = null;
    executionPrompt = null;
    await post('abandon', {}); current();
    status.textContent = 'Pending ceremony abandoned. This does not undo a consumed or uncertain native action.';
  }));
}

if (typeof document !== 'undefined') mount(document, window, navigator);
