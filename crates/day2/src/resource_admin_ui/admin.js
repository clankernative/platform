// Presentation only. Every authoring change and activation is validated by the host.
const session = new URLSearchParams(location.hash.slice(1)).get('session');
history.replaceState(null, '', '/');
let snapshot, selected, currentPreview;
const $ = (selector) => document.querySelector(selector);
const pretty = (value) => stringifyExact(value, 2);
const integerError = () => new Error('The browser requires exact whole numbers between -9007199254740991 and 9007199254740991. Use the native resource CLI for larger integers.');
function stringifyExact(value, space) {
  return JSON.stringify(value, (_key, item) => {
    if (typeof item === 'number' && !Number.isSafeInteger(item)) throw integerError();
    return item;
  }, space);
}
// This contract uses integers only. Check their original spelling before the
// browser can round them; the native CLI supports the full ledger integer range.
function parseExact(source) {
  const numbers = source.replace(/"(?:[^"\\]|\\.)*"/g, '""').match(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) || [];
  for (const token of numbers) {
    if (!/^-?(?:0|[1-9]\d*)$/.test(token) || token.replace('-', '').length > 16 || BigInt(token) < -9007199254740991n || BigInt(token) > 9007199254740991n) throw integerError();
  }
  return JSON.parse(source);
}
const node = (tag, text, className) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; };
function notice(message, error = false) { $('#notice').textContent = message; $('#notice').className = error ? 'error' : ''; }
const explanations = {
  resource_data_movement_review_required: 'Review the combined sources, destinations, identity and usage limits, then check the confirmation before approving.',
  resource_review_note_required: 'Add a short reason so the next reviewer can understand this decision.',
  resource_authoring_changed: 'Another editor saved changes. Refresh to review the current configuration before trying again.',
  resource_review_binding_changed: 'The effective access changed after this review was created. Refresh and create a new review.',
  authority_policy_changed: 'This app’s active authority changed. Refresh and review the new version before activating.',
  resource_review_requires_administrator: 'This change combines authority from multiple owners. An installation administrator must approve it.',
  resource_catalog_requires_administrator: 'Only an installation administrator can change the reusable policy ceiling. You can stage bindings within your approved policies.',
  resource_policy_owner_required: 'This policy belongs to another owner. Ask its owner or an installation administrator to review the request.',
  resource_binding_outside_policy: 'The selected resource is outside this policy. Choose an approved resource or ask the policy owner to expand its ceiling.',
  resource_policy_actor_widening: 'The requested people are outside the policy’s actor list. Choose a subset of approved actors.',
  resource_policy_revision_changed: 'This policy has a newer revision. Update its attachment and review the new effective access.',
  resource_review_already_decided: 'This review already has a recorded decision. Refresh to see its receipt.',
  company_budget_setup_required: 'Initialize the company budget ledger in Policies & resources before allocating capacity.',
  budget_company_pool_exhausted: 'The company pool has insufficient unallocated capacity for this request. Choose a smaller allocation or review the company ceiling.',
  budget_installation_reduction_requires_new_pool: 'Use the company ceiling reduction review to return unused app allocations before lowering the pool.',
  budget_pool_reduction_proof_required: 'Complete the company ceiling reduction and import its verified proof into this app before activating the lower budget.',
  budget_pool_reduction_pending: 'A company ceiling reduction is pending. Complete or cancel that review before allocating new capacity.',
  budget_pool_returns_insufficient: 'The reviewed returns leave more allocated capacity than the proposed ceiling. Increase the ceiling or explicitly return more unused capacity.',
  budget_pool_return_would_remove_liability: 'This app has spent or reserved capacity that the proposed return needs. Keep those liabilities backed; cancel and revise the reduction if needed.',
  budget_pool_returns_unacknowledged: 'Complete each reviewed app return before committing the lower ceiling. Unavailable apps retain their full allocations.',
  budget_pool_review_window_changed: 'The budget period changed since this review. Reload company accounting and review the new current period.',
  budget_usage_reconciliation_evidence_required: 'Record the reason and a reference to terminal provider usage evidence before reconciling.',
  budget_usage_reconciliation_requires_unknown: 'This attempt is not recorded as an unknown provider outcome. In-flight reservations cannot be reconciled through this action.',
  budget_usage_already_settled: 'This attempt already has immutable known usage. A reconciliation cannot rewrite it.',
  budget_restore_fresh_allocation_required: 'This restored app needs fresh company capacity. Existing allocations cannot be reused from its backup.',
  budget_overrun_evidence_changed: 'New usage incidents arrived after this preview. Refresh and review the complete incident set.',
};
async function api(action, fields = {}) {
  if (!session) throw new Error('Open the session link printed by day2 platform authority admin. This page does not use app login cookies.');
  const response = await fetch('/api', { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session}` }, body: stringifyExact({ action, ...fields }) });
  const result = parseExact(await response.text()); if (!response.ok) throw new Error(explanations[result.error?.split(':')[0]] || result.error || 'Request failed'); return result;
}
async function work(action) { try { await action(); } catch (error) { notice(error.message, true); } }
function button(text, action, className) { const el = node('button', text, className); el.addEventListener('click', () => work(async () => { el.disabled = true; try { await action(); } finally { el.disabled = false; } })); return el; }
function details(title, value) { const box = node('details'); box.append(node('summary', title), node('pre', pretty(value))); return box; }
function grantList(resources) {
  const fragment = document.createDocumentFragment();
  const operations = resources?.operations || {};
  if (!Object.keys(operations).length) fragment.append(node('p', 'No external resource grants.', 'muted'));
  for (const [operation, slots] of Object.entries(operations)) {
    const card = node('div', undefined, 'card'); card.append(node('h3', operation));
    for (const [slot, grant] of Object.entries(slots)) {
      card.append(node('p', `${slot} · ${(grant.actions || []).join(', ')}`));
      card.append(details('Exact resource, bounds and policy provenance', grant));
    }
    fragment.append(card);
  }
  return fragment;
}
function showCatalog() {
  const catalog = snapshot.authoring.catalog || {};
  $('#catalog-editor').value = pretty(snapshot.authoring.catalog);
  $('#bindings-editor').value = pretty(snapshot.authoring.bindings);
  $('#catalog-editor').readOnly = !snapshot.administrator;
  $('#bindings-editor').readOnly = !snapshot.administrator;
  $('#save').hidden = !snapshot.administrator;
  const summary = $('#catalog-summary'); summary.replaceChildren();
  for (const family of ['connections', 'resources', 'policies', 'budgets']) {
    const values = catalog[family] || {}; const card = node('div', undefined, 'card');
    card.append(node('h3', `${Object.keys(values).length} ${family}`));
    for (const [name, value] of Object.entries(values)) card.append(details(name, value));
    summary.append(card);
  }
  if (snapshot.administrator) {
    summary.append(button('Initialize company budget ledger', async () => { const result = await api('setup_company_budget'); notice(`Company budget ledger ready: ${result.allocator}`); }));
    const pool = node('section'); pool.append(node('h3', 'Company capacity'), node('p', 'Review fixed allocations across apps before lowering a company ceiling. Spent amounts and unresolved holds remain backed.', 'muted'));
    pool.append(button('Review company accounting', () => showCompanyBudget(pool))); summary.append(pool);
  }
}

async function showCompanyBudget(target) {
  const state = await api('company_budget');
  target.replaceChildren(node('h3', 'Company capacity'));
  target.append(button('Refresh company accounting', () => showCompanyBudget(target)), details('Central allocations, returns and app accounting', state));
  const appForLedger = ledger => Object.entries(state.apps).find(([, app]) => app.usage?.ledger_id === ledger)?.[0];
  for (const status of state.pool.reductions) {
    const { request } = status.proposal;
    const card = node('div', undefined, 'card');
    card.append(node('h3', `${request.budget_id} · ${status.decision ? (status.decision.completed ? 'Completed' : 'Cancelled') : 'Pending reduction'}`), node('p', request.reason), details('Exact reviewed ceiling and returns', status));
    for (const ledger of [...new Set(request.returns.map(item => item.ledger_id))]) {
      if (status.acknowledged_ledgers.includes(ledger)) { card.append(node('p', `Return acknowledged · ${appForLedger(ledger) || ledger}`, 'muted')); continue; }
      const app = appForLedger(ledger);
      if (!app) { card.append(node('p', `Ledger ${ledger} is unavailable. Its capacity remains fully allocated.`, 'muted')); continue; }
      const returns = request.returns.filter(item => item.ledger_id === ledger);
      card.append(details(`Reviewed return from ${app}`, returns));
      card.append(button(status.decision ? `Retry committed return · ${app}` : `Return reviewed capacity · ${app}`, async () => {
        await api('return_company_capacity', { app, request: { reduction: request.id, ledger_id: ledger } });
        await showCompanyBudget(target); notice('App fence committed and its exact return credited centrally. All spent amounts and unresolved holds remain.');
      }));
    }
    if (!status.decision) {
      card.append(node('p', 'Cancelling keeps the original company ceiling. Any capacity already returned stays available centrally; an explicit new allocation restores an app’s share.', 'muted'));
      const actions = node('div', undefined, 'actions');
      actions.append(button('Commit reviewed lower ceiling', async () => {
        await api('decide_pool_reduction', { request: { reduction: request.id, complete: true } });
        await showCompanyBudget(target); notice('Lower company ceiling committed. Import the verified proof, then stage and approve the new budget definition for each app.');
      }, 'primary'));
      actions.append(button('Cancel reduction', async () => {
        await api('decide_pool_reduction', { request: { reduction: request.id, complete: false } });
        await showCompanyBudget(target); notice('Original company ceiling retained. Completed returns remain available centrally; restoring app capacity requires an explicit new allocation.');
      })); card.append(actions);
    } else if (status.decision.completed) {
      card.append(node('p', 'The central ceiling is active. Import proof into an app before approving its lower budget. Importing proof alone does not change active grants.', 'muted'));
      const apps = selectField('App receiving verified proof', Object.keys(state.apps).map(app => [app, app])); card.append(apps.label);
      card.append(button('Import verified completion proof', async () => {
        await api('import_pool_reduction', { app: apps.select.value, request: { reduction: request.id } }); notice('Verified completion proof imported. Stage the approved budget definition in the catalog and review affected apps.');
      }));
    }
    target.append(card);
  }
  for (const [budget, expected] of Object.entries(state.pool.definitions)) {
    if (state.pool.reductions.some(status => status.proposal.request.budget_id === budget && !status.decision)) continue;
    const card = node('details'); card.append(node('summary', `Review a lower ceiling · ${budget}`));
    const at = state.now_seconds - state.now_seconds % expected.period_seconds;
    card.append(node('p', `Applies to the period starting ${new Date(at * 1000).toLocaleString()} and future periods, plus persistent concurrency. Historical period caps remain unchanged. New central allocations pause while pending; apps keep spending until their local return commits.`, 'muted'));
    const request = { id: crypto.randomUUID(), budget_id: budget, expected, definition: { ...expected, revision: expected.revision + 1 }, effective_window: at, returns: [], reason: '' };
    const editor = node('textarea'); editor.rows = 20; editor.value = pretty(request); editor.setAttribute('aria-label', `Exact reduction request for ${budget}`);
    card.append(node('p', 'Set lower definition limits, a reason, and explicit returns. Each return is {ledger_id, window_start, unit, amount}; amount is capacity returned, not the new app cap. Concurrency uses window_start 0. Do not return spent or reserved units.', 'muted'), editor);
    const checked = node('input'); checked.type = 'checkbox'; const label = node('label'); label.append(checked, document.createTextNode('I reviewed the exact per-app returns against current spent amounts and unresolved holds.')); card.append(label);
    card.append(button('Record reviewed reduction', async () => {
      if (!checked.checked) throw new Error('Review the exact company ceiling and app returns before recording this reduction.');
      await api('propose_pool_reduction', { request: parseExact(editor.value) }); await showCompanyBudget(target); notice('Reduction review recorded. Complete each explicit app return, then commit the lower ceiling.');
    }, 'primary')); target.append(card);
  }
}
async function refresh() {
  snapshot = await api('snapshot'); $('#identity').textContent = `${snapshot.operator} · ${snapshot.administrator ? 'Installation administrator' : 'Delegated policy owner'}`;
  const list = $('#app-list'); list.replaceChildren();
  for (const app of Object.keys(snapshot.authoring.bindings)) { const el = button(app, () => selectApp(app)); el.dataset.app = app; list.append(el); }
  showCatalog(); if (selected) await selectApp(selected); notice('Loaded current configuration. Active app access changes only after approval.');
}
async function selectApp(app) {
  selected = app; for (const el of document.querySelectorAll('[data-app]')) el.classList.toggle('selected', el.dataset.app === app);
  const [preview, reviewPage] = await Promise.all([api('preview', { app }), api('reviews', { app })]); currentPreview = preview;
  const target = $('#app-detail'); target.replaceChildren(node('h2', app));
  target.append(node('p', preview.enabled ? 'App enabled' : 'App disabled · Resource approval will keep it disabled', 'badge'));
  if (preview.review_requires_administrator) target.append(node('p', 'This app combines policies from multiple owners. You can stage your own bindings and request review; an installation administrator approves the combined access. Other owners’ grant details are hidden.', 'muted'));
  if (preview.validation_error) target.append(node('p', `Desired bindings need attention: ${preview.validation_error}. Update the attachment to the current approved policy version below. Active access is preserved.`, 'muted'));
  const pair = node('div', undefined, 'pair'); const active = node('section'); active.append(node('h3', 'Active access'), grantList(preview.active)); const desired = node('section'); desired.append(node('h3', 'Proposed access'), grantList(preview.proposed)); pair.append(active, desired); target.append(pair);
  if (!preview.validation_error) target.append(node('p', preview.changed ? 'This app has a resource change ready for review.' : 'Desired resources match this app’s active grants.', 'muted'));
  target.append(policyPicker(app, preview));
  target.append(usagePanel(app, preview));
  if (preview.changed) {
    const label = node('label', 'Why does this app need the change?'); const note = node('textarea'); note.rows = 3; note.id = 'proposal-note'; label.htmlFor = note.id;
    target.append(label, note, button('Create access review', async () => { await api('propose', { app, proposal: { id: crypto.randomUUID(), expected: currentPreview.expected, authoring_revision: currentPreview.authoring_revision, note: note.value } }); await selectApp(app); notice('Review recorded. Active access is unchanged until approval.'); }, 'primary'));
  }
  target.append(node('h3', 'Access reviews'));
  if (!reviewPage.reviews.length) target.append(node('p', 'No recorded access reviews.', 'muted'));
  for (const review of reviewPage.reviews) {
    const card = node('div', undefined, 'card'); card.append(node('span', review.decision || 'Awaiting decision', 'badge'), node('p', review.note));
    card.append(node('p', `${review.author} · ${new Date(review.created_ms).toLocaleString()}`, 'muted'), details('Review exact proposed access', review.resources));
    if (review.decision) { card.append(node('p', `${review.reviewer}: ${review.reason}`)); if (review.receipt) card.append(details('Activation receipt', review.receipt)); }
    else if (review.requires_administrator) { card.append(node('p', 'Routed to installation administrators for review of combined access.', 'muted')); }
    else {
      const acknowledged = node('input'); acknowledged.type = 'checkbox'; const label = node('label'); label.append(acknowledged, document.createTextNode('I reviewed the combined data sources, destinations, acting identity and usage limits.'));
      const reason = node('textarea'); reason.rows = 2; reason.setAttribute('aria-label', 'Decision reason'); reason.placeholder = 'Record the reason for your decision'; card.append(label, reason);
      const actions = node('div', undefined, 'actions');
      for (const [decision, text, style] of [['approve', 'Approve & activate', 'primary'], ['deny', 'Deny change', 'danger']]) actions.append(button(text, async () => { const result = await api('decide', { app, decision: { review: review.id, decision, reason: reason.value, reviewed_data_movement: acknowledged.checked } }); await selectApp(app); notice(result.receipt ? `Access activated at revision ${result.receipt.stamp.revision}.` : 'Change denied. Existing access is preserved.'); }, style));
      card.append(actions);
    }
    target.append(card);
  }
}
function selectField(labelText, choices) {
  const label = node('label', labelText); const select = node('select');
  for (const [value, text] of choices) { const option = node('option', text); option.value = value; select.append(option); }
  label.append(select); return { label, select };
}

function policyPicker(app, preview) {
  const box = node('details'); box.append(node('summary', 'Apply an approved policy'));
  const catalog = snapshot.authoring.catalog || {};
  const policies = Object.entries(catalog.policies || {}).filter(([, policy]) => policy.allowed_apps.includes(app));
  if (!policies.length) box.append(node('p', 'No reusable policies include this app. An installation administrator can add it to an approved template.', 'muted'));
  for (const [id, policy] of policies) {
    const card = node('div', undefined, 'card'); card.append(node('h3', `${id} · revision ${policy.revision}`), node('p', `Owner: ${policy.owner} · Actors: ${policy.actors.join(', ')}`, 'muted'));
    const operation = selectField('App operation', (preview.operations || []).map(name => [name, name])); card.append(operation.label);
    const slots = [];
    for (const [name, slot] of Object.entries(policy.slots)) {
      const resource = selectField(name, slot.allowed_resources.map(reference => [reference.id, `${reference.id} · ${slot.actions.join(', ')}`]));
      card.append(resource.label); slots.push([name, resource.select, slot]);
    }
    const expires = node('input'); expires.type = 'datetime-local';
    const expiryLabel = node('label', policy.max_duration_seconds ? `Access expires (maximum ${policy.max_duration_seconds} seconds)` : 'Optional expiry'); expiryLabel.append(expires); card.append(expiryLabel);
    if (policy.max_duration_seconds) { const date = new Date(Date.now() + policy.max_duration_seconds * 1000 - 1000); expires.value = new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
    card.append(button('Stage this binding', async () => {
      const bindings = Object.fromEntries(slots.map(([name, select, slot]) => [name, slot.allowed_resources.find(reference => reference.id === select.value)]));
      const attachment = { policy: { id, revision: policy.revision }, operation: operation.select.value, bindings, actors: null, expires_at_ms: expires.value ? new Date(expires.value).getTime() : null };
      const existing = snapshot.authoring.bindings[app].filter(item => !(item.policy.id === id && item.operation === attachment.operation));
      snapshot.authoring = await api('attach', { app, request: { revision: snapshot.authoring.revision, bindings: [...existing, attachment] } }); showCatalog(); await selectApp(app); notice('Binding staged within the policy ceiling. Review its combined access before activation.');
    }));
    box.append(card);
  }
  const editor = node('textarea'); editor.rows = 8; editor.value = pretty(snapshot.authoring.bindings[app]); editor.setAttribute('aria-label', 'This app’s policy attachments');
  const advanced = node('details'); advanced.append(node('summary', 'Edit or remove this app’s attachments'), editor, button('Validate & stage attachments', async () => { snapshot.authoring = await api('attach', { app, request: { revision: snapshot.authoring.revision, bindings: parseExact(editor.value) } }); showCatalog(); await selectApp(app); notice('Attachments staged. Active access is preserved until approval.'); })); box.append(advanced);
  return box;
}

function usagePanel(app, preview) {
  const box = node('details'); box.append(node('summary', 'Usage & spending capacity'));
  const usage = preview.usage;
  if (!usage) return box;
  box.append(node('p', usage.frozen_after_restore ? 'Accounting is frozen after restore. Recovery requires preserved liability and fresh company capacity.' : `${usage.outstanding_attempts} attempts have unresolved usage. Unknown outcomes retain their reservation.`, 'muted'));
  for (const account of usage.accounts) box.append(node('p', `${account.budget_id} · ${account.scope}/${account.subject} · ${account.unit}: ${account.used} used + ${account.reserved} reserved / ${account.limit}${account.frozen ? ' · Frozen' : ''}`));
  if (!usage.accounts.length) box.append(node('p', 'No metered provider attempts yet.', 'muted'));
  box.append(details('Accounting evidence', usage));
  if (snapshot.administrator && !usage.frozen_after_restore) for (const unknown of usage.unknown_usage || []) {
    if (unknown.reservation.ledger_id !== usage.ledger_id) continue;
    const card = node('div', undefined, 'card'); card.append(node('h3', 'Reconcile unknown usage'), details('Exact physical attempt and reserved maximum', unknown), node('p', 'Enter verified terminal usage and a provider receipt reference. This is your recorded evidence assertion; the platform does not verify the external invoice. Accounting reconciliation cannot retry or resume this app work.', 'muted'));
    const editor = node('textarea'); editor.rows = 6; editor.value = pretty({ ...unknown.quote, concurrency: 0 }); editor.setAttribute('aria-label', 'Verified actual terminal usage');
    const reason = node('textarea'); reason.rows = 2; reason.placeholder = 'Why is this usage now known?'; reason.setAttribute('aria-label', 'Usage reconciliation reason');
    const proof = node('textarea'); proof.rows = 2; proof.placeholder = 'Terminal provider receipt or usage evidence reference'; proof.setAttribute('aria-label', 'Provider usage evidence reference');
    const checked = node('input'); checked.type = 'checkbox'; const label = node('label'); label.append(checked, document.createTextNode('I verified the terminal provider evidence and the actual amounts entered above.'));
    const id = crypto.randomUUID(); card.append(editor, reason, proof, label, button('Record verified usage', async () => {
      if (!checked.checked) throw new Error('Verify terminal provider usage and check the confirmation before reconciling.');
      const result = await api('reconcile_usage', { app, request: { id, ledger_id: unknown.reservation.ledger_id, reservation: unknown.reservation.id, actual: parseExact(editor.value), reason: reason.value, proof: proof.value } });
      await selectApp(app); notice(result.receipt.settlement.overrun ? 'Full actual usage recorded. The overrun freeze remains and requires a separate reviewed repair.' : 'Usage recorded and unused holds released. Provider journals and app work remain unchanged.');
    })); box.append(card);
  }
  if (snapshot.administrator && usage.frozen_after_overrun && !usage.frozen_after_restore) {
    const card = node('div', undefined, 'card'); card.append(node('h3', 'Resolve a usage overrun'), node('p', 'Review every listed incident and repair or reconcile its cause. All charged usage remains; quota increases alone cannot acknowledge incidents.', 'muted'), details('Exact incidents being acknowledged', usage.overruns));
    const reason = node('textarea'); reason.rows = 2; reason.setAttribute('aria-label', 'Overrun resolution reason'); reason.placeholder = 'Reason for resuming admission';
    const proof = node('textarea'); proof.rows = 2; proof.setAttribute('aria-label', 'Repair or reconciliation evidence'); proof.placeholder = 'Reference to reviewed repair or reconciliation evidence';
    const id = crypto.randomUUID(); card.append(reason, proof, button('Record resolution & recheck limits', async () => { await api('resolve_overruns', { app, request: { id, ledger_id: usage.ledger_id, reservations: usage.overruns.map(event => event.reservation), reason: reason.value, proof: proof.value } }); await selectApp(app); notice('Overrun resolution recorded. All consumption remains charged and current limits still apply.'); })); box.append(card);
  }
  if (snapshot.administrator && usage.frozen_after_restore) {
    const card = node('div', undefined, 'card'); card.append(node('h3', 'Recover accounting after restore'), node('p', 'All existing consumption and unresolved holds remain charged. Company budgets require fresh allocations from the surviving central ledger. This does not enable the app.', 'muted'));
    const editor = node('textarea'); editor.rows = 5; editor.value = '{}'; editor.setAttribute('aria-label', 'Fresh recovery allocations by company budget');
    const id = crypto.randomUUID(); card.append(editor, button('Recover with preserved liabilities', async () => { await api('recover_budget', { app, request: { id, allocations: parseExact(editor.value) } }); await selectApp(app); notice('Accounting recovered with retained liabilities. App activation is still explicit.'); })); box.append(card);
  }
  if (snapshot.administrator) for (const [budget, definition] of Object.entries(preview.active?.budgets || {})) {
    if (definition.scope !== 'installation') continue;
    const card = node('div', undefined, 'card'); card.append(node('h3', `Allocate company capacity · ${budget}`), node('p', 'This reserves a fixed portion of the company pool for this app. Capacity is committed centrally before import and is not automatically returned.', 'muted'));
    const editor = node('textarea'); editor.rows = 5; editor.value = pretty(Object.fromEntries(Object.entries(definition.limits).map(([unit, value]) => [unit, value === null ? null : 1]))); editor.setAttribute('aria-label', `Allocation limits for ${budget}`);
    const id = crypto.randomUUID(); card.append(editor, button('Reserve & install allocation', async () => { await api('allocate', { app, request: { id, budget, limits: parseExact(editor.value) } }); await selectApp(app); notice('Company allocation committed and installed. Retrying uses the same allocation identity.'); })); box.append(card);
  }
  return box;
}

for (const button of document.querySelectorAll('[data-tab]')) button.addEventListener('click', () => { for (const el of document.querySelectorAll('[data-tab]')) el.setAttribute('aria-pressed', String(el === button)); for (const id of ['apps', 'catalog']) $(`#${id}`).hidden = id !== button.dataset.tab; });
$('#refresh').addEventListener('click', () => work(refresh));
$('#save').addEventListener('click', () => work(async () => { snapshot.authoring = await api('save', { authoring: { revision: snapshot.authoring.revision, catalog: parseExact($('#catalog-editor').value), bindings: parseExact($('#bindings-editor').value) } }); showCatalog(); notice('Desired configuration saved. Open affected apps to review and activate their exact changes.'); }));
work(refresh);
