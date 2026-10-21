// Platform-owned coordination for admitted GET query forms. No app expressions,
// operation callbacks, business calculations, or financial formatting execute here.
const MAX_REVISION = 18446744073709551615n;
const MAX_HTML = 1048576;

export function createLatestRead({read, publish, status, initialRevision = 0n,
  debounceMs = 150, schedule = setTimeout, cancelSchedule = clearTimeout,
  abortController = () => new AbortController()}) {
  let revision = BigInt(initialRevision), timer, active, activeDeadline, stopped = false;
  if (revision < 0n || revision > MAX_REVISION) throw new Error('query_revision');
  function cancel() {
    if (timer !== undefined) cancelSchedule(timer);
    timer = undefined;
    if (activeDeadline !== undefined) cancelSchedule(activeDeadline);
    activeDeadline = undefined;
    active?.abort(); active = undefined;
  }
  function invalidate() {
    cancel();
    if (stopped || revision === MAX_REVISION) throw new Error('query_revision_budget');
    revision += 1n;
    return revision;
  }
  async function run(input, expected) {
    if (stopped || expected !== revision) return;
    cancel();
    const controller = abortController(); active = controller;
    status('loading', 'Updating…');
    const deadline = schedule(() => {
      controller.abort();
      if (!stopped && expected === revision) status('error', 'The update timed out. Previous results are not current; try again.');
    }, 12000);
    activeDeadline = deadline;
    try {
      const result = await read(input, expected, controller.signal);
      if (stopped || expected !== revision || controller.signal.aborted) return;
      publish(result, expected);
      if (!stopped && expected === revision && !controller.signal.aborted) status('ready', '');
    } catch (error) {
      if (stopped || expected !== revision || controller.signal.aborted || error?.name === 'AbortError') return;
      status(error?.rejected ? 'invalid' : 'error', error?.userMessage
        ? error.message : 'Results could not be updated. Previous results are not current; try again.');
    } finally {
      cancelSchedule(deadline);
      if (activeDeadline === deadline) activeDeadline = undefined;
      if (active === controller) active = undefined;
    }
  }
  return Object.freeze({
    update(input, immediate = false) {
      const expected = invalidate();
      status('pending', 'Updating…');
      if (immediate) return run(input, expected);
      timer = schedule(() => { timer = undefined; void run(input, expected); }, debounceMs);
      return expected;
    },
    cancel() {
      if (stopped) return;
      const pending = timer !== undefined || active !== undefined;
      cancel();
      if (revision < MAX_REVISION) revision += 1n;
      if (pending) status('error', revision === MAX_REVISION
        ? 'The update was interrupted. Reload the page to update the results.'
        : 'The update was interrupted. Edit an input to update the results.');
    },
    stop() { if (!stopped) { stopped = true; cancel(); } },
    revision: () => revision,
  });
}

const controls = form => [...form.elements].filter(control => control.name && !control.disabled
  && (control.localName === 'input' || control.localName === 'textarea'));
const field = (form, name) => form.elements.namedItem(name);
function snapshot(form) {
  return new Map(controls(form).map(control => [control.name, control.value]));
}
function patchAttributes(current, incoming) {
  const hostAttributes = new Set(['id', 'aria-busy', 'data-query-stale']);
  for (const name of current.getAttributeNames()) {
    if (!hostAttributes.has(name) && !incoming.hasAttribute(name)) current.removeAttribute(name);
  }
  for (const name of incoming.getAttributeNames()) {
    if (!hostAttributes.has(name)) current.setAttribute(name, incoming.getAttribute(name));
  }
}
function owned(form, id) {
  const element = form.ownerDocument.getElementById(id);
  if (!element || !form.contains(element)) throw new Error('query_target');
  return element;
}
function choiceLabel(form, mirror, value) {
  const list = owned(form, mirror.dataset.queryLabels);
  return [...list.querySelectorAll('option')].find(option => option.value === value)?.label;
}
function mirrors(form, name) {
  return [...form.querySelectorAll('input[type="range"][data-query-input]')]
    .filter(control => control.dataset.queryInput === name);
}
function paintRange(form, mirror) {
  const value = Number(mirror.value), minimum = Number(mirror.min), maximum = Number(mirror.max);
  // Native range geometry and selection only; labels are supplied by Roc/server HTML.
  if (!Number.isFinite(value) || !Number.isFinite(minimum) || !Number.isFinite(maximum) || maximum <= minimum) return;
  mirror.style.setProperty('--query-progress', `${Math.max(0, Math.min(100, (value - minimum) * 100 / (maximum - minimum)))}%`);
  const label = choiceLabel(form, mirror, mirror.value);
  if (label !== undefined) mirror.setAttribute('aria-valuetext', label);
  const buttons = [...form.querySelectorAll('button[data-query-input]')]
    .filter(button => button.dataset.queryInput === mirror.dataset.queryInput);
  let nearest, distance = Infinity;
  for (const button of buttons) {
    const next = Math.abs(Number(button.dataset.queryValue) - value);
    if (Number.isFinite(next) && next < distance) { distance = next; nearest = button; }
  }
  for (const button of buttons) button.setAttribute('aria-pressed', String(button === nearest));
}

export function mountQueryForm(form, {fetch: fetchPage = form.ownerDocument.defaultView.fetch.bind(form.ownerDocument.defaultView),
  parseHTML = source => new form.ownerDocument.defaultView.DOMParser().parseFromString(source, 'text/html'),
  schedule = setTimeout, cancelSchedule = clearTimeout} = {}) {
  const document = form.ownerDocument, view = document.defaultView;
  const resultIDs = form.dataset.queryResults.split(/\s+/);
  const results = resultIDs.map(id => owned(form, id));
  const message = owned(form, form.dataset.queryStatus);
  const revisionField = form.dataset.queryRevision && field(form, form.dataset.queryRevision);
  const commitField = form.dataset.queryCommitField && field(form, form.dataset.queryCommitField);
  let accepted = snapshot(form), acceptedMirrors = new Map(), state = 'idle';
  const rememberMirrors = source => new Map([...source.querySelectorAll('input[type="range"][data-query-input]')]
    .map(control => [control.id, control.value]));
  acceptedMirrors = rememberMirrors(form);
  const setStatus = (next, text) => {
    state = next;
    form.dataset.queryState = next;
    form.setAttribute('aria-busy', String(next === 'loading'));
    for (const result of results) {
      result.setAttribute('aria-busy', String(next === 'pending' || next === 'loading'));
      // Retained results are explicitly marked stale until the current draft succeeds.
      result.dataset.queryStale = String(next !== 'ready' && next !== 'idle');
    }
    message.textContent = text;
  };
  function syncFields() {
    for (const control of controls(form)) {
      if (control === revisionField || control === commitField || control === document.activeElement) continue;
      if (accepted.has(control.name)) control.value = accepted.get(control.name);
    }
    for (const mirror of form.querySelectorAll('input[type="range"][data-query-input]')) {
      if (mirror !== document.activeElement && acceptedMirrors.has(mirror.id)) mirror.value = acceptedMirrors.get(mirror.id);
      paintRange(form, mirror);
    }
  }
  const query = createLatestRead({
    initialRevision: revisionField?.value || '0',
    debounceMs: Number(form.dataset.queryDebounce ?? '150'), schedule, cancelSchedule,
    status: setStatus,
    async read(values, revision, signal) {
      const url = new URL(form.action, document.baseURI);
      if (url.origin !== new URL(document.baseURI).origin || form.method.toLowerCase() !== 'get') throw new Error('query_transport');
      url.search = '';
      for (const [name, value] of values) url.searchParams.append(name, value);
      if (revisionField) url.searchParams.set(revisionField.name, String(revision));
      const response = await fetchPage(url.href, {method: 'GET', credentials: 'same-origin', cache: 'no-store', signal,
        redirect: 'error', headers: {Accept: 'text/html'}});
      if (!response.ok) {
        const error = new Error(response.status === 422
          ? 'These inputs were rejected. Previous results are not current; correct the draft.'
          : 'Results could not be updated. Previous results are not current; try again.');
        error.rejected = response.status === 422;
        error.userMessage = true;
        throw error;
      }
      if (!response.headers.get('content-type')?.includes('text/html')) throw new Error('query_response');
      const source = await response.text();
      if (source.length > MAX_HTML) throw new Error('query_response_budget');
      const parsed = parseHTML(source), canonical = parsed.getElementById(form.id);
      if (canonical?.localName !== 'form' || canonical.dataset.page !== form.dataset.page ||
          canonical.dataset.queryResults !== form.dataset.queryResults) throw new Error('query_form_identity');
      const incoming = resultIDs.map((id, index) => {
        const region = owned(canonical, id);
        if (region.localName !== results[index].localName ||
            region.querySelector('form,input,textarea,select,script')) throw new Error('query_result_identity');
        return region;
      });
      if (revisionField && field(canonical, revisionField.name)?.value !== String(revision)) throw new Error('query_revision_mismatch');
      for (const control of controls(form)) if (!field(canonical, control.name)) throw new Error('query_field_identity');
      return {canonical, incoming};
    },
    publish({canonical, incoming}, revision) {
      if (!form.isConnected) return;
      const replacements = incoming.map(region => document.importNode(region, true));
      const focused = document.activeElement;
      const focusID = results.some(region => region.contains(focused)) ? focused.id : null;
      for (let index = 0; index < results.length; index += 1) {
        const current = results[index], replacement = replacements[index];
        current.dispatchEvent(new view.CustomEvent('cui:before-patch', {
          bubbles: true, detail: {current, incoming: replacement},
        }));
        patchAttributes(current, replacement);
        current.replaceChildren(...replacement.childNodes);
      }
      accepted = snapshot(canonical);
      acceptedMirrors = rememberMirrors(canonical);
      if (revisionField) revisionField.value = String(revision);
      syncFields();
      if (focusID && document.activeElement === document.body) document.getElementById(focusID)?.focus({preventScroll: true});
    },
  });
  function update(immediate = false, commit = false) {
    if (commitField) commitField.value = String(commit);
    try { void query.update([...new view.FormData(form).entries()], immediate); }
    catch { setStatus('error', 'Results could not be updated. Reload the page to start a new query revision.'); }
  }
  function input(event) {
    const control = event.target;
    if (control.form !== form) return;
    if (control.matches('input[type="range"][data-query-input]')) {
      const label = choiceLabel(form, control, control.value);
      if (label === undefined) { setStatus('error', 'This control has no admitted label. Try another value.'); return; }
      field(form, control.dataset.queryInput).value = label;
      paintRange(form, control);
    } else if (!control.name || control === revisionField || control === commitField) return;
    update();
  }
  function click(event) {
    const button = event.target.closest?.('button[data-query-input]');
    if (!button || button.form !== form) return;
    event.preventDefault();
    const name = button.dataset.queryInput, related = mirrors(form, name);
    const label = related.length ? choiceLabel(form, related[0], button.dataset.queryValue) : button.dataset.queryLabel;
    if (label === undefined) { setStatus('error', 'This control has no admitted label. Try another value.'); return; }
    field(form, name).value = label;
    for (const mirror of related) { mirror.value = button.dataset.queryValue; paintRange(form, mirror); }
    update(true);
  }
  function blur(event) {
    const control = event.target;
    if (control.form !== form || !control.name || control === revisionField || control === commitField) return;
    const commit = control.dataset.queryCommit === 'blur' || form.dataset.queryCommitInput === control.name;
    if (state === 'invalid' && !commit) syncFields();
    update(true, commit);
  }
  function submit(event) {
    event.preventDefault(); event.stopImmediatePropagation();
    if (form.reportValidity()) update(true);
  }
  function keydown(event) {
    if (event.key === 'Enter' && event.target.localName === 'input' && event.target.name) {
      event.preventDefault(); event.target.blur();
    }
  }
  const listeners = [['input', input, false], ['click', click, false], ['blur', blur, true],
    ['submit', submit, true], ['keydown', keydown, false]];
  for (const [name, listener, capture] of listeners) form.addEventListener(name, listener, capture);
  for (const mirror of form.querySelectorAll('input[type="range"][data-query-input]')) paintRange(form, mirror);
  setStatus('idle', '');
  const stop = () => { query.stop(); for (const [name, listener, capture] of listeners) form.removeEventListener(name, listener, capture); };
  stop.suspend = () => query.cancel();
  return stop;
}

const installedRoots = new WeakMap();
export function installQueryForms(root = document) {
  if (installedRoots.has(root)) return installedRoots.get(root);
  const document = root.ownerDocument ?? root, view = document.defaultView, active = new Map();
  let stopped = false;
  function refresh() {
    for (const [form, stop] of active) if (!root.contains(form)) { stop(); active.delete(form); }
    for (const form of root.querySelectorAll('form[data-query-on="input"]')) if (!active.has(form)) active.set(form, mountQueryForm(form));
  }
  const observer = new view.MutationObserver(refresh);
  observer.observe(root, {childList: true, subtree: true});
  function hide(event) {
    if (!event.persisted) stop();
    else for (const cleanup of active.values()) cleanup.suspend();
  }
  function stop() {
    if (stopped) return;
    stopped = true;
    observer.disconnect();
    for (const cleanup of active.values()) cleanup();
    active.clear();
    view.removeEventListener('pagehide', hide);
    installedRoots.delete(root);
  }
  view.addEventListener('pagehide', hide);
  installedRoots.set(root, stop);
  try { refresh(); } catch (error) { stop(); throw error; }
  return stop;
}
if (typeof document !== 'undefined') installQueryForms(document);
