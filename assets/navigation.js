// Platform-owned navigation for admitted live regions. Apps supply view checks
// and UI feedback; route serialization and the live transport stay here.
export function canonicalPageURL(raw, base, defaults, origin) {
  let url, page;
  try { url = new URL(raw, base); page = new URL(base); } catch { return null; }
  if (url.origin !== origin || url.pathname !== page.pathname) return null;
  const keys = [...url.searchParams.keys()];
  if (new Set(keys).size !== keys.length || keys.some(key => !Object.hasOwn(defaults, key))) return null;
  const values = Object.fromEntries(Object.keys(defaults).map(key => [key, url.searchParams.get(key) ?? String(defaults[key])]));
  url.search = ''; url.hash = '';
  // Matches the host's named-route serializer, including default omission.
  for (const key of Object.keys(values).sort()) {
    if (values[key] !== String(defaults[key])) url.searchParams.set(key, values[key]);
  }
  return {url, values};
}

export function navigationState(acceptedURL) {
  let generation = 0, accepted = acceptedURL;
  return Object.freeze({
    begin() { if (generation >= 1000000) throw new Error('navigation_budget'); return ++generation; },
    current(token) { return token === generation; },
    accept(token, url) { if (token !== generation) return false; accepted = url; return true; },
    cancel() { if (generation >= 1000000) throw new Error('navigation_budget'); ++generation; },
    accepted() { return accepted; }
  });
}

export function createPageNavigation({document, view, location, history, fetch, parseHTML,
  createAbortController, schedule, cancelSchedule, target, accept, pending, accepted, failed, cancelled}) {
  const state = navigationState(location.href), timers = new Set();
  let request = null, stopped = false;
  function cancel() { state.cancel(); request?.abort(); request = null; cancelled(); }
  async function navigate(raw, historyMode = 'push') {
    if (stopped) return;
    const next = target(raw);
    if (!next) { failed(false); return; }
    const token = state.begin(); request?.abort();
    const controller = createAbortController(); request = controller;
    const timeout = schedule(() => {
      controller.abort();
      if (state.current(token) && !stopped) {
        if (historyMode === 'replace') history.replaceState(null, '', state.accepted());
        failed(true);
      }
    }, 12000); timers.add(timeout);
    pending();
    let previousLive = null, removedLive = false;
    const current = () => state.current(token) && !stopped && !controller.signal.aborted;
    function restore() {
      if (removedLive && previousLive && !stopped && !document.getElementById('day2-live')) {
        document.body.prepend(previousLive.cloneNode(true));
      }
      removedLive = false;
    }
    try {
      const response = await fetch(next.url, {credentials: 'same-origin', signal: controller.signal,
        redirect: 'error', headers: {Accept: 'text/html'}});
      if (!current()) return;
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error('page_response');
      const source = await response.text();
      if (!current()) return;
      if (source.length > 1048576) throw new Error('page_budget');
      const parsed = parseHTML(source), regions = accept(parsed, next);
      const live = parsed.getElementById('day2-live');
      previousLive = document.getElementById('day2-live');
      if (!regions?.length || !live || !previousLive?.isConnected) throw new Error('page_identity');
      const liveURL = new URL(live.dataset.liveUrl, location.origin);
      if (liveURL.origin !== location.origin || liveURL.pathname !== '/_live' ||
          liveURL.searchParams.get('path') !== next.url.pathname + next.url.search) throw new Error('live_identity');
      const ids = new Set();
      const replacements = regions.map(region => {
        const old = document.getElementById(region.id);
        if (!region.id || ids.has(region.id) || !region.hasAttribute('data-live') ||
            region.querySelector('form,input,textarea,select,script') || !old?.isConnected ||
            !old.hasAttribute('data-live')) throw new Error('page_region');
        ids.add(region.id);
        return [old, document.importNode(region, true)];
      });
      const nextLive = document.importNode(live, true);
      // Let Datastar abort the old stream before inserting the new regions.
      previousLive.remove(); removedLive = true; await Promise.resolve();
      if (!current()) { restore(); return; }
      for (const [old, replacement] of replacements) old.replaceWith(replacement);
      document.body.prepend(nextLive); removedLive = false;
      if (!state.accept(token, next.url.href)) return;
      if (historyMode === 'push') history.pushState(null, '', next.url);
      else history.replaceState(null, '', next.url);
      accepted(next);
    } catch {
      restore();
      if (state.current(token) && !stopped) {
        if (historyMode === 'replace') history.replaceState(null, '', state.accepted());
        failed(controller.signal.aborted);
      }
    } finally {
      cancelSchedule(timeout); timers.delete(timeout);
      if (state.current(token)) request = null;
    }
  }
  const pop = () => { void navigate(location.href, 'replace'); };
  const hide = event => { if (event.persisted) cancel(); else stop(); };
  view.addEventListener('popstate', pop); view.addEventListener('pagehide', hide);
  function stop() {
    if (stopped) return;
    stopped = true; state.cancel(); request?.abort();
    for (const timer of timers) cancelSchedule(timer);
    timers.clear();
    view.removeEventListener('popstate', pop); view.removeEventListener('pagehide', hide);
  }
  return {navigate, cancel, stop};
}
