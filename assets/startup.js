// Only anonymously rendered, form-free shells use this bootstrap. The HTTP
// cache serves their next navigation immediately; this refresh never gates paint.
const artifact = document.querySelector('meta[name="day2-startup-version"]')?.content;
const key = `day2.startup.refresh:${location.pathname}`;
const reloadKey = `day2.startup.reload:${location.pathname}`;
let pending;

const reloadOnce = (next) => {
  try {
    if (sessionStorage.getItem(reloadKey) === next) return;
    sessionStorage.setItem(reloadKey, next);
    location.reload();
  } catch { /* Storage-disabled browsers keep the visible shell. */ }
};

const refresh = (force = false) => {
  if (pending) return pending;
  if (!force) {
    try {
      const age = Date.now() - Number(localStorage.getItem(key));
      if (age >= 0 && age < 60000) return Promise.resolve();
    } catch { /* Cache refresh also works without storage. */ }
  }
  pending = (async () => {
    try {
      // Bypass the HTTP cache without locking/replacing its current entry.
      // A simultaneous new tab must still be able to read the cached document.
      const response = await fetch(location.href, {
        credentials: "same-origin", redirect: "error", cache: "no-store",
      });
      const next = response.headers.get("x-day2-startup-version");
      if (!response.ok || !next) return;
      await response.text();
      try { localStorage.setItem(key, String(Date.now())); } catch {}
      if (next !== artifact || force) reloadOnce(next);
    } catch { /* A failed refresh must not hide an already visible shell. */ }
  })().finally(() => { pending = undefined; });
  return pending;
};

const afterPaint = async () => {
  await refresh();
  if (document.readyState === "loading") {
    await new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve, { once: true }));
  }
  // Recover when cached HTML references assets evicted after a deployment.
  // Importing an already loaded module shares its module map and executes once.
  const scripts = [...document.querySelectorAll('head script[type="module"][src]')]
    .map(script => script.src).filter(src => new URL(src).pathname !== "/assets/platform/startup.js");
  const results = await Promise.allSettled(scripts.map(src => import(src)));
  if (results.some(result => result.status === "rejected")) await refresh(true);
};

if (artifact) {
  if (document.visibilityState === "hidden") setTimeout(afterPaint, 0);
  else requestAnimationFrame(() => setTimeout(afterPaint, 0));
}
