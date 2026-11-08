import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../../../assets/startup.js", import.meta.url), "utf8");
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
let sequence = 0;
async function harness(t, { next = "artifact-1", scripts = [], stored, fail = false } = {}) {
  const originals = new Map();
  const local = stored || new Map(), session = new Map(), requests = [], reloads = [];
  let painted;
  const storage = map => ({ getItem: key => map.get(key) ?? null, setItem: (key, value) => map.set(key, value) });
  for (const [key, value] of Object.entries({
    document: { visibilityState: "visible", querySelector: () => ({ content: "artifact-1" }), querySelectorAll: () => scripts },
    location: { pathname: "/", href: "https://shell.example.test/", reload: () => reloads.push(next) },
    localStorage: storage(local), sessionStorage: storage(session),
    requestAnimationFrame: callback => { painted = callback; },
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (fail) throw new TypeError("offline");
      return { ok: true, headers: new Headers({ "x-day2-startup-version": next }), text: async () => "anonymous HTML" };
    },
  })) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  t.after(() => { for (const [key, descriptor] of originals) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; } });
  await import(`data:text/javascript;base64,${Buffer.from(`${source}\n// test ${++sequence}`).toString("base64")}`);
  return { requests, reloads, local, paint: async () => { painted(); await tick(); await tick(); await tick(); } };
}

test("background refresh starts after paint and does not lock the HTTP cache", async t => {
  const h = await harness(t);
  assert.equal(h.requests.length, 0);
  await h.paint();
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].options.cache, "no-store");
  assert.equal(h.requests[0].options.credentials, "same-origin");
  assert.equal(h.requests[0].options.redirect, "error");
  assert.equal(h.reloads.length, 0);
  assert(h.local.has("day2.startup.refresh:/"));
});
test("a changed document triggers a reload after the background check completes", async t => {
  const h = await harness(t, { next: "artifact-2" });
  await h.paint(); assert.deepEqual(h.reloads, ["artifact-2"]);
});
test("tabs share a successful refresh timestamp", async t => {
  const h = await harness(t, { stored: new Map([["day2.startup.refresh:/", String(Date.now())]]) });
  await h.paint(); assert.equal(h.requests.length, 0);
});
test("an outage keeps the visible shell without recording a successful refresh", async t => {
  const h = await harness(t, { fail: true });
  await h.paint(); assert.equal(h.reloads.length, 0); assert.equal(h.local.size, 0);
});
test("missing old modules trigger one guarded recovery even when the artifact is unchanged", async t => {
  const h = await harness(t, { scripts: [{ src: "data:text/javascript,throw new Error('evicted module')" }] });
  await h.paint(); assert.equal(h.requests.length, 2); assert.deepEqual(h.reloads, ["artifact-1"]);
  await h.paint(); assert.deepEqual(h.reloads, ["artifact-1"]);
});
