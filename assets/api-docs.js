// Platform-owned presentation. Requests always use the fixed, same-origin API.
"use strict";
async function copyText(button, value) {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Select text to copy";
  }
  setTimeout(() => { button.textContent = label; }, 1600);
}
document.querySelectorAll(".copy-link").forEach((button) => {
  button.addEventListener("click", () => copyText(button, `${location.origin}${location.pathname}#${button.dataset.anchor}`));
});
document.querySelectorAll(".code-panel").forEach((panel) => {
  const tabs = [...panel.querySelectorAll(".code-tab")];
  function select(index, focus = false) {
    tabs.forEach((tab, i) => {
      tab.setAttribute("aria-selected", String(i === index));
      tab.tabIndex = i === index ? 0 : -1;
      if (i === index && focus) tab.focus();
    });
    panel.querySelectorAll(".code-sample").forEach((sample, i) => { sample.hidden = i !== index; });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => select(index));
    tab.addEventListener("keydown", (event) => {
      let next = index;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else return;
      event.preventDefault();
      select(next, true);
    });
  });
  const copy = panel.querySelector(".copy-code");
  copy.addEventListener("click", () => copyText(copy, panel.querySelector(".code-sample:not([hidden]) code").textContent));
});
document.querySelectorAll(".response-panel").forEach((panel) => {
  panel.querySelector(".response-select").addEventListener("change", (event) => {
    panel.querySelectorAll(".response-sample").forEach((sample) => { sample.hidden = sample.dataset.status !== event.target.value; });
  });
  const copy = panel.querySelector(".copy-code");
  copy.addEventListener("click", () => copyText(copy, panel.querySelector(".response-sample:not([hidden]) code").textContent));
});
// Token coloring uses text nodes only, including all app-authored example values.
document.querySelectorAll("code.json-example").forEach((code) => {
  const text = code.textContent;
  const tokens = /"(?:[^"\\]|\\.)*"(?=\s*:)|"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g;
  const fragment = document.createDocumentFragment();
  let end = 0;
  for (const match of text.matchAll(tokens)) {
    fragment.append(document.createTextNode(text.slice(end, match.index)));
    const span = document.createElement("span");
    span.className = match[0].startsWith('"') ? (/^\s*:/.test(text.slice(match.index + match[0].length)) ? "json-key" : "json-string") : "json-literal";
    span.textContent = match[0];
    fragment.append(span);
    end = match.index + match[0].length;
  }
  fragment.append(document.createTextNode(text.slice(end)));
  code.replaceChildren(fragment);
});
const search = document.querySelector("#search");
// Each operation owns one search index. Its article and sidebar link share the
// same match result, so prose elsewhere in the docs cannot leave one behind.
const operationLinks = new Map([...document.querySelectorAll(".operation-link")].map((link) => [link.getAttribute("href").slice(1), link]));
const operations = [...document.querySelectorAll("article.operation")].map((article) => ({
  article,
  link: operationLinks.get(article.id),
  text: article.dataset.search.toLowerCase(),
}));
const operationGroups = [...document.querySelectorAll(".operation-group")];
function filterOperations() {
  const term = search.value.trim().toLowerCase();
  let matches = 0;
  operations.forEach(({ article, link, text }) => {
    const visible = text.includes(term);
    article.hidden = link.hidden = !visible;
    if (visible) matches += 1;
  });
  operationGroups.forEach((group) => {
    group.hidden = !group.querySelector(".operation-link:not([hidden])");
  });
  document.querySelector("#overview").hidden = term !== "";
  document.querySelector('a[href="#overview"]').hidden = term !== "";
  document.querySelector("#empty").hidden = matches !== 0;
}
search.addEventListener("input", filterOperations);
window.addEventListener("pageshow", filterOperations);
filterOperations();
document.querySelectorAll("form.console").forEach((form) => {
  if (document.body.dataset.preview === "true") {
    form.querySelectorAll("input, textarea, button").forEach((control) => { control.disabled = true; });
    return;
  }
  const key = form.elements.namedItem("idempotency");
  const resetKey = () => { if (key) key.value = crypto.randomUUID(); };
  resetKey();
  form.querySelector(".send").disabled = false;
  form.querySelector(".new-key")?.addEventListener("click", resetKey);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector(".send");
    const result = form.querySelector(".result");
    const status = form.querySelector(".result-status");
    const output = result.querySelector("code");
    button.disabled = true;
    result.hidden = false;
    status.textContent = "Sending…";
    output.textContent = "";
    const started = performance.now();
    try {
      const url = new URL(form.dataset.path, location.origin);
      const options = { method: form.dataset.method, credentials: "same-origin", headers: { Accept: "application/json" } };
      if (options.method === "GET") {
        for (const [name, value] of new FormData(form)) {
          const input = form.elements.namedItem(name);
          if (input?.dataset.location === 'path') {
            url.pathname = url.pathname.replace(encodeURIComponent(`{${name}}`), encodeURIComponent(value)).replace(`{${name}}`, encodeURIComponent(value));
          } else {
            url.searchParams.set(name, value);
          }
        }
      } else {
        // Forward the original text: parsing and reserializing here loses int64 precision.
        options.body = form.elements.namedItem("body").value;
        JSON.parse(options.body); // Syntax check only.
        if (!/^[A-Za-z0-9_-]{1,128}$/.test(key.value)) throw new Error("Use an idempotency key containing 1–128 letters, numbers, underscores or hyphens.");
        const sessionResponse = await fetch("/api/session", { credentials: "same-origin", headers: { Accept: "application/json" } });
        if (!sessionResponse.ok) throw new Error(`Session unavailable (HTTP ${sessionResponse.status}). Sign in again before retrying.`);
        const session = await sessionResponse.json();
        options.headers["Content-Type"] = "application/json";
        options.headers["X-CSRF-Token"] = session.csrf_token;
        options.headers["Idempotency-Key"] = key.value;
      }
      const response = await fetch(url, options);
      const text = await response.text();
      status.textContent = `HTTP ${response.status} · ${Math.round(performance.now() - started)} ms`;
      status.dataset.ok = String(response.ok);
      output.textContent = text || "(empty response)";
    } catch (error) {
      status.textContent = "Request could not be completed";
      status.dataset.ok = "false";
      output.textContent = `${error.message}${key ? "\nKeep this key and the same input when retrying an uncertain response." : ""}`;
    } finally {
      button.disabled = false;
    }
  });
});
