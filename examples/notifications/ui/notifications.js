const form = document.getElementById("notification-editor");
const output = document.getElementById("configuration-result");
const preview = document.getElementById("notification-preview");
const fields = [{ name: "summary", kind: "text", max_length: 1000, choices: [] }];
const scope = () => ({ app_id: form.elements.app_id.value, event_key: form.elements.event_key.value });
const payload = () => [{ name: "summary", kind: "text", text: form.elements.summary.value, integer: 0, boolean: false }];
const pause = () => new Promise((resolve) => setTimeout(resolve, 1000));
let loaded = null;

async function query(operation, input) {
  const parameters = new URLSearchParams(Object.entries(input).map(([name, value]) => [name, typeof value === "object" ? JSON.stringify(value) : String(value)]));
  const response = await fetch(`/api/notifications.${operation}?${parameters}`);
  if (!response.ok) throw new Error("This operation could not be authorized or completed. Ownership may have changed.");
  return response.json();
}

async function run(work) {
  const buttons = form.querySelectorAll("button");
  buttons.forEach((button) => { button.disabled = true; });
  try { await work(); } catch (error) { output.textContent = error.message; }
  finally { buttons.forEach((button) => { button.disabled = false; }); }
}

function current() {
  if (!loaded || loaded.app_id !== scope().app_id || loaded.event_key !== scope().event_key) throw new Error("Load this event's current configuration first.");
  return loaded;
}

async function poll(command) {
  const deadline = Date.now() + 60000;
  while (command.status === "pending" && Date.now() < deadline) {
    await pause();
    const response = await fetch(command.status_url);
    if (!response.ok) throw new Error("The request is unresolved. Retry the same request to check its status.");
    command = { ...await response.json(), status_url: command.status_url };
  }
  return command;
}

// Keep exact input and transport identity across response loss and reloads.
// Provider uncertainty never authorizes a new publication identity.
async function command(operation, makeInput, durable = true) {
  const storageKey = `notification-${operation}`;
  let pending = durable ? JSON.parse(sessionStorage.getItem(storageKey) ?? "null") : null;
  if (!pending) {
    pending = { key: crypto.randomUUID(), input: makeInput() };
    if (durable) sessionStorage.setItem(storageKey, JSON.stringify(pending));
  }
  if (pending.status_url) {
    const response = await fetch(pending.status_url);
    if (!response.ok) throw new Error("The original request cannot be inspected. Keep its publication ID and restore access before retrying.");
    const state = await poll({ ...await response.json(), status_url: pending.status_url });
    if (state.status !== "success" || !state.result) throw new Error(`Original request ${state.status}. Delivery is not confirmed; keep its publication ID.`);
    if (durable) sessionStorage.removeItem(storageKey);
    return { input: pending.input, result: state.result };
  }
  const sessionResponse = await fetch("/api/session");
  if (!sessionResponse.ok) throw new Error("Sign in again, then retry the same request.");
  const session = await sessionResponse.json();
  const response = await fetch(`/api/notifications.${operation}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrf_token, "Idempotency-Key": pending.key },
    body: JSON.stringify(pending.input),
  });
  const invocation = response.headers.get("x-day2-invocation");
  if (durable && invocation) {
    pending.status_url = `/api/invocations/${encodeURIComponent(invocation)}`;
    sessionStorage.setItem(storageKey, JSON.stringify(pending));
  }
  if (response.status === 422) {
    const refusal = await response.json();
    if (durable) sessionStorage.removeItem(storageKey);
    loaded = null;
    throw new Error(refusal.error?.message ?? "Request refused. Reload the current configuration and review it.");
  }
  if (!response.ok) throw new Error("The request is unresolved. Retry the same request; do not change the publication ID.");
  let state = await response.json();
  state = response.status === 200 ? { status: "success", result: state } : await poll(state);
  if (state.status !== "success" || !state.result) {
    throw new Error(`Request ${state.status}. Keep the original publication ID and inspect its status; do not resend as a new event.`);
  }
  if (durable) sessionStorage.removeItem(storageKey);
  return { input: pending.input, result: state.result };
}

function deliveryText(enabled) { return `Delivery is ${enabled ? "enabled" : "disabled"}.`; }

document.getElementById("load-configuration").addEventListener("click", () => run(async () => {
  const configuration = await query("get", { ...scope(), version: 0 });
  const schema = configuration.fields.items;
  const summarySchema = schema.length === 1 && schema[0].name === "summary" && schema[0].kind === "text" && schema[0].max_length === 1000 && schema[0].choices.items.length === 0;
  if (configuration.found && !summarySchema) {
    loaded = null;
    throw new Error("This version uses a different field schema. Use its configuration API to edit it.");
  }
  loaded = { ...scope(), revision: configuration.revision, version: configuration.version, enabled: configuration.enabled };
  if (configuration.found) {
    form.elements.description.value = configuration.description;
    form.elements.template.value = configuration.template;
  }
  output.textContent = configuration.found ? `Loaded revision ${configuration.revision}, version ${configuration.version}. ${deliveryText(configuration.enabled)}` : "No configuration yet. Ready to create version 1.";
}));

document.getElementById("preview-notification").addEventListener("click", () => run(async () => {
  preview.textContent = "";
  const { result } = await command("preview", () => ({ app_id: scope().app_id, fields, template: form.elements.template.value, payload: payload() }), false);
  preview.textContent = result.message;
  output.textContent = result.valid ? "Preview ready. Nothing was sent." : result.findings.items.map((finding) => `${finding.field}: ${finding.code}`).join("; ");
}));

document.getElementById("save-configuration").addEventListener("click", () => run(async () => {
  const { input, result } = await command("save", () => {
    const state = current();
    return { ...scope(), description: form.elements.description.value, expected_revision: state.revision, version: state.version, fields, template: form.elements.template.value };
  });
  const refreshed = await query("get", { app_id: input.app_id, event_key: input.event_key, version: result.version });
  loaded = { app_id: input.app_id, event_key: input.event_key, revision: refreshed.revision, version: refreshed.version, enabled: refreshed.enabled };
  output.textContent = `Saved revision ${result.revision}, version ${result.version}. ${deliveryText(refreshed.enabled)}`;
}));

async function setEnabled(enabled) {
  const { input, result } = await command("set_enabled", () => ({ ...scope(), expected_revision: current().revision, enabled }));
  const refreshed = await query("get", { app_id: input.app_id, event_key: input.event_key, version: 0 });
  loaded = { app_id: input.app_id, event_key: input.event_key, revision: refreshed.revision, version: refreshed.version, enabled: refreshed.enabled };
  output.textContent = `Saved revision ${result.revision}. ${deliveryText(result.enabled)}`;
}
document.getElementById("enable-delivery").addEventListener("click", () => run(() => setEnabled(true)));
document.getElementById("disable-delivery").addEventListener("click", () => run(() => setEnabled(false)));

async function describePublication(receipt) {
  if (receipt.slack_accepted) {
    output.textContent = `Slack accepted publication ${receipt.notification_id}${receipt.duplicate ? " (existing publication; nothing resent)" : ""}.`;
    return;
  }
  const response = await fetch(receipt.status_url);
  if (!response.ok) throw new Error("Publication is retained without confirmed delivery. Its original actor can inspect command status; do not resend under a new ID.");
  const state = await poll({ ...await response.json(), status_url: receipt.status_url });
  if (state.status === "success" && state.result?.slack_accepted) {
    output.textContent = `Slack accepted publication ${receipt.notification_id}.`;
  } else {
    output.textContent = `Publication retained; original request ${state.status}. Delivery is not confirmed. Keep its publication ID; do not resend as a new event.`;
  }
}

document.getElementById("publish-notification").addEventListener("click", () => run(async () => {
  const { result } = await command("publish", () => {
    const state = current();
    if (!state.enabled || state.version === 0) throw new Error("Save and enable this event before publishing.");
    if (!form.elements.publication_id.value.trim()) throw new Error("Enter a stable publication ID for this event.");
    return { ...scope(), version: state.version, publication_id: form.elements.publication_id.value, payload: payload() };
  });
  await describePublication(result);
}));

document.getElementById("check-publication").addEventListener("click", () => run(async () => {
  await describePublication(await query("publication", { app_id: scope().app_id, publication_id: form.elements.publication_id.value }));
}));
