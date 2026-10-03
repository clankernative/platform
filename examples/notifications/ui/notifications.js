const form = document.getElementById("notification-editor");
const output = document.getElementById("configuration-result");
const preview = document.getElementById("notification-preview");
const fields = [{ name: "summary", kind: "text", max_length: 1000, choices: [] }];
const scope = () => ({ app_id: form.elements.app_id.value, event_key: form.elements.event_key.value });
const pause = () => new Promise((resolve) => setTimeout(resolve, 1000));
let loaded = null;
let pending = JSON.parse(sessionStorage.getItem("notification-save") ?? "null");

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

document.getElementById("load-configuration").addEventListener("click", () => run(async () => {
  const current = await query("get", { ...scope(), version: 0 });
  const schema = current.fields.items;
  const summarySchema = schema.length === 1 && schema[0].name === "summary" && schema[0].kind === "text" && schema[0].max_length === 1000 && schema[0].choices.items.length === 0;
  if (current.found && !summarySchema) {
    loaded = null;
    throw new Error("This version uses a different field schema. Use its configuration API to edit it.");
  }
  loaded = { ...scope(), revision: current.revision, version: current.version };
  if (current.found) {
    form.elements.description.value = current.description;
    form.elements.template.value = current.template;
  }
  output.textContent = current.found ? `Loaded revision ${current.revision}, version ${current.version}. Delivery is disabled.` : "No configuration yet. Ready to create version 1.";
}));

document.getElementById("preview-notification").addEventListener("click", () => run(async () => {
  preview.textContent = "";
  const input = {
    app_id: scope().app_id, fields, template: form.elements.template.value,
    payload: [{ name: "summary", kind: "text", text: form.elements.summary.value, integer: 0, boolean: false }],
  };
  const session = await fetch("/api/session").then((response) => response.json());
  const response = await fetch("/api/notifications.preview", {
    method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrf_token, "Idempotency-Key": crypto.randomUUID() },
    body: JSON.stringify(input),
  });
  if (!response.ok) throw new Error("Preview could not be authorized or completed. Ownership may have changed.");
  let command = await response.json();
  if (response.status === 200) command = { status: "success", result: command };
  const deadline = Date.now() + 60000;
  while (command.status === "pending" && Date.now() < deadline) {
    await pause();
    const status = await fetch(command.status_url);
    if (!status.ok) throw new Error("Preview could not be completed. Try again.");
    command = await status.json();
  }
  if (command.status !== "success" || !command.result) throw new Error("Preview could not be completed. Try again.");
  const result = command.result;
  preview.textContent = result.message;
  output.textContent = result.valid ? "Preview ready. Nothing was sent." : result.findings.items.map((finding) => `${finding.field}: ${finding.code}`).join("; ");
}));

document.getElementById("save-configuration").addEventListener("click", (event) => {
  event.preventDefault();
  run(async () => {
    if (!pending) {
      if (!loaded || loaded.app_id !== scope().app_id || loaded.event_key !== scope().event_key) throw new Error("Load this event's current configuration before saving.");
      pending = { key: crypto.randomUUID(), input: { ...scope(), description: form.elements.description.value, expected_revision: loaded.revision, version: loaded.version, fields, template: form.elements.template.value } };
      sessionStorage.setItem("notification-save", JSON.stringify(pending));
    }
    output.textContent = "Checking the saved request…";
    const session = await fetch("/api/session").then((response) => response.json());
    const response = await fetch("/api/notifications.save", {
      method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrf_token, "Idempotency-Key": pending.key },
      body: JSON.stringify(pending.input),
    });
    if (response.status === 422) {
      const refusal = await response.json();
      pending = null;
      loaded = null;
      sessionStorage.removeItem("notification-save");
      throw new Error(refusal.error?.message ?? "Save refused. Load the current configuration and review the edit.");
    }
    if (!response.ok) throw new Error("The save is unresolved. Retry to check the same request.");
    let command = await response.json();
    if (response.status === 200) command = { status: "success", result: command };
    const deadline = Date.now() + 60000;
    while (command.status === "pending" && Date.now() < deadline) {
      await pause();
      const status = await fetch(command.status_url);
      if (!status.ok) throw new Error("The save is unresolved. Retry to check the same request.");
      command = await status.json();
    }
    if (command.status === "pending") throw new Error("The save is unresolved. Retry to check the same request.");
    const submitted = pending.input;
    pending = null;
    sessionStorage.removeItem("notification-save");
    if (command.status !== "success" || !command.result) {
      loaded = null;
      throw new Error("Save refused. Load the current configuration and review ownership and changes.");
    }
    loaded = { app_id: submitted.app_id, event_key: submitted.event_key, revision: command.result.revision, version: command.result.version };
    output.textContent = `Saved revision ${loaded.revision}, version ${loaded.version}. Delivery is disabled.`;
  });
});
