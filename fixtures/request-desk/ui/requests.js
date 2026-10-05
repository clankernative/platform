const form = document.getElementById("stock-request");
const output = document.getElementById("request-result");
const pause = () => new Promise((resolve) => setTimeout(resolve, 1000));
let accepted = JSON.parse(sessionStorage.getItem("stock-request") ?? "null");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  event.stopImmediatePropagation();
  const button = form.querySelector("button");
  button.disabled = true;
  output.textContent = "Submitting…";
  try {
    accepted ??= { key: crypto.randomUUID(), quantity: Number(form.elements.quantity.value) };
    sessionStorage.setItem("stock-request", JSON.stringify(accepted));
    const session = await fetch("/api/session").then((response) => response.json());
    const response = await fetch("/api/request_desk.request", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrf_token, "Idempotency-Key": accepted.key },
      body: JSON.stringify({ quantity: accepted.quantity }),
    });
    if (!response.ok) throw new Error("This request could not be confirmed. Retry to check the same request.");
    let command = await response.json();
    const statusUrl = command.status_url;
    const deadline = Date.now() + 60000;
    while (command.status === "pending" && Date.now() < deadline) {
      output.textContent = "Accepted. Waiting for a receipt…";
      await pause();
      command = await fetch(statusUrl).then((result) => result.json());
    }
    const receipt = command.result?.receipt ?? command.receipt;
    if (!receipt) throw new Error("This request is still unresolved. Retry to check the same request.");
    output.textContent = `Receipt ${receipt}. Waiting for the reservation…`;
    let progress = { status: "pending" };
    while (progress.status === "pending" && Date.now() < deadline) {
      await pause();
      progress = await fetch(`/api/request_desk.progress?receipt=${encodeURIComponent(receipt)}`).then((result) => result.json());
    }
    output.textContent = `Reservation ${progress.status}. Receipt ${receipt}.`;
    if (progress.status === "success" || progress.status === "refused") {
      accepted = null;
      sessionStorage.removeItem("stock-request");
    }
  } catch (error) {
    output.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = accepted ? "Check request" : "Request stock";
  }
}, true);
