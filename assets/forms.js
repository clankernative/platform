// Presentation validation reads admitted domain rules attached by the host.
// Server validation remains authoritative for every transport.
const encoder = new TextEncoder();
function validate(control) {
  if (!(control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement)) return;
  const maximum = control.dataset.day2MaxUtf8Bytes;
  if (!maximum) return;
  const value = control.value;
  const blank = control.dataset.day2Nonblank === "true" && /^\p{White_Space}*$/u.test(value);
  const message = blank ? "Enter nonblank text." : encoder.encode(value).length > Number(maximum)
    ? `Use at most ${maximum} UTF-8 bytes.` : "";
  control.setCustomValidity(message);
}
document.addEventListener("input", event => validate(event.target), true);
document.addEventListener("submit", event => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  form.querySelectorAll("[data-day2-max-utf8-bytes]").forEach(validate);
  if (!form.reportValidity()) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);

// Datastar owns the SSE request and retries. Surface connection failures in the
// platform status region without introducing another transport or client store.
document.addEventListener("datastar-fetch", event => {
  const detail = event.detail;
  if (detail?.el instanceof HTMLFormElement && detail.el.matches("form[data-command]") &&
      (detail.type === "error" || detail.type === "retries-failed")) {
    const status = document.getElementById("day2-command-status");
    if (status) {
      const notice = document.createElement("div");
      notice.className = "notice error";
      notice.setAttribute("role", "status");
      notice.textContent = "The request could not be confirmed. Retry using this form.";
      status.replaceChildren(notice);
    }
    return;
  }
  if (detail?.el?.id !== "day2-live") return;
  const status = document.getElementById("day2-live-status");
  if (!status) return;
  if (detail.type === "started" || detail.type === "retrying") {
    status.textContent = detail.type === "started" ? "Connecting live updates…" : "Reconnecting live updates…";
  } else if (detail.type === "error" || detail.type === "retries-failed") {
    const link = document.createElement("a");
    link.href = window.location.href;
    link.textContent = "Reload to reconnect.";
    status.replaceChildren(document.createTextNode("Live updates are unavailable. "), link);
  }
});
