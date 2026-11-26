(() => {
    "use strict";
    const { frame: frameUrl, query: queryUrl, operation } = document.currentScript.dataset;
    const frame = document.querySelector("iframe");
    const status = document.getElementById("load-status");
    const request = {
        method: "GET", mode: "same-origin", credentials: "same-origin",
        redirect: "error", cache: "no-store", referrerPolicy: "no-referrer"
    };
    const inexactNumber = new Error("This browser cannot read the numeric result exactly.");
    const saveDenied = new Error("You don’t have permission to save.");
    let connected = false;

    function exactJson(text) {
        return JSON.parse(text, (_key, value, context) => {
            if (typeof value !== "number" || Number.isSafeInteger(value)) return value;
            if (Number.isFinite(value) && !Number.isInteger(value)) return value;
            // The native integer codec writes decimal digits. Use the original
            // JSON token because the numeric reviver argument is already rounded.
            if (!/^-?\d+$/.test(context?.source ?? "")) throw inexactNumber;
            return BigInt(context.source);
        });
    }

    // A WindowProxy outlives its document. Only the first opaque document
    // gets a channel, and replies travel exclusively on its original port.
    window.addEventListener("message", function connect(event) {
        if (connected || event.source !== frame.contentWindow || event.origin !== "null" ||
            event.data !== "day2.prototype.connect.v1" || event.ports.length !== 1) return;
        connected = true;
        window.removeEventListener("message", connect);
        status.hidden = true;
        const port = event.ports[0];
        let active = false;
        port.onmessage = async ({ data }) => {
            if (!data || !Number.isSafeInteger(data.id) || data.id < 1) return;
            const id = data.id;
            if (Object.keys(data).length !== 2 || data.operation !== operation) {
                port.postMessage({ id, error: "Unknown prototype operation or inputs." });
                return;
            }
            if (active) {
                port.postMessage({ id, error: "A read is already in progress." });
                return;
            }
            active = true;
            try {
                const response = await fetch(queryUrl, {
                    ...request, signal: AbortSignal.timeout(20000),
                    headers: { Accept: "application/json", "X-Day2-Prototype-Query": "1" }
                });
                if (response.status !== 200) {
                    const denied = [401, 403].includes(response.status);
                    port.postMessage({ id, error: denied ? "Access denied." : "Read unavailable." });
                    return;
                }
                port.postMessage({ id, result: exactJson(await response.text()) });
            } catch (error) {
                port.postMessage({ id, error: error === inexactNumber ? error.message : "Read unavailable." });
            } finally {
                active = false;
            }
        };
    });

    // frame-src 'none' in the parent permits srcdoc but blocks a network
    // navigation of this frame, including a location change made by its JS.
    async function loadFrame() {
        try {
            const response = await fetch(frameUrl, {
                ...request, signal: AbortSignal.timeout(20000), headers: { Accept: "text/html" }
            });
            if (!response.ok || !response.headers.get("Content-Type")?.startsWith("text/html")) {
                throw new Error();
            }
            frame.srcdoc = await response.text();
        } catch {
            status.textContent = "This prototype could not be loaded.";
        }
    }
    function checkSaveAccess(response) {
        if ([401, 403].includes(response.status)) throw saveDenied;
        if (!response.ok) throw new Error();
    }

    // The platform supplies an opaque invocation ID. Construct the only status
    // route we allow and require both the receipt and HTTP Location to agree.
    async function pendingInvocation(response) {
        const accepted = await response.json();
        if (accepted.status !== "pending" || typeof accepted.invocation_id !== "string" ||
            !/^[A-Za-z0-9_-]{1,128}$/.test(accepted.invocation_id)) throw new Error();
        const path = "/api/invocations/" + accepted.invocation_id;
        if (response.headers.get("Location") !== path || accepted.status_url !== path) throw new Error();
        return accepted.invocation_id;
    }

    async function pollSave(invocation, operation) {
        const deadline = AbortSignal.timeout(10000);
        try {
            for (let poll = 0; poll < 8; poll++) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                const response = await fetch("/api/invocations/" + invocation, {
                    ...request, headers: { Accept: "application/json" }, signal: deadline
                });
                checkSaveAccess(response);
                const receipt = exactJson(await response.text());
                if (receipt.invocation_id !== invocation || receipt.operation !== operation) throw new Error();
                if (receipt.status === "pending") continue;
                const id = receipt.result?.id;
                if (receipt.status !== "success" || !(typeof id === "bigint" || Number.isSafeInteger(id))) throw new Error();
                return String(id);
            }
        } catch (error) {
            if (!deadline.aborted) throw error;
        }
        return null;
    }

    const editor = document.getElementById("editor");
    if (editor) {
        const input = editor.querySelector("textarea");
        const save = document.getElementById("save");
        const feedback = document.getElementById("save-status");
        let attempt;
        save.addEventListener("click", async () => {
            if (save.disabled) return;
            const html = input.value;
            if (!attempt || attempt.html !== html) attempt = { html, key: crypto.randomUUID() };
            save.disabled = true;
            input.readOnly = true;
            feedback.textContent = "Saving…";
            try {
                const command = editor.dataset.saveCommand;
                let revision;
                if (!attempt.invocation) {
                    const session = await fetch("/api/session", {
                        ...request, headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15000)
                    });
                    checkSaveAccess(session);
                    const { csrf_token: csrfToken } = await session.json();
                    if (typeof csrfToken !== "string" || !csrfToken) throw new Error();
                    const response = await fetch("/api/" + encodeURIComponent(command), {
                        ...request, method: "POST", referrerPolicy: "same-origin",
                        signal: AbortSignal.timeout(20000),
                        headers: { Accept: "application/json", "Content-Type": "application/json",
                            "X-CSRF-Token": csrfToken, "Idempotency-Key": attempt.key },
                        body: JSON.stringify({ html })
                    });
                    checkSaveAccess(response);
                    if (response.status === 202) {
                        attempt.invocation = await pendingInvocation(response);
                    } else {
                        // This fixed one-field receipt is exact even in older browsers.
                        revision = /^\s*\{\s*"id"\s*:\s*([1-9][0-9]{0,19})\s*\}\s*$/.exec(await response.text())?.[1];
                    }
                }
                if (attempt.invocation) {
                    feedback.textContent = "Save accepted. Waiting for the revision…";
                    revision = await pollSave(attempt.invocation, command);
                    if (revision === null) {
                        feedback.textContent = "Still saving. Choose Save & preview to check again.";
                        return;
                    }
                }
                if (!/^[1-9][0-9]{0,19}$/.test(revision ?? "") || BigInt(revision) > 18446744073709551615n) throw new Error();
                location.assign("/_prototype/revisions/" + revision);
            } catch (error) {
                feedback.textContent = [saveDenied, inexactNumber].includes(error)
                    ? error.message : "Save failed. Your edits are still here.";
            } finally {
                input.readOnly = false;
                save.disabled = false;
            }
        });
    }
    void loadFrame();
})();
