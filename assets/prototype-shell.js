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
    const review = document.getElementById("submit-review");
    const attempts = new Map();

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
            if (Object.hasOwn(data, "submit")) {
                if (active || !review || !navigator.userActivation?.isActive ||
                    Object.keys(data).length !== 3 || !Object.hasOwn(data, "input") ||
                    data.submit !== review.dataset.operation.split(".")[1]) {
                    port.postMessage({ id, error: "Submission requires the declared operation and a user action." });
                    return;
                }
                active = true;
                try {
                    const body = submissionBody(data.input, JSON.parse(review.dataset.fields));
                    if (!await confirmSubmission(body)) throw new SubmissionError("Submission canceled.");
                    port.postMessage({ id, result: await submitApproved(body) });
                } catch (error) {
                    const message = (error instanceof SubmissionError || error === inexactNumber)
                        ? error.message : "Submission unavailable. Retry the same values to check its receipt.";
                    port.postMessage({ id, error: message });
                } finally {
                    active = false;
                }
                return;
            }
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

    class SubmissionError extends Error {}

    // The same immutable JSON string is shown to the human and posted. Escape
    // invisible direction/format controls as JSON, so they cannot reorder the
    // operation's trusted summary or disguise the next field.
    function submissionBody(input, fields) {
        const invalid = new SubmissionError("Submission fields do not match the operation.");
        if (!input || Object.getPrototypeOf(input) !== Object.prototype ||
            Object.keys(input).length !== Object.keys(fields).length) throw invalid;
        const quote = text => JSON.stringify(text).replace(/[\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g,
            ch => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
        const lines = Object.keys(fields).map(key => {
            if (!Object.hasOwn(input, key)) throw invalid;
            const value = input[key];
            let literal;
            if (fields[key] === "string" && typeof value === "string") literal = quote(value);
            else if (fields[key] === "boolean" && typeof value === "boolean") literal = String(value);
            else if (fields[key] === "integer" && (Number.isSafeInteger(value) || typeof value === "bigint")) literal = String(value);
            else throw invalid;
            return "  " + quote(key) + ": " + literal;
        });
        const body = "{\n" + lines.join(",\n") + "\n}";
        if (new TextEncoder().encode(body).length > 65536) throw new SubmissionError("Submission is too large.");
        return body;
    }

    function confirmSubmission(body) {
        const confirm = document.getElementById("confirm-submit");
        const cancel = document.getElementById("cancel-submit");
        document.getElementById("submit-input").textContent = body;
        review.returnValue = "";
        const accepted = new Promise(resolve => {
            const controller = new AbortController();
            const options = { signal: controller.signal };
            confirm.addEventListener("click", event => { if (event.isTrusted) review.close("confirm"); }, options);
            cancel.addEventListener("click", event => { if (event.isTrusted) review.close(); }, options);
            frame.addEventListener("load", () => review.close(), options);
            review.addEventListener("close", () => {
                controller.abort();
                document.getElementById("submit-input").textContent = "";
                resolve(review.returnValue === "confirm");
            }, { once: true });
        });
        review.showModal();
        cancel.focus();
        return accepted;
    }

    async function submitApproved(body) {
        let key = attempts.get(body);
        if (!key) {
            if (attempts.size >= 8) throw new SubmissionError("Check an earlier pending submission first.");
            key = crypto.randomUUID();
        }
        const session = await fetch("/api/session", {
            ...request, signal: AbortSignal.timeout(15000), headers: { Accept: "application/json" }
        });
        if (!session.ok) throw new SubmissionError("Sign in to submit.");
        const csrf = (await session.json()).csrf_token;
        if (typeof csrf !== "string" || !csrf) throw new Error();
        attempts.set(body, key);
        const options = { ...request, method: "POST", referrerPolicy: "same-origin", body,
            headers: { Accept: "application/json", "Content-Type": "application/json",
                "X-CSRF-Token": csrf, "Idempotency-Key": key, "X-Day2-Prototype-Submit": "1" } };
        // Recover a pending result through the same revision-granted operation
        // and the same business receipt. No status URL or credential reaches the frame.
        for (let i = 0; i < 3; i++) {
            if (i) await new Promise(resolve => setTimeout(resolve, 1000));
            const response = await fetch(review.dataset.url, { ...options, signal: AbortSignal.timeout(15000) });
            if (response.status === 202) { await pendingInvocation(response); continue; }
            if (response.status === 200) {
                const result = exactJson(await response.text());
                attempts.delete(body);
                return result;
            }
            if (response.status === 400 || response.status === 422) {
                attempts.delete(body);
                const { error } = await response.json();
                const message = typeof error?.message === "string" && error.message.length <= 2048
                    ? error.message : "Day2 rejected the submitted values.";
                throw new SubmissionError(message);
            }
            if ([401, 403, 404, 409].includes(response.status)) {
                // An invocation may already have committed before revocation. Keep
                // its key for an identical retry; distinct inputs get distinct keys.
                throw new SubmissionError([401, 403].includes(response.status)
                    ? "You don’t have permission to submit." : "Day2 rejected this submission.");
            }
            throw new Error();
        }
        throw new SubmissionError("Submission accepted. Retry the same values to check its receipt.");
    }

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
