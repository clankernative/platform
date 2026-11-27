(() => {
    "use strict";
    const { operation, submit: submitName } = document.currentScript.dataset;
    const channel = new MessageChannel();
    let sequence = 0;
    let pending;
    channel.port1.onmessage = ({ data }) => {
        if (!pending || pending.id !== data?.id) return;
        const { resolve, reject, timer } = pending;
        pending = undefined;
        clearTimeout(timer);
        if (typeof data.error === "string") reject(new Error(data.error));
        else resolve(data.result);
    };
    function request(message, read) {
        if (parent === window) return Promise.reject(new Error("Open the prototype viewer."));
        if (pending) return Promise.reject(new Error("An operation is already in progress."));
        return new Promise((resolve, reject) => {
            const id = ++sequence;
            // A human may keep the trusted submission dialog open while reviewing.
            const timer = read && setTimeout(() => {
                pending = undefined;
                reject(new Error("Read timed out."));
            }, 25000);
            try {
                channel.port1.postMessage({ id, ...message });
                pending = { id, timer, resolve, reject };
            } catch (error) {
                clearTimeout(timer);
                reject(error);
            }
        });
    }
    function call(name) {
        if (name !== operation || arguments.length !== 1) {
            return Promise.reject(new Error("Unknown prototype operation or inputs."));
        }
        return request({ operation }, true);
    }
    function submit(name, input) {
        if (arguments.length !== 2 || name !== submitName) {
            return Promise.reject(new Error("Unknown prototype submission."));
        }
        if (!navigator.userActivation?.isActive) {
            return Promise.reject(new Error("Start the submission from a user action."));
        }
        return request({ submit: name, input }, false);
    }
    Object.defineProperty(window, "day2", { value: Object.freeze(submitName ? { call, submit } : { call }) });
    if (parent !== window) parent.postMessage("day2.prototype.connect.v1", "*", [channel.port2]);
})();
