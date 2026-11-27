(() => {
    "use strict";
    const operation = document.currentScript.dataset.operation;
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
    function call(name) {
        if (name !== operation || arguments.length !== 1) {
            return Promise.reject(new Error("Unknown prototype operation or inputs."));
        }
        if (parent === window) return Promise.reject(new Error("Open the prototype viewer."));
        if (pending) return Promise.reject(new Error("A read is already in progress."));
        return new Promise((resolve, reject) => {
            const id = ++sequence;
            const timer = setTimeout(() => {
                pending = undefined;
                reject(new Error("Read timed out."));
            }, 25000);
            pending = { id, timer, resolve, reject };
            channel.port1.postMessage({ id, operation });
        });
    }
    Object.defineProperty(window, "day2", { value: Object.freeze({ call }) });
    if (parent !== window) parent.postMessage("day2.prototype.connect.v1", "*", [channel.port2]);
})();
