"use strict";

self.onmessage = async event => {
    const challenge = event.data;
    if (typeof challenge !== "string" || challenge.length > 512 || !self.crypto?.subtle) {
        self.postMessage({ error: true });
        return;
    }
    const encoder = new TextEncoder();
    const deadline = performance.now() + 15000;
    try {
        for (let n = 0; n <= 4294967295; n++) {
            if (performance.now() >= deadline) break;
            const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(challenge + ":" + n)));
            if (hash[0] === 0 && hash[1] === 0) {
                self.postMessage({ solution: String(n) });
                return;
            }
            if (n % 4096 === 0) self.postMessage({ progress: true });
        }
    } catch {
        self.postMessage({ error: true });
        return;
    }
    self.postMessage({ error: true });
};
