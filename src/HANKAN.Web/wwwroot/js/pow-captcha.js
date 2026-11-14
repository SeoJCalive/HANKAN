"use strict";

document.querySelectorAll("[data-pow-captcha]").forEach(widget => {
    const form = widget.closest("form");
    const start = widget.querySelector("[data-pow-start]");
    const status = widget.querySelector("[role=status]");
    const challenge = widget.querySelector("[name=Challenge]");
    const solution = widget.querySelector("[name=Solution]");
    let worker;
    let timer;
    let running = false;

    function stop() {
        if (worker) worker.terminate();
        clearTimeout(timer);
        worker = null;
        running = false;
        start.disabled = false;
    }

    function fail() {
        stop();
        solution.value = "";
        status.textContent = "추가 확인을 완료하지 못했습니다. JavaScript와 Web Crypto를 사용할 수 있는 브라우저에서 새로고침 후 다시 시도하세요.";
    }

    form.addEventListener("submit", event => {
        if (!solution.value) {
            event.preventDefault();
            status.textContent = running ? "추가 확인을 계산하고 있습니다." : "추가 확인 버튼을 먼저 누르세요.";
            if (!running) start.focus();
        }
    });

    start.addEventListener("click", () => {
        if (running || !form.reportValidity()) return;
        if (!window.Worker || !window.crypto?.subtle) {
            fail();
            return;
        }
        running = true;
        start.disabled = true;
        solution.value = "";
        status.textContent = "추가 확인을 계산하고 있습니다.";
        timer = setTimeout(fail, 15000);
        try {
            worker = new Worker("/js/pow-captcha-worker.js");
            worker.onerror = fail;
            worker.onmessage = event => {
                if (event.data.error) {
                    fail();
                } else if (typeof event.data.solution === "string") {
                    solution.value = event.data.solution;
                    stop();
                    status.textContent = "추가 확인을 완료했습니다. 제출합니다.";
                    form.requestSubmit();
                } else {
                    status.textContent = "추가 확인을 계산하고 있습니다.";
                }
            };
            worker.postMessage(challenge.value);
        } catch {
            fail();
        }
    });
    window.addEventListener("pagehide", stop);
});
