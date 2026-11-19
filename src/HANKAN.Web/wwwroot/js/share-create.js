"use strict";

const shareDialog = document.getElementById("share-dialog");
const shareForm = shareDialog.querySelector("form");
const localExpiry = shareForm.querySelector("[type=datetime-local]");
let shareTrigger;

for (const button of document.querySelectorAll("[data-create-share]")) {
    button.addEventListener("click", () => {
        const row = button.closest(".storage-row");
        shareTrigger = button.closest(".storage-menu").querySelector("summary");
        button.closest(".storage-menu").open = false;
        shareForm.reset();
        shareForm.elements.FileId.value = row.dataset.selectionId;
        shareDialog.querySelector("#share-file-name").textContent = button.dataset.createShare;
        shareDialog.querySelector(".info-tip").open = false;
        const tomorrow = new Date(Date.now() + 86400000);
        localExpiry.value = new Date(tomorrow.getTime() - tomorrow.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        shareDialog.showModal();
    });
}
shareDialog.addEventListener("close", () => shareTrigger?.focus());
shareForm.addEventListener("submit", event => {
    if (shareForm.elements.Mode.value === "public" && !confirm("공개 목록에 이 파일의 이름이 표시됩니다. 게시하시겠습니까?")) {
        event.preventDefault();
        return;
    }
    shareForm.elements.ExpiresUtc.value = new Date(localExpiry.value).toISOString();
});
