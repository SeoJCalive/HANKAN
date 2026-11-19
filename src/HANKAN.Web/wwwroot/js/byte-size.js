function formatByteSize(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return { short: "—", exact: null };
    const units = ["B", "KB", "MB", "GB", "TB"];
    const value = BigInt(bytes);
    let scale = 1n, unit = 0;
    while (unit < units.length - 1 && value / scale >= 1024n) { scale *= 1024n; unit++; }
    let tenths = (value * 10n + scale / 2n) / scale;
    if (unit < units.length - 1 && tenths === 10240n) { tenths = 10n; unit++; }
    return { short: `${Number(tenths) / 10} ${units[unit]}`, exact: `${value.toLocaleString("en-US")} 바이트` };
}

function showDeleteSize(bytes) {
    const cell = document.getElementById("delete-size");
    const { short, exact } = formatByteSize(bytes);
    if (!exact) { cell.textContent = short; return; }
    const button = document.createElement("button");
    const popover = document.createElement("span");
    popover.id = "delete-size-exact";
    popover.className = "byte-exact";
    popover.popover = "auto";
    popover.textContent = exact;
    button.type = "button";
    button.className = "byte-size";
    button.title = exact;
    button.setAttribute("aria-label", `파일 크기: ${exact}`);
    button.setAttribute("popovertarget", popover.id);
    button.textContent = short;
    cell.replaceChildren(button, popover);
}
