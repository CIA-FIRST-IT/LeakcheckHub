"use strict";

function csrfToken() {
  const prefix = "__Host-leakcheck-csrf=";
  const item = document.cookie.split(";").map((value) => value.trim()).find((value) => value.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : "";
}

document.body.addEventListener("htmx:configRequest", (event) => {
  const token = csrfToken();
  if (token) {
    event.detail.headers["X-CSRF-Token"] = token;
  }
});

document.body.addEventListener("htmx:responseError", (event) => {
  const form = event.detail.elt.closest("form");
  const output = form ? form.querySelector(".form-error") : null;
  if (output) {
    output.textContent = event.detail.xhr.responseText || "The request could not be completed.";
  }
});

const findingsBody = document.querySelector("[data-findings-body]");
const findingsSearch = document.querySelector("#result-search");
const findingsCount = document.querySelector("#findings-count");
const findingsPageSize = document.querySelector("#findings-page-size");
const findingsPrevious = document.querySelector("#findings-prev");
const findingsNext = document.querySelector("#findings-next");
const findingsPageStatus = document.querySelector("#findings-page-status");
let findingsPage = 1;

function findingRows() {
  return findingsBody ? [...findingsBody.querySelectorAll("tr[data-search-values]")] : [];
}

function matchingFindingRows() {
  const needle = findingsSearch?.value.trim().toLocaleLowerCase() || "";
  return findingRows().filter((row) => !needle || row.dataset.searchValues.includes(needle));
}

function selectedPageSize(total) {
  return findingsPageSize?.value === "all" ? Math.max(total, 1) : Number(findingsPageSize?.value || 10);
}

function renderFindingsPage() {
  const allRows = findingRows();
  const matches = matchingFindingRows();
  const pageSize = selectedPageSize(matches.length);
  const pageCount = Math.max(1, Math.ceil(matches.length / pageSize));
  findingsPage = Math.min(Math.max(findingsPage, 1), pageCount);
  const start = (findingsPage - 1) * pageSize;
  const end = Math.min(start + pageSize, matches.length);
  const visible = new Set(matches.slice(start, end));
  for (const row of allRows) row.hidden = !visible.has(row);
  if (findingsCount) findingsCount.textContent = `${matches.length} matches`;
  if (findingsPageStatus) {
    findingsPageStatus.textContent = matches.length ? `Page ${findingsPage} of ${pageCount}` : "No results";
  }
  if (findingsPrevious) findingsPrevious.disabled = findingsPage <= 1;
  if (findingsNext) findingsNext.disabled = findingsPage >= pageCount || matches.length === 0;
}

findingsSearch?.addEventListener("input", () => {
  findingsPage = 1;
  renderFindingsPage();
});
findingsPageSize?.addEventListener("change", () => {
  findingsPage = 1;
  renderFindingsPage();
});
findingsPrevious?.addEventListener("click", () => {
  findingsPage -= 1;
  renderFindingsPage();
});
findingsNext?.addEventListener("click", () => {
  findingsPage += 1;
  renderFindingsPage();
});

for (const button of document.querySelectorAll(".sort-button")) {
  button.addEventListener("click", () => {
    if (!findingsBody) return;
    const column = Number(button.dataset.sortColumn);
    const direction = button.dataset.sortDirection === "asc" ? "desc" : "asc";
    const multiplier = direction === "asc" ? 1 : -1;
    const rows = findingRows();
    rows.sort((left, right) => {
      const leftValue = left.cells[column]?.dataset.sortValue || "";
      const rightValue = right.cells[column]?.dataset.sortValue || "";
      if (!leftValue && rightValue) return 1;
      if (leftValue && !rightValue) return -1;
      return leftValue.localeCompare(rightValue, undefined, { numeric: true, sensitivity: "base" }) * multiplier;
    });
    for (const row of rows) findingsBody.append(row);
    for (const item of document.querySelectorAll(".sort-button")) {
      item.dataset.sortDirection = "";
      item.removeAttribute("aria-sort");
      const indicator = item.querySelector("span");
      if (indicator) indicator.textContent = "↕";
    }
    button.dataset.sortDirection = direction;
    button.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
    const indicator = button.querySelector("span");
    if (indicator) indicator.textContent = direction === "asc" ? "↑" : "↓";
    findingsPage = 1;
    renderFindingsPage();
  });
}

const findingsTable = document.querySelector("#findings-table");
const columnToggles = [...document.querySelectorAll("[data-column-toggle]")];
const columnVisibilityKey = "leakcheck.findings.hidden-columns";

function hiddenColumns() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(columnVisibilityKey) || "[]");
    return new Set(Array.isArray(stored) ? stored.map(Number) : []);
  } catch (_) {
    return new Set();
  }
}

function setColumnVisibility(index, visible) {
  if (!findingsTable) return;
  findingsTable.querySelectorAll("col")[index]?.classList.toggle("column-hidden", !visible);
  findingsTable.tHead?.rows[0]?.cells[index]?.classList.toggle("column-hidden", !visible);
  for (const row of findingsTable.tBodies[0]?.rows || []) {
    row.cells[index]?.classList.toggle("column-hidden", !visible);
  }
}

const initiallyHiddenColumns = hiddenColumns();
for (const toggle of columnToggles) {
  const index = Number(toggle.value);
  toggle.checked = !initiallyHiddenColumns.has(index);
  setColumnVisibility(index, toggle.checked);
  toggle.addEventListener("change", () => {
    setColumnVisibility(index, toggle.checked);
    const hidden = columnToggles.filter((item) => !item.checked).map((item) => Number(item.value));
    try {
      window.localStorage.setItem(columnVisibilityKey, JSON.stringify(hidden));
    } catch (_) {
      // The controls still work for this page when browser storage is unavailable.
    }
  });
}

for (const handle of document.querySelectorAll("[data-resize-handle]")) {
  handle.addEventListener("pointerdown", (event) => {
    if (!findingsTable) return;
    event.preventDefault();
    const header = handle.closest("th");
    const column = findingsTable.querySelectorAll("col")[header.cellIndex];
    const startX = event.clientX;
    const startWidth = column.getBoundingClientRect().width;
    const startTableWidth = findingsTable.getBoundingClientRect().width;
    handle.setPointerCapture(event.pointerId);
    const resize = (moveEvent) => {
      const delta = moveEvent.clientX - startX;
      const width = Math.max(80, startWidth + delta);
      column.style.width = `${width}px`;
      findingsTable.style.width = `${Math.max(900, startTableWidth + width - startWidth)}px`;
    };
    const finish = () => {
      handle.removeEventListener("pointermove", resize);
      handle.removeEventListener("pointerup", finish);
      handle.removeEventListener("pointercancel", finish);
    };
    handle.addEventListener("pointermove", resize);
    handle.addEventListener("pointerup", finish);
    handle.addEventListener("pointercancel", finish);
  });
}

renderFindingsPage();

function showCopyConfirmation(event, target) {
  document.querySelector(".copy-confirmation")?.remove();
  const rect = target.getBoundingClientRect();
  const x = event.clientX || rect.right;
  const y = event.clientY || rect.top;
  const confirmation = document.createElement("span");
  confirmation.className = "copy-confirmation";
  confirmation.setAttribute("role", "status");
  confirmation.textContent = "Copied";
  confirmation.style.left = `${Math.min(x + 10, window.innerWidth - 80)}px`;
  confirmation.style.top = `${Math.min(y + 10, window.innerHeight - 40)}px`;
  document.body.append(confirmation);
  window.setTimeout(() => confirmation.remove(), 1000);
}

document.body.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-copy-value]");
  if (!target) return;
  try {
    await navigator.clipboard.writeText(target.dataset.copyValue);
    showCopyConfirmation(event, target);
    target.classList.add("copied");
    window.setTimeout(() => {
      target.classList.remove("copied");
    }, 1000);
  } catch (_) {
    target.title = "Copy failed";
  }
});

// Sign out. POST + CSRF so a stray link or prefetch cannot end someone's session.
document.querySelector("#sign-out")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await fetch("/auth/csrf", { credentials: "same-origin" });
    const token = (document.cookie.split("; ").find((p) => p.startsWith("__Host-leakcheck-csrf=")) || "").split("=")[1] || "";
    const response = await fetch("/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": token },
    });
    if (response.ok) {
      window.location.assign("/");
      return;
    }
  } catch (error) {
    // fall through to re-enable
  }
  button.disabled = false;
});
