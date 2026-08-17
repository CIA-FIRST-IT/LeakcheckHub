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

document.body.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-copy-value]");
  if (!target) return;
  try {
    await navigator.clipboard.writeText(target.dataset.copyValue);
    const originalTitle = target.title;
    target.title = "Copied";
    target.classList.add("copied");
    window.setTimeout(() => {
      target.title = originalTitle;
      target.classList.remove("copied");
    }, 1200);
  } catch (_) {
    target.title = "Copy failed";
  }
});
