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

function visibleFindingRows() {
  return findingsBody ? [...findingsBody.querySelectorAll("tr[data-search-values]")] : [];
}

function filterFindings() {
  if (!findingsSearch) return;
  const needle = findingsSearch.value.trim().toLocaleLowerCase();
  let visible = 0;
  for (const row of visibleFindingRows()) {
    const matches = !needle || row.dataset.searchValues.includes(needle);
    row.hidden = !matches;
    if (matches) visible += 1;
  }
  if (findingsCount) findingsCount.textContent = `${visible} shown`;
}

findingsSearch?.addEventListener("input", filterFindings);
filterFindings();

for (const button of document.querySelectorAll(".sort-button")) {
  button.addEventListener("click", () => {
    if (!findingsBody) return;
    const column = Number(button.dataset.sortColumn);
    const direction = button.dataset.sortDirection === "asc" ? "desc" : "asc";
    const multiplier = direction === "asc" ? 1 : -1;
    const rows = visibleFindingRows();
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
  });
}

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
