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
