"use strict";

function cookieValue(name) {
  const prefix = `${name}=`;
  const item = document.cookie.split("; ").find((part) => part.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
}

async function submitJson(form, url) {
  await fetch("/auth/csrf", { credentials: "same-origin" });
  const payload = Object.fromEntries(new FormData(form).entries());
  for (const key of ["leakcheck_rps", "leakcheck_concurrency", "leakcheck_max_response_bytes", "smtp_port"]) {
    if (payload[key]) payload[key] = Number(payload[key]);
  }
  if (payload.google_workspace_domains) {
    payload.google_workspace_domains = payload.google_workspace_domains.split(",").map((v) => v.trim()).filter(Boolean);
  }
  for (const [key, value] of Object.entries(payload)) if (value === "") delete payload[key];
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf") },
    body: JSON.stringify(payload),
  });
  const result = document.querySelector("#result");
  result.textContent = response.ok ? "Saved." : `Failed (${response.status}).`;
  if (response.ok) form.reset();
}

document.querySelector("#settings-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  void submitJson(event.currentTarget, "/admin/settings");
});
document.querySelector("#user-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  void submitJson(event.currentTarget, "/admin/users");
});

for (const button of document.querySelectorAll("[data-dialog-open]")) {
  button.addEventListener("click", () => {
    const dialog = document.getElementById(button.dataset.dialogOpen);
    if (dialog instanceof HTMLDialogElement) dialog.showModal();
  });
}
