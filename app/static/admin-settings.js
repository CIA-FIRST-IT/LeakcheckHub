"use strict";

function cookieValue(name) {
  const prefix = `${name}=`;
  const item = document.cookie.split("; ").find((part) => part.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
}

// Reflect the post-write state the server just returned, so the operator sees the effect of a
// save without reloading and losing their place on a long form.
function applyConfiguredState(configured) {
  if (!configured) return;
  for (const [key, isSet] of Object.entries(configured)) {
    const cell = document.querySelector(`[data-setting-status="${CSS.escape(key)}"]`);
    if (cell && cell.textContent !== (isSet ? "configured" : "blank")) {
      cell.textContent = isSet ? "configured" : "blank";
      cell.classList.remove("just-changed");
      // Restart the highlight animation even if this cell changed a moment ago.
      void cell.offsetWidth;
      cell.classList.add("just-changed");
    }
    const field = document.querySelector(`[data-setting-input="${CSS.escape(key)}"]`);
    if (field && field.type === "password") {
      field.placeholder = isSet ? "configured — leave blank to keep" : "";
    }
  }
}

function setBusy(button, busy, label) {
  if (!button) return;
  button.disabled = busy;
  button.classList.toggle("is-busy", busy);
  if (busy) {
    button.dataset.idleLabel = button.dataset.idleLabel || button.textContent;
    button.textContent = label;
  } else if (button.dataset.idleLabel) {
    button.textContent = button.dataset.idleLabel;
  }
}

function flash(button, ok) {
  if (!button) return;
  const state = ok ? "is-ok" : "is-error";
  button.classList.add(state);
  window.setTimeout(() => button.classList.remove(state), 1600);
}

async function submitJson(form, url) {
  const button = form.querySelector('button[type="submit"]');
  const result = document.querySelector("#result");
  setBusy(button, true, "Saving…");
  result.textContent = "";
  try {
    await fetch("/auth/csrf", { credentials: "same-origin" });
    const payload = Object.fromEntries(new FormData(form).entries());
    for (const key of ["leakcheck_rps", "leakcheck_concurrency", "leakcheck_max_response_bytes", "smtp_port", "retention_days"]) {
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
    const body = await response.json().catch(() => ({}));
    if (response.ok) {
      applyConfiguredState(body.configured);
      const count = Array.isArray(body.updated) ? body.updated.length : 0;
      result.textContent = count ? `Saved ${count} setting${count === 1 ? "" : "s"}.` : "Saved.";
      form.reset();
    } else {
      // A 422 carries the field that failed validation; show it instead of a bare status code.
      const detail = Array.isArray(body.detail)
        ? body.detail.map((d) => d.msg || "").filter(Boolean).join("; ")
        : body.detail;
      result.textContent = detail || `Failed (${response.status}).`;
    }
    flash(button, response.ok);
  } catch (error) {
    result.textContent = "Could not reach the server.";
    flash(button, false);
  } finally {
    setBusy(button, false);
  }
}

const result = document.querySelector("#result");
const workspaceSync = document.querySelector("#workspace-sync");
if (workspaceSync) {
  workspaceSync.addEventListener("click", async () => {
    await fetch("/auth/csrf", { credentials: "same-origin" });
    workspaceSync.disabled = true;
    try {
      const response = await fetch("/admin/workspace/sync", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf") },
      });
      result.textContent = response.ok ? "Workspace users synchronized." : "Workspace sync failed.";
    } finally {
      workspaceSync.disabled = false;
    }
  });
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

for (const button of document.querySelectorAll("[data-test-alert]")) {
  button.addEventListener("click", async () => {
    await fetch("/auth/csrf", { credentials: "same-origin" });
    const response = await fetch(`/admin/alerts/test/${button.dataset.testAlert}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf") },
    });
    result.textContent = response.ok ? "Test alert queued." : "Could not queue test alert.";
  });
}

for (const button of document.querySelectorAll("[data-save-user]")) {
  button.addEventListener("click", async () => {
    const row = button.closest("tr");
    const userId = row?.dataset.userId;
    if (!userId) return;
    await fetch("/auth/csrf", { credentials: "same-origin" });
    const role = row.querySelector('[name="role"]');
    const active = row.querySelector('[name="is_active"]');
    const payload = { display_name: row.querySelector('[name="display_name"]').value };
    // Disabled controls are omitted so the server keeps the current value untouched.
    if (!role.disabled) payload.role = role.value;
    if (!active.disabled) payload.is_active = active.checked;
    button.disabled = true;
    try {
      const response = await fetch(`/admin/users/${encodeURIComponent(userId)}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf") },
        body: JSON.stringify(payload),
      });
      if (response.ok) {
        result.textContent = "User updated.";
      } else {
        const body = await response.json().catch(() => ({}));
        result.textContent = body.detail || `Failed (${response.status}).`;
      }
    } finally {
      button.disabled = false;
    }
  });
}

for (const button of document.querySelectorAll("[data-revoke-sessions]")) {
  button.addEventListener("click", async () => {
    const userId = button.closest("tr")?.dataset.userId;
    if (!userId) return;
    if (!window.confirm("Sign this account out of every browser?")) return;
    await fetch("/auth/csrf", { credentials: "same-origin" });
    button.disabled = true;
    try {
      const response = await fetch(`/admin/users/${encodeURIComponent(userId)}/sessions/revoke`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf") },
      });
      const body = await response.json().catch(() => ({}));
      result.textContent = response.ok
        ? `Revoked ${body.revoked} session(s).`
        : body.detail || `Failed (${response.status}).`;
    } finally {
      button.disabled = false;
    }
  });
}

// Branding. The logo is sent as base64 in JSON so the app needs no multipart dependency.
function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("could not read the file"));
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.readAsDataURL(file);
  });
}

async function postBranding(payload, button, okMessage) {
  setBusy(button, true, "Saving…");
  try {
    await fetch("/auth/csrf", { credentials: "same-origin" });
    const response = await fetch("/admin/branding", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf") },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (response.ok) {
      result.textContent = okMessage;
      const preview = document.querySelector("#logo-preview");
      if (preview) {
        preview.innerHTML = body.has_logo
          ? `<img class="logo-preview" alt="Current organisation logo" src="/branding/logo?v=${encodeURIComponent(body.logo_sha256 || "")}">`
          : "No logo uploaded.";
      }
    } else {
      result.textContent = body.detail || `Failed (${response.status}).`;
    }
    flash(button, response.ok);
  } catch (error) {
    result.textContent = "Could not reach the server.";
    flash(button, false);
  } finally {
    setBusy(button, false);
  }
}

document.querySelector("#branding-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const file = document.querySelector("#logo-file")?.files?.[0];
  const payload = { organization_name: form.querySelector('[name="organization_name"]').value };
  if (file) {
    if (file.size > 1024 * 1024) {
      result.textContent = "The logo exceeds 1 MB.";
      flash(button, false);
      return;
    }
    payload.logo_base64 = await readAsBase64(file);
  }
  await postBranding(payload, button, "Branding saved.");
});

document.querySelector("#clear-logo")?.addEventListener("click", async (event) => {
  if (!window.confirm("Remove the organisation logo?")) return;
  await postBranding({ clear_logo: true }, event.currentTarget, "Logo removed.");
});
