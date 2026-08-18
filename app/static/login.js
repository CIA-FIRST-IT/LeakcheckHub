"use strict";

function cookieValue(name) {
  const prefix = `${name}=`;
  const item = document.cookie.split("; ").find((part) => part.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
}

document.querySelector("#local-login")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const result = document.querySelector("#login-result");
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  result.className = "form-status";
  result.textContent = "Signing in…";
  try {
    await fetch("/auth/csrf", { credentials: "same-origin" });
    const payload = Object.fromEntries(new FormData(form).entries());
    if (!payload.totp_code) delete payload.totp_code;
    const response = await fetch("/auth/local/login", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf"),
      },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      window.location.assign("/");
      return;
    }
    result.className = "form-status form-status--error";
    result.textContent = "Sign-in failed. Check your email, password, and authenticator code.";
  } catch (_) {
    result.className = "form-status form-status--error";
    result.textContent = "Could not reach LeakCheck. Please try again.";
  } finally {
    button.disabled = false;
  }
});

// The local form is deliberately behind a control: this portal is Google-first, and the
// password path exists for break-glass super-admin access.
const adminToggle = document.querySelector("#admin-toggle");
const adminDialog = document.querySelector("#admin-login");
if (adminToggle && adminDialog instanceof HTMLDialogElement) {
  adminToggle.addEventListener("click", () => {
    adminDialog.showModal();
    adminToggle.setAttribute("aria-expanded", "true");
    adminDialog.querySelector('[name="username"]')?.focus();
  });
  document.querySelector("#admin-close")?.addEventListener("click", () => adminDialog.close());
  adminDialog.addEventListener("close", () => adminToggle.setAttribute("aria-expanded", "false"));
}
