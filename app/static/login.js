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
