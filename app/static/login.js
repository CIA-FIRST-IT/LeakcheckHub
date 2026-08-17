"use strict";

function cookieValue(name) {
  const prefix = `${name}=`;
  const item = document.cookie.split("; ").find((part) => part.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
}

document.querySelector("#local-login")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = document.querySelector("#login-result");
  result.textContent = "Signing in…";
  await fetch("/auth/csrf", { credentials: "same-origin" });
  const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
  if (!payload.totp_code) delete payload.totp_code;
  const response = await fetch("/auth/local/login", {
    method: "POST",
    credentials: "same-origin",
    redirect: "manual",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf"),
    },
    body: JSON.stringify(payload),
  });
  if (response.ok || response.type === "opaqueredirect") window.location.assign("/");
  else result.textContent = "Sign-in failed.";
});
