"use strict";

function cookieValue(name) {
  const prefix = `${name}=`;
  const item = document.cookie.split("; ").find((part) => part.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
}

document.querySelector("#mfa-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const result = document.querySelector("#mfa-result");
  await fetch("/auth/csrf", { credentials: "same-origin" });
  const response = await fetch("/account/mfa/enable", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf"),
    },
    body: JSON.stringify(Object.fromEntries(new FormData(form).entries())),
  });
  result.textContent = response.ok ? "MFA enabled. It will be required on your next sign-in." : "Code not accepted.";
  if (response.ok) form.remove();
});
