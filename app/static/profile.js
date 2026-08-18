"use strict";

function cookieValue(name) {
  const prefix = `${name}=`;
  const item = document.cookie.split("; ").find((part) => part.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
}

document.querySelector("#password-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const result = document.querySelector("#profile-result");
  await fetch("/auth/csrf", { credentials: "same-origin" });
  const response = await fetch("/account/profile/password", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": cookieValue("__Host-leakcheck-csrf"),
    },
    body: JSON.stringify(Object.fromEntries(new FormData(form).entries())),
  });
  const payload = await response.json();
  result.textContent = response.ok ? "Password changed." : payload.detail || "Password change failed.";
  if (response.ok) form.reset();
});
