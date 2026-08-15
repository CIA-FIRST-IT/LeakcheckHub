# LeakCheck SOC Portal

An internal, self-hosted portal for controlled use of the LeakCheck Enterprise API. The project is
deliberately small: FastAPI, PostgreSQL, server-rendered UI, and no JavaScript build chain.

## Local start

1. Copy `.env.example` to `.env`, then generate unique values for every `replace-with-…` setting.
2. Start the hardened development stack:

   ```sh
   docker compose up --build
   ```

3. Visit `http://localhost:8000/healthz`. The unauthenticated health endpoint intentionally returns
   only `{"status":"ok"}`.

The `migrate` service is the only development service that connects as the PostgreSQL bootstrap
superuser. Its initial Alembic migration creates the separate, non-superuser migration and runtime
roles. Web and worker processes use the runtime role only.

## Google sign-in

Create a confidential Web OAuth client in Google Cloud and register the exact
`LC_GOOGLE_REDIRECT_URI` value (normally `https://<portal-host>/auth/google/callback`). Set the client
ID, client secret, redirect URI, and one or more Workspace domains in `.env`; startup rejects missing,
placeholder, wildcard, or unsafe values. The web deployment needs outbound HTTPS only to Google's OIDC
hosts: `accounts.google.com`, `oauth2.googleapis.com`, and `www.googleapis.com`.

## Super-admin bootstrap

Super-admins are local accounts only: their email/password login always also requires TOTP. They are
never self-registered. After the stack has migrated, run the following from an operator terminal:

```sh
docker compose exec web python -m app.create_superadmin --email admin@example.test --display-name "SOC Admin"
```

The command prompts twice for a 15+ character password and prints one TOTP provisioning URI exactly
once for an authenticator app. It deliberately has no password command-line option, so passwords do
not enter shell history or process arguments. Local login is available at `POST /auth/local/login` and
requires the account email, password, and a current six-digit TOTP code over HTTPS.

Before any state-changing browser request, retrieve `GET /auth/csrf`, read the host-only
`__Host-leakcheck-csrf` cookie from same-origin code, and return its value in the `X-CSRF-Token`
header. The token is signed and bound to the active session, then rotated after sign-in.

## Quality checks

The CI workflow is authoritative. Locally, with Python 3.12 and dependencies installed:

```sh
ruff check .
ruff format --check .
mypy app
bandit -q -r app
semgrep --config p/ci app tests
pip-audit -r requirements.txt
pytest
```

`requirements.txt` is the production lock. `requirements-dev.txt` adds tools used exclusively by
quality checks. No test may contact the live LeakCheck API.
