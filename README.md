# LeakCheck SOC Portal

An internal, self-hosted portal for controlled use of the LeakCheck API. The project is
deliberately small: FastAPI, PostgreSQL, server-rendered UI, and no JavaScript build chain.

## Local start

1. Copy `.env.example` to `.env`, then generate unique values for the database, session, and root
   encryption bootstrap secrets. In production, inject these from the deployment secret manager.
2. Start the hardened development stack:

   ```sh
   docker compose up --build
   ```

3. Visit `http://localhost:8000/healthz`. The unauthenticated health endpoint intentionally returns
   only `{"status":"ok"}`.

The `migrate` service is the only development service that connects as the PostgreSQL bootstrap
superuser. Its initial Alembic migration creates the separate, non-superuser migration and runtime
roles. Web and worker processes use the runtime role only.

The development stack in `compose.yaml` keeps `migrate` and `worker` as separate services. The
Portainer stack in `compose.portainer.yaml` is deliberately smaller: it runs only `init`, `postgres`,
and `web`, with schema upgrades and the batch worker folded into the `web` container. Privileged
migration credentials are removed from the process environment once the schema is current.

## Platform configuration

Fresh installations intentionally contain no operational integration configuration. After creating
the first super-admin, sign in and open `/admin/settings` to add users and configure LeakCheck, Google
OIDC/Workspace, Wazuh, DFIR-IRIS, SMTP, and the SOC address. The Workspace help popup walks through
read-only domain-wide delegation and service-account JSON setup. Secret fields are encrypted in PostgreSQL,
are never displayed again, and can be left blank when updating unrelated settings.

The database URL, database passwords, session signing secret, trusted-host boundary, and root data key
remain deployment bootstrap configuration. They cannot safely be stored in the database they are
needed to connect to or decrypt. Local development reads them from `.env`; the Portainer stack
generates them automatically and persists them outside the database in a dedicated named volume.

For Google sign-in, create a confidential Web OAuth client and register the configured redirect URI
(normally `https://<portal-host>/auth/google/callback`). Until the complete Google configuration is
saved, the app boots normally and Google sign-in returns HTTP 503.

## Super-admin bootstrap

Super-admins hold local password credentials and are never self-registered. TOTP is enrolled from
inside the portal after the first sign-in, and is required at every sign-in once enrolled. After the stack has migrated, run the following from an operator terminal:

```sh
docker compose exec web python -m app.create_superadmin --email admin@example.test --display-name "SOC Admin"
```

The command prompts twice for a 15+ character password and creates a password-only account. It
deliberately has no password command-line option, so passwords do not enter shell history or
process arguments. Sign in, then open **Account security** to scan the enrollment QR code and
enable MFA. Local login is available at `POST /auth/local/login`; it requires a six-digit TOTP code
in addition to the email and password once the account has completed enrollment.

Before any state-changing browser request, retrieve `GET /auth/csrf`, read the host-only
`__Host-leakcheck-csrf` cookie from same-origin code, and return its value in the `X-CSRF-Token`
header. The token is signed and bound to the active session, then rotated after sign-in.

For local tests, the repository uses an isolated Python 3.12 environment:

```sh
.venv/bin/python -m pytest
```

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

## Operations

- [DEPLOYMENT.md](DEPLOYMENT.md) — TLS, network exposure, egress allow-list, secret provisioning,
  and the pre-production checklist.
- [RUNBOOK.md](RUNBOOK.md) — backup and restore, root data-key rotation, offboarding, and
  troubleshooting.

## Portainer deployment

Use the Git-backed production stack in `compose.portainer.yaml`. GitHub publishes the application
image to GHCR after the `main` branch passes CI, and Portainer re-pulls that image on every stack
redeployment. See [PORTAINER.md](PORTAINER.md) for the zero-input setup, persistent-data behavior, and
optional automatic redeployment webhook.
