# Portainer deployment

This deployment keeps two responsibilities separate:

- GitHub Actions builds the tested `main` branch and publishes
  `ghcr.io/cia-first-it/leakcheckhub:latest` plus an immutable commit-SHA tag.
- Portainer reads `compose.portainer.yaml` from GitHub and pulls the GHCR image directly. The stack
  never depends on Portainer successfully building a Compose `build:` context.

The stack requires no environment variables. On its first launch, a one-shot initializer generates
the database passwords, session signing secret, and encryption key with the operating system's secure
random generator. They are saved in a dedicated Docker named volume and mounted read-only into the
services that need them. Portainer's environment-variable screen never contains the secret values.

The application containers do not set `no-new-privileges` or drop all Linux capabilities. The
deployment host refused to execute the interpreter under those two settings combined, reporting
`exec /usr/local/bin/python: operation not permitted`. The containers still run as an unprivileged
image user, with a read-only root filesystem, on an internal network. If your host tolerates the
stricter settings, re-add them one service at a time and confirm the stack still starts.

The stack runs three services: a one-shot `init` job that generates any missing bootstrap secret and
exits, `postgres`, and `web`. The `web` container creates the least-privilege database roles only when
the Alembic database is blank, upgrades the existing schema, and then serves the application while
draining the batch queue in-process. There is no separate worker container: batch scans, schedules,
and notification delivery run as a supervised background task inside `web`, restarting automatically
if that task fails.

The PostgreSQL and bootstrap-secret named volumes are not replaced by an image update. Every step is
safe to repeat on each redeployment.

## 1. Publish the first image

Merge the deployment files into `main`. The `CI` workflow publishes the image only after all quality,
security, and test checks pass. The first GHCR package may be private. Either make the package public
in the GitHub package settings, or add a `ghcr.io` registry in Portainer using a GitHub classic PAT
with only `read:packages` permission.

## 2. Create the Git-backed stack

In Portainer, open **Stacks -> Add stack -> Git repository** and use:

- Name: `leakcheck`
- Repository URL: `https://github.com/CIA-FIRST-IT/LeakcheckHub`
- Repository reference: `refs/heads/main`
- Compose path: `compose.portainer.yaml`

If the repository is private, enable repository authentication and use a read-only GitHub token.
Do not enter the Compose file in Portainer's editor; keeping it Git-backed ensures GitHub remains the
source of truth.

Enable **Re-pull image**. If your Portainer edition provides GitOps updates, also enable **Force
redeployment**. `pull_policy: always` is included in the Compose file as an additional safeguard.

## 3. Leave environment variables empty

Do not add stack environment variables. Deploy the Compose file as supplied. LeakCheck, Google, SMTP,
IRIS, Wazuh, users, and roles remain blank on first launch and are configured in the platform's
Settings page.

Back up both named volumes together:

- `leakcheck_postgres-data`
- `leakcheck_bootstrap-secrets`

The generated encryption key and database passwords intentionally cannot be reconstructed. Losing the
bootstrap-secret volume while retaining the database volume makes the existing deployment unusable.

## 4. Put HTTPS in front of the service

Production cookies require HTTPS. Route the public hostname through the existing reverse proxy to
port `8000` on the Portainer host. The zero-input stack accepts the hostname supplied by that proxy,
so the proxy should enforce the intended public hostname. Do not expose PostgreSQL; only the web port
is published.

## 5. Automatic updates from GitHub

The image is rebuilt after every successful push to `main`. If your Portainer edition provides a
GitOps stack webhook, save its complete URL as the GitHub Actions repository secret
`PORTAINER_WEBHOOK_URL`. The workflow calls it only after `:latest` has finished publishing, which
avoids Portainer racing the image build. The webhook causes Portainer to pull the new image and
recreate the stack.

Without that webhook, use GitOps polling if available, or click **Pull and redeploy** after a green CI
run. Because the stack has **Re-pull image** enabled and `pull_policy: always`, every such update pulls
the current GHCR image rather than reusing the host's cached image.

## First administrator

After the stack is healthy, open the `web` container console in Portainer and run:

```sh
python -m app.create_superadmin --email admin@example.com --display-name "SOC Admin"
```

The command prompts for the initial password and returns the enrollment information. No administrator
password is stored in the Compose file or Portainer environment.
