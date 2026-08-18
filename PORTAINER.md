# Portainer deployment

This deployment keeps two responsibilities separate:

- GitHub Actions builds the tested `main` branch and publishes
  `ghcr.io/cia-first-it/leakcheckhub:latest` plus an immutable commit-SHA tag.
- Portainer reads `compose.portainer.yaml` from GitHub and pulls the GHCR image directly. The stack
  never depends on Portainer successfully building a Compose `build:` context.

The PostgreSQL named volume is not replaced by an image update. The bootstrap job is safe to run on
every redeployment: it creates the least-privilege database roles only when the Alembic database is
blank, then the migration job upgrades the existing schema before web and worker start.

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

## 3. Add Portainer environment variables

Add these under the stack's environment variables. Generate three independent database passwords;
hex output avoids URL-encoding problems in PostgreSQL connection strings.

```sh
openssl rand -hex 32  # LC_POSTGRES_PASSWORD
openssl rand -hex 32  # LC_MIGRATOR_DB_PASSWORD
openssl rand -hex 32  # LC_RUNTIME_DB_PASSWORD
openssl rand -hex 32  # LC_SESSION_SECRET
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='  # LC_DATA_KEY
```

Required variables:

| Variable | Value |
| --- | --- |
| `LC_POSTGRES_PASSWORD` | First generated database password |
| `LC_MIGRATOR_DB_PASSWORD` | Second generated database password |
| `LC_RUNTIME_DB_PASSWORD` | Third generated database password |
| `LC_SESSION_SECRET` | Generated session secret |
| `LC_DATA_KEY` | Base64-URL data key |
| `LC_TRUSTED_HOSTS` | Public hostname only, for example `leakcheck.example.com` |

Optional variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LC_HTTP_BIND` | `0.0.0.0` | Host interface used for the published port |
| `LC_HTTP_PORT` | `8000` | Host port mapped to LeakCheck Hub |
| `LC_IMAGE` | `ghcr.io/cia-first-it/leakcheckhub:latest` | Override registry or tag |

Keep these bootstrap values unchanged across redeployments. In particular, changing `LC_DATA_KEY`
would make integration secrets already stored in PostgreSQL impossible to decrypt. LeakCheck, Google,
SMTP, IRIS, Wazuh, users, and roles remain blank on first launch and are configured in the platform's
Settings page.

## 4. Put HTTPS in front of the service

Production cookies require HTTPS. Route the configured hostname through the existing reverse proxy
to the Portainer host's `LC_HTTP_PORT`. Do not expose PostgreSQL; only the web port is published.

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
