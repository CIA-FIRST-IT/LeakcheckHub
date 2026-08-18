# LeakCheckHub handoff

Last updated: 2026-08-18

## Current repository state

- Repository: `CIA-FIRST-IT/LeakcheckHub`
- Default branch: `main`
- Sanitized release commit: `c0303640e25224e0693d123c3c24e5b498dfbb52`
- Commit message: `chore: sanitize repository for public release`
- Working tree was clean and tracking `origin/main` at handoff.
- The milestone branches were removed; `main` is the only normal branch.
- The application image was published to GHCR by the green CI run.
- The latest full test run passed: `163 passed`.

## What is implemented

The current application includes:

- FastAPI/PostgreSQL application with Alembic migrations and least-privilege database roles.
- Local super-admin bootstrap with password hashing and TOTP MFA.
- Optional MFA enrollment after login; MFA is not forced on ordinary users at first login.
- Session, CSRF, login-rate-limit, authorization, audit, and security-header protections.
- Admin settings page for users and platform integrations. Operational values are encrypted in the
  database and are not hardcoded in the image or Compose file.
- Configurable LeakCheck API, Google OIDC/Workspace, SMTP, Wazuh, DFIR-IRIS, and SOC settings.
- Google Workspace help popup with step-by-step service-account and domain-wide-delegation guidance.
- Analyst scan UI with findings, remediation state, raw-field search, sortable columns, pagination,
  column visibility, column resizing, readable dates, and copy-to-clipboard feedback.
- User portal with a single-page scan action and the user's results.
- Batch scans, schedules, latest scheduled results, watchlists, alerts, notifications, and the
  remediation event trail.
- LeakCheck normalization for list-valued origins and partial breach dates such as `2019-04`.
- Passwords and other sensitive finding fields are encrypted at rest; cleartext values are never
  returned in error messages.

## Deployment

For Portainer, use the Git-backed stack file `compose.portainer.yaml`:

1. Add a Git repository stack pointing at `https://github.com/CIA-FIRST-IT/LeakcheckHub`.
2. Use `refs/heads/main` and Compose path `compose.portainer.yaml`.
3. Enable image re-pull (and force redeployment/GitOps polling if available).
4. Leave stack environment variables empty.

The stack generates database passwords, the session secret, and the data-encryption key on first
launch and stores them in the `leakcheck_bootstrap-secrets` named volume. PostgreSQL data is stored
in `leakcheck_postgres-data`. Back up both volumes together. Losing the bootstrap-secret volume
while keeping the database volume makes the existing deployment unreadable.

After the stack is healthy, create the first administrator from the web container console:

```sh
python -m app.create_superadmin --email admin@example.com --display-name "SOC Admin"
```

Then sign in and configure integrations and users at `/admin/settings`. Put HTTPS/reverse-proxy
protection in front of port `8000`; do not expose PostgreSQL.

## Development and validation

With the project virtual environment installed:

```sh
.venv/bin/python -m pytest
ruff check .
ruff format --check .
mypy app
bandit -q -r app
semgrep --config p/ci app tests
pip-audit -r requirements.txt
```

Tests must remain offline; the test suite blocks accidental calls to the live LeakCheck API.

## Public-repository cleanup

The internal files `API-NOTES.md`, `TODO.md`, and `plan.md` were deleted and removed from all
normal branch history. `.gitignore` and `.dockerignore` now exclude local environment files, IDE
state, logs, credential/service-account files, private keys, and internal notes.

GitHub keeps read-only hidden refs for historical pull requests. PRs #1–#7 still have those refs,
which ordinary Git cannot force-delete. Because the removed notes contained internal operational
details, submit a GitHub Support request asking them to dereference those PR refs, clear cached
views, and run repository garbage collection. Include the original first affected commit
`ba285f05fe2319e4866b9d4f8b9966ba8708edd9` and the sanitized main commit above. Existing clones
should be re-cloned rather than used to push old branches back to the repository.

## Suggested next work

1. Ask GitHub Support to purge the hidden PR refs and cached views.
2. Re-authenticate `gh` locally if GitHub CLI work is needed (`gh auth login -h github.com`).
3. Deploy the Git-backed Portainer stack and verify the generated-secret volumes are backed up.
4. Configure the LeakCheck API and any Google, SMTP, IRIS, and Wazuh endpoints through Settings.
5. Run a non-production scan, verify finding dates/origins/search/sort/pagination, and test the
   remediation workflow before exposing the service to users.

