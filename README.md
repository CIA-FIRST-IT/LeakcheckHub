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

