# TODO — LeakCheck SOC Portal

Work queue for this project. Design rationale lives in [`plan.md`](plan.md); **read it before starting
any milestone.** IDs are stable — never renumber them, append instead.

## How to use this file

- Work milestones in order. Each is independently shippable; do not start M(n+1) until M(n)'s
  **Done when** holds.
- Tick `[x]` only when the item's code **and** its tests are committed and CI is green.
- If an item turns out wrong, strike it and append a replacement with a new ID rather than editing in
  place — the history is useful.

## Standing rules (apply to every item)

- Security outranks features. Prefer deleting a feature to shipping an unsafe one.
- No new runtime dependency without a note in the commit saying why an existing one won't do.
- No test may call the live LeakCheck API. Use the recorded fixtures from `M2-04`.
- Never log, template, or serialize a cleartext password outside the analyst decrypt route.
- Every state change by a human gets an `audit_log` row.

---

## M0 — Scaffold & security baseline

- [x] `M0-01` Repo skeleton, hash-pinned `requirements.txt`, `pyproject.toml` (ruff + mypy config)
- [x] `M0-02` `app/config.py` with pydantic-settings, fail-fast secret validation, `.env.example`
- [x] `M0-03` Docker Compose: web, worker, postgres; non-root user, read-only root filesystem
- [x] `M0-04` `app/main.py` app factory + security-headers/CSP middleware + `/healthz`
- [x] `M0-05` Alembic wired; bootstrap migration creating the migration and runtime DB roles
- [x] `M0-06` CI pipeline: ruff, mypy, bandit, semgrep, pip-audit, pytest

**Done when:** `docker compose up` serves a hardened empty app and CI is green.

## M1 — Auth & RBAC

- [x] `M1-01` `users`, `admin_credentials`, `sessions` models + migration
- [x] `M1-02` Server-side session issue/verify/revoke with idle + absolute expiry
- [x] `M1-03` Google OIDC auth-code + PKCE, JWKS verification, `hd` allow-list, auto-provision as `User`
- [x] `M1-04` Super-admin local login: argon2id + mandatory TOTP, lockout, `create-superadmin` CLI
- [x] `M1-05` `require_role()` dependency + CSRF middleware (double-submit token)
- [x] `M1-06` `audit_log` model + helper; log every auth event
- [x] `M1-07` Tests: role matrix, session expiry/revocation, CSRF rejection, **route-guard-coverage test**
      (enumerate `app.routes`, fail if any non-public route lacks an explicit guard)

**Done when:** all three roles can sign in, the guard-coverage test passes, auth events are audited.

_Completed 2026-08-17:_ implementation and tests are committed; CI is green on PR #1.

## M2 — LeakCheck client

> Read [`API-NOTES.md`](API-NOTES.md) first. The vendor docs are wrong about pagination and two of the
> deviations cause **silent false negatives**. Build against the measurements, not the docs.

- [x] `M2-01` Async client: `GET /api/v2/query/{q}`, `X-API-Key`, always-explicit `type`,
      **120 s timeout** (responses up to 2.7 MB / 29 s are normal, not pathological)
- [x] `M2-02` Token-bucket limiter at **3 req/sec** (measured hard ceiling; platform configurable)
      \+ concurrency semaphore + backoff/retry + circuit breaker.
      **Self-pace — there is no `Retry-After` or `X-RateLimit-*` header to react to.**
- [x] `M2-03` Per-type pagination:
      - email → send **no `limit`, and never `offset`** (`offset>0` returns `found:0`, indistinguishable
        from "no leaks"). Enforce at the type level so callers cannot pass it.
      - domain → `limit=1000` + increasing `offset`, page until a short/empty page; `found` is page size,
        **not** the total, so `truncated` comes from loop termination, never a `found` comparison.
- [x] `M2-04` Hard response-size cap (default 32 MB) that errors loudly instead of exhausting memory
- [x] `M2-05` Tolerant response parser — every `source` subfield optional (`name` is often `"Unknown"`,
      `breach_date` often `null`); retain the full record in `raw`
- [x] `M2-06` Quota tracking: record `quota` on every scan. Note it **lags one request** and that
      misses cost 0 — never gate a scan on a pre-flight quota read
- [ ] `M2-07` **Capture real fixtures for all six types**, including one large response (`admin@example.com`,
      8,240 records) as the batching/perf fixture
- [ ] `M2-08` Tests against fixtures incl. 429, 400 `Invalid type`/`Invalid limit`, 401 `Invalid X-API-Key`,
      malformed body, empty result, oversized body
- [x] `M2-09` **Regression test: an email query is never issued with `offset`** — this is the guard against
      the worst failure mode in the app (reporting a breached user as clean)

**Done when:** all six query types return normalized records offline from fixtures, and the
no-offset-on-email guard is enforced by a test.

- [x] `M2-10` Encrypted, super-admin-managed platform settings for LeakCheck, Google OIDC, Wazuh,
      DFIR-IRIS, SMTP, SOC mail, and user provisioning; operational configuration blank on shipment

_Status 2026-08-17:_ implemented items are committed and green on PR #1. M2-07/M2-08 still require
sanitized real fixtures captured after an API key is configured.

## M3 — Data model & ingest engine ← core

- [x] `M3-01` `subjects`, `scans`, `breach_sources`, `findings`, `finding_events` + migration
- [x] `M3-02` Per-kind normalization (email NFKC+lower, domain punycode, phone E.164, username, origin)
- [x] `M3-03` AES-256-GCM envelope crypto with finding-id AAD; mask / length / charset computation
- [x] `M3-04` Fingerprint function + idempotent `ON CONFLICT` upsert returning `is_new`
      (password SHA-256 is part of the fingerprint — see plan.md §3)
- [x] `M3-05` Re-leak detection: `superseded_by_id`, `re_leaked` event, severity escalation
- [x] `M3-06` Remediation API: mark remediated / un-remediate, with event trail
- [x] `M3-07` **Tests: the full Bob/Canva scenario** — 2019 leak → remediate → re-scan stays remediated
      → 2026 leak with a new password creates a fresh unremediated finding flagged as a re-leak
- [x] `M3-08` Tests: repeat-ingest idempotency, passwordless records, crypto round-trip, AAD tamper

**Done when:** the Bob scenario passes end to end and re-ingest produces zero spurious new findings.

_Completed 2026-08-17:_ M3-01 through M3-08 are committed and green on PR #1.

## M4 — Analyst UI

- [x] `M4-01` Base layout, vendored HTMX + hand-written CSS, nav
- [x] `M4-02` Six check forms (domain, email, password, username, origin, phone) → scan → results
- [x] `M4-03` Results table: source, breach date, all fields, origin, masked password, remediation state
- [x] `M4-04` Reveal-password action: decrypt on demand, audit-logged, `password_viewed` event
- [x] `M4-05` Subject history view: findings timeline, re-leak highlighting, event trail
- [x] `M4-06` Filters (unremediated / re-leaked / by source / by date); CSV export, audit-logged
- [x] `M4-07` Tests: analyst-only access, reveal is audited, **XSS payloads in breach fields render inert**

**Done when:** an analyst can run all six checks and see the complete detail stream.

_Completed 2026-08-17:_ M4-01 through M4-07 are committed and green on PR #2.

## M5 — Self-service user portal

- [x] `M5-01` User dashboard — **no identifier parameter**; subject derived from the session
- [x] `M5-02` Masked-only serializer in its own module, with no code path to `password_ciphertext`
- [x] `M5-03` Self-remediation with event trail; per-finding guidance text
- [x] `M5-04` Rate limit + cooldown on self-check
- [x] `M5-05` Tests: user cannot reach analyst routes, cannot query another email by any parameter
      manipulation, and **no response to a User ever contains cleartext**

**Done when:** a `User` sees only their own findings, masked, and can close them out.

_Completed 2026-08-17:_ M5-01 through M5-05 are committed and green on PR #3.

## M6 — Workspace sync & batch scans

- [x] `M6-01` Service-account client, domain-wide delegation, read-only Directory scopes
- [x] `M6-02` `list_org_units()` / `list_users()`; additive sync marking departed users inactive
- [x] `M6-03` `scan_queue` + worker drain via `SELECT ... FOR UPDATE SKIP LOCKED`
- [x] `M6-04` Batch builder: by OU / by domain / by selection; live HTMX progress view.
      At 3 RPS a 5,000-user OU takes ~30–90 min, so batches are strictly background jobs with progress
      and resumability — never request-scoped
- [x] `M6-05` Tests: sync idempotency, queue concurrency, rate-limit adherence under batch load

**Done when:** "scan every user in OU X" completes without exceeding the RPS budget.

_Completed 2026-08-17:_ M6-01 through M6-05 are committed and green on PR #4.

## M7 — Scheduling

- [ ] `M7-01` `schedules` model + APScheduler on the Postgres job store
- [ ] `M7-02` Postgres advisory-lock single-leader guarantee
- [ ] `M7-03` Schedule CRUD UI with timezone + next-run preview
- [ ] `M7-04` Tests: no double-execution with two workers running; misfire handling

**Done when:** a nightly OU scan and a weekly domain scan run unattended.

## M8 — Notifications

- [ ] `M8-01` SMTP sender with STARTTLS/TLS; MailHog wired for dev
- [ ] `M8-02` Templates — **no credentials or masks in the body**, portal link only
- [ ] `M8-03` Targeting by user / OU / domain / selection; preview → explicit confirm
- [ ] `M8-04` Per-user cooldown + `dedupe_key` unique index; `NOTIFY_DRY_RUN` defaults on
- [ ] `M8-05` Automatic notification on new unremediated findings; scheduled digest job
- [ ] `M8-06` Tests: dry-run sends nothing, double-submit sends once, cooldown honoured,
      **no password material in any rendered body**

**Done when:** SOC can mail all users with unremediated leaks, by any of the four targeting modes.

## M9 — Watchlist & SIEM alerts

- [ ] `M9-01` **Verify the live Wazuh and DFIR-IRIS API contracts against the real instances first** —
      do not write the mapping from documentation alone
- [ ] `M9-02` `AlertSink` interface + `alert_outbox` with retry and dead-lettering
- [ ] `M9-03` Wazuh sink: API `/events` with JWT auth from `/security/user/authenticate`; syslog fallback
- [ ] `M9-04` DFIR-IRIS sink: `/alerts/add`, finding → alert mapping including the email as an IOC
- [ ] `M9-05` `watchlist` model + UI with per-entry channel toggles
- [ ] `M9-06` Fan-out on new / re-leaked findings for watchlisted subjects
- [ ] `M9-07` "Send test alert" admin action; tests with mocked sinks incl. total-outage path

**Done when:** a new leak on a watchlisted VIP mails SOC + user and lands in both SIEMs.

## M10 — Hardening & operations

- [ ] `M10-01` Admin UI: role assignment, integration config, quota display, session revocation
- [ ] `M10-02` Audit-log viewer with filters
- [ ] `M10-03` Key-rotation CLI (`reencrypt`) + documented procedure
- [ ] `M10-04` Backup/restore runbook, noting the DB holds encrypted credentials
- [ ] `M10-05` Deployment doc: reverse proxy, TLS, egress allow-list, secret provisioning
- [ ] `M10-06` Full security review pass (`/security-review`) + threat-model doc

**Done when:** the app is deployable by someone other than its author from the runbook alone.

---

## Open items to confirm with the SOC team

- [x] `Q-01` ~~Actual RPS ceiling on the Enterprise key~~ — **measured 2026-08-14: 3 requests per
      1 second, hard.** Quota is 1,000,000 units and **only queries that return results cost anything**,
      so throughput, not quota, is the binding constraint. See [`API-NOTES.md`](API-NOTES.md).
- [ ] `Q-01b` Confirm the quota **reset period** (daily / monthly / one-off) — the API exposes no reset
      field and the docs don't state one. Check the dashboard or contract; our own recorded `quota`
      history will also reveal it within a few days.
- [ ] `Q-01c` **Rotate the LeakCheck API key before production.** The current key was pasted into a chat
      transcript during planning. It is not in the repo and must never be committed; enter the rotated
      value only through encrypted Platform Settings.
- [ ] `Q-02` Workspace domain allow-list for the `hd` claim, and which admin the service account impersonates
- [ ] `Q-03` SOC distribution address for alert emails
- [ ] `Q-04` Wazuh manager URL + DFIR-IRIS URL, customer ID, and API credentials
- [ ] `Q-05` Retention policy — how long findings are kept after remediation (nothing is auto-deleted today)
