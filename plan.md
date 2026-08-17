# LeakCheck SOC Portal — Implementation Plan

> Design record. Work items with stable IDs live in [`TODO.md`](TODO.md).

## Context

The team has a LeakCheck **Enterprise** account, but the vendor portal permits only one concurrent
interactive session — so the SOC team cannot use it in parallel. We do have an API key, which has no
such restriction.

This project wraps that API key in a small self-hosted web app so that:

- The whole SOC team works concurrently against one key, with per-analyst attribution and audit.
- Results are **cached in our own database**, so we stop burning quota re-querying the same subjects,
  and we gain history the vendor portal does not give us (what was new, when, who remediated it).
- End users can self-serve a check against **their own** email only, and mark their own results fixed.
- Breach exposure becomes a tracked, closeable workflow (remediation state) rather than a one-off lookup.

The dataset is about as sensitive as it gets — cleartext credentials for our own staff. **Security
constraints outrank feature completeness everywhere in this plan.** The corresponding design rule is
deliberate minimalism: one service, one database, a small dependency set, no JS build chain. Every
module added is attack surface, so the plan below adds none that aren't load-bearing.

### Confirmed decisions

| Decision | Choice |
|---|---|
| Stack | Python 3.12 · FastAPI · SQLAlchemy + Alembic · PostgreSQL 16 · Jinja2 + HTMX (no npm) |
| Password storage | AES-256-GCM envelope encryption, decrypt-on-view, every decryption audit-logged |
| Google Workspace | Service account + domain-wide delegation, Directory API **read-only** |
| Outbound email | Configurable SMTP relay |

---

## 1. Architecture

One FastAPI application, two entrypoints from the **same image**:

```
web/     uvicorn — HTTP, sessions, UI, API                (N replicas)
worker/  scheduler + scan queue drainer                   (exactly 1, enforced by PG advisory lock)
postgres/                                                  (single source of truth, incl. job store)
```

No Redis, no Celery, no message broker. The scan queue is a Postgres table drained with
`SELECT ... FOR UPDATE SKIP LOCKED`; the scheduler is APScheduler with a SQLAlchemy job store. This
removes an entire network service and its auth surface from the deployment.

```
app/
  main.py            # app factory, middleware, security headers, router mounting
  config.py          # bootstrap-only DB/session/root-key configuration
  platform_settings.py # encrypted DB-backed integration configuration
  db.py              # engine, session dependency
  models.py          # all SQLAlchemy models (single file — the schema is ~12 tables)
  security.py        # RBAC dependencies, CSRF, crypto (AES-GCM), argon2, masking
  auth/
    google.py        # OIDC auth-code + PKCE, id_token verification, hd-claim check
    local.py         # super-admin username+password+TOTP
    session.py       # server-side session issue/verify/revoke
  leakcheck.py       # the only outbound LeakCheck client; rate limiter + pagination
  ingest.py          # normalize -> fingerprint -> upsert -> new/re-leak detection   <-- core
  scans.py           # scan orchestration, queue, batch expansion
  google_ws.py       # Directory API: list OUs, list users, sync into `users`
  notify.py          # SMTP templates, cooldowns, bulk preview/confirm
  alerts.py          # AlertSink: Wazuh + DFIR-IRIS, retry + dead-letter
  jobs.py            # schedule definitions, worker loop
  routers/
    analyst.py  user.py  admin.py  auth.py  health.py
  templates/   static/   (HTMX + a single hand-written CSS file, both vendored)
tests/
migrations/
```

---

## 2. Data model

Twelve tables. The ones that carry the design are `findings` and `finding_events`.

**`users`** — `id, email (citext unique), google_sub (unique, nullable), display_name, ou_path,
role (user|analyst|super_admin), is_active, source (google|workspace_sync|manual), created_at, last_login_at`

**`admin_credentials`** — `user_id FK, password_hash (argon2id), totp_secret_enc, failed_attempts, locked_until`.
Separate table so the ordinary user path never loads a hash.

**`sessions`** — `id_hash (sha256 of the 256-bit opaque token), user_id, created_at, expires_at,
last_seen_at, idle_expires_at, ip_hash, ua_hash, revoked_at`. Tokens are never stored in plaintext.

**`subjects`** — the scannable thing. `id, kind (email|domain|username|phone|origin|password),
value_norm (unique with kind), value_display, first_scanned_at, last_scanned_at, linked_user_id`.
Normalization is per-kind and total: emails lowercased and NFKC'd, domains punycoded and lowercased,
phones to E.164 digits. `value_norm` for `kind='password'` stores **only** a SHA-256 — a searched
password is never persisted in the clear.

**`scans`** — `id, subject_id, requested_by, trigger (manual|self|batch|scheduled), status, started_at,
finished_at, result_count, new_count, truncated, error`.

**`breach_sources`** — deduplicated source catalog: `id, name, breach_date, unverified, passwordless,
compilation, extra jsonb`. Unique on `(name, breach_date)` with `breach_date` normalized to a sentinel
rather than `NULL`, because Postgres treats `NULL`s as distinct in a unique index and would otherwise
create a new source row on every single ingest.

Live data contains a great many records with `source.name = "Unknown"` and `breach_date = null` — this
is common, not an edge case. All of those collapse into **one** `Unknown` source bucket, which is the
behaviour we want: it means a given `(person, password)` pair from unattributed dumps dedups to a single
finding instead of accumulating duplicates forever. The consequence to accept knowingly is that an
`Unknown` finding cannot participate in per-breach re-leak detection (there is no breach date to
distinguish old from new) — such findings dedup purely on the password, which §3 handles.

**`findings`** — one row per distinct exposure. Columns:
`id, subject_id, source_id, email, username, phone, origin,
password_ciphertext (bytea, nullable), password_nonce, password_sha256, password_mask, password_len,
password_charset, fields jsonb, raw jsonb, fingerprint (unique), severity,
first_seen_at, last_seen_at, remediated_at, remediated_by, remediation_note,
superseded_by_id, notified_at`

**`finding_events`** — append-only history:
`finding_id, event (discovered|remediated|unremediated|re_leaked|password_viewed|notified|alerted), actor_id, at, meta jsonb`

**`audit_log`** — append-only: `actor_id, action, target_type, target_id, ip_hash, at, meta jsonb`.
The app's DB role has `INSERT` only on this table and on `finding_events` — `UPDATE`/`DELETE` are
revoked in Postgres, so tampering requires DB-admin credentials the app does not hold.

**`watchlist`** — `subject_id|user_id, alert_soc, alert_user, alert_wazuh, alert_iris, enabled, created_by`.
For senior leadership / high-value accounts.

**`schedules`** — `id, kind (workspace_sync|scan_ou|scan_domain|scan_watchlist|digest), target,
cron, timezone, enabled, last_run_at, next_run_at, created_by`.

**`notifications`** — `id, user_id, template, finding_ids int[], sent_at, status, error,
dedupe_key (unique)`.

**`scan_queue`** — `id, subject_id, batch_id, priority, state, attempts, locked_by, locked_at`.

**`alert_outbox`** — `id, sink (wazuh|iris), payload jsonb, attempts, next_attempt_at, state, last_error`.
A down SIEM must never block or fail a scan.

---

## 3. The dedup / remediation engine (`ingest.py`)

This is the heart of the app and the part worth getting exactly right, because it encodes the
Bob-and-Canva rule the SOC will rely on.

**Fingerprint** — a SHA-256 over a canonical, length-prefixed tuple:

```
fingerprint = sha256(
    subject.kind, subject.value_norm,
    source.name_norm, source.breach_date_norm,
    identity_email_norm, identity_username_norm, identity_phone_norm,
    password_sha256 or b'\x00' * 32          # <-- password identity is PART of the fingerprint
)
```

Ingest is a single idempotent statement:

```sql
INSERT INTO findings (...) VALUES (...)
ON CONFLICT (fingerprint) DO UPDATE
   SET last_seen_at = now(), raw = EXCLUDED.raw
RETURNING id, (xmax = 0) AS is_new;
```

The behaviour that falls out of this:

| Situation | Fingerprint | Result |
|---|---|---|
| Re-scan, same leak, same password | identical | `last_seen_at` bumped. **Remediation preserved.** No alert. |
| Canva 2019, Bob marks remediated | — | `remediated_at` set, event logged |
| Canva **2026** breach, Bob's **new** password leaks | different (new breach_date **and** new password hash) | **new row, `remediated_at = NULL`** — a fresh unremediated finding |
| Same source/date, password changed in the dataset | different (password hash differs) | new row; linked to the old one as a re-leak |
| Passwordless leak (no credential in dump) | password component = zero sentinel | still distinct per breach date |
| Unattributed dump (`source.name = "Unknown"`, no date) | source component is the `Unknown` sentinel | dedups on password alone — same password from many unknown dumps is **one** finding, not dozens |

**Re-leak detection** — after insert, if `is_new` and a prior finding exists with the same
`(subject_id, source_id, identity)` but a different `password_sha256` **and** that prior finding was
remediated, then: set `prior.superseded_by_id = new.id`, write a `re_leaked` event, and mark the new
finding `severity = high`. "Remediated, then leaked again" is the single highest-signal state in the
system — it gets its own UI filter and is a default alert trigger.

Only rows where `is_new` is true feed notifications and alerts. That is what makes re-scanning cheap
and silent, satisfying "subsequent scans only update the DB with new info".

**Password handling at ingest:**

1. Compute `password_sha256` (for fingerprinting and for cross-user password-reuse queries).
2. Compute `password_mask`, `password_len`, `password_charset` — server-side, stored as plain columns.
3. Encrypt cleartext with AES-256-GCM; AAD binds the ciphertext to `finding.id` so it cannot be
   relocated between rows. Key comes from env (`LC_DATA_KEY`), never the DB.
4. Discard cleartext from memory. It is never logged and never enters a Jinja context except on the
   explicit analyst decrypt route.

**Mask format** — `first 2 chars + • × (len-3) + last char`, e.g. `Pa••••••3`; under 6 chars, first
char only. Plus length and charset class ("lower+digits"). Enough for a user to recognise which
password of theirs it is; not enough to reconstruct it.

---

## 4. LeakCheck client (`leakcheck.py`)

Single module, single outbound host. **The behaviour below was measured against our live Enterprise
key on 2026-08-14, not taken from the docs** — several documented behaviours do not hold, and two of
the deviations are silent-false-negative hazards. See [`API-NOTES.md`](API-NOTES.md) for the raw probe
results.

- `GET https://leakcheck.io/api/v2/query/{quoted_query}` with header `X-API-Key`, `Accept: application/json`.
- `type` is **always explicit** — never rely on auto-detect.
- Exposed types, mapped 1:1 to the six checks: `email`, `domain`, `username`, `phone`, `origin`, `password`.
  (`phash` and `keyword` are wired in the client but not exposed in the UI initially.)

### Rate limit — measured: 3 requests per 1 second, hard

Bursts of 5/10/20 concurrent all yielded **exactly 3 × HTTP 200** and the rest 429. Sustained 3/sec for
6 seconds gave 18/18 success. The 429 body states the rule outright:
`{"success": false, "error": "Reached allowed limit 3 hits per 1 second!"}`.

There is **no `Retry-After` and no `X-RateLimit-*` header** — Cloudflare fronts the API and exposes
nothing. The client must therefore self-pace rather than react: a token bucket of 3/sec is the
authority, with 429 handling as a backstop, not the primary mechanism. `LEAKCHECK_RPS` stays
configurable in case the plan is upgraded, but 3 is the real current ceiling.

**Consequence for batch scans:** 3 RPS is ~10,800 lookups/hour at best, and slow queries push the real
figure well below that. A 5,000-user OU scan takes roughly 30–90 minutes. Batch scans must be
background jobs with progress reporting — never a request-scoped operation.

### Quota — measured: only queries that return results cost anything

The key currently reports **999,986 remaining of an apparent 1,000,000**. Measured cost model:

| Request | Cost |
|---|---|
| Query returning ≥1 result | **1** |
| Query returning `found: 0` | **0** — five distinct misses left the counter unmoved |
| HTTP 429 (rate-limited) | 0 |
| 4xx errors (bad type, bad limit, bad key) | 0 |

The counter also **lags one request behind** — the `quota` in a response reflects state before that
request is billed. So quota must be read as approximate, and never used for a hard pre-flight check.

This inverts the economics assumed earlier in planning: **scanning clean users is free.** A domain-wide
or OU-wide sweep costs only as many units as it finds actual exposures, so quota is not a meaningful
constraint on scan frequency — the 3 RPS ceiling is. The reset period (daily vs monthly vs one-off
allotment) is **not exposed by the API** and is not in the public docs; it needs confirming on the
dashboard or contract. The app records `quota` on every scan, so the reset cadence will be evident from
our own history within a few days regardless.

### Pagination — per-type, and it does not work the way the docs say

The documented "`limit` ≤1000, `offset` ≤2500, applies to all types" is wrong. Measured:

| | `type=email` | `type=domain` |
|---|---|---|
| `limit` | **Ignored.** Returns the full set every time (1362 results with `limit=1`, `=5`, `=1000`) | **Works.** 1–1000 valid; ≥1001 → `400 Invalid limit` |
| `offset` | **Dangerous.** `offset=1000` on a 1362-result subject returns `found: 0` | Works — returns a distinct page |
| `found` | True total for the subject | **Only the size of the returned page**, not the total |

Two rules fall out, and both are enforced by tests:

1. **Never send `offset` on an email query.** It returns `found: 0`, which is indistinguishable from
   "this person has no leaks" — a silent false negative on the single most important query type in the
   app. The client rejects the combination at the type level rather than trusting callers.
2. **For domain queries, `found` cannot tell you when to stop.** Page with `limit=1000` and increasing
   `offset` until a short or empty page comes back; the true total is unknowable up front, so
   `scans.truncated` is set from the paging loop's own termination, not from a `found` comparison.

### Response size and latency — the real operational constraint

Measured on single email lookups: `test@example.com` → 1,362 records in 6.4 s; `admin@example.com` →
**8,240 records, 2.68 MB, 28.7 seconds**. One common-alias query can therefore produce thousands of
findings and a multi-megabyte body.

- Per-request timeout of **120 s**, not the usual 10–30 s. An aggressive timeout would fail exactly on
  the highest-value queries.
- A hard response-size cap (default 32 MB) that fails loudly rather than exhausting memory — the body
  is attacker-influenced in size.
- Ingest processes results in batches so an 8,000-record response doesn't build one giant transaction.
- The UI must show progress/pending state on analyst checks; a 30-second synchronous request needs
  HTMX polling against the `scans` row, not a blocked page load.

### Error shapes (measured)

| Condition | Status | Body |
|---|---|---|
| Bad key | 401 | `{"success": false, "error": "Invalid X-API-Key"}` |
| Bad `type` | 400 | `{"success": false, "error": "Invalid type"}` |
| `limit` ≥ 1001 | 400 | `{"success": false, "error": "Invalid limit"}` |
| Rate limited | 429 | `{"success": false, "error": "Reached allowed limit 3 hits per 1 second!"}` |

Errors are JSON with `success: false` and a human-readable `error`. The client maps 401 to a loud
config alarm (the key is wrong — page someone), 400 to a bug (never surfaced to end users), and 429 to
backoff.

### Response shape (observed)

Top level: `success`, `quota`, `found`, `result[]`. Each result: `password`, `email`, `fields[]`, and
`source{name, breach_date, unverified, passwordless, compilation}`. Note that `source.name` is
frequently the literal **`"Unknown"`** and `breach_date` is frequently **`null`** — see §2 for how the
schema handles that.

**Tolerant parsing** stays the rule: parse known fields into columns, always retain the whole record in
`findings.raw`. Enterprise returns more fields than the public docs describe, and the docs were wrong
about pagination, so treating the documentation as authoritative is not safe.

**Password check caveat, to be surfaced in the UI:** `type=password` transmits a cleartext password to
a third party. It is restricted to Analyst+, is audit-logged with the actor, and the entered value is
persisted only as a SHA-256. The UI will recommend `phash` where the analyst already has a hash.

---

## 5. AuthN / AuthZ

**Google Sign-In (everyone except Super Admin)** — OIDC authorization-code flow with PKCE, `state`, and
`nonce`. The `id_token` is verified against Google's JWKS (signature, `iss`, `aud`, `exp`, `nonce`), and
the `hd` claim is checked against an allow-list of our Workspace domains. Implicit flow and Google One
Tap are not used. First sign-in auto-provisions a `User`; role elevation is always manual.

**Super Admin** — username + password (argon2id) **plus mandatory TOTP**, seeded by a CLI command, never
self-registerable. Constant-time comparison, per-account lockout, per-IP rate limit, and a distinct
audit action so any super-admin login is trivially alertable.

**Sessions** — opaque 256-bit token in an `HttpOnly; Secure; SameSite=Lax` cookie; only its SHA-256 is
stored. Rotated on privilege change and on login. Idle expiry (default 60 min) and absolute expiry
(default 12 h). Server-side revocation, plus "revoke all sessions" for admins.

**RBAC** — three roles, deny-by-default:

| | User | Analyst | Super Admin |
|---|---|---|---|
| Check own email | ✅ | ✅ | ✅ |
| Mark own findings remediated | ✅ | ✅ | ✅ |
| See own password | masked only | masked only | masked only |
| All six check types, any subject | — | ✅ | ✅ |
| Full cleartext passwords + all details | — | ✅ | ✅ |
| Batch/OU/domain scans, schedules | — | ✅ | ✅ |
| Send notifications | — | ✅ | ✅ |
| Watchlist + alert config | — | ✅ | ✅ |
| Role assignment, integrations, audit log | — | — | ✅ |

Enforcement is a FastAPI dependency (`require_role(...)`) on every router, and a test enumerates
`app.routes` asserting each non-public route carries an explicit guard — so a forgotten decorator fails
CI rather than shipping.

**Blank-slate configuration** — LeakCheck, Google OIDC, Workspace, SMTP, Wazuh, DFIR-IRIS, SOC mail,
and other operational integrations are configured by a Super Admin in the application. Values are
AES-256-GCM encrypted in `platform_settings`; secrets are write-only in the UI. Only pre-database
bootstrap material (database access, session signing, the root encryption key, and host boundary)
remains deployment configuration.

**The structural anti-IDOR guarantee:** the self-service endpoint accepts **no identifier parameter at
all**. It reads the email from the session and derives the subject server-side. There is nothing to
tamper with. User-facing serializers live in a separate module from analyst serializers and have no code
path that touches `password_ciphertext` — the separation is enforced by a test that greps the user
serializer's output for cleartext.

---

## 6. Google Workspace integration (`google_ws.py`)

Service account with domain-wide delegation, impersonating a dedicated read-only admin. Scopes:
`admin.directory.user.readonly`, `admin.directory.orgunit.readonly` — nothing else, so the credential
cannot mutate the directory even if stolen. Key file path from env, mode 600, mounted read-only.

- `list_org_units()` → OU tree for the scan-target picker.
- `list_users(ou_path, include_suspended=False)` → sync into `users` (email, name, `ou_path`, active).
- Sync is additive: users vanishing from Workspace are marked inactive, never deleted, so their finding
  history survives offboarding.
- Runs on demand and on a schedule.

---

## 7. Batch scans & scheduling

A batch expands to rows in `scan_queue`; the worker drains it inside the global rate limit, so a
5,000-user OU scan degrades gracefully instead of tripping 429s. Batch progress (queued / running /
done / failed) is a live HTMX-polled view.

Schedulable jobs: `workspace_sync`, `scan_ou`, `scan_domain`, `scan_watchlist`, `digest`. Cron
expressions with an explicit timezone. Single-worker execution is guaranteed by a Postgres advisory
lock, so scaling the web tier can never double-run a job.

---

## 8. Notifications (`notify.py`)

Targeting: **by user**, **by OU**, **by domain**, or **by explicit selection**. Trigger modes: manual
(with preview), automatic (on new finding for a watchlisted subject), and scheduled digest.

Guardrails, because this is a system capable of mass-mailing the entire company:

- Bulk sends are always **preview → explicit confirm**, showing the exact recipient count.
- Per-user cooldown (default 7 days) plus a `dedupe_key` unique index — a retry or a double-click cannot
  double-send.
- Global `NOTIFY_DRY_RUN` defaults to **true**; a super admin flips it once the templates are verified.
- **Emails never contain passwords, masks, or breach specifics.** They state that exposure was found and
  link to the portal, which requires Google sign-in. Mail is not a trusted channel and must not become
  an offline copy of the credential database.
- Every send writes an audit row and a `notified` finding event.

---

## 9. Alerts: Wazuh & DFIR-IRIS (`alerts.py`)

A common `AlertSink` interface with two implementations, both fully configurable endpoints, both
routed through `alert_outbox` with retry and dead-lettering so an unreachable SIEM degrades to a queued
alert rather than a failed scan.

- **Wazuh** — `POST {WAZUH_API_URL}/events` authenticated by JWT obtained from
  `/security/user/authenticate`. Syslog output to the local agent is implemented as a fallback for
  deployments where the API route isn't available.
- **DFIR-IRIS** — `POST {IRIS_URL}/alerts/add` with `Authorization: Bearer {IRIS_API_KEY}`, mapping the
  finding to alert title/description/severity/source, with the raw record as source content and the
  affected email as an IOC.

Both endpoint contracts are **verified against the live instances as the first task of M9** before the
mapping is written — the exact field sets vary by version, and guessing them is how integrations
silently drop alerts. A "send test alert" button in the admin UI is part of the deliverable.

Trigger: a new (or re-leaked) finding for any watchlisted subject fans out to SOC email, user email,
Wazuh, and IRIS per that watchlist entry's toggles.

---

## 10. Security baseline (applies to every milestone)

- CSRF: `SameSite=Lax` + double-submit token on all state-changing requests.
- CSP with no `unsafe-inline` (HTMX and CSS are vendored locally, not CDN-loaded), HSTS,
  `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`.
- All SQL through SQLAlchemy bound parameters; no string-built SQL anywhere.
- **Breach data is attacker-controlled input.** Jinja autoescape on, no `|safe` on any leak-derived
  field, and a test that ingests XSS/template-injection payloads in every breach field and asserts the
  rendered output is inert.
- Rate limits on login, self-check, and every scan endpoint.
- Secrets from env only: `LC_DATA_KEY`, `LEAKCHECK_API_KEY`, SMTP creds, service-account path, SIEM
  tokens. Startup fails loudly if any are missing or if `LC_DATA_KEY` is the dev default.
  A documented key-rotation procedure with a re-encrypt CLI command.
- Two DB roles: a migration role that owns the schema, and a runtime role with no DDL and no
  `UPDATE`/`DELETE` on the append-only tables.
- Structured logging with a redaction filter for password fields, plus a test asserting a known
  cleartext never appears in captured logs.
- Container runs non-root with a read-only root filesystem; egress restricted to `leakcheck.io`,
  `googleapis.com`, the SMTP relay, and the two SIEM endpoints.
- CI: `ruff`, `mypy`, `bandit`, `semgrep`, `pip-audit`, hash-pinned requirements, and the full test suite.

---

## 11. Milestones

Each milestone is independently shippable and testable. Work items and their stable IDs are in
[`TODO.md`](TODO.md).

| Milestone | Scope | Done when |
|---|---|---|
| **M0** | Scaffold & security baseline | `docker compose up` serves a hardened empty app; CI green |
| **M1** | Auth & RBAC | All three roles sign in; route-guard-coverage test passes; auth events audited |
| **M2** | LeakCheck client | All six query types return normalized records offline from fixtures |
| **M3** | Data model & ingest engine ← **core** | Bob/Canva scenario passes end to end; re-ingest yields zero spurious findings |
| **M4** | Analyst UI | An analyst can run all six checks and see the complete detail stream |
| **M5** | Self-service user portal | A `User` sees only their own findings, masked, and can close them out |
| **M6** | Workspace sync & batch scans | "Scan every user in OU X" completes within the RPS budget |
| **M7** | Scheduling | A nightly OU scan and a weekly domain scan run unattended |
| **M8** | Notifications | SOC can mail all users with unremediated leaks, by any of the four targeting modes |
| **M9** | Watchlist & SIEM alerts | A new leak on a watchlisted VIP mails SOC + user and lands in both SIEMs |
| **M10** | Hardening & operations | Deployable by someone other than its author from the runbook alone |

---

## 12. Verification

**Per milestone:** `pytest` with a Postgres test container; no test may hit the live LeakCheck API —
all client tests run against recorded fixtures.

**The four tests that matter most** (these encode the requirements that are easiest to regress):

1. **Bob/Canva remediation lifecycle** (`M3-07`) — the exact scenario from the brief, asserted step by step.
2. **Route-guard coverage** (`M1-07`) — enumerates every route and fails if any lacks an explicit role guard.
3. **No-cleartext-to-users** (`M5-05`) — drives the full user flow and asserts a known cleartext password
   appears in no user-facing response, template render, or log line.
4. **Hostile breach data** (`M4-07`) — XSS and template-injection payloads in every breach field render inert.

**End-to-end manual pass before go-live:**

```bash
docker compose up -d && docker compose exec web alembic upgrade head
```

```bash
docker compose exec web python -m app.cli create-superadmin
```

Then, in order: super-admin login with TOTP → configure integrations → Workspace sync and confirm the OU
tree → run one of each of the six checks as an Analyst → reveal a password and confirm the audit row →
sign in as an ordinary user and confirm masked-only, own-email-only → mark remediated → re-scan and
confirm nothing changes → inject a synthetic newer breach with a different password and confirm a fresh
unremediated re-leak finding, a SOC email, a user email, and alerts in both Wazuh and IRIS.

---

## 13. Deliberately out of scope

Not built, to keep the surface small: public/unauthenticated pages, a REST API for third parties,
multi-tenancy, self-service role requests, in-app password resets (Google owns identity), file uploads,
and any CDN-loaded asset.

---

## References

- [LeakCheck API overview](https://docs.leakcheck.io/overview)
- [LeakCheck API v2 Pro](https://wiki.leakcheck.io/en/api/api-v2-pro)
- [LeakCheck official Python wrapper](https://github.com/LeakCheck/leakcheck-api) — authoritative list of query types
