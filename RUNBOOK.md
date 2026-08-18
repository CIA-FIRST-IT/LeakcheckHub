# LeakCheckHub operations runbook

Everything an operator needs to run this portal without its author. Read
[PORTAINER.md](PORTAINER.md) first for the initial deployment.

## What the database holds

Treat the PostgreSQL volume as credential material, not as ordinary application data. It contains:

- Breach passwords, encrypted with AES-256-GCM under the root data key.
- Every platform integration secret (LeakCheck API key, Google client secret, service-account JSON,
  SMTP password, Wazuh and DFIR-IRIS credentials), encrypted under the same key.
- Super-admin Argon2id password hashes and encrypted TOTP seeds.
- Subject email addresses, usernames, phone numbers, and breach origins in cleartext. These are not
  encrypted: they are the search keys the portal exists to query.

A database dump alone is not readable without the root data key. A database dump **plus** the
bootstrap-secret volume is a complete compromise. Store them with different access control.

## 1. Backup

Two volumes must be captured together and kept consistent with each other:

| Volume | Holds | Losing it means |
| --- | --- | --- |
| `leakcheck_postgres-data` | all application data | total data loss |
| `leakcheck_bootstrap-secrets` | DB passwords, session secret, root data key | surviving data is undecryptable |

A backup of one without the other is worthless. Back them up in the same job, to the same
retention schedule.

### Logical backup (preferred)

```sh
docker compose exec postgres pg_dump -U postgres -Fc leakcheck > leakcheck-$(date +%F).dump
docker run --rm -v leakcheck_bootstrap-secrets:/secrets -v "$PWD":/out alpine \
  tar czf /out/leakcheck-secrets-$(date +%F).tgz -C /secrets .
```

Encrypt both artefacts at rest. The second file is the root data key in cleartext.

### Volume snapshot

Stop the stack first — a copy of a running PostgreSQL data directory is not crash-consistent:

```sh
docker compose stop web
docker compose stop postgres
# snapshot both named volumes with your storage tooling
docker compose start postgres web
```

### Verify

An unverified backup is not a backup. Quarterly, restore into a scratch stack and confirm the portal
starts, an analyst can sign in, and one known finding decrypts.

## 2. Restore

1. Deploy the stack, then stop `web` so migrations do not race the restore.
2. Restore the bootstrap-secret volume **first**. Without the original data key the restored
   database is unreadable.
   ```sh
   docker run --rm -v leakcheck_bootstrap-secrets:/secrets -v "$PWD":/in alpine \
     tar xzf /in/leakcheck-secrets-YYYY-MM-DD.tgz -C /secrets
   ```
3. Restore the database:
   ```sh
   docker compose exec -T postgres pg_restore -U postgres -d leakcheck --clean --if-exists \
     < leakcheck-YYYY-MM-DD.dump
   ```
4. Start `web`. It runs any outstanding migrations on boot.
5. Confirm `/healthz`, sign in, and reveal one known password to prove the data key matches.

If step 5 fails to decrypt, the bootstrap-secret volume does not match the database. Stop and find
the matching secret backup rather than rotating the key, which cannot repair a mismatch.

## 3. Rotating the root data key

Rotate on a suspected key disclosure, on operator turnover, or on a schedule your policy sets.
The command rewrites finding passwords, platform settings, and TOTP seeds in one transaction.

**Take a backup first.** An interrupted rotation is recoverable only from that backup.

The command prompts for the new key twice and never accepts it as an argument, so it does not
enter shell history or the process list. Use an interactive terminal (`-it`).

```sh
# 1. Generate a replacement key and record it in your secret store first.
docker compose exec web python -m app.reencrypt --generate

# 2. Rehearse. Decrypts and re-encrypts everything, then rolls back without writing.
docker compose exec -it web python -m app.reencrypt --dry-run

# 3. Stop the application so nothing writes ciphertext under the old key mid-rotation.
docker compose stop web

# 4. Rotate for real.
docker compose run --rm -it web python -m app.reencrypt

# 5. Install the new key, then restart. Paste the key at the prompt rather than in the command.
docker run --rm -it -v leakcheck_bootstrap-secrets:/secrets alpine \
  sh -c "read -r k && printf '%s\n' \"$k\" > /secrets/data-key && chmod 0444 /secrets/data-key"
docker compose start web
```

If the dry run reports any failure it writes nothing and exits non-zero. That means the current key
does not match the stored ciphertext — investigate before going further; a real rotation would only
report the same failure and roll back.

After rotating, verify by revealing one known password, then destroy old copies of the previous key,
including old bootstrap-secret backups whose retention has lapsed.

## 4. Routine operations

**Create the first super-admin** (once, after the first deployment):

```sh
docker compose exec web python -m app.create_superadmin --email admin@example.org \
  --display-name "SOC Admin"
```

It prompts twice for a 15+ character password and creates a password-only account. Sign in with it,
then enroll MFA from **Account security**, which shows a QR code and a manual key. TOTP is required
at every subsequent sign-in for that account.

**Offboarding.** In `/admin/settings`, clear the user's Active checkbox and press Sign out to revoke
every live session. Deactivation alone does not end sessions already issued.

**Suspected account compromise.** Sign the account out, deactivate it, then read `/admin/audit`
filtered by that actor's email to establish what was accessed. Password reveals appear as
`finding.password_viewed`.

**Quota.** `/admin/settings` shows the most recent observation. It lags one request, and queries that
return nothing cost nothing, so throughput rather than quota is the binding constraint.

## 5. Health and troubleshooting

| Symptom | Cause | Action |
| --- | --- | --- |
| `/healthz` fails | web cannot reach PostgreSQL | check `postgres` health and the `database` network |
| Google sign-in returns 503 | Google settings incomplete | finish the Google panel in `/admin/settings` |
| Batch scans never progress | in-process worker stopped | check `web` logs for `batch worker crashed`; it restarts every 5s |
| Reveal fails on every finding | data key does not match the database | restore the matching bootstrap-secret volume |
| Stack fails on `init` | bootstrap-secret volume unwritable | read the container log; it names the remedy |
