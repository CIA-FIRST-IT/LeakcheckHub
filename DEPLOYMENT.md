# Production deployment

[PORTAINER.md](PORTAINER.md) covers the zero-input stack. This document covers what must be true
around it before the portal handles real breach data.

## 1. Put TLS in front of it

The application speaks plain HTTP on the published port (`8800` by default). It must never be
reachable directly from a user network. Session and CSRF cookies are issued with the `__Host-`
prefix and the `Secure` attribute, so **sign-in does not work over plain HTTP** except on
`localhost` — this is deliberate, not a bug to work around.

Terminate TLS in a reverse proxy on the same host and forward to `127.0.0.1:8800`. Caddy, which
obtains and renews certificates automatically:

```
leakcheck.example.org {
    reverse_proxy 127.0.0.1:8800 {
        header_up X-Forwarded-Proto https
    }
}
```

Equivalent nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name leakcheck.example.org;

    ssl_certificate     /etc/letsencrypt/live/leakcheck.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/leakcheck.example.org/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass         http://127.0.0.1:8800;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_read_timeout 180s;   # large domain queries legitimately run ~30s
    }
}
```

Bind the published port to the loopback interface so the proxy is the only path in. In
`compose.portainer.yaml`, set `LEAKCHECK_HTTP_PORT` and change the mapping to `127.0.0.1:8800:8000`
if your host has other interfaces exposed.

Do not publish PostgreSQL. It sits on an `internal: true` Compose network with no route off the
host, and it must stay there.

## 2. Restrict who can reach it

This is an internal SOC tool. Put it behind whatever your organisation already uses — VPN, an
identity-aware proxy, or a source-address allow-list on the reverse proxy:

```nginx
allow 10.0.0.0/8;
allow 192.168.0.0/16;
deny  all;
```

## 3. Egress allow-list

The application makes outbound connections to a small, fixed set of hosts. Everything else can be
denied at the firewall.

| Destination | Purpose | Required |
| --- | --- | --- |
| `leakcheck.io:443` | breach queries | yes |
| `oauth2.googleapis.com:443`, `accounts.google.com:443`, `www.googleapis.com:443` | Google sign-in and Directory sync | only if Google is configured |
| your SMTP relay | notification email | only if SMTP is configured |
| your Wazuh manager | SIEM alerts | only if Wazuh is configured |
| your DFIR-IRIS instance | case creation | only if IRIS is configured |
| `ghcr.io:443`, `pkg-containers.githubusercontent.com:443` | image pulls, from the Docker daemon | at deploy time |

Only the last row is needed by the host rather than the container. If your network performs TLS
interception, the Docker daemon must trust the interception root or image pulls fail with an x509
error — the daemon reads the system trust store and `/etc/docker/certs.d/`, not a user's browser
trust store.

## 4. Secret provisioning

The zero-input stack generates its own database passwords, session secret, and root data key on
first launch and stores them in the `leakcheck_bootstrap-secrets` volume. That is appropriate for a
single-host deployment where the volume is backed up. See [RUNBOOK.md](RUNBOOK.md).

Where policy requires a managed secret store, do not use the generated path. Deploy with
`compose.yaml` instead and inject these as environment variables from your secret manager:

| Variable | Notes |
| --- | --- |
| `LC_DATABASE_URL` | must use the `postgresql+asyncpg://` scheme |
| `LC_SESSION_SECRET` | 32+ bytes; rotating it signs everyone out |
| `LC_DATA_KEY` | base64url 32 bytes; rotating it requires `app.reencrypt` |
| `LC_TRUSTED_HOSTS` | explicit public hostname allow-list |

`LC_TRUSTED_HOSTS` is the one setting the zero-input stack cannot infer, because it does not know
its own public name before the first request. It ships permissive and relies on the reverse proxy to
enforce the host. If you are not fronting it with a proxy that does so, set an explicit list.

Everything else — LeakCheck, Google, SMTP, Wazuh, DFIR-IRIS — is configured in `/admin/settings`,
encrypted in PostgreSQL, and must not be placed in environment variables.

## 5. Container hardening

Every container drops all Linux capabilities (`cap_drop: ALL`), runs as an unprivileged image
user, and has a read-only root filesystem. PostgreSQL adds back only `CHOWN`, `SETGID`, and
`SETUID`.

`no-new-privileges` is deliberately not set. On the reference host it caused
`exec /usr/local/bin/python: operation not permitted` — the kernel refusing `execve` outright.
Probing each option separately showed `cap_drop: ALL` passes and `no-new-privileges` alone fails,
so the two were not equally at fault and only the failing one is omitted.

That signature is characteristic of an AppArmor profile transition being refused while
`no_new_privs` is set. It appears on hosts running Docker from a snap, Docker nested inside
LXC/LXD, or with a `docker-default` profile that is missing or altered. If your host does not have
that problem, add:

```yaml
security_opt:
  - no-new-privileges:true
```

and confirm the stack still starts. Fixing the host's AppArmor configuration is preferable to
leaving the option off; `docker info` under **Host → Details** in Portainer lists the active
security options.

## 6. Before going live

- [ ] TLS terminating in front of the portal; plain HTTP unreachable from user networks
- [ ] PostgreSQL not published; `database` network still `internal: true`
- [ ] Both named volumes backed up together, and one restore rehearsed ([RUNBOOK.md](RUNBOOK.md))
- [ ] Egress allow-list applied
- [ ] First super-admin created, TOTP enrolled, provisioning URI destroyed
- [ ] LeakCheck API key rotated if it has ever been pasted anywhere outside the portal
- [ ] `/admin/audit` reachable and recording sign-ins
- [ ] A non-production scan run end to end, including one password reveal and one remediation
