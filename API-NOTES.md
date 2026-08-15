# LeakCheck API — measured behaviour

Probed against our live **Enterprise** key on **2026-08-14**. Everything here is empirical. Where it
contradicts the vendor docs, the measurement wins — the published pagination rules in particular are
wrong for this key.

Reproduce with `curl` and the key from `$LEAKCHECK_API_KEY` (never hardcode it):

```bash
curl -sS -H "X-API-Key: $LEAKCHECK_API_KEY" -H 'Accept: application/json' \
  "https://leakcheck.io/api/v2/query/test%40example.com?type=email" | head -c 400
```

## Rate limit: 3 requests per 1 second

| Concurrency in one burst | HTTP 200 | HTTP 429 |
|---|---|---|
| 5 | 3 | 2 |
| 10 | 3 | 7 |
| 20 | 3 | 17 |

Sustained 3 requests/second for 6 seconds: **18/18 succeeded**. The ceiling is a flat 3 per second, not
3 concurrent.

429 body: `{"success": false, "error": "Reached allowed limit 3 hits per 1 second!"}`

**No `Retry-After`. No `X-RateLimit-*` headers.** Response headers are just Cloudflare's
(`server: cloudflare`, `cf-ray`, `cf-cache-status`) plus HSTS. The client must self-pace with its own
token bucket; 429 handling is a backstop only.

Practical throughput: 3 RPS ≈ 10,800 lookups/hour absolute ceiling, less in practice because slow
queries hold slots. Budget ~30–90 min for a 5,000-user OU sweep.

## Quota: only queries that find something cost anything

Key reported **999,986 remaining** at end of probing (apparent allotment 1,000,000).

| Request | Quota cost |
|---|---|
| Query returning ≥1 result | 1 |
| Query returning `found: 0` | **0** |
| HTTP 429 | 0 |
| HTTP 400 / 401 | 0 |

Evidence — five distinct never-before-seen addresses, all missing, counter frozen:

```
missA1z9@example.invalid  quota=999990 found=0
missA2z9@example.invalid  quota=999990 found=0
missA3z9@example.invalid  quota=999990 found=0
missA4z9@example.invalid  quota=999990 found=0
missA5z9@example.invalid  quota=999990 found=0
```

Then five distinct addresses that hit — one unit each:

```
bob@example.com    quota=999990 found=132
alice@example.com  quota=999989 found=44
john@example.com   quota=999988 found=431
admin@example.com  quota=999986 found=8240
info@example.com   quota=999987 found=208
```

**The counter lags one request.** The `quota` in a response reflects the state *before* that request is
billed (visible above: `admin`'s row is out of sequence because the preceding request's bill landed
first). Treat `quota` as approximate; never gate a scan on a pre-flight quota read.

**Implication:** scanning clean users is free, so quota does not constrain scan frequency — the 3 RPS
ceiling does. A domain-wide sweep costs only as many units as it finds real exposures.

**Reset period is unknown.** The API exposes no reset timestamp and the public docs don't state one.
Confirm on the dashboard/contract. We record `quota` on every scan, so our own history will reveal the
cadence within days.

## Pagination differs by type, and the docs are wrong

Docs claim `limit` ≤1000 and `offset` ≤2500 apply generally. Measured against `test@example.com`
(true total 1,362) and `example.com`:

| | `type=email` | `type=domain` |
|---|---|---|
| `limit` | **ignored** — returned all 1362 at `limit=1`, `5`, `10`, `100`, `1000` | **works** — `limit=3`→3, `100`→110, `1000`→1245; `≥1001` → `400 Invalid limit` |
| `offset` | **returns `found: 0`** at `offset=1000` | works — returns a different page |
| `found` | true total for the subject | **size of the returned page only** |

```
type=email                      -> found=1362 ret=1362
type=email&limit=10             -> found=1362 ret=1362
type=email&offset=1000          -> found=0    ret=0     <-- silent false negative
type=email&limit=10&offset=1000 -> found=0    ret=0
```

### Two hard rules for the client

1. **Never send `offset` on an email query.** `found: 0` is indistinguishable from "no leaks" — a silent
   false negative on the most important query type in the app. Reject the combination at the type level;
   don't trust callers.
2. **For domain queries, `found` cannot tell you when to stop.** Page with `limit=1000` and increasing
   `offset` until a short/empty page. The true total is unknowable up front, so `scans.truncated` comes
   from the paging loop's termination, never from comparing against `found`.

Note `limit=100` returning **110** records — `limit` is approximate for domain queries, probably batched
per source. Don't assert exact page sizes in tests.

## Response size and latency

| Query | Records | Body | Time |
|---|---|---|---|
| `test@example.com` | 1,362 | ~440 KB | 6.4 s |
| `test@example.com` (repeat) | 1,362 | ~440 KB | 2.0 s |
| `admin@example.com` | **8,240** | **2.68 MB** | **28.7 s** |
| miss | 0 | 52 B | 0.95 s |

A single common-alias lookup can return thousands of findings and multiple megabytes. Therefore:
per-request timeout **120 s** (a 10–30 s timeout fails precisely on the highest-value queries), a hard
response-size cap that errors rather than exhausts memory, batched ingest, and an async/polled UI for
analyst checks.

## Error shapes

| Condition | Status | Body |
|---|---|---|
| Bad key | 401 | `{"success": false, "error": "Invalid X-API-Key"}` |
| Bad `type` | 400 | `{"success": false, "error": "Invalid type"}` |
| `limit` ≥ 1001 | 400 | `{"success": false, "error": "Invalid limit"}` |
| Rate limited | 429 | `{"success": false, "error": "Reached allowed limit 3 hits per 1 second!"}` |

All errors are JSON with `success: false` and a readable `error`. Map 401 → loud config alarm, 400 →
internal bug (never shown to end users), 429 → backoff.

## Response shape

```json
{
  "success": true,
  "quota": 999986,
  "found": 1362,
  "result": [
    {
      "password": "0844",
      "email": "test@example.com",
      "fields": ["password", "email"],
      "source": {
        "name": "saveonlens.com",
        "breach_date": null,
        "unverified": 0,
        "passwordless": 0,
        "compilation": 0
      }
    }
  ]
}
```

`source.name` is very often the literal `"Unknown"` and `breach_date` very often `null` — common, not an
edge case. Some records carry only `{"name": "Unknown"}` with no other source keys at all, so every
source field must be treated as optional. See `plan.md` §2 for how the schema buckets these.
