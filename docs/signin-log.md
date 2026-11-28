# Sign-in log

The console is a restricted surface, so every successful sign-in is appended to
a small server-side log. It answers two questions an operator actually asks —
*who has access?* and *is anyone using this?* — without putting a third-party
analytics script in the browser.

## What is stored

One JSON record per sign-in:

```json
{
  "email": "analyst@tenet.ai",
  "provider": "google",
  "role": "SOC Analyst",
  "org_domain": null,
  "at": "2026-11-27T09:14:02.114+00:00",
  "day": "2026-11-27"
}
```

**Nothing else.** No IP address, no user agent, no prompt or event content, no
cookies, no device fingerprint.

Redis keys, when Redis is available:

| Key | Type | Purpose |
| --- | --- | --- |
| `tenet:signins:log` | list | Newest first, capped at 5,000 entries |
| `tenet:signins:accounts` | set | Distinct emails, for the unique count |
| `tenet:signins:day:YYYY-MM-DD` | counter | Daily totals, 400-day expiry |
| `tenet:signins:provider:<name>` | counter | Google vs password |

Without Redis the service keeps the same data in process memory (bounded,
lost on restart) so dev and tests behave the same way.

## Endpoints

```http
POST /v1/signins
X-API-Key: <key with ingest permission>
{"email": "analyst@tenet.ai", "provider": "google", "role": "SOC Analyst"}
→ {"recorded": true, "storage": "redis"}
```

```http
GET /v1/signins/stats?days=7
X-API-Key: <key with read permission>
→ { "window_days": 7, "total": 42, "unique_accounts": 11,
    "by_day": [...], "by_provider": {"google": 38, "password": 4},
    "last_signin": {...} }
```

The console calls both. Recording is fire-and-forget: if the write fails, the
analyst still gets in. The System health view shows the seven-day total, the
accounts, the split by provider and the last sign-in.

## Turning it off

```bash
SIGNIN_LOG_ENABLED=false   # on the ingest service
```

The endpoints stay, they just answer `{"recorded": false, "storage": "none"}`,
and the console panel says the log is switched off.

## Before you use it for marketing

The log exists for access auditing. Using it to email people who signed in is a
different purpose, and in most jurisdictions a different lawful basis:

- **India (DPDP Act 2023)** — consent is required for processing that is not
  necessary for the security purpose; a sign-in log kept for security does not
  automatically cover outreach.
- **EU/UK (GDPR)** — legitimate interest can cover security logging; direct
  marketing to a business email usually needs an opt-out and, in some member
  states, prior consent.
- **Retention** — keep the log as long as you need the audit trail (90 days is a
  common default), then let it go. The daily counters expire after 400 days; the
  log list is capped, not dated, so trim it on a schedule.

Practical middle ground: keep the audit log for security, and add a separate,
clearly labelled opt-in if you want a marketing list.

## Privacy notice on the screen

The sign-in card says it plainly: *"Signing in records your email and the time,
for access auditing."* If you change what you store, change that line too.
