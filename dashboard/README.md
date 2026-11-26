# TENET AI — SOC console

The analyst surface: live interceptions, triage queue, alert feed and service
health. React 19 + TypeScript + Vite, charts on recharts.

Design tokens, type scale and component rules live in
[`../docs/DESIGN_SYSTEM.md`](../docs/DESIGN_SYSTEM.md). Read that before changing
anything visual.

## Run

```bash
npm install
# the console sends this key to the ingest API — use the same value as API_KEY in ../.env
API_KEY=$(sed -n 's/^API_KEY=//p' ../.env); printf 'VITE_API_KEY=%s\n' "$API_KEY" > .env.local
npm run dev          # http://localhost:5174
```

## Sign-in

Analysts sign in with Google (Identity Services). Set the OAuth *web* client id
in `dashboard/.env.local`:

```bash
printf 'VITE_GOOGLE_CLIENT_ID=%s\n' '<id>.apps.googleusercontent.com' > .env.local
```

Authorised JavaScript origins must include `http://localhost:5174` for dev and
your console origin in production. Without the variable the console falls back
to the local credential form (`analyst@tenet.ai` / `password123`), which is what
the e2e suite uses.

The console decodes the ID token to greet the analyst; **the API must verify the
token server-side and decide who may read events.** A Google account is proof of
identity, not of authorisation. See [`../docs/DESIGN_SYSTEM.md`](../docs/DESIGN_SYSTEM.md#sign-in).

Sign-ins are recorded server-side by the ingest service and counted in **System
health** (`/v1/signins/stats`). See [`../docs/signin-log.md`](../docs/signin-log.md).

With no backend running the console falls back to `src/data/mockEvents.ts`, so it
is usable offline.

## Views

| View | What it answers |
| --- | --- |
| Overview | Is anything on fire, and what does the last 24 h look like? |
| Triage queue | Which alert do I work next, and what is its evidence? |
| Alert feed | The raw stream, newest first. |
| System health | Are ingest and analyzer reachable, and what is in the buffer? |

The queue is keyboard-first: `j`/`k` move, `a` acknowledge, `f` false positive,
`r` resolve, `/` filter, `g` switch view, `?` shortcuts.

## Layout

```
src/
  App.tsx                 shell, data polling, filters, exports
  components/
    Rail.tsx TopBar.tsx   console chrome
    OverviewView.tsx      KPIs, SLA strip, charts, feed, health
    TriageView.tsx        queue + filters + detail
    DetailPane.tsx        investigation tabs and workflow actions
    AlertDetailModal.tsx  full-screen investigation
    LoginView.tsx         analyst sign-in (Google + local credentials)
    GoogleSignIn.tsx      Google Identity Services button
    charts/               recharts panels, one skin
  styles/console.css      design tokens + console chrome
  styles/product.css      product-only surfaces (sign-in, modal, filters, charts)
  utils/alerts.ts         severity, SLA and age derivations
```

## Scripts

```bash
npm run dev        # dev server on :5174
npm run build      # tsc -b && vite build
npm run lint       # eslint
npm test           # vitest
```
