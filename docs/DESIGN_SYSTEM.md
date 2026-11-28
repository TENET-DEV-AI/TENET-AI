# TENET AI — design system

One identity for the marketing site and the console. This document is the
contract: if a screen diverges from it, the screen is wrong.

## The idea

TENET is a security instrument, not a SaaS dashboard. The identity borrows from
printed field manuals and instrumentation: warm ink grounds, paper-coloured
type, hairline rules, small mono labels that read like engraved legends — and a
single ember accent that **only ever means threat**.

Three consequences drive every decision:

1. **Ink, not navy.** No blue-grey "security dark mode". The ground is warm black.
2. **Paper type, not neon.** Text is cream, not white; the accent is a hot ember, not red.
3. **One accent, one meaning.** Ember = threat/blocked. Amber = warning/SLA. Sage = safe.
   Nothing else is coloured. If a number is important it is bigger, not brighter.

## Tokens

Defined once in `dashboard/src/styles/console.css` and `landing/src/styles/tenet.css`.

| Token | Value | Use |
| --- | --- | --- |
| `--ink` | `#0C0A09` | App ground, chart wells |
| `--ink-2` | `#131010` | Panels, rail |
| `--ink-3` | `#1A1512` | Raised surfaces, hover |
| `--ink-4` | `#221C18` | Pressed, selected, badges |
| `--paper` | `#EFE9DD` | Primary text, logo on ink |
| `--dim` | `rgba(239,233,221,.56)` | Secondary text |
| `--faint` | `rgba(239,233,221,.34)` | Labels, axes, metadata |
| `--line` | `rgba(239,233,221,.10)` | Hairline borders |
| `--ember` | `#E1593C` | Threat, blocked, primary action |
| `--ember-2` | `#F0704F` | Ember on hover / on ink-2 |
| `--amber` | `#D9A441` | Warning, flagged, SLA pressure |
| sage | `#8FA68E` | Safe, allowed, resolved |

Radii: `6px` controls, `9–10px` panels, `999px` pills. Borders are always `1px`
hairlines — never 2px, never a shadow in place of a border.

## Type

Three families, each with one job:

| Role | Family | Notes |
| --- | --- | --- |
| Display | **Fraunces** (serif, optical sizing) | Headlines and hero numbers only. Never below 20px. |
| Body | **Archivo** | UI text, prose, table cells. |
| Data | **IBM Plex Mono** | Labels, IDs, timestamps, scores, keys. Uppercase at 9–10px with `letter-spacing:.14em` for legends. |

Rules:

- Labels are mono, uppercase, `9–10px`, `--faint`. They are never sentence case.
- Body copy is 12–14px, line-height 1.55.
- Numbers that matter (KPI values) are Fraunces, 28–40px, `letter-spacing:-.02em`.
- Never mix a serif headline with a serif label; labels are always mono.

## Layout

- Console: `228px` rail + fluid main. Views stack at `12px` gutters.
- Marketing: `1180px` max content width, 12-column grid, generous vertical rhythm (`§` numbered sections).
- Panels: header (title + right-aligned mono label), body, optional footer action bar.
- Every table row and list item is a hairline-separated rule, not a card.

## Components

| Component | Rule |
| --- | --- |
| `.stat` | Label (mono) → value (Fraunces) → delta (12px). Sparkline sits right, 76×26, stroke `--dim` or ember. |
| `.panel` | Hairline border, `--ink-2`, header with mono label right-aligned. |
| `.att` | Attention card: 2px ember bar on the left edge, title + mono meta, `triage` affordance right. |
| `.qitem` | Queue row: 3px severity bar, title, meta badges, hover reveals nothing (actions stay visible — analysts use keyboards). |
| `.badge` | Mono, uppercase, 9px. Status colour comes from the workflow class, not the label. |
| `.abtn` | Mono, uppercase, 9.5px, hairline border. `.primary` is ember fill — one per view. |
| `.vchip` | Queue view switcher. Active = `--ink-4` fill + paper text. |
| `.promptbox` | Mono 11.5px on `--ink`, pre-wrapped, max 220px with scroll. Evidence must be readable, never truncated mid-payload. |
| Charts | Ember line/area, hairline grid `#2A2320`, axis text in mono `--faint`. Animations off — the data is live. |

## Motion

- Console: 140–180ms, `ease`, opacity/border/background only. No bounce, no scale on hover.
- Marketing: one reveal per section (fade/wipe on intersection), 1400ms count-ups.
- `prefers-reduced-motion` disables all of it in both surfaces.

## Accessibility

- Body text on ink is `--paper` (≈13.9:1). Secondary text `--dim` (≈7.4:1) passes AA at 12px.
- `--faint` (≈4.3:1) is used **only** for uppercase mono labels at 9–10px — decorative, duplicated by the adjacent value.
- Colour never carries meaning alone: verdict badges pair colour with a word, queue severity pairs the bar with a text label and an SLA string.
- Focus is always visible: `:focus-visible { outline: 2px solid var(--ember); outline-offset: 2px }`.
- The console is keyboard-first: `j`/`k` move, `a` acknowledge, `f` false positive, `/` filter, `g` switch view, `?` shortcuts.

## Copy

- Buttons name the outcome: `Acknowledge`, `Resolve`, `Open investigation` — never `Submit` or `OK`.
- Labels are nouns; actions are verbs. No exclamation marks, no "Oops".
- Numbers carry units (`14 ms`, `3h 5m left`), never a bare figure.
- Empty states say what will appear: "Waiting for events…", "Nothing in this view."

## Sign-in

The console is a restricted surface, so identity is the first screen, not a
modal after it.

- **Google Identity Services is the primary path.** The official button is
  rendered with `theme: 'filled_black'` so it sits on the ink ground without
  fighting the page — Google's branding rules require their button, so we theme
  it rather than replace it.
- **Local credentials remain** for self-hosted installs without an OAuth client
  and for the e2e suite. When Google is configured the password form is folded
  behind "Sign in with a password" — one primary path, not two competing ones.
- **Sign-out is explicit.** Signing out clears the stored session and calls
  `google.accounts.id.disableAutoSelect()`, so the next visit does not silently
  reuse the Google account.
- **Copy is plain about scope:** "Sign in with the Google account your
  organisation issued you." No "Secure login", no "One-click access".

### What the client checks, and what it must not

The console decodes the ID token and checks `iss`, `aud`, `exp` and
`email_verified` — enough to greet the analyst and keep the session in this tab.
That is **not** authentication: a JWT is trivially forged in the browser.

The API owns authorisation. It must verify the token against Google's keys on
every request, then map the account to a role — allowed Workspace domain,
analyst allowlist, whatever the deployment uses. A Google account proves who
someone is; it does not prove they may read your events.

## Surfaces

| Surface | Stack | Why |
| --- | --- | --- |
| `landing/` | Static HTML + one CSS file + one TS module, built by Vite | A marketing page does not need a framework runtime; the build is 8 kB of JS. |
| `dashboard/` | React 19 + TypeScript + Vite + recharts | The console is stateful: filters, workflow actions, live polling. |

Shared tokens are duplicated per surface on purpose — the landing page ships
without a component library, and both files are small enough to keep in step by
review.
