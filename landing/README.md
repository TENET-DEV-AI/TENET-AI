# TENET AI — landing page

The marketing site: an editorial field-manual page — ink ground, paper type, one
ember accent — with a working payload test bench that runs the signature rules
in the browser. Nothing you type leaves the page.

Static HTML, one stylesheet, one behaviour module, built by Vite. There is no
framework runtime here on purpose: the whole page ships ~8 kB of JavaScript.

```
index.html                 the page (markup, sprite, meta)
src/main.ts                reveal, masthead, theme, test bench, mobile sheet
src/styles/tenet.css       the design system for this surface
public/media/*.webp        the plates
```

## Run

```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # tsc --noEmit && vite build -> dist/
```

## Editing

- Copy and structure live in `index.html`. Keep section numbering (`§ 01`…) in
  order — the masthead links and the colophon reference them.
- Design tokens are the `:root` block at the top of `tenet.css`. Do not add a
  colour that is not already a token.
- The test bench rules are in `src/main.ts` (`RULES`). They are deliberately the
  same rule families the analyzer reports, with client-side weights for demo use.
- `prefers-reduced-motion` disables reveals, counters and the scan animation.
