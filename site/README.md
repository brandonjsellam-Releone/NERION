<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion site

`index.html` is a **self-contained, static** landing page — no build step, no external runtime
dependencies (system fonts only). The interactive sections are an illustrative concept demo of the
protocol logic, not the production crypto (see the on-page disclaimer).

## Deploy

Pick any static host — the page is one file.

- **GitHub Pages:** repo **Settings → Pages → Build and deployment → Deploy from a branch**, branch
  `main`, folder `/site`. (Enabling Pages is a repo-settings action the maintainer performs.)
- **Netlify / Vercel / Cloudflare Pages:** point the project at this `site/` directory; publish
  directory = `site`, build command = none.
- **Any web server / object store:** copy `index.html` to the document root.

## Maintenance

Keep the post-quantum posture band in sync with `crypto/src/suites.ts`, `../nerion.cbom.json`, and
`../docs/PQC_MIGRATION_POSTURE.md` whenever the suite registry changes.
