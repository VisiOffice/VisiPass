---
name: modern-web-guidance
description: |
  Modern web platform best practices, read from guides bundled in this repo. Use FIRST when writing or changing HTML, CSS or client-side JS: the extension's popup, inline menu and save card (extension/), and the visipass.app site (site/). Web APIs move fast and training data holds obsolete patterns.
  Trigger for: dialogs/popovers, forms, validation, autofill, passkeys, accessibility, dark mode, anchor positioning, container queries, view transitions, animations, custom selects, performance (LCP, INP, CLS), images, security, HTML sanitization, web components, dates/timezones, built-in AI.
  Do NOT trigger for: Rust, the daemon or CLI, CI, packaging, tests, or copy changes.
---

# Modern Web Guidance

Read the relevant guide **before** implementing or changing web UI, CSS, or client-side JS, instead
of writing ad-hoc solutions or adding dependencies.

Copied from [googlechrome/modern-web-guidance](https://github.com/googlechrome/modern-web-guidance)
and adapted to work offline. See `SOURCE.md`. **Never run `npx modern-web-guidance`** (or `pnpx`)
from this repo: everything it would return is in `guides/`.

## Workflow

### 1. Find guides

`guides/INDEX.md` lists every guide on one line: id, folder, title, first sentence. Grep it with
2–5 words naming the **UI primitive or platform feature**, not the app's own nouns:

```sh
grep -i -E 'dialog|popover' .claude/skills/modern-web-guidance/guides/INDEX.md
```

- Translate intent into the primitive: "confirm before archiving" → `dialog`; "pick a date" →
  `date`; "menu next to the field" → `anchor|popover`.
- One capability per search; split compound tasks.
- If nothing matches, try one synonym, then grep the guide bodies
  (`grep -ril '<term>' .claude/skills/modern-web-guidance/guides`). If still nothing, proceed
  without a guide.

### 2. Read them

Read each matching guide in full at `guides/<folder>/<id>.md`, plus the broad discipline guide
that applies (`html`, `css`, `forms`, `accessibility`, `color`, `performance`, `security`).
Guides cross-reference each other by path.

### 3. Check the work against them

Before finishing, confirm the change applies the guide's modern pattern **and** its required
fallbacks, without forcing in features nobody asked for.

### 4. Say what you used

When a guide shaped the change, end with a short `### Modern Web Guidance` section: one bullet per
guide id, naming the non-obvious choice it led to. Don't cite guides from memory; re-read them.

## In this repo

- **The extension** runs in Chrome, Chromium and Brave. Use the `chrome-extensions` skill for
  extension APIs (service worker, content scripts, messaging, permissions); use this skill for
  the HTML and CSS of the popup, the inline menu and the save card.
- **The extension's security rules win over any guide.** It acts only on trusted input with its
  menu visible, fills only visible fields on the approved origin, and pages never get a password
  back (AGENTS.md, Invariant 13). Don't adopt a pattern that loosens that.
- **The site** (`site/`) is Astro on Cloudflare Workers. Guides are vanilla HTML/CSS/JS; adapt
  them to Astro components without dropping the modern feature, and guard `window`/`document` in
  code that runs on the server.

## Browser support

- Features that are **Baseline Widely available** are safe without fallbacks.
- Anything newer: follow the guide's fallback advice, unless AGENTS.md states a narrower browser
  policy. For "Baseline YYYY" targets, a feature qualifies if its "Baseline since" year ≤ YYYY.
- The extension targets current Chromium browsers only, so a Chromium-shipped feature needs no
  cross-browser fallback there. The site still needs fallbacks for Safari and Firefox.
