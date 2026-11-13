# Source

Copied from https://github.com/googlechrome/modern-web-guidance at commit
`4dd968349e54ca45a05dd5c818fb035c9054b022` (2026-11-13), Apache License 2.0 (`LICENSE`).
Copyright Google LLC.

Changes from the original:

- `SKILL.md` is rewritten. Upstream, every search and retrieval runs
  `npx -y modern-web-guidance@latest`, which downloads unpinned code from npm on each use. Here the
  agent greps `guides/INDEX.md` and reads the guides directly, so nothing is downloaded or run.
  The `legacy-scan` flow is dropped because it needs that package. A section on this repo
  (extension, site, Invariant 13) is added.
- `guides/INDEX.md` is new: one line per guide, generated from the guides.
- In the guides, each cross-reference of the form
  ``(via `npx -y modern-web-guidance@latest retrieve "<id>"`)`` is replaced by the guide's path.
  Nothing else in the guides changed.

To update, take a newer commit and repeat the same steps.
