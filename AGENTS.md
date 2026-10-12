# VisiPass

Password manager for coding agents. Rust workspace; M0 runs on 1Password through `op`.
Spec and roadmap: Obsidian vault, `Projects/VisiPass/VisiPass Spec.md`.

## Purpose

Let a coding agent use credentials as freely as a trusted teammate would, without the secret entering the model's context and without the human babysitting every shell. Optimise, in order:

1. Plaintext in the model's context: zero by default. References everywhere; revealing is a named, granted, logged act.
2. Human interruptions: one approval per task at most, zero inside a standing grant.
3. Agent success on the first try: one obvious command per goal, compact JSON, errors that say what to do next.
4. Trustworthy writes: never lose, duplicate or silently overwrite a credential.

Not a sandbox: a command given a secret by `vp run` can do anything with it.

```sh
cargo test --workspace          # never touches real 1Password, the clipboard or a display
cargo build -p vp-gui        # the GPUI approval window (slow first build)
cargo clippy --workspace --all-targets
cargo fmt --all
```

## Map

```
crates/vp-core     pure: refs, env files, find scoring, audit, masking, IPC types, Backend trait
crates/vp-op       Backend over 1Password's op (ported from 2password)
crates/vp-daemon   visipassd: grants, approval prompt, access log, process identification
crates/vp-cli      vp: parse flags, call visipassd, print JSON; no logic
crates/vp-gui   visipass-prompt: GPUI approval window (layer-shell overlay on Wayland), themed from Omarchy;
                   excluded from default-members, build with `cargo build -p vp-gui`
skills/visipass    the agent skill; keep it in sync with the CLI
```

## Invariants

Security properties. Do not weaken them.

1. Secrets never appear in argv, stdout (except `read` and `inject` without `--output`), stderr, errors, receipts, the access log or diagnostics. Plaintext reaches `op` only on stdin (`Call::input`).
2. Any `op` call that sends or reveals plaintext passes a fixed `failure`, which suppresses op's stderr.
3. Writes run once, are read back and compared. A failure after a write says "unverified" and is never retried.
4. No preflight (`op whoami`); the operation is the capability check.
5. Batch: one `op` call per discovery or consumption command, so one backend prompt covers it.
6. Values leave the daemon only after a grant covers the exact agent, project, operation and references, or the human approves. Approval is never something an agent can run: no `vp approve`.
7. Grants never widen silently. A new reference or operation goes back to the human.
8. Every request except status, grant listing and log reading is written to the access log before its result is returned; if the log cannot be written, the request fails.
9. `vp run` strips VisiPass and 1Password tokens from the child and masks injected values by default.
10. Never read configuration that changes which program the daemon runs (`op`, `visipass-prompt`, `zenity`) from the environment beyond PATH. `visipass-prompt` is looked up next to visipassd first.
11. Results are JSON on stdout, notices on stderr, `visipass: <message>` with exit 1 for expected errors.
12. The approval window defaults to Deny (selected on open, Escape denies, closing or crashing denies) and ignores input for its first 700ms.

## Changing things

- Logic goes in `vp-core` (pure) or the daemon; `vp-cli/src/main.rs` only parses and prints.
- Test end to end in `crates/vp-cli/tests/cli.rs`: fake `op`, scripted approver, sentinel secrets asserted absent from stdout, stderr, op argv and the log.
- Do not let clap parse arguments that may hold a secret: its errors echo the rejected value.
- User-facing change: update `skills/visipass/SKILL.md`.

## Release

```sh
# bump version in Cargo.toml ([workspace.package]), commit, then:
git tag v0.1.1 && git push origin main v0.1.1
# CI tests, builds x86_64 + aarch64 tarballs and creates the GitHub release (0.x = prerelease).
packaging/aur/update.sh 0.1.1   # fills PKGBUILD checksums + .SRCINFO; push to the AUR visipass-bin repo
```
