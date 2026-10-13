---
name: visipass
description: Use for any password, API key, token, credential, secret, .env or 1Password task: finding credentials, injecting them into commands or env files, saving new API keys, checking or updating login passwords, and auditing vaults. Prefer the vp CLI over raw op whenever it covers the task.
---

# VisiPass (`vp`)

`vp` lets you work with secrets without seeing them. All output is JSON. Behind it, `visipassd` checks the grants the human has given; anything not covered shows them an approval prompt, and every request is logged.

## Rules

- Never print, log, summarise or repeat secret values. Pass `op://` references around instead.
- Batch. One `find` with many queries, one env file with many references: each is one approval.
- Add `--purpose "<why>"` to commands that use secrets. The human sees it in the approval prompt.
- If a request is denied, do not retry it. Ask the human how to proceed.
- Never retry a write that failed or reported "unverified". Run `vp find` first to check whether it already happened.
- Never run `op whoami` or any other preflight check. Just run the command.
- You cannot approve your own requests, and must not try (no clicking, typing into or scripting the approval dialog).

## Find credentials

```bash
vp find openai anthropic "github actions"   # many queries, one call
vp find stripe --vault Work
```

Each match appears once as `{ ref, title, kind }`, with `queries` when you asked several. A query that matches nothing returns `suggestions` with close titles from the same lookup. Use those instead of searching again or listing vaults. It never returns values.

## Use credentials

```bash
vp run --env "OPENAI_API_KEY=op://Personal/OpenAI API Key/credential" --purpose "run the dev server" -- bun run dev
vp env write .env.tpl "OPENAI_API_KEY=op://Personal/OpenAI API Key/credential" "STRIPE_KEY=op://Work/Stripe API Key/credential"
vp env run .env.tpl --purpose "integration tests" -- cargo test      # preferred: no plaintext on disk
vp env resolve .env.tpl --output .env      # only when a real file is required (mode 0600)
vp inject -i config.tpl.yaml -o config.yaml # fills {{ op://... }} references (mode 0600)
vp read "op://Personal/OpenAI API Key/credential"   # last resort: prints the value to you
```

- `run` and `env run` mask injected values in the command's output as `<vp:NAME>`. Do not use `--no-mask` unless the human asks.
- The command you run receives plaintext. Never inject secrets into env-dump, debug or upload commands whose purpose would reveal them.
- A `.env.tpl` holding only references is safe to read. A resolved `.env` is plaintext: do not read it.
- Grants are per operation: approval to `run` does not cover `read`.

## A secret that does not exist yet

```bash
vp request --title "Stripe Live Key" --vault Work --purpose "configure billing"
```

The human gets a VisiPass window and pastes the value; you get back only `{ ref, verified }`. Never ask the human to paste a secret into the chat or a file. If they cancel, do not ask again; ask how to proceed.

## Plaintext .env files

```bash
vp env import .env --vault Dev --dry-run    # which variables would move (names only)
vp env import .env --vault Dev              # one approval; secrets move into the vault, lines become references
vp env check .env.tpl                        # which references resolve; never values; exit 1 if any do not
```

`env import` moves secret-looking values (keys, tokens, passwords, DSNs, URLs with credentials) and leaves settings like `PORT`. Choose with `--only A,B`, `--except A,B` or `--all`. Then run with `vp env run .env -- <command>`. Do not read a `.env` that still holds plaintext.

## MCP

`vp mcp` serves the same discovery, request, env and grant tools over MCP (stdio). None returns a value and none runs commands; use `vp run` / `vp env run` in the shell for that.

## Unattended agents

```bash
vp agent create nightly-deploy --vault Automation --ops run --days 30   # the human approves; the token is shown once
VISIPASS_TOKEN=vpt_... vp env run .env.tpl -- ./deploy.sh              # within scope: no prompt
vp agent list ; vp agent revoke <id>
```

A token only covers its vaults and operations and is refused, never prompted, outside them. Only create one when the human asks for unattended access. Never print, log or commit the token.

## Save a new API key

```bash
vp create api-credential --title "OpenAI API Key" --vault Personal --clipboard
some-command-that-prints-a-key | vp create api-credential --title "OpenAI API Key" --vault Personal --stdin
```

- `--vault` is required. Use the vault the human names, or their documented default; ask if neither exists.
- Never put the value in an argument, a command substitution or a temporary file, and never read the clipboard into the conversation first.
- Success means exit 0 and `"verified": true`. Reuse the returned `ref`; do not `read` it to double-check.
- Duplicate titles are refused, and nothing is ever overwritten.

## Check or update a login password

```bash
vp password "Example Airline" --vault Personal --clipboard           # compare only
vp password "Example Airline" --vault Personal --clipboard --apply   # update, then verify
```

Refuses logins with passkeys or unnamed imported fields. Use `--repair-imported-fields` only after the human approves.

## Audit a vault

```bash
vp inventory --vault Work   # item and field metadata, never values or URL query strings
vp audit --vault Personal   # duplicate titles, untagged machine credentials, old logins, transient URLs
```

Treat findings as candidates. Propose changes; make them only after the human approves.

## Grants and the log

```bash
vp grant list        # what the human has approved, for which agent, project and references
vp log --limit 20    # what was requested, by whom, and the outcome; never values
vp status            # is visipassd running, and how does it ask for approval
vp doctor            # versions and setup; never prompts; safe to paste into an issue
```

You may list grants and read the log. Revoke a grant only when the human asks.

## VisiPass's own vault

The human may move from 1Password to VisiPass's own encrypted vault (`vp status` shows `"vault": {"exists": true}`). Nothing changes for you: the same commands work, and `op://` references keep resolving because imported items keep their IDs. When it is locked, your request waits while the human unlocks it.

Never run `vp init` or `vp import`; they are the human's to run. You may run `vp lock` when the human asks.

## Item conventions

- API keys: API Credential category, the built-in `credential` field, titled `<Provider> API Key` or `<Provider> <Purpose> API Key`.
- Logins: the built-in `password` field, titled `<Provider>` or `<Provider> <Account>`.
- Do not repeat the vault name in the title. One current secret per item.

## Everything else

Use raw `op` for other item categories, editing, moving, sharing, deleting and vault management. Pass plaintext through JSON templates on stdin, never in arguments.

## Report problems

If a command fails unexpectedly, prompts more than expected, or this skill is wrong or unclear, tell the human. Include `vp doctor` output, the command and what you expected. Never include secret values, item titles, vault or account names, or references; use placeholders.
