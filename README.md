<p align="center"><img src="assets/brand/visipass.svg" width="96" alt="VisiPass"></p>

# VisiPass

A password manager built for coding agents. Your agent finds, uses and saves secrets without ever seeing them, and you approve per task and project instead of per shell.

## Status

0.x, Linux only (x86_64 and aarch64), Omarchy first.

- **The agent layer over 1Password is the part to rely on.** `vp` reaches your existing vaults through the 1Password CLI and adds standing grants, an approval prompt that names the agent, project and command, output masking, and a hash-chained access log. 1Password still stores and encrypts everything.
- **VisiPass's own vault is experimental** (`vp init`, `vp import op`). Its design ([docs/crypto-design.md](docs/crypto-design.md)) has had an internal review, but neither the design nor the code has had an outside audit. Keep 1Password as your backup, and don't store anyone else's credentials in it yet.
- **The browser extension** works in Chrome and Chromium, loaded unpacked (see [extension/README.md](extension/README.md)); it is not in the Chrome Web Store.
- No sync, and no macOS or Windows builds, yet.
- VisiPass is not a sandbox: a command given a secret by `vp run` can do anything with it.

## Install

Requires the [1Password CLI](https://developer.1password.com/docs/cli/get-started/) with app integration turned on (Settings > Developer > Integrate with 1Password CLI). Linux on x86_64 or aarch64; Omarchy first.

**Arch / Omarchy** (AUR):

```sh
yay -S visipass-bin 1password-cli
```

**Any Linux** from [the latest release](https://github.com/VisiOffice/VisiPass/releases):

```sh
tar xzf visipass-*-linux-x86_64.tar.gz
install -m755 visipass-*/vp visipass-*/visipassd visipass-*/visipass-prompt ~/.local/bin/
```

**From source:**

```sh
cargo install --path crates/vp-cli
cargo install --path crates/vp-daemon
cargo install --path crates/vp-gui     # the approval window (GPUI); first build takes several minutes
```

The three binaries (`vp`, `visipassd`, `visipass-prompt`) must sit side by side or on PATH. `vp` starts the daemon when needed. Without `visipass-prompt`, approvals fall back to `zenity`, or to the terminal running `vp daemon`.

Then give your agent the skill: copy `SKILL.md` (in the release, or `skills/visipass/SKILL.md` here) into its skills directory, e.g. `~/.claude/skills/visipass/SKILL.md` for Claude Code. Check the setup with `vp doctor`.

On Omarchy the approval window matches your theme: it reads the palette, the polkit-prompt tokens and fonts from `~/.local/state/omarchy/current/theme`, and Hyprland's rounding, every time it opens. Preview it with `visipass-prompt --demo` (Escape to close).

## Use

```sh
vp find openai stripe                     # op:// references, never values
vp run --env "OPENAI_API_KEY=op://Personal/OpenAI API Key/credential" -- bun dev
vp env run .env.tpl -- cargo test         # one approval for every reference in the file
vp create api-credential --title "OpenAI API Key" --vault Personal --clipboard
vp request --title "Stripe Live Key" --vault Work   # you paste it; the agent gets a reference
vp env import .env --vault Dev            # move plaintext secrets into the vault, rewrite to refs
vp app                                    # the desktop app; vp quick for Quick Access
vp grant list                             # what you have approved
vp log                                    # what was asked for, by whom
```

Give your agent `skills/visipass/SKILL.md`.

## VisiPass's own vault (early)

```sh
vp init          # choose a master password in the VisiPass window; it shows your Secret Key once
vp import op     # copy your 1Password vaults in; op:// references keep working
vp import proton ~/Downloads/Proton\ Pass_export.zip
                 # Proton Pass → Settings → Export → ZIP (or CSV); asks first, skips what is already here
                 # then vp app → Duplicates: logins saved twice (same site and username), exact
                 # copies first; keep one and the rest's websites, codes and notes move onto it
vp lock          # erase the keys from memory; it also locks after 10 idle minutes,
                 # when the screen locks, and before the machine sleeps
vp quick-unlock on   # optional: for 8 hours after you type the master password, unlocking
                     # again takes your fingerprint or login password (polkit)
vp lock --full   # lock and end that window
vp emergency-kit # print your Secret Key and account ID (asks for the master password)
```

After `vp init`, VisiPass serves your own encrypted vault instead of 1Password. The design is in [docs/crypto-design.md](docs/crypto-design.md). It has had an internal review but **not yet an outside one**, so keep 1Password as your backup for now.

## Kamal

In `.kamal/secrets`, fetch everything a deploy needs in one request (one approval, or none inside a
grant), then let Kamal hand each one out:

```sh
SECRETS=$(vp kamal-fetch --from "op://Domus/Production Secrets" RAILS_MASTER_KEY POSTGRES_PASSWORD \
  KAMAL_REGISTRY_PASSWORD=op://Varda/Production/GITHUB_TOKEN)
RAILS_MASTER_KEY=$(kamal secrets extract RAILS_MASTER_KEY $SECRETS)
POSTGRES_PASSWORD=$(kamal secrets extract POSTGRES_PASSWORD $SECRETS)
KAMAL_REGISTRY_PASSWORD=$(kamal secrets extract KAMAL_REGISTRY_PASSWORD $SECRETS)
```

A bare name is a field of the `--from` item; `NAME=op://…` takes any other reference. If anything
is missing or refused, `vp` prints nothing and `kamal secrets extract` stops the deploy, instead
of Kamal shipping a blank secret as it does when a `$(op read …)` line fails. A field that is
empty in the vault stops it too; name each one that may be blank with `--allow-empty NAME`. Values containing
`$` arrive intact (Kamal expands `$NAME` inside a plain `$(op read …)` result). Kamal itself drops
a trailing newline from any value.

## Approvals

When an agent asks for a secret no grant covers, a dialog names the agent (Claude Code, Codex, ...), the project and git remote, the command, the references, and the agent's stated purpose. Answer *Deny*, *Allow once*, *This task* (until the agent exits), *This project, 8 hours*, or *Always for this project*. Grants cover exactly the references and operation approved; anything new asks again.

The agent label comes from the process tree. It helps you decide; it is not proof of identity.

## Safety

- Only `read`, and `inject` without `--output`, print a secret. `env resolve` and `inject --output` write plaintext files (mode 0600).
- `run` and `env run` give plaintext to the command you choose and mask it in that command's output. They are not a sandbox.
- New secrets come in through the clipboard or a pipe, never as arguments. Every write is read back and checked, and never retried automatically.

AGPL-3.0-only.
