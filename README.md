<p align="center"><img src="assets/brand/visipass.svg" width="96" alt="VisiPass"></p>

# VisiPass

A password manager built for coding agents. Your agent finds, uses and saves secrets without ever seeing them, and you approve per task and project instead of per shell.

Milestone 0 runs on top of 1Password: `vp` talks to your existing vaults through the 1Password CLI, and adds standing grants, an approval prompt that names the agent, project and command, output masking, and an access log. VisiPass's own encrypted store follows in M0.5.

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
vp lock          # erase the keys from memory; it also locks after 10 idle minutes,
                 # when the screen locks, and before the machine sleeps
vp quick-unlock on   # optional: for 8 hours after you type the master password, unlocking
                     # again takes your fingerprint or login password (polkit)
vp lock --full   # lock and end that window
```

After `vp init`, VisiPass serves your own encrypted vault instead of 1Password. The design is in [docs/crypto-design.md](docs/crypto-design.md). It has had an internal review but **not yet an outside one**, so keep 1Password as your backup for now.

## Approvals

When an agent asks for a secret no grant covers, a dialog names the agent (Claude Code, Codex, ...), the project and git remote, the command, the references, and the agent's stated purpose. Answer *Deny*, *Allow once*, *This task* (until the agent exits), *This project, 8 hours*, or *Always for this project*. Grants cover exactly the references and operation approved; anything new asks again.

The agent label comes from the process tree. It helps you decide; it is not proof of identity.

## Safety

- Only `read`, and `inject` without `--output`, print a secret. `env resolve` and `inject --output` write plaintext files (mode 0600).
- `run` and `env run` give plaintext to the command you choose and mask it in that command's output. They are not a sandbox.
- New secrets come in through the clipboard or a pipe, never as arguments. Every write is read back and checked, and never retried automatically.

AGPL-3.0-only.
