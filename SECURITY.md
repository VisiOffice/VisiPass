# Security

## Reporting a vulnerability

Report it privately through GitHub: [Report a vulnerability](https://github.com/VisiOffice/VisiPass/security/advisories/new) on this repository's Security tab. Do not open a public issue, and do not include real credentials. Only the latest release is supported.

## What VisiPass promises

VisiPass keeps secret values out of agent-visible surfaces by default. A value may cross that boundary only through an explicit, granted, logged path:

- `vp read`, and `vp inject` without `--output`, write a secret to stdout.
- `vp env resolve` and `vp inject --output` write plaintext to the requested file (mode 0600).
- `vp run` and `vp env run` inject secrets into the chosen command's environment. That command is inside the trust boundary; VisiPass masks its output but cannot stop it from using or sending the value.
- `vp kamal-fetch` prints the requested secrets in the form `kamal secrets fetch` uses, for `.kamal/secrets` to read.

Anything else is a vulnerability: a secret in an error, diagnostic, argument, receipt, log entry, metadata response or unrelated process environment; a value released without a grant or an approval; a grant covering more than the human approved; an agent able to approve its own request; or a web page able to read or fill credentials through the browser extension without the user picking them.

For VisiPass's own vault (`vp init`), also report anything that weakens [docs/crypto-design.md](docs/crypto-design.md) or where the code departs from it. That vault has not had an outside audit yet.

## The agent is a process running as you

A coding agent runs as your own user, so VisiPass cannot stop it the way an operating system stops another user. What VisiPass does promise is that **nothing the agent can do through VisiPass, or with ordinary commands, gets it an approval or a value you did not give**. In scope, and a vulnerability if it works:

- answering its own approval: restarting the daemon with the display cleared, a terminal it controls, `script`, a detached tmux, a fake `visipass-prompt` or `zenity` first on PATH;
- passing as you: running a command detached (`setsid`, `nohup &`) to use grants you gave commands typed in your terminal, or `cd`-ing into another project to use its grants;
- using a grant beyond what the prompt said: another login's password under a "save new items" grant, another session's "this task" grant;
- asking for browser fills or logins from anything but the browser extension;
- misleading the prompt with control, bidirectional or zero-width characters, or very long text;
- turning on quick unlock.

The name in the approval prompt is still a hint, not authentication: an agent can rename its process.

## Out of scope

- Tampering with your account directly: editing VisiPass's state files (grants, tokens, the access log), its configuration or its installed programs, attaching a debugger to visipassd, or injecting keystrokes into your desktop. Any program running as you can do these, to any password manager. Run agents in a sandbox that cannot write `~/.local/state/visipass` or `~/.local/share/visipass` if you need protection from that.
- What a command does with a secret you approved for it (`vp run`).
- A compromised browser, operating system or 1Password.
