# Security

VisiPass keeps secret values out of agent-visible surfaces by default. A value may cross that boundary only through an explicit, granted, logged path:

- `vp read`, and `vp inject` without `--output`, write a secret to stdout.
- `vp env resolve` and `vp inject --output` write plaintext to the requested file (mode 0600).
- `vp run` and `vp env run` inject secrets into the chosen command's environment. That command is inside the trust boundary; VisiPass masks its output but cannot stop it from using or sending the value.

Anything else is a vulnerability: a secret in an error, diagnostic, argument, receipt, log entry, metadata response or unrelated process environment; a value released without a grant or an approval; a grant covering more than the human approved; or an agent able to approve its own request.

Out of scope in M0: another process running as the same user. It can talk to the daemon (every value still needs a grant or a human click) and imitate an agent's process name (the label is a hint, not authentication).

Report vulnerabilities privately to the maintainer. Do not open a public issue, and do not include real credentials.
