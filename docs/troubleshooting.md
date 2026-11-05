# Troubleshooting

Run `ssh-1password doctor` first: it names most of these causes directly.

| Symptom | Usual cause |
|---|---|
| `Could not open a connection to your authentication agent` | agent toggle off, or wrong socket path; `doctor` shows which |
| `Too many authentication failures` | a `Host *` of yours adds more `IdentityFile`s, or `agent.toml` missing; `doctor` runs `ssh -G` |
| `agent refused operation` | approval denied or 1Password locked; check the tray icon |
| `no such identity: ~/.ssh/1password/<slug>.pub`, then `Permission denied (publickey)` | `sync` ran while 1Password was locked or closed, so the `.pub` was never written (`sync` exits 1, `doctor` reports it missing): unlock 1Password and re-run `sync` |
| `Permission denied (publickey)` with the right alias | the `.pub` on the server is not the one 1Password offers, or the local `.pub` is stale because you replaced the key in 1Password (`doctor` reports it as rotated): re-run `sync`, then compare fingerprints |
| Key not offered although it exists in 1Password | item in a non-default vault: add `vault:` and re-run `sync` |
| Command hangs | pending approval: unlock 1Password |
| `git commit -S` fails with `Load key ... invalid format` or `op-ssh-sign: no such file` | `gpg.ssh.program` does not point at the binary inside the installed 1Password app; `doctor` names the expected path, re-run `sync` after reinstalling the app |
| Commit shows "Unverified" on GitHub/GitLab although `git log --show-signature` is good | the public key was uploaded as an Authentication key only: add it again as a **Signing key** (and authorize SSO) |
| Signed commit although the host has `sign: manual` | a global or local `commit.gpgsign true` of yours; `doctor` reports it |

## AI agents and scripts

AI agents and scripts from your desktop: the agent works if 1Password is unlocked. If a command
hangs, look for **"SSH request waiting"** in the 1Password tray icon. `BatchMode=yes` silences ssh's
own prompts, not 1Password's. Authorize the terminal by hand once before a long session.
