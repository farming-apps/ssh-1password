# A new machine in five minutes

With file keys, a new laptop means copying `~/.ssh` around (or generating keys and uploading them to
every server and forge again). With ssh-1password the private keys stay in your 1Password vault, and
the only thing that describes your setup is the registry, `hosts.yml`, which holds **no secrets**:
aliases, hostnames, users and key titles.

## What travels with you

| Thing | Where it lives | On a new machine |
|---|---|---|
| Private keys | 1Password vault | already there once you sign in |
| `hosts.yml` (registry) | your dotfiles, or a 1Password Secure Note | copy or link it |
| `~/.ssh/config.d/1password.conf`, `~/.ssh/1password/*.pub`, `agent.toml`, git identity files | generated | `ssh-1password sync` recreates them |
| Public keys on servers, GitHub, GitLab | the servers | nothing to do: same keys |

The registry contains hostnames, which are endpoints worth keeping to yourself: keep it in a
**private** dotfiles repository or in 1Password, not in a public repo.

## Steps

1. Install 1Password, sign in, and enable **Settings → Developer → Use the SSH agent**.
2. Install the tool:

   ```sh
   curl -fLO https://github.com/farming-apps/ssh-1password/releases/latest/download/install.sh
   sh install.sh
   ```

3. Put the registry in place, in one of these ways:
   - copy it to `~/.config/ssh-1password/hosts.yml`;
   - or point at your dotfiles with `export SSH_1P_HOSTS=~/dotfiles/ssh/hosts.yml` (or `--file`).

4. Generate everything and check it:

   ```sh
   ssh-1password sync
   ssh-1password doctor
   ssh -T git@github-acme        # 1Password asks once; GitHub answers "Hi <user>!"
   ```

The generated files spell paths with `~`, and `sync` picks the agent socket for the platform
(macOS or Linux), so the same registry works on every machine you own.

## Leaving a machine

There is no private key on disk to wipe or revoke. What `sync` wrote is public by nature: `.pub`
files and ssh/git config. Sign out of 1Password (or remove the device from your account) and that
machine can no longer use your keys. `sh install.sh --uninstall` removes the tool.

Coming from file keys? See [migrating from file keys](security.md#migrating-from-file-keys).
