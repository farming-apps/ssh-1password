# ssh-1password

[![test](https://github.com/farming-apps/ssh-1password/actions/workflows/test.yml/badge.svg)](https://github.com/farming-apps/ssh-1password/actions/workflows/test.yml)

Use SSH keys stored in 1Password through the **1Password SSH agent**, with each host offered
**only its key**. The private key never touches the disk and every use asks for Touch ID (or the
system unlock). This tool adds a small registry that maps host aliases to keys, generates the ssh
and git config from it, and a `doctor` that tells you when something drifted.

One script, Python 3.8+ standard library, macOS and Linux. No `op` CLI needed.

## Install

```sh
curl -fLO https://github.com/farming-apps/ssh-1password/releases/latest/download/install.sh
sh install.sh                                # sh install.sh --uninstall removes it
```

It verifies the release checksum and links `~/.local/bin/ssh-1password`; it does not touch your
shell profile or `~/.ssh`. Options and manual install: [docs/install.md](docs/install.md).

## Quick start

1. Install the 1Password app and enable **Settings → Developer → Use the SSH agent**.
2. Create your SSH keys in 1Password (one per trust domain, see below).
3. In a terminal (not from an AI agent session: it writes under `~/.ssh`):

```sh
ssh-1password sync             # creates ~/.config/ssh-1password/hosts.yml
$EDITOR ~/.config/ssh-1password/hosts.yml
ssh-1password sync             # fetches the .pub files, writes the ssh config
ssh-1password doctor
ssh -T git@github-work         # 1Password asks once; GitHub answers "Hi <user>!"
```

Re-run `sync` whenever you edit the registry or rename a key in 1Password. It is idempotent, and
`--dry-run` shows what it would write.

## The registry

```yaml
# alias: what you type after "ssh" and what git remotes use
github-work:
  hostname: github.com
  user: git                   # SSH login, always "git" on GitHub/GitLab
  key: GitHub work            # title of the SSH key item in 1Password
  email: me@work.example      # optional: git identity for repos cloned through this alias
homelab:
  hostname: 192.0.2.10
  user: admin
  key: Homelab
```

- `key` is required; everything else is optional (`port`, `vault`, `name`, `sign`, …).
- Git remotes use the **alias**: `git@github-work:org/repo.git`.
- **One key per trust domain, not per host**: fewer keys to rotate, and a compromised domain does
  not open the others.

## Documentation

- [Reference](docs/reference.md): all registry fields, what `sync` writes, git identity per alias,
  commit signing, `agent.toml`, `doctor`.
- [Troubleshooting](docs/troubleshooting.md)
- [Security notes and migrating from file keys](docs/security.md)
- [Install options](docs/install.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
