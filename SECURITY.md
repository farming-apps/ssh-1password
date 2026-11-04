# Security policy

`ssh-1password` writes under `~/.ssh`, `~/.config/1Password/ssh/agent.toml` and your global git
config, so a bug can change which key is offered to which host or how commits are signed.

## Reporting a vulnerability

Please report it privately through
[GitHub private vulnerability reporting](https://github.com/farming-apps/ssh-1password/security/advisories/new),
not in a public issue. Include the version (`ssh-1password --version`), your OS, and the smallest
`hosts.yml` that reproduces it, with real hostnames and key titles replaced.

You can expect a first reply within a week. Fixes ship as a new release; the advisory is published
once a fixed version is available.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: `ssh-1password.py`, `install.sh` and the release workflow. Issues in 1Password, its SSH
agent or `op-ssh-sign` belong to 1Password.
