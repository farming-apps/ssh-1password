# Install

macOS or Linux with Python 3.8+. Download the installer, read it if you like, and run it:

```sh
curl -fLO https://github.com/farming-apps/ssh-1password/releases/latest/download/install.sh
less install.sh                              # optional: see what it does
sh install.sh                                # or: sh install.sh --version 0.1.1
```

`install.sh` downloads the release tarball, checks it against the release's `SHA256SUMS`, unpacks it
into `~/.local/share/ssh-1password/<version>/` and links `~/.local/bin/ssh-1password` to it. It writes
nothing else: it does not edit your shell profile (it prints the `PATH` line when one is needed) and
never runs `sync`. Re-run it to upgrade; `sh install.sh --uninstall` removes it. `--prefix <dir>`
installs under another directory.

## Manual install, without the script

```sh
v=0.1.1
base=https://github.com/farming-apps/ssh-1password/releases/download/v$v
curl -fLO "$base/ssh-1password-$v.tar.gz" -fLO "$base/SHA256SUMS"
shasum -a 256 -c --ignore-missing SHA256SUMS   # must print "OK"
mkdir -p ~/.local/share ~/.local/bin
tar xzf "ssh-1password-$v.tar.gz" -C ~/.local/share
ln -sf ~/.local/share/ssh-1password-$v/ssh-1password.py ~/.local/bin/ssh-1password
export PATH="$HOME/.local/bin:$PATH"         # also add this to your shell startup file
ssh-1password --version
```

The tarball holds `ssh-1password.py`, `templates/hosts.yml`, `README.md` and `LICENSE`; keep them
together (the symlink is fine).

## From a clone

Cloning the repo and running `python3 -I ssh-1password.py` works the same way as the installed
`ssh-1password` command.
