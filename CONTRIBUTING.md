# Contributing

Bug reports and pull requests are welcome. For anything larger than a small fix, open an issue first
so we can agree on the approach. Keep to the Python 3.8 standard library, add a test in
`tests/test_ssh_1password.py` for the behaviour you change, and run the tests below before opening
the PR. Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## Development

```sh
python3 -I tests/test_ssh_1password.py      # runs against a temporary --home and a fake ssh-add
python3 -I ssh-1password.py sync --dry-run --home /tmp/fake-home --file templates/hosts.yml
```

## Releasing

1. Bump `__version__` in `ssh-1password.py` and merge to `main`.
2. Tag and push: `git tag v0.1.1 && git push origin v0.1.1`.
3. The `release` workflow runs the tests, checks that the tag matches `__version__`, and publishes
   `ssh-1password-<version>.tar.gz`, `install.sh` and `SHA256SUMS` as a GitHub Release.
