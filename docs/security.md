# Security notes

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

- Nothing on disk to steal: the `.pub` files and the config are public by nature. A file key can be
  copied by anyone with root on the machine; a 1Password key requires the vault unlocked and your
  approval, and every use shows in the item's **Activity** tab.
- Keep biometric approval on, auto-lock after a few minutes and on screen lock, and **deny any
  approval prompt you did not expect**: that is the signal that something on the machine is using
  your keys.
- `ForwardAgent no` by default. Use `ProxyJump` for intermediate hops.
- Unattended jobs (cron, systemd timers, CI runners) should **not** use the agent: there is nobody to
  approve. Give them a dedicated file key restricted in `authorized_keys`
  (`command="..."`, `no-pty`, `no-port-forwarding`, `no-agent-forwarding`) and a `Host` entry with
  `IdentityAgent none` in your own config, above the Include.
- AI agents and scripts from your desktop: see [Troubleshooting](troubleshooting.md#ai-agents-and-scripts).

## Migrating from file keys

1. Inventory your keys and the hosts that accept each one.
2. Create new ed25519 keys in 1Password (one per trust domain); import a legacy key only if some
   device cannot accept a new one.
3. Per host, in parallel with the old key: add the new public key to `authorized_keys`, test with
   `ssh -o IdentitiesOnly=yes -i ~/.ssh/1password/<slug>.pub <host>`, then remove the old one.
4. Move retired private keys out of `~/.ssh`, wait a few days, delete them.
