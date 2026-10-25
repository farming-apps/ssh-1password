#!/usr/bin/env python3
"""Tests for ssh-1password.py. Everything runs against a temporary --home and a fake ssh-add,
so nothing under the real ~/.ssh is read or written.  Run: python3 -I tests/test_ssh_1password.py"""
import base64
import contextlib
import importlib.util
import io
import os
import stat
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("ssh1p", os.path.join(ROOT, "ssh-1password.py"))
ssh1p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh1p)

FAKE_SSH_ADD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake-ssh-add.py")


def blob(seed):
    return base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + seed.encode().ljust(32, b"x")).decode()


KEYS = [("ssh-ed25519", blob("personal"), "GitHub personal"),
        ("ssh-ed25519", blob("work"), "GitHub work"),
        ("ssh-ed25519", blob("dup"), "Twice"),
        ("ssh-ed25519", blob("dup2"), "Twice")]

REGISTRY = textwrap.dedent("""\
    # comment line
    github-personal:
      hostname: github.com
      user: git
      key: GitHub personal   # trailing comment
    github-work:
      hostname: github.com
      user: git
      key: GitHub work
      vault: "Work"
    "pve router":
      key: GitHub personal
      port: 2222
    """)


@contextlib.contextmanager
def captured():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        self.registry = os.path.join(self.home, "hosts.yml")
        with open(self.registry, "w") as fh:
            fh.write(REGISTRY)
        self.fake_out = os.path.join(self.home, "fake-keys.txt")
        with open(self.fake_out, "w") as fh:
            fh.write("".join(f"{t} {b} {c}\n" for t, b, c in KEYS))
        self._saved = (ssh1p.SSH_ADD, ssh1p.PLATFORM, ssh1p.app_installed)
        ssh1p.SSH_ADD = [sys.executable, "-I", FAKE_SSH_ADD, self.fake_out, "0"]
        ssh1p.PLATFORM = "darwin"
        ssh1p.app_installed = lambda: True

    def tearDown(self):
        ssh1p.SSH_ADD, ssh1p.PLATFORM, ssh1p.app_installed = self._saved
        self.tmp.cleanup()

    def env(self, dry=False):
        return ssh1p.Env(self.home, self.registry, dry)

    def run_install(self, dry=False):
        with captured() as buf:
            rc = ssh1p.cmd_install(self.env(dry))
        return rc, buf.getvalue()

    def run_doctor(self):
        with captured() as buf:
            rc = ssh1p.cmd_doctor(self.env())
        return rc, buf.getvalue()

    def read(self, rel):
        with open(os.path.join(self.home, rel)) as fh:
            return fh.read()

    def mode(self, rel):
        return stat.S_IMODE(os.stat(os.path.join(self.home, rel)).st_mode)


class Parsing(unittest.TestCase):
    def test_simple_yaml(self):
        d = ssh1p.parse_simple_yaml(REGISTRY)
        self.assertEqual(list(d), ["github-personal", "github-work", "pve router"])
        self.assertEqual(d["github-personal"]["key"], "GitHub personal")
        self.assertEqual(d["github-work"]["vault"], "Work")
        self.assertEqual(d["pve router"]["port"], "2222")

    def test_slug_and_fingerprint(self):
        self.assertEqual(ssh1p.slug("GitHub personal"), "github-personal")
        self.assertEqual(ssh1p.slug("  Ünicode/Key #1 "), "nicode-key-1")
        fp = ssh1p.fingerprint(blob("x"))
        self.assertTrue(fp.startswith("SHA256:") and "=" not in fp)
        self.assertTrue(ssh1p.slug(fp).startswith("fp-"))

    def test_parse_pubkeys_ignores_noise(self):
        text = "The agent has no identities.\nssh-ed25519 AAAA comment with spaces\nssh-rsa BBBB\n"
        self.assertEqual(ssh1p.parse_pubkeys(text),
                         [("ssh-ed25519", "AAAA", "comment with spaces"), ("ssh-rsa", "BBBB", "")])

    def test_registry_problems(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write("nokey:\n  hostname: x\nfine:\n  key: K\n  bogus: 1\nempty:\n")
        hosts, problems = ssh1p.load_registry(fh.name)
        os.unlink(fh.name)
        self.assertEqual([h["alias"] for h in hosts], ["fine"])
        self.assertEqual(len(problems), 3)


class Install(Base):
    def test_full_install_then_idempotent(self):
        rc, out = self.run_install()
        self.assertEqual(rc, 0)
        conf = self.read(".ssh/config.d/1password.conf")
        self.assertIn("Host github-work\n    HostName github.com\n    User git\n"
                      "    IdentityFile ~/.ssh/1password/github-work.pub\n    IdentitiesOnly yes", conf)
        self.assertIn("Host pve router\n    Port 2222\n    IdentityFile ~/.ssh/1password/github-personal.pub", conf)
        self.assertIn('Host *\n    IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"\n'
                      "    ForwardAgent no\n    AddKeysToAgent no\n", conf)
        self.assertEqual(self.read(".ssh/1password/github-work.pub"), f"ssh-ed25519 {blob('work')} GitHub work\n")
        self.assertEqual(sorted(os.listdir(os.path.join(self.home, ".ssh/1password"))),
                         ["github-personal.pub", "github-work.pub"])
        config = self.read(".ssh/config")
        self.assertTrue(config.endswith("Match all\nInclude config.d/1password.conf\n"))
        toml = self.read(".config/1Password/ssh/agent.toml")
        self.assertIn('[[ssh-keys]]\nitem = "GitHub personal"\n\n[[ssh-keys]]\nitem = "GitHub work"\nvault = "Work"\n', toml)
        self.assertIn("lock and unlock 1Password", out)
        self.assertEqual(self.mode(".ssh"), 0o700)
        self.assertEqual(self.mode(".ssh/config"), 0o600)
        self.assertEqual(self.mode(".ssh/config.d/1password.conf"), 0o600)
        self.assertEqual(self.mode(".ssh/1password/github-work.pub"), 0o644)

        rc, out = self.run_install()
        self.assertEqual(rc, 0)
        self.assertNotIn("update", out)
        self.assertNotIn("create", out)
        self.assertEqual(out.count("(no changes)"), 4)  # 2 pub + conf + agent.toml
        self.assertIn("already includes", out)
        self.assertEqual(len([f for f in os.listdir(os.path.join(self.home, ".ssh")) if ".bak." in f]), 0)

    def test_config_ending_in_host_block_gets_match_all_and_backup(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(os.path.join(self.home, ".ssh/config"), "w") as fh:
            fh.write("Host cliente\n    HostName bastion.example\n    IdentityAgent none\n")
        self.run_install()
        config = self.read(".ssh/config")
        self.assertTrue(config.startswith("Host cliente\n    HostName bastion.example\n    IdentityAgent none\n\n# ssh-1password"))
        self.assertIn("\nMatch all\nInclude config.d/1password.conf\n", config)
        baks = [f for f in os.listdir(os.path.join(self.home, ".ssh")) if f.startswith("config.bak.")]
        self.assertEqual(len(baks), 1)

    def test_existing_glob_include_is_respected(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(os.path.join(self.home, ".ssh/config"), "w") as fh:
            fh.write("Host x\n    User y\n\nInclude config.d/*.conf\n")
        _rc, out = self.run_install()
        self.assertIn("already includes", out)
        self.assertNotIn("Match all", self.read(".ssh/config"))

    def test_foreign_agent_toml_is_not_touched(self):
        path = os.path.join(self.home, ".config/1Password/ssh/agent.toml")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write('[[ssh-keys]]\nitem = "GitHub personal"\n')
        _rc, out = self.run_install()
        self.assertEqual(self.read(".config/1Password/ssh/agent.toml"), '[[ssh-keys]]\nitem = "GitHub personal"\n')
        self.assertIn('item = "GitHub work"', out)  # snippet for the missing one

    def test_dry_run_writes_nothing(self):
        rc, out = self.run_install(dry=True)
        self.assertEqual(rc, 0)
        self.assertIn("Include config.d/1password.conf", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".ssh")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/1Password")))

    def test_agent_unreachable_still_writes_config(self):
        ssh1p.SSH_ADD = [sys.executable, "-I", FAKE_SSH_ADD, self.fake_out, "2"]
        _rc, out = self.run_install()
        self.assertIn("Use the SSH agent", out)
        self.assertTrue(os.path.exists(os.path.join(self.home, ".ssh/config.d/1password.conf")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".ssh/1password")))

    def test_duplicate_title_and_unknown_key(self):
        with open(self.registry, "a") as fh:
            fh.write("dup:\n  key: Twice\nmissing:\n  key: Nope\n")
        _rc, out = self.run_install()
        self.assertIn("2 items share this title", out)
        self.assertIn("Nope: the agent does not offer it", out)

    def test_fingerprint_spec(self):
        fp = ssh1p.fingerprint(blob("work"))
        with open(self.registry, "w") as fh:
            fh.write(f"w:\n  key: {fp}\n")
        self.run_install()
        self.assertTrue(os.path.exists(os.path.join(self.home, ".ssh/1password", ssh1p.slug(fp) + ".pub")))
        self.assertNotIn("[[ssh-keys]]", self.read(".config/1Password/ssh/agent.toml"))

    def test_template_without_hosts(self):
        os.unlink(self.registry)
        env = ssh1p.Env(self.home, None, False)
        with captured() as buf:
            ssh1p.cmd_install(env)
        self.assertTrue(os.path.isfile(os.path.join(self.home, ".config/ssh-1password/hosts.yml")))
        self.assertIn("no hosts registered yet", buf.getvalue())
        self.assertIn("an empty agent.toml would hide every key", buf.getvalue())
        self.assertIn("Host *", self.read(".ssh/config.d/1password.conf"))


class Doctor(Base):
    def test_doctor_after_install_is_clean(self):
        self.run_install()
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("FAIL", out)
        self.assertIn("ssh -G checks skipped", out)

    def test_doctor_detects_drift(self):
        self.run_install()
        with open(self.registry, "a") as fh:
            fh.write("extra:\n  key: GitHub work\n")
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("out of date with the registry", out)

    def test_doctor_without_install(self):
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("does not include", out)
        self.assertIn(".pub missing", out)

    def test_doctor_warns_on_orphan_and_rotated_key(self):
        self.run_install()
        pubdir = os.path.join(self.home, ".ssh/1password")
        with open(os.path.join(pubdir, "old.pub"), "w") as fh:
            fh.write("ssh-ed25519 AAAA old\n")
        with open(self.fake_out, "w") as fh:  # the "GitHub work" item now holds another key
            fh.write(f"ssh-ed25519 {blob('personal')} GitHub personal\nssh-ed25519 {blob('rotated')} GitHub work\n")
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0)
        self.assertIn("orphan", out)
        self.assertIn("different key under this title", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
