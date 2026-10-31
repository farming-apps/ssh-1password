#!/usr/bin/env python3
"""Tests for ssh-1password.py. Everything runs against a temporary --home and a fake ssh-add,
so nothing under the real ~/.ssh is read or written.  Run: python3 -I tests/test_ssh_1password.py"""
import base64
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import stat
import subprocess
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
        ("ssh-ed25519", blob("sign"), "Signing work"),
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
        self.signer = os.path.join(self.home, "op-ssh-sign")  # stands in for the binary inside 1Password.app
        with open(self.signer, "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        self._saved = (ssh1p.SSH_ADD, ssh1p.PLATFORM, ssh1p.app_installed, ssh1p.signer_path)
        ssh1p.SSH_ADD = [sys.executable, "-I", FAKE_SSH_ADD, self.fake_out, "0"]
        ssh1p.PLATFORM = "darwin"
        ssh1p.app_installed = lambda: True
        ssh1p.signer_path = lambda: self.signer

    def tearDown(self):
        ssh1p.SSH_ADD, ssh1p.PLATFORM, ssh1p.app_installed, ssh1p.signer_path = self._saved
        self.tmp.cleanup()

    def env(self, dry=False):
        return ssh1p.Env(self.home, self.registry, dry)

    def run_sync(self, dry=False):
        with captured() as buf:
            rc = ssh1p.cmd_sync(self.env(dry))
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

    def test_sign_field_validation(self):
        text = ("noemail:\n  key: K\n  sign: manual\n"
                "bad:\n  key: K\n  email: e@x\n  sign: yes\n"
                "nosign:\n  key: K\n  email: e@x\n  signing_key: S\n"
                "fine:\n  key: K\n  email: e@x\n  sign: always\n  signing_key: S\n")
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(text)
        hosts, problems = ssh1p.load_registry(fh.name)
        os.unlink(fh.name)
        by = {h["alias"]: h for h in hosts}
        self.assertEqual(by["noemail"]["sign"], "")
        self.assertEqual(by["bad"]["sign"], "")
        self.assertEqual(by["nosign"]["signing_key"], "")
        self.assertEqual((by["fine"]["sign"], by["fine"]["signing_key"]), ("always", "S"))
        self.assertTrue(any("sign: without email:" in p for p in problems))
        self.assertTrue(any("must be always or manual" in p for p in problems))
        self.assertTrue(any("signing_key: without sign:" in p for p in problems))
        self.assertEqual(len(problems), 3)


class Install(Base):
    def test_full_install_then_idempotent(self):
        rc, out = self.run_sync()
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
        self.assertTrue(all(n.endswith(".pub") for n in os.listdir(os.path.join(self.home, ".ssh/1password"))))
        config = self.read(".ssh/config")
        self.assertTrue(config.endswith("Match all\nInclude config.d/1password.conf\n"))
        toml = self.read(".config/1Password/ssh/agent.toml")
        self.assertIn('[[ssh-keys]]\nitem = "GitHub personal"\n\n[[ssh-keys]]\nitem = "GitHub work"\nvault = "Work"\n', toml)
        self.assertIn("lock and unlock 1Password", out)
        self.assertEqual(self.mode(".ssh"), 0o700)
        self.assertEqual(self.mode(".ssh/config"), 0o600)
        self.assertEqual(self.mode(".ssh/config.d/1password.conf"), 0o600)
        self.assertEqual(self.mode(".ssh/1password/github-work.pub"), 0o644)

        rc, out = self.run_sync()
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
        self.run_sync()
        config = self.read(".ssh/config")
        self.assertTrue(config.startswith("Host cliente\n    HostName bastion.example\n    IdentityAgent none\n\n# ssh-1password"))
        self.assertIn("\nMatch all\nInclude config.d/1password.conf\n", config)
        baks = [f for f in os.listdir(os.path.join(self.home, ".ssh")) if f.startswith("config.bak.")]
        self.assertEqual(len(baks), 1)

    def test_existing_glob_include_is_respected(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(os.path.join(self.home, ".ssh/config"), "w") as fh:
            fh.write("Host x\n    User y\n\nInclude config.d/*.conf\n")
        _rc, out = self.run_sync()
        self.assertIn("already includes", out)
        self.assertNotIn("Match all", self.read(".ssh/config"))

    def test_foreign_agent_toml_is_not_touched(self):
        path = os.path.join(self.home, ".config/1Password/ssh/agent.toml")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write('[[ssh-keys]]\nitem = "GitHub personal"\n')
        _rc, out = self.run_sync()
        self.assertEqual(self.read(".config/1Password/ssh/agent.toml"), '[[ssh-keys]]\nitem = "GitHub personal"\n')
        self.assertIn('item = "GitHub work"', out)  # snippet for the missing one

    def test_dry_run_writes_nothing(self):
        rc, out = self.run_sync(dry=True)
        self.assertEqual(rc, 0)
        self.assertIn("Include config.d/1password.conf", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".ssh")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/1Password")))

    def test_agent_unreachable_still_writes_config(self):
        ssh1p.SSH_ADD = [sys.executable, "-I", FAKE_SSH_ADD, self.fake_out, "2"]
        rc, out = self.run_sync()
        self.assertIn("Use the SSH agent", out)
        self.assertTrue(os.path.exists(os.path.join(self.home, ".ssh/config.d/1password.conf")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".ssh/1password")))
        # without the .pub files ssh offers no key (IdentitiesOnly): sync must not look successful
        self.assertEqual(rc, 1)
        self.assertIn("FAIL   GitHub work: ~/.ssh/1password/github-work.pub missing", out)
        self.assertIn("sync: 2 key(s) without .pub", out)

    def test_agent_unreachable_keeps_existing_pubs(self):
        self.assertEqual(self.run_sync()[0], 0)
        ssh1p.SSH_ADD = [sys.executable, "-I", FAKE_SSH_ADD, self.fake_out, "2"]
        rc, out = self.run_sync()
        self.assertEqual(rc, 0)
        self.assertIn("(keeping existing .pub)", out)
        self.assertNotIn("FAIL", out)

    def test_duplicate_title_and_unknown_key(self):
        with open(self.registry, "a") as fh:
            fh.write("dup:\n  key: Twice\nmissing:\n  key: Nope\n")
        rc, out = self.run_sync()
        self.assertIn("2 items share this title", out)
        self.assertIn("Nope: the agent does not offer it", out)
        self.assertEqual(rc, 1)
        self.assertIn("sync: 2 key(s) without .pub", out)
        self.assertNotIn("FAIL   GitHub work", out)

    def test_fingerprint_spec(self):
        fp = ssh1p.fingerprint(blob("work"))
        with open(self.registry, "w") as fh:
            fh.write(f"w:\n  key: {fp}\n")
        _rc, out = self.run_sync()
        self.assertTrue(os.path.exists(os.path.join(self.home, ".ssh/1password", ssh1p.slug(fp) + ".pub")))
        # an allowlist with zero entries would hide every key: it must not be written
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/1Password/ssh/agent.toml")))
        self.assertIn("needs item titles", out)

    def test_fingerprint_only_does_not_rewrite_generated_toml(self):
        self.run_sync()  # generates agent.toml from titled keys
        before = self.read(".config/1Password/ssh/agent.toml")
        with open(self.registry, "w") as fh:
            fh.write(f"w:\n  key: {ssh1p.fingerprint(blob('work'))}\n")
        self.run_sync()
        self.assertEqual(self.read(".config/1Password/ssh/agent.toml"), before)

    # --- host-registry ---------------------------------------------------------------------

    def test_registry_path_precedence(self):
        saved = {k: os.environ.get(k) for k in ("HOME", "SSH_1P_HOSTS", "XDG_CONFIG_HOME")}
        try:
            os.environ["HOME"] = self.home  # makes self.home the "real" home for Env
            os.environ.pop("XDG_CONFIG_HOME", None)
            os.environ.pop("SSH_1P_HOSTS", None)
            self.assertEqual(ssh1p.Env(self.home).registry,
                             os.path.join(self.home, ".config/ssh-1password/hosts.yml"))
            os.environ["SSH_1P_HOSTS"] = "/elsewhere/hosts.yml"
            self.assertEqual(ssh1p.Env(self.home).registry, "/elsewhere/hosts.yml")
            self.assertEqual(ssh1p.Env(self.home, "/explicit.yml").registry, "/explicit.yml")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_existing_registry_is_never_rewritten(self):
        with open(self.registry) as fh:
            before = fh.read()
        self.run_sync()
        self.run_sync()
        with open(self.registry) as fh:
            self.assertEqual(fh.read(), before)

    # --- agent-public-keys -----------------------------------------------------------------

    def test_app_missing_changes_nothing(self):
        ssh1p.app_installed = lambda: False
        rc, out = self.run_sync()
        self.assertEqual(rc, 0)
        self.assertIn("not installed", out)
        self.assertEqual(sorted(os.listdir(self.home)), ["fake-keys.txt", "hosts.yml", "op-ssh-sign"])  # fixtures only

    # --- ssh-client-config -----------------------------------------------------------------

    def test_missing_config_is_created_with_include_only(self):
        self.run_sync()
        self.assertEqual(self.read(".ssh/config"), ssh1p.INCLUDE_BLOCK.lstrip("\n"))
        self.assertEqual(self.mode(".ssh/config"), 0o600)
        self.assertEqual([f for f in os.listdir(os.path.join(self.home, ".ssh")) if ".bak." in f], [])

    def test_minimal_entry_block(self):
        with open(self.registry, "a") as fh:
            fh.write("bare:\n  key: GitHub personal\n")
        self.run_sync()
        self.assertIn("\nHost bare\n    IdentityFile ~/.ssh/1password/github-personal.pub\n    IdentitiesOnly yes\n\n",
                      self.read(".ssh/config.d/1password.conf"))

    def test_template_without_hosts(self):
        os.unlink(self.registry)
        env = ssh1p.Env(self.home, None, False)
        with captured() as buf:
            ssh1p.cmd_sync(env)
        self.assertTrue(os.path.isfile(os.path.join(self.home, ".config/ssh-1password/hosts.yml")))
        self.assertIn("no hosts registered yet", buf.getvalue())
        self.assertIn("an empty agent.toml would hide every key", buf.getvalue())
        self.assertIn("Host *", self.read(".ssh/config.d/1password.conf"))


class Packaging(unittest.TestCase):
    SCRIPT = os.path.join(ROOT, "ssh-1password.py")

    def test_version_flag(self):
        for flag in ("--version", "-V"):
            out = subprocess.run([sys.executable, "-I", self.SCRIPT, flag], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0)
            self.assertEqual(out.stdout.strip(), f"ssh-1password {ssh1p.__version__}")

    def test_install_sh_from_local_tarball_and_uninstall(self):
        import tarfile
        with tempfile.TemporaryDirectory() as tmp:
            tarball = os.path.join(tmp, "release.tar.gz")
            top = f"ssh-1password-{ssh1p.__version__}"
            with tarfile.open(tarball, "w:gz") as tf:
                for rel in ("ssh-1password.py", "templates/hosts.yml", "README.md", "LICENSE"):
                    tf.add(os.path.join(ROOT, rel), arcname=f"{top}/{rel}")
            prefix = os.path.join(tmp, "prefix")
            sh = ["sh", os.path.join(ROOT, "install.sh"), "--prefix", prefix]
            out = subprocess.run(sh + ["--from", tarball], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            link = os.path.join(prefix, "bin", "ssh-1password")
            self.assertTrue(os.path.islink(link))
            self.assertIn("is not in your PATH", out.stdout)
            ver = subprocess.run([link, "--version"], capture_output=True, text=True)
            self.assertEqual(ver.stdout.strip(), f"ssh-1password {ssh1p.__version__}")
            out = subprocess.run(sh + ["--uninstall"], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(os.path.lexists(link))
            self.assertFalse(os.path.exists(os.path.join(prefix, "share", "ssh-1password")))

    def test_install_sh_rejects_foreign_tarball(self):
        import tarfile
        with tempfile.TemporaryDirectory() as tmp:
            tarball = os.path.join(tmp, "other.tar.gz")
            with tarfile.open(tarball, "w:gz") as tf:
                tf.add(os.path.join(ROOT, "LICENSE"), arcname="something-else/LICENSE")
            out = subprocess.run(["sh", os.path.join(ROOT, "install.sh"), "--prefix", os.path.join(tmp, "p"),
                                  "--from", tarball], capture_output=True, text=True)
            self.assertEqual(out.returncode, 1)
            self.assertIn("does not look like an ssh-1password release", out.stderr)
            self.assertFalse(os.path.exists(os.path.join(tmp, "p", "bin", "ssh-1password")))

    def test_install_command_was_renamed_to_sync(self):
        with captured() as buf, contextlib.redirect_stderr(buf):
            self.assertEqual(ssh1p.main(["install"]), 2)
        self.assertIn("unknown argument: install", buf.getvalue())

    def test_template_found_through_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "ssh-1password")
            os.symlink(self.SCRIPT, link)
            loader = importlib.machinery.SourceFileLoader("ssh1p_link", link)
            mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("ssh1p_link", loader))
            loader.exec_module(mod)
            self.assertTrue(os.path.isfile(mod.TEMPLATE), mod.TEMPLATE)


class Doctor(Base):
    def test_doctor_after_install_is_clean(self):
        self.run_sync()
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("FAIL", out)
        self.assertIn("ssh -G checks skipped", out)

    def test_doctor_detects_drift(self):
        self.run_sync()
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

    def test_doctor_fails_without_app(self):
        self.run_sync()
        ssh1p.app_installed = lambda: False
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL 1Password app not found", out)

    def test_doctor_warns_when_agent_unreachable(self):
        self.run_sync()
        ssh1p.SSH_ADD = [sys.executable, "-I", FAKE_SSH_ADD, self.fake_out, "2"]
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("WARN SSH agent not reachable", out)
        self.assertIn("agent not available to confirm", out)

    def test_doctor_warns_on_loose_permissions(self):
        self.run_sync()
        os.chmod(os.path.join(self.home, ".ssh/config.d/1password.conf"), 0o644)
        os.chmod(os.path.join(self.home, ".ssh"), 0o755)
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("1password.conf is readable by others", out)
        self.assertIn(".ssh is accessible by others", out)

    def test_doctor_warns_on_missing_agent_toml(self):
        self.run_sync()
        os.remove(os.path.join(self.home, ".config/1Password/ssh/agent.toml"))
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("WARN ~/.config/1Password/ssh/agent.toml missing", out)

    def test_doctor_warns_on_foreign_agent_toml_missing_title(self):
        self.run_sync()
        with open(os.path.join(self.home, ".config/1Password/ssh/agent.toml"), "w") as fh:
            fh.write('[[ssh-keys]]\nitem = "GitHub personal"\n')
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("(yours) does not list: GitHub work", out)

    def test_doctor_warns_on_orphan_and_rotated_key(self):
        self.run_sync()
        pubdir = os.path.join(self.home, ".ssh/1password")
        with open(os.path.join(pubdir, "old.pub"), "w") as fh:
            fh.write("ssh-ed25519 AAAA old\n")
        with open(self.fake_out, "w") as fh:  # the "GitHub work" item now holds another key
            fh.write(f"ssh-ed25519 {blob('personal')} GitHub personal\nssh-ed25519 {blob('rotated')} GitHub work\n")
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0)
        self.assertIn("orphan", out)
        self.assertIn("different key under this title", out)


class GitIdentity(Base):
    WORK = "github-work:\n  hostname: github.com\n  user: git\n  key: GitHub work\n  email: me@work.example\n  name: Work Me\n"

    def setUp(self):
        super().setUp()
        with open(self.registry, "w") as fh:
            fh.write("github-personal:\n  hostname: github.com\n  user: git\n  key: GitHub personal\n" + self.WORK)

    def gitconfig(self):
        path = os.path.join(self.home, ".gitconfig")
        if not os.path.exists(path):
            return ""
        with open(path) as fh:
            return fh.read()

    def test_identity_applied_probed_and_removed(self):
        _rc, out = self.run_sync()
        ident = self.read(".config/ssh-1password/git/github-work.gitconfig")
        self.assertIn("[user]\n\temail = me@work.example\n\tname = Work Me\n", ident)
        self.assertEqual(self.mode(".config/ssh-1password/git/github-work.gitconfig"), 0o600)
        cfg = self.gitconfig()
        self.assertIn('[includeIf "hasconfig:remote.*.url:git@github-work:*/**"]', cfg)
        self.assertIn('[includeIf "hasconfig:remote.*.url:git@github-work:*"]', cfg)
        self.assertIn('[includeIf "hasconfig:remote.*.url:ssh://git@github-work/**"]', cfg)
        self.assertIn('[includeIf "hasconfig:remote.*.url:github-work:*/**"]', cfg)
        self.assertNotIn("github-personal", cfg)  # no email -> no identity

        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("github-work: repos cloned through this alias commit as <me@work.example>", out)

        _rc, out = self.run_sync()
        self.assertIn("git identities for 1 alias(es) (no changes)", out)
        self.assertNotIn("set    git includeIf", out)

        with open(self.registry, "w") as fh:
            fh.write("github-work:\n  hostname: github.com\n  user: git\n  key: GitHub work\n")
        _rc, out = self.run_sync()
        self.assertIn("unset  git includeIf", out)
        self.assertIn("remove ~/.config/ssh-1password/git/github-work.gitconfig", out)
        self.assertNotIn("includeIf", self.gitconfig())
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/ssh-1password/git/github-work.gitconfig")))

    def test_doctor_detects_missing_include(self):
        self.run_sync()
        os.remove(os.path.join(self.home, ".gitconfig"))
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("includeIf entries are missing", out)
        self.assertIn("would commit as", out)

    def test_dry_run_touches_no_git_config(self):
        _rc, out = self.run_sync(dry=True)
        self.assertIn('set    git includeIf "hasconfig:remote.*.url:git@github-work:*/**"', out)
        self.assertEqual(self.gitconfig(), "")
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/ssh-1password/git")))

    def probe(self, url):
        env = self.env()
        with tempfile.TemporaryDirectory() as tmp:
            ssh1p.git_run(env, "init", "-q", cwd=tmp)
            ssh1p.git_run(env, "remote", "add", "origin", url, cwd=tmp)
            _rc, email = ssh1p.git_run(env, "config", "--get", "user.email", cwd=tmp)
        return email.strip()

    def test_flat_remote_and_alias_without_user(self):
        with open(self.registry, "a") as fh:
            fh.write("plain:\n  key: GitHub personal\n  email: plain@example\n")
        self.run_sync()
        self.assertEqual(self.probe("git@github-work:repo.git"), "me@work.example")
        self.assertEqual(self.probe("git@github-work:org/sub/repo.git"), "me@work.example")
        self.assertEqual(self.probe("plain:org/repo.git"), "plain@example")
        self.assertEqual(self.probe("ssh://plain/org/repo.git"), "plain@example")
        self.assertEqual(self.probe("ssh://plain:2222/org/repo.git"), "plain@example")
        self.assertEqual(self.probe("ssh://git@github-work:32222/org/sub/repo.git"), "me@work.example")
        self.assertEqual(self.probe("git@github-personal:org/repo.git"), "")
        self.assertNotIn("git@plain", self.gitconfig())  # no user: only bare patterns

    def test_old_git_skips_identities(self):
        saved = ssh1p.git_supports_hasconfig
        ssh1p.git_supports_hasconfig = lambda env: False
        try:
            _rc, out = self.run_sync()
            self.assertIn("git < 2.36", out)
            self.assertEqual(self.gitconfig(), "")
            self.assertFalse(os.path.exists(os.path.join(self.home, ".config/ssh-1password/git")))
            rc, out = self.run_doctor()
            self.assertEqual(rc, 0, out)
            self.assertIn("WARN git missing or older than 2.36", out)
        finally:
            ssh1p.git_supports_hasconfig = saved

    def test_name_without_email_is_ignored(self):
        with open(self.registry, "a") as fh:
            fh.write("lonely:\n  key: GitHub personal\n  name: Nobody\n")
        hosts, problems = ssh1p.load_registry(self.registry)
        self.assertEqual([h["alias"] for h in hosts], ["github-personal", "github-work", "lonely"])
        self.assertEqual(hosts[2]["name"], "")
        self.assertTrue(any("name: without email:" in p for p in problems))


class CommitSigning(Base):
    PERSONAL = "github-personal:\n  hostname: github.com\n  user: git\n  key: GitHub personal\n  email: me@home.example\n"
    WORK = "github-work:\n  hostname: github.com\n  user: git\n  key: GitHub work\n  email: me@work.example\n  name: Work Me\n"
    IDENT = ".config/ssh-1password/git/github-work.gitconfig"
    ALLOWED = ".config/ssh-1password/allowed_signers"

    def setUp(self):
        super().setUp()
        self.write_registry(self.PERSONAL + self.WORK + "  sign: manual\n")

    def write_registry(self, text):
        with open(self.registry, "w") as fh:
            fh.write(text)

    def probe(self, url, key):
        env = self.env()
        with tempfile.TemporaryDirectory() as tmp:
            ssh1p.git_run(env, "init", "-q", cwd=tmp)
            ssh1p.git_run(env, "remote", "add", "origin", url, cwd=tmp)
            _rc, value = ssh1p.git_run(env, "config", "--get", key, cwd=tmp)
        return value.strip()

    def test_manual_then_always(self):
        rc, out = self.run_sync()
        self.assertEqual(rc, 0)
        ident = self.read(self.IDENT)
        self.assertIn(f"[user]\n\temail = me@work.example\n\tname = Work Me\n\tsigningkey = ssh-ed25519 {blob('work')}\n"
                      f"[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = {self.signer}\n"
                      "\tallowedSignersFile = ~/.config/ssh-1password/allowed_signers\n", ident)
        self.assertNotIn("gpgsign", ident)
        self.assertNotIn("signingkey", self.read(".config/ssh-1password/git/github-personal.gitconfig"))
        self.assertEqual(self.read(self.ALLOWED).splitlines()[1:], [f'me@work.example namespaces="git" ssh-ed25519 {blob("work")}'])
        self.assertEqual(self.mode(self.ALLOWED), 0o644)
        self.assertIn("Signing key", out)
        url = "git@github-work:org/repo.git"
        self.assertEqual(self.probe(url, "user.signingkey"), f"ssh-ed25519 {blob('work')}")
        self.assertEqual(self.probe(url, "gpg.format"), "ssh")
        self.assertEqual(self.probe(url, "commit.gpgsign"), "")
        self.assertEqual(self.probe("git@github-personal:org/repo.git", "gpg.format"), "")

        self.write_registry(self.PERSONAL + self.WORK + "  sign: always\n")
        self.run_sync()
        self.assertIn("[commit]\n\tgpgsign = true\n[tag]\n\tgpgsign = true\n", self.read(self.IDENT))
        self.assertEqual(self.probe(url, "commit.gpgsign"), "true")
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("signs with 'GitHub work' (always)", out)

    def test_dedicated_signing_key(self):
        self.write_registry(self.PERSONAL + self.WORK + "  sign: manual\n  signing_key: Signing work\n")
        self.run_sync()
        self.assertEqual(sorted(os.listdir(os.path.join(self.home, ".ssh/1password"))),
                         ["github-personal.pub", "github-work.pub", "signing-work.pub"])
        self.assertIn('item = "Signing work"', self.read(".config/1Password/ssh/agent.toml"))
        self.assertIn(f"signingkey = ssh-ed25519 {blob('sign')}", self.read(self.IDENT))
        self.assertIn("Host github-work\n    HostName github.com\n    User git\n    IdentityFile ~/.ssh/1password/github-work.pub",
                      self.read(".ssh/config.d/1password.conf"))
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn("signs with 'Signing work' (manual)", out)

    def test_signer_missing(self):
        ssh1p.signer_path = lambda: None
        _rc, out = self.run_sync()
        self.assertIn("WARN   github-work: op-ssh-sign not found", out)
        ident = self.read(self.IDENT)
        self.assertIn("email = me@work.example", ident)
        self.assertNotIn("signingkey", ident)
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL github-work: op-ssh-sign not found", out)

    def test_signing_key_not_offered(self):
        self.write_registry(self.PERSONAL + self.WORK + "  sign: manual\n  signing_key: Nope\n")
        _rc, out = self.run_sync()
        self.assertIn("Nope: the agent does not offer it", out)
        self.assertIn("signing key 'Nope' is not offered", out)
        ident = self.read(self.IDENT)
        self.assertIn("email = me@work.example", ident)
        self.assertNotIn("signingkey", ident)
        self.assertFalse(os.path.exists(os.path.join(self.home, self.ALLOWED)))

    def test_allowed_signers_two_emails_share_a_key(self):
        self.write_registry(self.PERSONAL + self.WORK + "  sign: manual\n"
                            "github-other:\n  hostname: github.com\n  user: git\n  key: GitHub work\n  email: other@work.example\n  sign: always\n")
        self.run_sync()
        lines = self.read(self.ALLOWED).splitlines()
        self.assertTrue(lines[0].startswith("# generated by ssh-1password.py"))
        self.assertEqual(lines[1:], [f'me@work.example namespaces="git" ssh-ed25519 {blob("work")}',
                                     f'other@work.example namespaces="git" ssh-ed25519 {blob("work")}'])

    def test_signing_removed(self):
        self.run_sync()
        self.write_registry(self.PERSONAL + self.WORK)
        _rc, out = self.run_sync()
        self.assertIn("remove ~/.config/ssh-1password/allowed_signers", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, self.ALLOWED)))
        self.assertNotIn("signingkey", self.read(self.IDENT))
        self.assertEqual(self.probe("git@github-work:org/repo.git", "gpg.format"), "")

    def test_dry_run_and_repeat_run(self):
        _rc, out = self.run_sync(dry=True)
        self.assertIn(f"signingkey = ssh-ed25519 {blob('work')}", out)
        self.assertIn('namespaces="git"', out)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/ssh-1password")))
        self.run_sync()
        _rc, out = self.run_sync()
        self.assertIn("github-work.gitconfig (no changes)", out)
        self.assertIn("allowed_signers (no changes)", out)
        self.assertNotIn("update", out)

    # --- doctor ----------------------------------------------------------------------------

    def test_doctor_detects_replaced_key(self):
        self.run_sync()
        with open(self.fake_out, "w") as fh:  # the "GitHub work" item now holds another key
            fh.write(f"ssh-ed25519 {blob('personal')} GitHub personal\nssh-ed25519 {blob('rotated')} GitHub work\n")
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL github-work: the signing key changed in 1Password", out)
        self.assertIn("run sync", out)
        self.run_sync()
        rc, out = self.run_doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn(f'me@work.example namespaces="git" ssh-ed25519 {blob("rotated")}', self.read(self.ALLOWED))

    def test_doctor_detects_missing_allowed_signer_line(self):
        self.run_sync()
        with open(os.path.join(self.home, self.ALLOWED), "w") as fh:
            fh.write("# generated by ssh-1password.py\n")
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("allowed_signers lacks this identity", out)

    def test_doctor_detects_signer_removed_after_install(self):
        self.run_sync()
        ssh1p.signer_path = lambda: None
        rc, out = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL github-work: op-ssh-sign not found", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
