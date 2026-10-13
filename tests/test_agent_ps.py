import io
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_ps import cli, installs, procs  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_etime(self):
        self.assertEqual(procs.parse_etime("05:07"), 307)
        self.assertEqual(procs.parse_etime("01:00:00"), 3600)
        self.assertEqual(procs.parse_etime("6-14:07:44"), 6 * 86400 + 14 * 3600 + 7 * 60 + 44)

    def test_procargs2(self):
        raw = struct.pack("i", 3) + b"/usr/bin/codex\0\0\0\0codex\0app-server\0daemon\0GH_TOKEN=ghp_x\0HOME=/h\0\0junk\0"
        exe, argv, env = procs.parse_procargs2(raw)
        self.assertEqual(exe, "/usr/bin/codex")
        self.assertEqual(argv, ["codex", "app-server", "daemon"])
        self.assertEqual(env, [("GH_TOKEN", "ghp_x"), ("HOME", "/h")])


class ClassifyTests(unittest.TestCase):
    def test_secret_names(self):
        self.assertEqual(procs.classify_env("GH_TOKEN", "abcdefghijkl"), "secret")
        self.assertEqual(procs.classify_env("OPENAI_API_KEY", "abcdefghijkl"), "secret")
        self.assertEqual(procs.classify_env("AWS_SECRET_ACCESS_KEY", "abcdefghijkl"), "secret")

    def test_not_secret(self):
        self.assertIsNone(procs.classify_env("GIT_CONFIG_KEY_0", "safe.directory"))
        self.assertIsNone(procs.classify_env("CLAUDE_CODE_OAUTH_SCOPES", "user:inference profile"))
        self.assertIsNone(procs.classify_env("MAX_TOKEN_LIMIT", "100000"))
        self.assertIsNone(procs.classify_env("SOME_TOKEN", "true"))
        self.assertIsNone(procs.classify_env("HOME", "/Users/x"))

    def test_access(self):
        self.assertEqual(procs.classify_env("SSH_AUTH_SOCK", "/tmp/x"), "access")
        self.assertEqual(procs.classify_env("GIT_ASKPASS", "/usr/libexec/askpass"), "access")

    def test_value_shape_wins(self):
        self.assertEqual(procs.classify_env("INNOCENT", "ghp_" + "a" * 36), "secret")
        self.assertEqual(procs.classify_env("X", "sk-ant-" + "b" * 30), "secret")


class MatchTests(unittest.TestCase):
    def test_agents(self):
        self.assertEqual(procs.match_agent("/opt/homebrew/bin/claude", ["claude"]), "claude")
        self.assertEqual(procs.match_agent("/h/.codex/packages/app-server-daemon/releases/0.162.1/bin/codex", []), "codex")
        self.assertEqual(procs.match_agent("/usr/bin/node", ["node", "/usr/lib/node_modules/@google/gemini-cli/dist/index.js"]), "gemini")
        self.assertEqual(procs.match_agent("/usr/bin/node", ["node", "/x/@anthropic-ai/claude-code/cli.js"]), "claude")
        self.assertIsNone(procs.match_agent("/Applications/Claude.app/Contents/MacOS/Claude", ["Claude"]))
        self.assertIsNone(procs.match_agent("/usr/bin/vim", ["vim", "claude.md"]))

    def test_kinds(self):
        k = procs.kind_of
        self.assertEqual(k("/h/.codex/packages/app-server-daemon/releases/1/bin/codex", ["codex", "app-server", "daemon", "pid-update-loop"], "??"), "updater")
        self.assertEqual(k("/h/.codex/packages/app-server-daemon/releases/1/bin/codex", ["codex", "app-server", "--listen"], "??"), "daemon")
        self.assertEqual(k("/usr/bin/codex", ["codex", "app-server", "--managed-daemon"], "?"), "daemon")
        self.assertEqual(k("/opt/homebrew/bin/claude", ["claude"], "ttys003"), "session")
        self.assertEqual(k("/opt/homebrew/bin/claude", ["claude", "-p"], "??"), "detached")
        self.assertEqual(k("/h/Library/Application Support/Claude/claude-code/2.1.295/x/claude", ["claude"], "??"), "desktop")
        self.assertEqual(k("/A.app/Contents/Resources/codex-cli/codex", ["codex", "sandbox"], "??"), "helper")


class VersionTests(unittest.TestCase):
    def test_paths(self):
        v = installs.version_from_path
        self.assertEqual(v("/h/.codex/packages/standalone/releases/0.150.1-aarch64-apple-darwin/bin/codex"), "0.150.1")
        self.assertEqual(v("/h/.local/share/claude/versions/2.1.296"), "2.1.296")
        self.assertEqual(v("/h/Library/Application Support/Claude/claude-code/2.1.295/abc/claude"), "2.1.295")
        self.assertEqual(v("/opt/homebrew/Caskroom/claude-code/2.1.296/claude"), "2.1.296")

    def test_package_json(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "node_modules", "@openai", "codex")
            os.makedirs(os.path.join(pkg, "bin"))
            with open(os.path.join(pkg, "package.json"), "w") as f:
                json.dump({"name": "@openai/codex", "version": "0.157.0"}, f)
            self.assertEqual(installs.version_from_path(os.path.join(pkg, "bin", "codex.js")), "0.157.0")


def make_home(d):
    rel = os.path.join(d, ".codex", "packages", "app-server-daemon", "releases")
    for v in ("0.160.1-aarch64-apple-darwin", "0.161.0-aarch64-apple-darwin", "0.162.0-aarch64-apple-darwin",
              "0.162.1-aarch64-apple-darwin"):
        os.makedirs(os.path.join(rel, v, "bin"))
        with open(os.path.join(rel, v, "bin", "codex"), "wb") as f:
            f.write(b"x" * 1000)
    os.symlink(os.path.join(rel, "0.162.1-aarch64-apple-darwin"),
               os.path.join(d, ".codex", "packages", "app-server-daemon", "current"))
    cl = os.path.join(d, ".local", "share", "claude", "versions")
    os.makedirs(cl)
    for v in ("2.1.9", "2.1.10", "2.1.11"):
        with open(os.path.join(cl, v), "wb") as f:
            f.write(b"y" * 500)
    os.makedirs(os.path.join(d, ".local", "bin"))
    os.symlink(os.path.join(cl, "2.1.11"), os.path.join(d, ".local", "bin", "claude"))
    return rel, cl


class InstallTests(unittest.TestCase):
    def test_scan_and_prune(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            rel, cl = make_home(d)
            fake_procs = [{"exe": os.path.join(rel, "0.161.0-aarch64-apple-darwin", "bin", "codex")},
                          {"exe": os.path.join(cl, "2.1.10")}]
            inst = installs.scan(fake_procs, home=d)
            by = {i["label"]: i for i in inst}
            codex = {e["name"].split("-")[0]: e for e in by["Codex app-server daemon"]["entries"]}
            self.assertTrue(codex["0.162.1"]["current"])
            self.assertEqual(codex["0.161.0"]["in_use"], 1)
            self.assertEqual([k for k, e in codex.items() if e["reclaimable"]], ["0.160.1", "0.162.0"])
            claude = {e["name"]: e for e in by["Claude Code (native)"]["entries"]}
            # numeric sort: 2.1.9 < 2.1.10 < 2.1.11
            self.assertEqual([e["name"] for e in by["Claude Code (native)"]["entries"]], ["2.1.9", "2.1.10", "2.1.11"])
            self.assertTrue(claude["2.1.11"]["current"])
            self.assertFalse(claude["2.1.10"]["reclaimable"])
            self.assertTrue(claude["2.1.9"]["reclaimable"])

            dry = installs.prune(inst, dry_run=True)
            self.assertEqual({s for _p, _b, s in dry}, {"would remove"})
            self.assertTrue(os.path.exists(os.path.join(cl, "2.1.9")))
            done = installs.prune(inst, dry_run=False)
            self.assertEqual(len(done), 3)
            self.assertFalse(os.path.exists(os.path.join(cl, "2.1.9")))
            self.assertFalse(os.path.exists(os.path.join(rel, "0.160.1-aarch64-apple-darwin")))
            for keep in ("0.161.0-aarch64-apple-darwin", "0.162.1-aarch64-apple-darwin"):
                self.assertTrue(os.path.exists(os.path.join(rel, keep)))
            self.assertTrue(os.path.exists(os.path.join(cl, "2.1.10")))

    def test_keep_extra(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            make_home(d)
            inst = installs.scan([], home=d, keep=1)
            codex = [i for i in inst if i["agent"] == "codex"][0]
            rec = [e["name"].split("-")[0] for e in codex["entries"] if e["reclaimable"]]
            self.assertEqual(rec, ["0.160.1", "0.161.0"])

    def test_no_current_link_keeps_newest(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "Library", "Application Support", "Claude", "claude-code")
            for v in ("2.1.293", "2.1.295"):
                os.makedirs(os.path.join(root, v))
            inst = installs.scan([], home=d)
            es = inst[0]["entries"]
            self.assertTrue(es[-1].get("newest"))
            self.assertEqual([e["name"] for e in es if e["reclaimable"]], ["2.1.293"])


class FindingTests(unittest.TestCase):
    def proc(self, **kw):
        p = {"pid": 1, "ppid": 10, "agent": "codex", "kind": "session", "age": 60, "rss_kb": 1000,
             "secrets": [], "access": [], "env_readable": True}
        p.update(kw)
        return p

    def test_background_secret_is_warning(self):
        ps = [self.proc(pid=5, kind="daemon", secrets=["GH_TOKEN"]), self.proc(pid=6, secrets=["GH_TOKEN"])]
        fs = cli.findings(ps, [], 24)
        warn = [m for lvl, m, _a, _c in fs if lvl == "warn"]
        self.assertEqual(len(warn), 1)
        self.assertIn("1 background agent process(es)", warn[0])
        self.assertTrue(any("daemon_auto_start" in (c or "") for _l, _m, _a, c in fs))

    def test_foreground_secret_alone_is_quiet(self):
        fs = cli.findings([self.proc(secrets=["GH_TOKEN"])], [], 24)
        self.assertEqual(fs, [])

    def test_stale_and_drift(self):
        ps = [self.proc(age=3 * 86400)]
        inst = [{"agent": "claude", "label": "Claude Code (native)", "reclaimable_bytes": 0,
                 "entries": [{"name": "2.1.10", "in_use": 2, "current": False, "reclaimable": False},
                             {"name": "2.1.11", "in_use": 0, "current": True, "reclaimable": False}]}]
        msgs = " | ".join(m for _l, m, _a, _c in cli.findings(ps, inst, 24))
        self.assertIn("open for more than 24h", msgs)
        self.assertIn("2× Claude Code (native) 2.1.10 (current 2.1.11)", msgs)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_commands_run(self):
        for cmd in (["ps"], ["--all"], ["env"], ["disk"], ["doctor"], ["prune"]):
            code, out = self.run_cli(*cmd, "--no-color")
            self.assertEqual(code, 0, cmd)
            self.assertTrue(out.strip(), cmd)

    def test_json_never_contains_env_values(self):
        os.environ["AGENT_PS_TEST_TOKEN"] = "ghp_" + "Z" * 36
        try:
            code, out = self.run_cli("doctor", "--json")
        finally:
            del os.environ["AGENT_PS_TEST_TOKEN"]
        self.assertEqual(code, 0)
        self.assertNotIn("Z" * 36, out)
        json.loads(out)


if __name__ == "__main__":
    unittest.main()
