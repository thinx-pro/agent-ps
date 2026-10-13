"""Known install layouts of coding agents that keep one directory (or file) per version."""
import json
import os
import re
import shutil

# root: directory holding one entry per version.
# current: symlinks whose target marks the active version (first that resolves wins).
LAYOUTS = [
    {"agent": "codex", "label": "Codex app-server daemon", "root": "~/.codex/packages/app-server-daemon/releases",
     "current": ["~/.codex/packages/app-server-daemon/current"]},
    {"agent": "codex", "label": "Codex standalone", "root": "~/.codex/packages/standalone/releases",
     "current": ["~/.codex/packages/standalone/current", "~/.local/bin/codex"]},
    {"agent": "claude", "label": "Claude Code (native)", "root": "~/.local/share/claude/versions",
     "current": ["~/.local/bin/claude"]},
    {"agent": "claude", "label": "Claude Code (desktop app, macOS)", "root": "~/Library/Application Support/Claude/claude-code",
     "current": []},
    {"agent": "claude", "label": "Claude Code (desktop app, Linux)", "root": "~/.config/Claude/claude-code",
     "current": []},
    {"agent": "cursor-agent", "label": "Cursor Agent CLI", "root": "~/.local/share/cursor-agent/versions",
     "current": ["~/.local/bin/cursor-agent"]},
    {"agent": "opencode", "label": "OpenCode", "root": "~/.opencode/versions", "current": ["~/.opencode/bin/opencode"]},
]

_VER = [
    re.compile(r"/releases/(\d+\.\d+[\w.+-]*?)(?:-(?:aarch64|x86_64|arm64)[\w-]*)?/"),
    re.compile(r"/versions/([^/]+)"),
    re.compile(r"/claude-code/(\d+\.\d+[\w.]*)/"),
    re.compile(r"/Cellar/[^/]+/(\d+\.\d+[\w.]*)/"),
    re.compile(r"/Caskroom/[^/]+/(\d+\.\d+[\w.]*)/"),
    re.compile(r"/Versions/(\d+\.\d+[\d.]*)/"),
]


def version_from_path(path):
    if not path:
        return None
    for rx in _VER:
        m = rx.search(path + "/")
        if m:
            return m.group(1)
    # npm-style install: look for the nearest package.json with a version
    d = os.path.dirname(path)
    for _ in range(6):
        pj = os.path.join(d, "package.json")
        if os.path.isfile(pj):
            try:
                with open(pj, encoding="utf-8") as f:
                    v = json.load(f).get("version")
                if v:
                    return str(v)
            except (OSError, ValueError):
                pass
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return None


def _ver_sort_key(name):
    # numbers sort numerically and above any text, so 0.162.1 > 0.162.0 > 0.162.0-rc
    return [(1, int(x), "") if x.isdigit() else (0, 0, x) for x in re.split(r"[.\-+]", name)]


def du(path):
    if os.path.islink(path):
        return 0
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for r, _ds, fs in os.walk(path):
        for f in fs:
            try:
                total += os.lstat(os.path.join(r, f)).st_size
            except OSError:
                pass
    return total


def scan(procs=(), home=None, keep=0):
    """List versioned installs. keep = extra newest versions to keep besides current/in-use."""
    home = home or os.path.expanduser("~")
    ex = lambda p: os.path.join(home, p[2:]) if p.startswith("~/") else p
    running = [os.path.realpath(p["exe"]) for p in procs if p.get("exe", "").startswith("/")]
    out = []
    for lay in LAYOUTS:
        root = ex(lay["root"])
        if not os.path.isdir(root):
            continue
        cur_target = None
        for c in lay["current"]:
            c = ex(c)
            if os.path.islink(c) or os.path.exists(c):
                cur_target = os.path.realpath(c)
                break
        entries = []
        for name in sorted(os.listdir(root), key=_ver_sort_key):
            if name.startswith(".") or name in ("current", "latest"):
                continue
            p = os.path.join(root, name)
            if os.path.islink(p):
                continue
            real = os.path.realpath(p)
            e = {"name": name, "path": p, "bytes": du(p),
                 "current": bool(cur_target and (cur_target == real or cur_target.startswith(real + os.sep))),
                 "in_use": sum(1 for r in running if r == real or r.startswith(real + os.sep))}
            entries.append(e)
        if not entries:
            continue
        if not any(e["current"] for e in entries):
            entries[-1]["newest"] = True  # no link to tell us: treat the newest as current
        kept_extra = 0
        for e in reversed(entries):
            protected = e["current"] or e.get("newest") or e["in_use"]
            if not protected and kept_extra < keep:
                kept_extra += 1
                e["kept"] = True
                protected = True
            e["reclaimable"] = not protected
        out.append({"agent": lay["agent"], "label": lay["label"], "root": root, "entries": entries,
                    "bytes": sum(e["bytes"] for e in entries),
                    "reclaimable_bytes": sum(e["bytes"] for e in entries if e["reclaimable"])})
    return out


def prune(installs, dry_run=True):
    """Delete reclaimable entries. Returns list of (path, bytes, status)."""
    done = []
    for inst in installs:
        root = os.path.realpath(inst["root"])
        for e in inst["entries"]:
            if not e["reclaimable"]:
                continue
            p = e["path"]
            real = os.path.realpath(p)
            if os.path.dirname(real) != root or os.path.islink(p):
                done.append((p, e["bytes"], "skipped: outside root"))
                continue
            if dry_run:
                done.append((p, e["bytes"], "would remove"))
                continue
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p)
                else:
                    os.remove(p)
                done.append((p, e["bytes"], "removed"))
            except OSError as err:
                done.append((p, e["bytes"], f"failed: {err}"))
    return done
