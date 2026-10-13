"""Process discovery: find coding-agent processes and read their argv / env / cwd.

Environment *values* are only ever used to classify a variable; they are never
returned to callers, printed or written anywhere.
"""
import ctypes
import ctypes.util
import os
import re
import struct
import subprocess
import sys

# (agent, regex matched against exe path, argv[0] and argv[1])
AGENTS = [
    ("codex", r"(^|/)codex(-[a-z-]+)?$|/codex-cli/|/\.codex/packages/|@openai/codex"),
    ("claude", r"(^|/)claude$|/claude-code/|@anthropic-ai/claude-code"),
    ("cursor-agent", r"(^|/)cursor-agent$|/cursor-agent/"),
    ("gemini", r"(^|/)gemini$|@google/gemini-cli"),
    ("opencode", r"(^|/)opencode$|opencode-ai"),
    ("copilot", r"@github/copilot(/|$)|(^|/)copilot$"),
    ("aider", r"(^|/)aider$"),
    ("amp", r"(^|/)amp$|@sourcegraph/amp"),
    ("goose", r"(^|/)goose$"),
    ("qwen", r"(^|/)qwen$|@qwen-code/"),
    ("crush", r"(^|/)crush$"),
]
_AGENT_RX = [(a, re.compile(rx)) for a, rx in AGENTS]
INTERPRETERS = {"node", "bun", "deno", "python", "python3"}

# Names that look like credentials. Matched case-insensitively on the variable name.
SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|SIGNING_?KEY|"
    r"CREDENTIALS?$|COOKIE|(^|_)PAT$|SESSION_?KEY|AUTH_?KEY|DSN$)", re.I)
# Variables that grant indirect credential access (agent sockets, askpass helpers).
ACCESS_NAME = re.compile(r"^(SSH_AUTH_SOCK|GIT_ASKPASS|SSH_ASKPASS|SUDO_ASKPASS|GPG_AGENT_INFO|"
                         r"DOCKER_HOST|KUBECONFIG|AWS_PROFILE|GOOGLE_APPLICATION_CREDENTIALS)$")
# Names that match SECRET_NAME but are not credentials.
NOT_SECRET = re.compile(r"(_SCOPES?$|^USE_.*OAUTH$|_HAS_|_LIMIT$|_MAX_|_COUNT$|_FILE_?NAME$|"
                        r"^TOKENIZERS_|_ENABLED$|_DISABLED$|_URL$|_HOST$|_PORT$|_REGION$)", re.I)
# Value shapes of well-known credential formats, independent of the variable name.
SECRET_VALUE = re.compile(
    r"^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)")


def classify_env(name, value):
    """Return 'secret', 'access' or None for one environment variable."""
    if value and SECRET_VALUE.match(value):
        return "secret"
    if ACCESS_NAME.match(name):
        return "access"
    if SECRET_NAME.search(name) and not NOT_SECRET.search(name):
        v = value or ""
        if len(v) < 8 or v.lower() in ("true", "false", "none", "null") or v.isdigit():
            return None
        if v.startswith("/") and "KEY" not in name.upper():  # a path, not a credential
            return "access"
        return "secret"
    return None


def match_agent(exe, argv):
    cands = [exe or ""]
    if argv:
        cands.append(argv[0])
        base = os.path.basename(argv[0])
        if (base in INTERPRETERS or os.path.basename(exe or "") in INTERPRETERS) and len(argv) > 1:
            cands.append(argv[1])
    for agent, rx in _AGENT_RX:
        for c in cands:
            if c and rx.search(c):
                return agent
    return None


def kind_of(exe, argv, tty):
    """session | daemon | updater | desktop | helper | detached"""
    joined = " ".join(argv or [])
    path = exe or ""
    if re.search(r"update-loop|\bupdater\b|self-update", joined):
        return "updater"
    if "/app-server-daemon/" in path or re.search(r"\bdaemon\b|--managed-daemon", joined):
        return "daemon"
    base = os.path.basename(path)
    if re.search(r"-(host|helper|server|sandbox)$", base) or (len(argv or []) > 1 and argv[1] in ("sandbox", "mcp-server")):
        return "helper"
    if re.search(r"\.app/Contents/Resources/|/Application Support/Claude/claude-code/|/\.config/Claude/claude-code/", path):
        return "desktop"
    if tty and tty not in ("??", "?", "-"):
        return "session"
    return "detached"


def parse_etime(s):
    """ps etime '[[dd-]hh:]mm:ss' -> seconds."""
    s = s.strip()
    days = 0
    if "-" in s:
        d, s = s.split("-", 1)
        days = int(d)
    parts = [int(p) for p in s.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0)
    h, m, sec = parts
    return days * 86400 + h * 3600 + m * 60 + sec


def _ps_rows():
    out = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,etime=,rss=,time=,tty=,args="],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        f = line.split(None, 6)
        if len(f) < 7:
            continue
        try:
            rows.append({"pid": int(f[0]), "ppid": int(f[1]), "age": parse_etime(f[2]),
                         "rss_kb": int(f[3]), "cpu": parse_etime(f[4].split(".")[0]),
                         "tty": f[5], "args": f[6]})
        except ValueError:
            continue
    return rows


# ---- argv / env readers ---------------------------------------------------

_libc = None


def _procargs_mac(pid):
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"))
    argmax = ctypes.c_int(0)
    sz = ctypes.c_size_t(ctypes.sizeof(argmax))
    if _libc.sysctl((ctypes.c_int * 2)(1, 8), 2, ctypes.byref(argmax), ctypes.byref(sz), None, ctypes.c_size_t(0)) != 0:
        return None
    buf = ctypes.create_string_buffer(argmax.value)
    size = ctypes.c_size_t(argmax.value)
    if _libc.sysctl((ctypes.c_int * 3)(1, 49, pid), 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return None
    return parse_procargs2(buf.raw[:size.value])


def parse_procargs2(raw):
    """Parse a KERN_PROCARGS2 buffer -> (exe, argv, [(name, value)])."""
    if len(raw) < 4:
        return None
    argc = struct.unpack("i", raw[:4])[0]
    exe, _, rest = raw[4:].partition(b"\0")
    parts = rest.lstrip(b"\0").split(b"\0")
    argv = [p.decode("utf-8", "replace") for p in parts[:argc]]
    env = []
    for p in parts[argc:]:
        if not p:
            break
        k, _, v = p.decode("utf-8", "replace").partition("=")
        env.append((k, v))
    return exe.decode("utf-8", "replace"), argv, env


def _procargs_linux(pid):
    base = f"/proc/{pid}"
    try:
        argv = [a.decode("utf-8", "replace") for a in open(f"{base}/cmdline", "rb").read().split(b"\0") if a]
    except OSError:
        return None
    try:
        exe = os.readlink(f"{base}/exe")
    except OSError:
        exe = argv[0] if argv else ""
    env = []
    try:
        for p in open(f"{base}/environ", "rb").read().split(b"\0"):
            if p:
                k, _, v = p.decode("utf-8", "replace").partition("=")
                env.append((k, v))
    except OSError:
        env = None
    return exe, argv, env


def read_procargs(pid):
    try:
        if sys.platform == "darwin":
            return _procargs_mac(pid)
        if os.path.isdir("/proc"):
            return _procargs_linux(pid)
    except Exception:
        return None
    return None


def read_cwd(pid):
    if os.path.isdir(f"/proc/{pid}"):
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return None
    try:
        out = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        if line.startswith("n"):
            return line[1:]
    return None


def scan(with_cwd=False):
    """Return a list of agent process dicts. Env values are reduced to classifications."""
    rows = _ps_rows()
    by_pid = {r["pid"]: r for r in rows}
    me = os.getpid()
    procs = []
    for r in rows:
        if r["pid"] == me:
            continue
        info = read_procargs(r["pid"])
        if info:
            exe, argv, env = info
        else:
            exe, argv, env = "", r["args"].split(), None
        exe = exe or (argv[0] if argv else "")
        agent = match_agent(exe, argv)
        if not agent:
            continue
        p = dict(r)
        p.pop("args")
        p.update(agent=agent, exe=exe, argv=argv, kind=kind_of(exe, argv, r["tty"]))
        try:
            p["real_exe"] = os.path.realpath(exe) if exe.startswith("/") else exe
        except OSError:
            p["real_exe"] = exe
        if env is None:
            p["env_readable"] = False
            p["secrets"], p["access"] = [], []
        else:
            p["env_readable"] = True
            p["env_count"] = len(env)
            p["secrets"] = sorted({k for k, v in env if classify_env(k, v) == "secret"})
            p["access"] = sorted({k for k, v in env if classify_env(k, v) == "access"})
        parent = by_pid.get(r["ppid"])
        p["parent"] = os.path.basename(parent["args"].split()[0]) if parent else ("launchd/init" if r["ppid"] == 1 else "?")
        procs.append(p)
    pids = {p["pid"] for p in procs}
    for p in procs:
        p["child_of_agent"] = p["ppid"] in pids
        if with_cwd and p["kind"] in ("daemon", "updater", "detached"):
            p["cwd"] = read_cwd(p["pid"])
    return procs
