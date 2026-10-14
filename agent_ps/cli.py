"""agent-ps: ps + du + env audit for the coding agents on this machine."""
import argparse
import json
import os
import sys

from . import __version__, installs, procs as P

HOME = os.path.expanduser("~")
BACKGROUND = ("daemon", "updater", "detached")


class C:
    on = False
    codes = {"b": "1", "dim": "2", "red": "31", "yel": "33", "grn": "32", "cyan": "36", "mag": "35"}

    @classmethod
    def s(cls, text, *styles):
        if not cls.on or not styles:
            return text
        return "".join(f"\033[{cls.codes[x]}m" for x in styles) + text + "\033[0m"


def tilde(p):
    if not p:
        return p or ""
    return "~" + p[len(HOME):] if p == HOME or p.startswith(HOME + os.sep) else p


def wrap(text):
    import shutil
    import textwrap
    width = min(shutil.get_terminal_size((100, 24)).columns, 100) - 4
    return textwrap.wrap(text, max(width, 40))


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024.0


def human_cpu(sec):
    return f"{sec}s" if sec < 60 else human_age(sec)


def human_age(sec):
    if sec >= 86400:
        return f"{sec // 86400}d{(sec % 86400) // 3600}h"
    if sec >= 3600:
        return f"{sec // 3600}h{(sec % 3600) // 60:02d}m"
    return f"{sec // 60}m"


def _width(s):
    import re
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def table(headers, rows, aligns=None):
    aligns = aligns or ["<"] * len(headers)
    w = [_width(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            w[i] = max(w[i], _width(c))
    def fmt(r):
        cells = []
        for i, c in enumerate(r):
            pad = " " * (w[i] - _width(c))
            cells.append(pad + c if aligns[i] == ">" else c + pad)
        return "  ".join(cells).rstrip()
    lines = [C.s(fmt(headers), "dim")]
    lines += [fmt(r) for r in rows]
    return "\n".join(lines)


KIND_STYLE = {"daemon": ("mag", "b"), "updater": ("mag", "b"), "detached": ("yel",), "session": (),
              "desktop": ("cyan",), "helper": ("dim",)}


def collect(args, with_cwd=False):
    ps = P.scan(with_cwd=with_cwd)
    for p in ps:
        p["version"] = installs.version_from_path(p.get("real_exe") or p["exe"])
    inst = installs.scan(ps, keep=getattr(args, "keep", 0) or 0)
    return ps, inst


def visible(ps, show_all):
    if show_all:
        return ps
    return [p for p in ps if p["kind"] not in ("helper",) and not (p["kind"] == "desktop" and p["child_of_agent"])]


# ---- commands ---------------------------------------------------------------

def cmd_ps(args):
    ps, _ = collect(args)
    if args.json:
        return _dump({"processes": ps})
    shown = sorted(visible(ps, args.all), key=lambda p: (p["agent"], BACKGROUND.count(p["kind"]) == 0, -p["age"]))
    if not shown:
        print("No coding-agent processes found.")
        return 0
    rows = []
    for p in shown:
        flags = []
        if p["secrets"]:
            flags.append(C.s(f"{len(p['secrets'])} secret env", "red" if p["kind"] in BACKGROUND else "yel"))
        if p["ppid"] == 1 and p["kind"] != "desktop":
            flags.append(C.s("orphan", "yel"))
        if p["age"] > args.stale * 3600 and p["kind"] == "session":
            flags.append(C.s("stale", "dim"))
        rows.append([p["agent"], str(p["pid"]), C.s(p["kind"], *KIND_STYLE.get(p["kind"], ())),
                     p.get("version") or "?", human_age(p["age"]), human_bytes(p["rss_kb"] * 1024),
                     p["tty"] if p["tty"] not in ("??", "?") else "-", p["parent"], " ".join(flags)])
    print(table(["AGENT", "PID", "KIND", "VERSION", "AGE", "RSS", "TTY", "PARENT", "FLAGS"], rows,
                ["<", ">", "<", "<", ">", ">", "<", "<", "<"]))
    hidden = len(ps) - len(shown)
    tot = sum(p["rss_kb"] for p in ps) * 1024
    print(C.s(f"\n{len(shown)} processes shown" + (f", {hidden} helpers hidden (--all)" if hidden else "")
              + f" · total RSS {human_bytes(tot)}", "dim"))
    return 0


def cmd_env(args):
    ps, _ = collect(args, with_cwd=True)
    if args.pid:
        ps = [p for p in ps if p["pid"] in args.pid]
    if args.json:
        return _dump({"processes": [{k: p.get(k) for k in ("pid", "agent", "kind", "secrets", "access", "env_readable", "cwd")} for p in ps]})
    shown = [p for p in ps if p["secrets"] or p["access"] or not p["env_readable"]]
    shown.sort(key=lambda p: (p["kind"] not in BACKGROUND, p["agent"], p["pid"]))
    if not shown:
        print("No secret-looking environment variables in agent processes.")
        return 0
    print(C.s("Environment variable NAMES only; values are never printed.\n", "dim"))
    # Background processes one by one; foreground processes grouped by identical findings.
    groups = {}
    for p in shown:
        if p["kind"] in BACKGROUND or args.pid:
            groups[("pid", p["pid"])] = [p]
        else:
            key = (p["agent"], p["kind"], tuple(p["secrets"]), tuple(p["access"]), p["env_readable"])
            groups.setdefault(key, []).append(p)
    for members in groups.values():
        p = members[0]
        bg = p["kind"] in BACKGROUND
        if len(members) == 1:
            head = f"{p['agent']} {p['pid']} {p['kind']} · up {human_age(p['age'])}"
        else:
            pids = ", ".join(str(m["pid"]) for m in members[:6]) + (", …" if len(members) > 6 else "")
            head = f"{p['agent']} {p['kind']} ×{len(members)} (pids {pids})"
        if p.get("cwd"):
            head += f" · cwd {tilde(p['cwd'])}"
        print(C.s(head, "b", "mag") if bg else C.s(head, "b"))
        if not p["env_readable"]:
            print("  " + C.s("environment not readable (other user or protected process)", "dim"))
        if p["secrets"]:
            print("  " + C.s("secret  ", "red" if bg else "yel") + ", ".join(p["secrets"]))
        if p["access"]:
            print("  " + C.s("access  ", "cyan") + ", ".join(p["access"]))
        if bg and p["secrets"]:
            for line in wrap("↳ long-lived background process: these were inherited from whichever session started it "
                             "and stay visible to every later session it serves."):
                print("  " + C.s(line, "dim"))
    return 0


def cmd_disk(args):
    ps, inst = collect(args)
    if args.json:
        return _dump({"installs": inst})
    if not inst:
        print("No versioned agent installs found in known locations.")
        return 0
    rows = []
    for i in inst:
        for e in i["entries"]:
            state = []
            if e["current"]:
                state.append(C.s("current", "grn"))
            if e.get("newest"):
                state.append(C.s("newest", "grn"))
            if e["in_use"]:
                state.append(C.s(f"in use ×{e['in_use']}", "cyan"))
            if e.get("kept"):
                state.append("kept")
            if e["reclaimable"]:
                state.append(C.s("reclaimable", "yel", "b"))
            rows.append([i["label"], e["name"], human_bytes(e["bytes"]), " ".join(state)])
    print(table(["INSTALL", "VERSION", "SIZE", "STATE"], rows, ["<", "<", ">", "<"]))
    tot = sum(i["bytes"] for i in inst)
    rec = sum(i["reclaimable_bytes"] for i in inst)
    print(f"\n{human_bytes(tot)} in versioned installs · " + C.s(f"{human_bytes(rec)} reclaimable", "yel", "b")
          + (C.s("  →  agent-ps prune --yes", "dim") if rec else ""))
    return 0


def cmd_prune(args):
    ps, inst = collect(args)
    res = installs.prune(inst, dry_run=not args.yes)
    if args.json:
        return _dump({"dry_run": not args.yes, "results": [{"path": p, "bytes": b, "status": s} for p, b, s in res]})
    if not res:
        print("Nothing to prune: only current and in-use versions are present.")
        return 0
    for p, b, s in res:
        print(f"{s:14} {human_bytes(b):>9}  {tilde(p)}")
    total = sum(b for _p, b, s in res if s in ("removed", "would remove"))
    if args.yes:
        print(f"\nFreed {human_bytes(total)}.")
    else:
        print(C.s(f"\nDry run: {human_bytes(total)} would be freed. Re-run with --yes to delete. "
                  "Current and in-use versions are never touched.", "dim"))
    return 0


def runaways(ps, minutes, include_mcp=False, rows=None):
    trees = P.agent_trees(ps, rows)
    hidden = {"tooling", "zombie", "app-helper"} | (set() if include_mcp else {"mcp/lsp"})
    keep = [t for t in trees if t["age"] >= minutes * 60 and t["category"] not in hidden]
    return sorted(keep, key=lambda t: -t["age"])


def _signal_trees(trees, pids, sig, verb):
    import signal as S
    sigs = {"pause": S.SIGSTOP, "resume": S.SIGCONT, "kill": S.SIGTERM}
    by_root = {t["root_pid"]: t for t in trees}
    done = []
    for pid in pids:
        t = by_root.get(pid)
        if not t:
            print(C.s(f"pid {pid} is not the root of an agent-started process tree; skipped", "yel"), file=sys.stderr)
            continue
        ok = 0
        # leaves first, so a parent never sees its child vanish mid-signal
        for p in reversed(t["pids"]):
            try:
                os.kill(p, sigs[sig])
                ok += 1
            except (ProcessLookupError, PermissionError):
                pass
        done.append((pid, ok, len(t["pids"])))
        print(f"{verb} tree {pid}: {ok}/{len(t['pids'])} process(es) signalled")
    return done


def cmd_runaway(args):
    import time
    seen = set()
    while True:
        ps = P.scan()
        trees_all = P.agent_trees(ps)
        acts = [("pause", args.pause, "paused"), ("resume", args.resume, "resumed"), ("kill", args.kill, "terminated")]
        if any(pids for _, pids, _ in acts):
            if not args.yes:
                print("Refusing to signal processes without --yes. Pause is SIGSTOP (undo: --resume), kill is SIGTERM.",
                      file=sys.stderr)
                return 2
            for sig, pids, verb in acts:
                if pids:
                    _signal_trees(trees_all, pids, sig, verb)
            return 0
        found = runaways(ps, args.minutes, args.include_mcp)
        if args.json and not args.watch:
            return _dump({"minutes": args.minutes, "runaways": found})
        new = [t for t in found if t["root_pid"] not in seen]
        if not args.watch:
            _print_runaways(found, args.minutes)
        elif new:
            stamp = time.strftime("%H:%M:%S")
            for t in new:
                print(f"{stamp}  " + C.s("runaway", "yel", "b") + f" {t['agent']} {t['agent_pid']} → tree {t['root_pid']} "
                      f"up {human_age(t['age'])}, cpu {human_age(t['cpu'])}: {t['command'][:90]}", flush=True)
                if args.auto_pause and not t["paused"]:
                    _signal_trees(found, [t["root_pid"]], "pause", f"{stamp}  auto-paused")
            seen.update(t["root_pid"] for t in new)
        if not args.watch:
            return 1 if (args.strict and found) else 0
        time.sleep(args.watch)


def _print_runaways(found, minutes):
    if not found:
        print(C.s(f"✓ no agent-started process trees older than {minutes:g} min", "grn"))
        return
    rows = []
    for t in found:
        state = C.s("paused", "cyan") if t["paused"] else (C.s("busy", "red", "b") if t["busy"] > 0.2 else C.s("running", "dim"))
        cmd = t["command"]
        cmd = tilde(cmd.replace(HOME, "~"))
        rows.append([str(t["root_pid"]), f"{t['agent']} {t['agent_pid']}", human_age(t["age"]), human_cpu(t["cpu"]),
                     str(t["count"]), human_bytes(t["rss_kb"] * 1024), state, cmd[:70]])
    print(table(["TREE", "STARTED BY", "AGE", "CPU", "PROCS", "RSS", "STATE", "COMMAND"], rows,
                [">", "<", ">", ">", ">", ">", "<", "<"]))
    print(C.s(f"\n{len(found)} process tree(s) started by agents and running ≥ {minutes:g} min "
              "(MCP/LSP servers, app helpers and zombies hidden; --include-mcp)", "dim"))
    print(C.s("pause:  agent-ps runaway --pause TREE --yes    (SIGSTOP the whole tree; undo with --resume TREE --yes)", "dim"))


def findings(ps, inst, stale_h, runaway_trees=None, runaway_min=60):
    out = []
    ra = runaway_trees or []
    if ra:
        desc = "; ".join(f"tree {t['root_pid']} from {t['agent']} {t['agent_pid']}, up {human_age(t['age'])}: "
                         f"{t['command'][:60].replace(HOME, '~')}" for t in ra[:5])
        out.append(("warn", f"{len(ra)} process tree(s) started by an agent have been running ≥ {runaway_min} min: {desc}",
                    "Background test loops and dev servers keep running (and calling paid APIs) after the agent "
                    "has moved on or reports itself idle.", "agent-ps runaway"))
    bg_secret = [p for p in ps if p["kind"] in BACKGROUND and p["secrets"]]
    if bg_secret:
        names = sorted({n for p in bg_secret for n in p["secrets"]})
        out.append(("warn", f"{len(bg_secret)} background agent process(es) hold secret-looking env vars: {', '.join(names)}",
                    "They were inherited from the session that started them and outlive it. Restart the daemon from a "
                    "clean shell, or launch agents without long-lived tokens in the environment.",
                    "agent-ps env"))
    bg = [p for p in ps if p["kind"] in ("daemon", "updater")]
    if bg:
        desc = ", ".join(f"{p['agent']} {p['kind']} (pid {p['pid']}, up {human_age(p['age'])})" for p in bg)
        out.append(("info", f"Persistent background services: {desc}", None, None))
    if any(p["agent"] == "codex" and p["kind"] in ("daemon", "updater") for p in ps):
        out.append(("info", "Codex auto-started daemon detected. To turn it off (workaround from openai/codex#48195):",
                    None, "codex features disable daemon_auto_start\ncodex app-server daemon stop\n"
                          "pkill -f 'app-server daemon pid-update-loop'"))
    drift = []
    for i in inst:
        cur = next((e["name"] for e in i["entries"] if e["current"] or e.get("newest")), None)
        for e in i["entries"]:
            if e["in_use"] and not (e["current"] or e.get("newest")):
                drift.append(f"{e['in_use']}× {i['label']} {e['name']} (current {cur})")
    if drift:
        out.append(("warn", "Processes still running an older binary: " + "; ".join(drift),
                    "Restart them to pick up fixes; until then those versions can't be pruned.", None))
    rec = sum(i["reclaimable_bytes"] for i in inst)
    if rec >= 50 * 1024 * 1024:
        n = sum(1 for i in inst for e in i["entries"] if e["reclaimable"])
        out.append(("warn", f"{human_bytes(rec)} in {n} old agent version(s) nobody is running",
                    None, "agent-ps prune        # dry run\nagent-ps prune --yes"))
    stale = [p for p in ps if p["kind"] == "session" and p["age"] > stale_h * 3600]
    if stale:
        rss = sum(p["rss_kb"] for p in stale) * 1024
        out.append(("info", f"{len(stale)} interactive session(s) open for more than {stale_h}h, holding {human_bytes(rss)} RSS",
                    "Each keeps the environment and binary it started with; `agent-ps` marks them as stale.", None))
    orph = [p for p in ps if p["ppid"] == 1 and p["kind"] not in ("desktop", "daemon", "updater")]
    if orph:
        out.append(("warn", f"{len(orph)} orphaned agent process(es) (parent exited): pids "
                    + ", ".join(str(p["pid"]) for p in orph[:10]), None, None))
    unread = [p for p in ps if not p["env_readable"]]
    if unread:
        out.append(("info", f"{len(unread)} process(es) could not be inspected (other user or protected)", None, None))
    return out


def cmd_doctor(args):
    ps, inst = collect(args, with_cwd=True)
    fs = findings(ps, inst, args.stale, runaways(ps, 60))
    if args.json:
        return _dump({"findings": [{"level": l, "message": m, "advice": a, "commands": c} for l, m, a, c in fs],
                      "processes": ps, "installs": inst})
    agents = sorted({p["agent"] for p in ps} | {i["agent"] for i in inst})
    tot_disk = sum(i["bytes"] for i in inst)
    print(C.s("agent-ps doctor", "b") + C.s(f"  ·  {len(ps)} agent processes · agents: {', '.join(agents) or 'none'}"
                                             f" · {human_bytes(tot_disk)} in versioned installs\n", "dim"))
    if not fs:
        print(C.s("✓ nothing to report", "grn"))
        return 0
    icon = {"warn": C.s("▲", "yel", "b"), "info": C.s("●", "cyan")}
    for level, msg, advice, cmds in fs:
        print(f"{icon[level]} {msg}")
        if advice:
            for line in wrap(advice):
                print("  " + C.s(line, "dim"))
        if cmds:
            for line in cmds.splitlines():
                print("    " + C.s("$ " + line, "grn"))
        print()
    warns = sum(1 for f in fs if f[0] == "warn")
    return 1 if (args.strict and warns) else 0


def _dump(obj):
    def clean(o):
        if isinstance(o, dict):
            return {k: clean(v) for k, v in o.items()}
        if isinstance(o, list):
            return [clean(v) for v in o]
        if isinstance(o, str):
            return tilde(o) if o.startswith(HOME) else o
        return o
    json.dump(clean(obj), sys.stdout, indent=2)
    print()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="agent-ps",
        description="ps + du + env audit for coding agents (Claude Code, Codex, Cursor Agent, Gemini CLI, OpenCode, ...). "
                    "Read-only except `prune --yes`.")
    ap.add_argument("--version", action="version", version=f"agent-ps {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output (home dir shown as ~)")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colors (also: NO_COLOR env)")
    common.add_argument("--all", action="store_true", help="include helper processes")
    common.add_argument("--stale", type=int, default=24, metavar="HOURS", help="flag sessions older than this (default 24)")
    common.add_argument("--keep", type=int, default=0, metavar="N", help="keep N extra old versions per install (default 0)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("ps", parents=[common], help="list agent processes (default)")
    e = sub.add_parser("env", parents=[common], help="secret-looking env var names held by agent processes")
    e.add_argument("pid", nargs="*", type=int)
    sub.add_parser("disk", parents=[common], help="versioned installs, sizes, what is reclaimable")
    d = sub.add_parser("doctor", parents=[common], help="findings + suggested commands")
    d.add_argument("--strict", action="store_true", help="exit 1 if there are warnings")
    pr = sub.add_parser("prune", parents=[common], help="delete old versions nobody runs (dry run unless --yes)")
    pr.add_argument("--yes", action="store_true", help="actually delete")
    ra = sub.add_parser("runaway", parents=[common],
                        help="long-running process trees started by agents (test loops, dev servers); pause / resume / kill")
    ra.add_argument("--minutes", type=float, default=30, help="report trees running at least this long (default 30)")
    ra.add_argument("--include-mcp", action="store_true", help="also list MCP / language servers")
    ra.add_argument("--pause", type=int, nargs="+", metavar="TREE", help="SIGSTOP every process in these trees")
    ra.add_argument("--resume", type=int, nargs="+", metavar="TREE", help="SIGCONT every process in these trees")
    ra.add_argument("--kill", type=int, nargs="+", metavar="TREE", help="SIGTERM every process in these trees")
    ra.add_argument("--yes", action="store_true", help="required for --pause / --resume / --kill")
    ra.add_argument("--watch", type=float, metavar="SECONDS", help="re-check every SECONDS and print new runaways")
    ra.add_argument("--auto-pause", action="store_true", help="with --watch: SIGSTOP each new runaway tree")
    ra.add_argument("--strict", action="store_true", help="exit 1 if any runaway is found")
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["ps"] + list(argv)
    args = ap.parse_args(argv)
    C.on = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    if os.environ.get("FORCE_COLOR") and not args.no_color:
        C.on = True
    return {"ps": cmd_ps, "env": cmd_env, "disk": cmd_disk, "doctor": cmd_doctor, "prune": cmd_prune,
            "runaway": cmd_runaway}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
