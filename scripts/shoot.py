"""Regenerate README screenshots from live agent-ps output (macOS, Google Chrome).

usage: python3 scripts/shoot.py [--redact OLD=NEW ...]
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SHOTS = [("doctor.png", "doctor", 1300, 640), ("disk-env.png", "disk :: env", 1300, 660)]


def main():
    redact = sys.argv[1:]
    tmp = tempfile.mkdtemp()
    for png, cmds, w, h in SHOTS:
        page = os.path.join(tmp, png + ".html")
        args = cmds.split()
        pids = os.environ.get("SHOOT_PIDS")
        if pids and "env" in args:
            args = args[: args.index("env") + 1] + pids.split()
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "render_demo.py"), page, *redact, "--", *args],
                       check=True, env=dict(os.environ, COLUMNS="104"))
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        f"--window-size={w},{h}", f"--screenshot={os.path.join(ROOT, 'assets', png)}", "file://" + page],
                       capture_output=True, check=True)
        print("wrote assets/" + png)


if __name__ == "__main__":
    main()
