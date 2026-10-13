"""Render real agent-ps output (ANSI) into a terminal-styled HTML page for screenshots.

usage: python3 scripts/render_demo.py OUT.html [--redact OLD=NEW ...] -- CMD1 :: CMD2
Each command is an agent-ps argument list, e.g. "doctor" :: "disk".
"""
import html
import os
import re
import subprocess
import sys

COLORS = {"31": "#ff6b6b", "32": "#7bd88f", "33": "#fcd566", "35": "#d49cff", "36": "#5ad4e6"}


def ansi_to_html(text):
    out, stack = [], []
    pos = 0
    for m in re.finditer(r"\033\[([0-9;]*)m", text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        codes = m.group(1).split(";")
        if codes == ["0"] or codes == [""]:
            out.append("</span>" * len(stack))
            stack = []
            continue
        style = []
        for c in codes:
            if c == "1":
                style.append("font-weight:700")
            elif c == "2":
                style.append("color:#8a8f98")
            elif c in COLORS:
                style.append(f"color:{COLORS[c]}")
        out.append(f'<span style="{";".join(style)}">')
        stack.append(1)
    out.append(html.escape(text[pos:]))
    out.append("</span>" * len(stack))
    return "".join(out)


def main():
    a = sys.argv[1:]
    out_path = a.pop(0)
    redact = []
    while a and a[0] == "--redact":
        a.pop(0)
        old, new = a.pop(0).split("=", 1)
        redact.append((old, new))
    if a and a[0] == "--":
        a.pop(0)
    cmds = [c.strip().split() for c in " ".join(a).split("::") if c.strip()]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, FORCE_COLOR="1")
    blocks = []
    for cmd in cmds:
        r = subprocess.run([sys.executable, "-m", "agent_ps", *cmd], cwd=root, env=env, capture_output=True, text=True)
        text = r.stdout
        for old, new in redact:
            text = text.replace(old, new)
        blocks.append(f'<div class="cmd"><span class="p">$</span> agent-ps {html.escape(" ".join(cmd))}</div>'
                      f"<pre>{ansi_to_html(text.rstrip())}</pre>")
    page = """<!doctype html><meta charset="utf-8"><style>
body{margin:0;background:#0f1115;font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;color:#e6e6e6}
.win{margin:24px;border-radius:10px;background:#16181d;box-shadow:0 10px 40px #0008;overflow:hidden;width:max-content;min-width:900px}
.bar{background:#22252b;padding:10px 14px}.bar i{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:7px}
.body{padding:16px 22px 20px}pre{margin:6px 0 18px;white-space:pre}.cmd{color:#e6e6e6;font-weight:700}.p{color:#7bd88f}
</style><div class="win"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i></div>
<div class="body">""" + "".join(blocks) + "</div></div>"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    print(out_path)


if __name__ == "__main__":
    main()
