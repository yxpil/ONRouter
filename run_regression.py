# -*- coding: utf-8 -*-
"""全量回归：tools/*_e2e.py + 根目录场景脚本，逐个跑并汇总退出码。
结果写到 logs/regression/<输出文件名>，每行 "EXIT <code> <脚本>"。"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "logs", "regression", sys.argv[1] if len(sys.argv) > 1 else "summaryD.txt")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

scripts = sorted(
    os.path.join("tools", f) for f in os.listdir(os.path.join(ROOT, "tools"))
    if f.endswith("_e2e.py")
)
scripts += [
    "scenario_test.py", "realworld_e2e_test.py", "upstream_test.py",
    "timer_e2e_test.py", "static_test.py", "compat_test.py", "sec_test.py",
    "smoke_suite.py",
]

lines = []
with open(OUT, "w", encoding="utf-8") as rep:
    for s in scripts:
        t0 = time.time()
        log = os.path.join(ROOT, "logs", "regression", os.path.basename(s) + ".log")
        with open(log, "wb") as fh:
            rc = subprocess.run([sys.executable, s], cwd=ROOT, stdout=fh,
                                stderr=subprocess.STDOUT).returncode
        line = f"EXIT {rc:3d} {time.time()-t0:6.1f}s {s}"
        lines.append(line)
        print(line, flush=True)
        rep.write(line + "\n")
        rep.flush()
    bad = [l for l in lines if not l.startswith("EXIT   0")]
    rep.write(f"TOTAL {len(scripts)} scripts, nonzero={len(bad)}\n")
    for l in bad:
        rep.write("  !! " + l + "\n")
    print(f"TOTAL {len(scripts)} scripts, nonzero={len(bad)}")
    for l in bad:
        print("  !!", l)
