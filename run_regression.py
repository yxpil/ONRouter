# -*- coding: utf-8 -*-
"""全量回归：tools/*_e2e.py + 根目录场景脚本，逐个跑并汇总退出码。
结果写到 logs/regression/<输出文件名>，每行 "EXIT <code> <脚本>"。

  python run_regression.py                       # 全量，汇总写 summaryD.txt
  python run_regression.py reg_102.txt           # 全量，汇总写指定名字
  python run_regression.py --only expires_e2e    # 只跑名字含该子串的脚本
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
argv = list(sys.argv[1:])
only = None
for a in list(argv):
    if a.startswith("--only="):
        only = a.split("=", 1)[1]
        argv.remove(a)
if "--only" in argv:
    i = argv.index("--only")
    if i + 1 >= len(argv):
        raise SystemExit("!! --only 需要一个子串，例如 --only expires_e2e")
    only = argv[i + 1]
    del argv[i:i + 2]
if only == "":
    raise SystemExit("!! --only 的子串不能为空")
OUT = os.path.join(ROOT, "logs", "regression", argv[0] if argv else "summaryD.txt")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

# 不进气泡回归的套件：红/绿目前不构成证据，宁可写清原因，也不留一条"长期红"的噪声。
# 手工执行仍然有效，但回归里不认它。
SKIP = {
    # （此处曾长期挂着 tools/random_scenarios_e2e.py：它的 TLS 预言机把"证书按 SNI 选"
    #  与"站点按 Host/:authority 选"记成了同一件事，证书断言成片红。2026-10-22 三条都修了：
    #  探针改为真的按 host 发 SNI（原来把 127.0.0.1 当了 SNI）、预言机按 SNI 单独算证书
    #  （精确 > 通配 > 该地址 default_server）、网关的兜底证书也改成跟 default_server 而不是
    #  跟配置顺序。20 轮随机拓扑 4122/4122，所以它回到回归里了。）
}

scripts = sorted(
    os.path.join("tools", f) for f in os.listdir(os.path.join(ROOT, "tools"))
    if f.endswith("_e2e.py")
    and os.path.join("tools", f) not in SKIP
)
scripts += [
    "scenario_test.py", "realworld_e2e_test.py", "upstream_test.py",
    "timer_e2e_test.py", "static_test.py", "compat_test.py", "sec_test.py",
    "smoke_suite.py",
]
if only:
    scripts = [s for s in scripts if only in s]
    # 子串打错时不能"0 条全绿"，那会被当成通过
    if not scripts:
        raise SystemExit(f"!! --only {only!r} 一条都没匹配到（SKIP 里的也不会跑）")
    print(f"--only {only!r} 匹配 {len(scripts)} 条：", ", ".join(scripts))

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
