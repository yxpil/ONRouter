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
# 手工执行仍然有效，问题是它现在会误报。
SKIP = {
    # tools/random_scenarios_e2e.py：站点路由/别名/L4 那半边是可信的（正是它把"双 Host 头"
    # 这个真问题挖出来的），但 TLS 那半边的预言机把"证书按 SNI"与"站点按 :authority"两件事
    # 记成了一件：一轮随机拓扑里同一端口上的多个站点会共享一份证书账，于是证书指纹断言成片红。
    # 多域名单端口的证书/串站判定由 tools/https_matrix_e2e.py 71/71（含变异校验）负责。
    # TODO(证书账): 让 plan 记录每个站点实际写出的 ssl_certificate 再纳回回归。
    "tools" + chr(92) + "random_scenarios_e2e.py",
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
