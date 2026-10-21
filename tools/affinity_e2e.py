# -*- coding: utf-8 -*-
# CPU 亲和性 E2E：证明 worker 线程真的被绑到了声明的核心上。
#
# 三层证据，缺一不可：
#   1) -t 打出的**逐线程计划**：0=[0], 1=[1], 2=[0]（显式掩码按声明顺序轮换）；
#   2) 启动日志里的绑定结果：绑定函数返回成功才会打"worker 线程 N 绑定 CPU 核心 [x]"，
#      失败会打"绑定失败"——两种行都要能被找到（这里断言前者、并确认没有后者）；
#   3) 绑定之后网关照常服务并发请求（绑定不是把线程钉死到无法调度）。
# 另外验证越界掩码的裁剪告警与 auto 模式的一线程一核计划。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/affinity_e2e.py
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "affinity_e2e.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "affinity_e2e_err.log")
OUT_LOG = os.path.join(ROOT, "conf", "logs", "affinity_e2e_out.log")

GW, GW_PORT = "127.0.0.1", 18410
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    cands = [
        os.path.join(ROOT, p, n)
        for p in ("target/release", "target/debug")
        for n in ("onrouter.exe", "onrouter")
    ]
    have = [p for p in cands if os.path.exists(p)]
    if not have:
        raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")
    exe = max(have, key=os.path.getmtime)
    out = subprocess.run([exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8", errors="replace")
    blob = (out.stdout or "") + (out.stderr or "")
    if out.returncode != 0 or "worker_cpu_affinity=" not in blob or "亲和性：" not in blob:
        raise SystemExit("!! %s 的 -t 里没有亲和性计划：\n%s" % (exe, blob[-1400:]))
    print("使用网关二进制：", exe)
    return exe, blob


def wait_port(port, up=True, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.connect(("127.0.0.1", port))
            ok = True
        except Exception:
            ok = False
        finally:
            s.close()
        if ok == up:
            return True
        time.sleep(0.1)
    return False


def read_log():
    try:
        with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def wait_for(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = read_log()
        if predicate(text):
            return text
        time.sleep(0.1)
    return read_log()


def ping():
    try:
        resp = _opener.open(f"http://{GW}:{GW_PORT}/ping", timeout=10)
        return resp.status, resp.read().decode()
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def main():
    exe, test_out = find_binary()

    check("-t 计划：worker_threads=3，掩码按 0=[0] / 1=[1] / 2=[0] 轮换",
          "worker_threads=3" in test_out and "0=[0], 1=[1], 2=[0]" in test_out,
          [ln for ln in test_out.splitlines() if "亲和性" in ln][:2])

    if wait_port(GW_PORT, up=True, timeout=0.2):
        raise SystemExit(f"!! 端口 {GW_PORT} 已被占用，先确认没有残留进程")
    for f in (ERR_LOG, OUT_LOG):
        if os.path.exists(f):
            os.remove(f)

    proc = subprocess.Popen([exe, "-c", CONF_REL], cwd=ROOT,
                            stdout=open(OUT_LOG, "w"), stderr=subprocess.STDOUT)
    try:
        if not wait_port(GW_PORT, up=True, timeout=20):
            raise SystemExit("!! 网关没起来，看 " + ERR_LOG)
        log = wait_for(lambda t: t.count("绑定 CPU 核心") >= 3)
        bound = re.findall(r"worker 线程 (\d+) 绑定 CPU 核心 \[([0-9,]+)\]", log)
        check("3 个 worker 线程都完成了真实绑定（系统调用返回成功）",
              len(bound) >= 3, f"bound={bound} log_tail={log[-500:]}")
        check("绑定结果与计划一致：线程 0 -> CPU0，线程 1 -> CPU1，线程 2 -> CPU0",
              {(i, cores) for i, cores in bound} >= {("0", "0"), ("1", "1"), ("2", "0")},
              str(bound))
        check("没有任何线程绑定失败", "CPU 亲和性绑定失败" not in log, log[-400:])

        with ThreadPoolExecutor(max_workers=16) as pool:
            replies = list(pool.map(lambda _: ping(), range(64)))
        check("绑定之后照常服务并发请求（64 问全部 200/ok）",
              all(r == (200, "ok") for r in replies), str(replies[:4]))

        # 越界掩码：高位在逻辑核之外的位必须被裁掉并告警（-t 就能看见）
        cpus = os.cpu_count() or 1
        if cpus < 64:
            body = ("worker_threads 1;\n"
                    "worker_cpu_affinity ffffffffffffffff;\n"
                    "server { listen 127.0.0.1:18411; location / { return 200 ok; } }\n")
            import tempfile
            fd, path = tempfile.mkstemp(suffix=".conf", dir=os.path.join(ROOT, "conf"))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(body)
                rel = os.path.relpath(path, ROOT)
                out = subprocess.run([exe, "-t", "-c", rel], cwd=ROOT, capture_output=True,
                                     text=True, encoding="utf-8", errors="replace")
                blob = (out.stdout or "") + (out.stderr or "")
                check("掩码里超出逻辑核数的位被裁剪并留下告警",
                      out.returncode == 0 and "已裁剪为" in blob,
                      blob[-400:])
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass

        # auto：一个线程一个核（核数足够时）
        if cpus >= 2:
            body = ("worker_threads 2;\n"
                    "worker_cpu_affinity auto;\n"
                    "server { listen 127.0.0.1:18411; location / { return 200 ok; } }\n")
            import tempfile
            fd, path = tempfile.mkstemp(suffix=".conf", dir=os.path.join(ROOT, "conf"))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(body)
                rel = os.path.relpath(path, ROOT)
                out = subprocess.run([exe, "-t", "-c", rel], cwd=ROOT, capture_output=True,
                                     text=True, encoding="utf-8", errors="replace")
                blob = (out.stdout or "") + (out.stderr or "")
                check("auto：两个线程各占一个不同的逻辑核（0=[0], 1=[1]）",
                      out.returncode == 0 and "0=[0], 1=[1]" in blob, blob[-400:])
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    passed = sum(1 for _n, ok in results if ok)
    print("\n==== CPU 亲和性 E2E: %d/%d passed ====" % (passed, len(results)))
    for n, ok in results:
        if not ok:
            print("FAILED:", n)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
