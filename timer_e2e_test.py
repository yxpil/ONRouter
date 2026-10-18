# -*- coding: utf-8 -*-
"""E2E 定时器语义测试：断言移植自 OpenResty lua-nginx-module
t/106-timer.t (TEST 1/9) 、t/152-timer-every.t (TEST 1/4/abort-false)、
t/107-timer-errors.t 的核心期望。用法：python timer_e2e_test.py
"""
import subprocess, sys, time, os, re
import urllib.request

RUST = os.path.dirname(os.path.abspath(__file__))
BASE = "http://127.0.0.1:8080"

def req(path, timeout=10):
    r = urllib.request.Request(BASE + path, method="GET")
    resp = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r, timeout=timeout)
    return resp.status, resp.read().decode()

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)

def main():
    exe = os.path.join(RUST, "target", "debug", "onrouter.exe")
    logf = open(os.path.join(RUST, "timer_e2e.log"), "wb")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "onrouter.conf")],
                          cwd=RUST, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                req("/health")
                break
            except Exception:
                time.sleep(0.2)

        # === t/106-timer.t TEST 1/9: at（0.05s 秒单位 + premature + 用户变参转发）===
        st, body = req("/api/timer_test")
        check("at/every 注册成功返回 ok", st == 200 and "registered, pending=" in body, f"{st} {body[:80]}")
        m = re.search(r"registered, pending=\s*(\d+)\s+running=\s*(\d+)", body)
        check("pending_count 反映排队数", m and int(m.group(1)) >= 2, body[:120])

        time.sleep(2.0)
        logf.flush()
        with open(os.path.join(RUST, "timer_e2e.log"), "rb") as f:
            log = f.read().decode("utf-8", errors="ignore")

        # 对标 106-timer.t --- error_log: "timer prematurely expired: false"
        check("at 回调触发且 premature=false",
              re.search(r"at fired\s+premature=\s+false", log), log[-400:])
        # 对标 106-timer.t TEST 9: 用户变参原样转发
        check("at 用户变参转发 (hello 42)",
              re.search(r"args=\s+hello\s+42", log), log[-400:])
        # 对标 152-timer-every.t：回调收到 premature 首参
        check("every 回调触发（premature=false）",
              re.search(r"every tick\s+1\s+premature=\s+false", log), log[-400:])

        # === t/152 移植：every 回调 return false 应停止 ===
        ticks = re.findall(r"every tick\s+(\d+)", log)
        check("return false 后周期停止", sorted(set(ticks)) == ["1", "2", "3"], f"ticks={ticks}")

        # === 官方 API 返回语义：失败 -> (nil, err) ===（ngx.say 多参以空格分隔）
        st, body = req("/api/timer_errors")
        lines = body.strip().splitlines()
        check("invalid delay 负数", re.match(r"nil\s*:\s*invalid delay", lines[0]), body[:120])
        check("invalid delay 非数字", re.match(r"nil\s*:\s*invalid delay", lines[1]), body[:120])
        check("invalid callback type", re.match(r"nil\s*:\s*invalid callback type", lines[2]), body[:120])
        check("every invalid interval", re.match(r"nil\s*:\s*invalid interval", lines[3]), body[:120])

        # === 请求隔离：content 线程继续跑时定时器不干扰（官方 no_error_log [error]）===
        check("无 [error] 日志串扰", "[error]" not in log and "回调执行失败" not in log, log[-300:])

    finally:
        gw.terminate()
        try:
            gw.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gw.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{'='*50}\n结果: {passed}/{len(results)} 通过\n{'='*50}")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
