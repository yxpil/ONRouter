# -*- coding: utf-8 -*-
# 配置热重载 E2E —— 零停机验证。
#
# 证明了什么（都在**同一个进程、同一批监听 socket** 上发生）：
#   1) 就地改写 conf 里的 `return` 正文后，一条**从不重连的长连接**会在同一条 TCP 上
#      先拿到 v1、再拿到 v2 —— 说明连接没被断开、新请求即时用上新路由（请求级热替换）。
#   2) 期间**每 40ms 新建一条连接**做请求，连接失败数为 0 —— 说明 accept 循环/监听
#      socket 从未关闭（无 accept 空窗，新连接始终被接受）。
#   3) 写入一份**语法错误**的配置后，服务**继续用旧路由**返回 v2（不中断、不采用坏配置），
#      随后写入 v3 又能生效 —— 说明坏配置被安全拒绝、旧配置继续服务。
#   4) pid 文件内容 == 子进程 pid 且服务进程全程存活 —— 说明这是**进程内热替换**，不是重启。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/hotreload_e2e.py
import http.client
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "hotreload.conf")
PORT = 18126

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def emit_conf(body):
    """生成一份完整 conf；body 是 location / 的 return 正文。"""
    return (
        'error_log "logs/hotreload_err.log" info;\n'
        'pid "logs/hotreload.pid";\n'
        "reload 200ms;\n"
        "\n"
        "server {\n"
        f"    listen 127.0.0.1:{PORT};\n"
        "    server_name hotreload.local;\n"
        "    location / {\n"
        f'        return 200 "{body}\\n";\n'
        "    }\n"
        "    location /still-up {\n"
        '        return 200 "up\\n";\n'
        "    }\n"
        "}\n"
    )


# 语法错误的配置：server 块没有闭合括号 -> Config::load 解析失败 -> 保留旧配置
BROKEN = 'server {\n    listen 127.0.0.1:%d;\n    location / {\n        return 200 "oops\\n";\n    }\n' % PORT


def write_conf(text):
    # 稍微停顿，确保 mtime 单调变化（Windows 时间戳粒度问题）
    time.sleep(0.05)
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
    os.utime(CONF, None)


def get_once(path="/"):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
    try:
        c.request("GET", path)
        r = c.getresponse()
        data = r.read().decode(errors="replace").strip()
        return r.status, data
    finally:
        c.close()


def continuity_thread(stop, log, errors):
    """单条长连接持续请求 /：任何 socket 异常都记进 errors（意味着连接被断开=有停机）。"""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
    try:
        while not stop.is_set():
            try:
                c.request("GET", "/")
                r = c.getresponse()
                body = r.read().decode(errors="replace").strip()
                log.append((time.time(), r.status, body))
            except (http.client.HTTPException, socket.timeout, ConnectionError, OSError) as e:
                errors.append(("continuity", repr(e)))
                break  # 不再重连：一次断开即证明非零停机
            time.sleep(0.05)
    finally:
        c.close()


def newconn_thread(stop, fails, total):
    """每 40ms 新建一条连接：连接/请求失败即计入 fails（说明 accept 空窗或进程重启）。"""
    while not stop.is_set():
        try:
            st, _ = get_once("/still-up")
            total.append(1)
            if st != 200:
                fails.append(("status", st))
        except (http.client.HTTPException, socket.timeout, ConnectionError, OSError) as e:
            fails.append(("conn", repr(e)))
        time.sleep(0.04)


def wait_for(stop, log, want, timeout):
    """等长连接日志里出现某个 body（want），返回是否等到。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(b == want for _, _, b in log):
            return True
        time.sleep(0.05)
    return False


def main():
    if not os.path.exists(os.path.join(ROOT, "conf")):
        raise SystemExit("!! 缺 conf 目录")
    os.makedirs(os.path.join(ROOT, "conf", "logs"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    original = open(CONF, encoding="utf-8").read() if os.path.exists(CONF) else emit_conf("v1")

    write_conf(emit_conf("v1"))
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "hotreload_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)

    stop = threading.Event()
    clog, cerrors = [], []
    nfail, ntotal = [], []

    try:
        # 就绪：确认 v1 已被服务
        ready = False
        for _ in range(100):
            try:
                st, body = get_once("/")
                if st == 200 and body == "v1":
                    ready = True
                    break
            except OSError:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 %d 被占用？看 logs/hotreload_out.log）" % PORT)

        # 启动持续流量：一条永不重连的长连接 + 每 40ms 新建连接
        t_cont = threading.Thread(target=continuity_thread, args=(stop, clog, cerrors), daemon=True)
        t_new = threading.Thread(target=newconn_thread, args=(stop, nfail, ntotal), daemon=True)
        t_cont.start()
        t_new.start()

        time.sleep(0.5)

        # ---- 1) 热替换 v1 -> v2（同一条长连接上应能看到变化，且不重连）----
        write_conf(emit_conf("v2"))
        saw_v2 = wait_for(stop, clog, "v2", timeout=8)
        check("热重载后长连接拿到新配置 v2", saw_v2, "未在长连接上观察到 v2")

        # ---- 2) 坏配置：解析失败 -> 保留旧配置（仍 v2），服务不中断 ----
        write_conf(BROKEN)
        time.sleep(1.2)  # 多个轮询周期
        after_broken = [b for _, _, b in clog if b]
        check("坏配置期间继续用旧路由返回 v2", after_broken and after_broken[-1] == "v2",
              f"last={after_broken[-1] if after_broken else None!r}")
        check("坏配置没有污染出 oops（旧配置被保留）", "oops" not in after_broken)

        # ---- 3) 再写合法 v3 -> 生效 ----
        write_conf(emit_conf("v3"))
        saw_v3 = wait_for(stop, clog, "v3", timeout=8)
        check("坏配置之后的下一次重载 v3 生效", saw_v3, "未观察到 v3")

        time.sleep(0.3)
    finally:
        stop.set()
        time.sleep(0.2)

        # ---- 4) 零停机核心断言（在停止流量后统计）----
        alive = proc.poll() is None
        check("全程为同一进程（子进程未被重启/杀死）", alive, f"returncode={proc.poll()}")

        # pid 文件内容应与子进程 pid 一致（只写一次 = 没有重启）
        pid_file = os.path.join(ROOT, "conf", "logs", "hotreload.pid")
        pid_ok = os.path.exists(pid_file) and open(pid_file).read().strip() == str(proc.pid)
        check("pid 文件记录的是当前进程 pid（进程内热替换）", pid_ok,
              f"file={open(pid_file).read().strip() if os.path.exists(pid_file) else None!r} actual={proc.pid}")

        # 长连接未因重载而断开
        check("长连接全程未断开（0 次 socket 异常）", len(cerrors) == 0, f"errors={cerrors}")

        # 顺序性：长连接先见 v1、再见 v2、最后见 v3
        firsts = {}
        for _, _, b in clog:
            if b and b not in firsts:
                firsts[b] = len(firsts)
        seq_ok = all(v in firsts for v in ("v1", "v2", "v3")) and \
            firsts["v1"] < firsts.get("v2", 99) < firsts.get("v3", 99)
        check("长连接上 v1->v2->v3 依序出现（请求级热替换）", seq_ok, f"order={firsts}")

        # 新建连接零失败（accept 从未空窗）
        check("重载期间新建连接零失败（无 accept 空窗）", len(nfail) == 0, f"fails={nfail[:5]}")
        check("重载期间持续成功服务（>=10 次新建连接成功）", len(ntotal) >= 10, f"count={len(ntotal)}")

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        # 还原模板 conf，保持仓库干净
        write_conf(original)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== 配置热重载 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
