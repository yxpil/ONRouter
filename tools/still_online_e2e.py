# -*- coding: utf-8 -*-
# Still ONLine E2E —— 用真实"后端崩溃 → 恢复"流量验证副本层，重点在凭证安全边界：
#   * 后端活着：GET 2xx 写入 last-known-good 副本；响应不带 X-Still-Online
#   * 后端被杀：GET 回放副本（200 + X-Still-Online: stale + Age），页面内容仍是崩溃前那一份
#   * 硬规则 1：上游发 Set-Cookie 的响应永不入区 → 后端死后该 key 只能 502
#   * 硬规则 3：带 Cookie/Authorization 的请求永不写入，默认也不读别人的副本（502）；
#     allow_credentials on 才放开"读公共副本"，且回放响应里绝不带 Set-Cookie
#   * 非 GET 永不回放：POST 在故障期保持 502（绝不把别人的动作结果当成你的提交）
#   * still_online_max_body：超过单条上限的响应不收（不截断）→ 故障期 502
#   * 对照组（没开区）永远干净 502
#   * 恢复后后台重取：脏 key 被匿名 GET 重新走一遍正常请求路径，副本换成新鲜内容，
#     refreshed 计数上升；再次杀掉后端，回放的是恢复后那一份
#   * /metrics 的 onrouter_still_online_total{kind=...} 与 zone 占用随真实读写走
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/still_online_e2e.py
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "still_online.conf")

GW_HOST, GW_PORT = "127.0.0.1", 18270
BE_HOST, BE_PORT = "127.0.0.1", 18271
BASE = f"http://{GW_HOST}:{GW_PORT}"

lock = threading.Lock()
hits = {}
# 后端每收到一个请求就自增；副本里的 v 能直接对比出"是不是崩溃前那一份"
version = 0
backend_box = {"srv": None}
# "进程被杀"的等价模拟：只 shutdown() 关不掉已经建立的 keep-alive 连接，
# 网关会继续复用旧连接拿到 200，测不出真实故障。置位后每个请求直接断连、不给响应。
dead = threading.Event()

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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, timeout=15, method="GET", headers=None, data=None):
    req = urllib.request.Request(BASE + path, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def metric(text, kind):
    m = re.search(r'onrouter_still_online_total\{kind="%s"\}\s+(\d+)' % kind, text)
    return int(m.group(1)) if m else None


def zone_metric(text, name, role):
    m = re.search(
        r'onrouter_still_online_zone_bytes\{zone="%s",role="%s"\}\s+(\d+)' % (name, role),
        text,
    )
    return int(m.group(1)) if m else None


def pending(text):
    m = re.search(r"onrouter_still_online_pending_jobs\s+(\d+)", text)
    return int(m.group(1)) if m else None


def metrics():
    st, _, body = request("/metrics", timeout=5)
    assert st == 200, f"metrics 未就绪: {st}"
    return body.decode(errors="replace")


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, body, extra=None):
        self.send_response(status)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def _dropped(self):
        """模拟崩溃的进程：连接直接断，不给任何响应字节。"""
        self.close_connection = True
        try:
            self.connection.close()
        except OSError:
            pass

    def do_POST(self):
        if dead.is_set():
            return self._dropped()
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        with lock:
            global version
            version += 1
            hits["POST " + self.path] = hits.get("POST " + self.path, 0) + 1
            v = version
        self._reply(200, f"posted=v{v}".encode())

    def do_GET(self):
        if dead.is_set():
            return self._dropped()
        path = self.path.split("?")[0]
        with lock:
            global version
            version += 1
            hits[path] = hits.get(path, 0) + 1
            v = version
        if path.startswith("/cred/"):
            # 会话签发：这份响应天生属于当前访客，绝不能进公共副本区
            self._reply(200, b"login-form", {"Set-Cookie": "sid=secret-%d; Path=/" % v})
        elif path.startswith("/big/"):
            self._reply(200, b"x" * 200_000)
        else:
            self._reply(200, f"v={v}".encode())

    def log_message(self, *a):
        pass


def backend_start():
    dead.clear()
    for _ in range(40):
        try:
            srv = ThreadingHTTPServer((BE_HOST, BE_PORT), Backend)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            backend_box["srv"] = srv
            return
        except OSError:
            time.sleep(0.25)
    raise SystemExit(f"!! 后端端口 {BE_PORT} 起不来")


def backend_stop():
    dead.set()
    srv = backend_box["srv"]
    if srv is not None:
        srv.shutdown()
        srv.server_close()
        backend_box["srv"] = None
    # Windows 上刚关闭的监听端口可能短暂无 TIME_WAIT 冲突，等到能重新绑定为止
    time.sleep(0.3)


def version_of(body):
    m = re.search(rb"v=(\d+)", body)
    return int(m.group(1)) if m else None


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    backend_start()

    logf = open(os.path.join(ROOT, "logs", "still_online_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping", timeout=2)[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit(
                f"!! 网关未就绪（端口 {GW_PORT}/{BE_PORT} 被占用？看 logs/still_online_out.log）"
            )

        # ---- 1) 健康期：写入副本 ----
        st, hs, body = request("/lkg/v")
        v_first = version_of(body)
        check(
            "健康期 /lkg/v 200 且来自后端",
            st == 200 and v_first is not None and body == f"v={v_first}".encode(),
            f"st={st} body={body[:40]!r}",
        )
        check("健康期不带 X-Still-Online", hdr(hs, "X-Still-Online") is None)
        request("/readallow/v")
        request("/off/v")

        m0 = metrics()
        check(
            "两条 GET 各写一份副本",
            (metric(m0, "stored") or 0) >= 2,
            f"stored={metric(m0, 'stored')}",
        )
        used = zone_metric(m0, "lkg", "used")
        check("指标里 lkg 区有占用字节", (used or 0) > 0, f"used={used}")
        check("指标里 lkg 区预算=8m", zone_metric(m0, "lkg", "budget") == 8 * 1024 * 1024)

        # ---- 2) 硬规则：Set-Cookie / 超上限的响应不入区 ----
        st, hs, body = request("/cred/v")
        check("登录页 200 且带 Set-Cookie", st == 200 and hdr(hs, "Set-Cookie") is not None)
        st, hs, body = request("/big/v")
        check("大响应 200", st == 200 and len(body) == 200_000, f"len={len(body)}")

        # ---- 3) 杀掉后端 ----
        backend_stop()
        time.sleep(0.4)

        st, hs, body = request("/lkg/v")
        age = hdr(hs, "Age")
        check(
            "故障期 /lkg/v 回放副本（200 + stale）",
            st == 200 and hdr(hs, "X-Still-Online") == "stale",
            f"st={st} xso={hdr(hs, 'X-Still-Online')}",
        )
        check(
            "回放内容与崩溃前那一份字节一致",
            v_first is not None and version_of(body) == v_first,
            f"body={body[:40]!r} v_first={v_first}",
        )
        check(
            "回放带 Age（副本存放秒数）",
            age is not None and age.isdigit() and int(age) < 60,
            f"age={age}",
        )

        st, _, _ = request("/lkg/v", headers={"Cookie": "sid=mine"})
        check(
            "硬规则3：带 Cookie 的请求默认不读别人的副本 → 502",
            st == 502,
            f"st={st}",
        )

        st, hs, body = request("/readallow/v", headers={"Cookie": "sid=mine"})
        check(
            "allow_credentials on 才能读到公共副本",
            st == 200 and hdr(hs, "X-Still-Online") == "stale",
            f"st={st} xso={hdr(hs, 'X-Still-Online')}",
        )
        check("回放响应里绝不带 Set-Cookie", hdr(hs, "Set-Cookie") is None, f"hs={hs}")

        st, _, _ = request("/lkg/v", method="POST", data=b"action=1")
        check("非 GET 永不回放 → POST 保持 502", st == 502, f"st={st}")
        st, _, _ = request("/cred/v")
        check("硬规则1：Set-Cookie 响应没入区 → 故障期 502", st == 502, f"st={st}")
        st, _, _ = request("/big/v")
        check("超 max_body 的响应没入区 → 故障期 502", st == 502, f"st={st}")
        st, _, _ = request("/off/v")
        check("对照组（没开区）始终干净 502", st == 502, f"st={st}")

        m1 = metrics()
        check(
            "served 计数随回放增长",
            (metric(m1, "served") or 0) - (metric(m0, "served") or 0) >= 2,
            f"served={metric(m1, 'served')}",
        )
        check(
            "凭证闸门留痕（rejected_credential）",
            (metric(m1, "rejected_credential") or 0) >= 3,
            f"rc={metric(m1, 'rejected_credential')}",
        )
        # 单飞语义：某条 key 正在被后台重取时，它短暂不在表里（due_jobs 取走即出表），
        # 所以这里取多次采样的峰值，而不是要求某一瞬间两条同时挂在那里。
        pend_peak = pending(m1)
        for _ in range(8):
            time.sleep(0.2)
            p = pending(metrics())
            if p is not None and p > pend_peak:
                pend_peak = p
        check(
            "回放过的 key 进了待重取队列（故障期非空）",
            pend_peak >= 1,
            f"peak={pend_peak}",
        )

        # ---- 4) 恢复：后台匿名重取把副本换成新鲜内容 ----
        #     回放过的两条 key（/lkg/v 与 /readallow/v）各自重取一次 = refreshed +2
        refreshed0 = metric(m1, "refreshed") or 0
        backend_start()
        refreshed_after = refreshed0
        for _ in range(120):
            refreshed_after = metric(metrics(), "refreshed") or 0
            if refreshed_after >= refreshed0 + 2:
                break
            time.sleep(0.5)
        check(
            "恢复后两条待重取 key 都被后台重取（refreshed +2）",
            refreshed_after >= refreshed0 + 2,
            f"{refreshed0} -> {refreshed_after}",
        )

        # 重取的请求确实走了真实路由与后端（后端计数增加），且不带凭证
        st, hs, body = request("/lkg/v")
        check(
            "恢复后 /lkg/v 回到真实 200（不再 stale）",
            st == 200 and hdr(hs, "X-Still-Online") is None,
            f"st={st} xso={hdr(hs, 'X-Still-Online')}",
        )
        v_live = version_of(body)

        # 队列被后台重取消化干净（重取成功 = 出表，不会留下无限重试的僵尸任务）
        pend_after = pending(m1)
        for _ in range(30):
            pend_after = pending(metrics())
            if pend_after == 0:
                break
            time.sleep(0.5)
        # 单飞会短暂把在途 key 取出表，所以清空判定要再等一轮确认真的静默了
        time.sleep(2.5)
        check(
            "重取成功后待重取队列清空",
            pend_after == 0 and pending(metrics()) == 0,
            f"outage={pend_peak} -> now={pend_after}",
        )

        # 再杀一次：回放的应当是"恢复之后"那一份，证明副本被后台任务更新过
        backend_stop()
        time.sleep(0.4)
        st, hs, body = request("/lkg/v")
        v_copy = version_of(body)
        check(
            "二次故障回放的副本已更新到恢复后的版本",
            st == 200 and hdr(hs, "X-Still-Online") == "stale" and v_copy is not None
            and v_copy > v_first,
            f"st={st} v_first={v_first} v_copy={v_copy} v_live={v_live}",
        )

        # 全区只有开区的那两条 key：对照组与不合格响应都没往里写
        m2 = metrics()
        ent = re.search(r'onrouter_still_online_zone_entries\{zone="lkg"\}\s+(\d+)', m2)
        check(
            "lkg 区条目数=2（/lkg/v 与 /readallow/v，其它一律不进）",
            ent is not None and int(ent.group(1)) == 2,
            f"entries={ent.group(1) if ent else None}",
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend_stop()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== still_online E2E: {passed}/{total} passed ====")
    print(f"     后端请求计数: {dict(sorted(hits.items()))}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
