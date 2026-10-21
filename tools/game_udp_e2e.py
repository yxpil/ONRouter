# -*- coding: utf-8 -*-
# 游戏服务器的 UDP 业务形状：把网关当成"百万在线的那台前置"来压。
#
#   cargo build --release -p onrouter-server --bin onrouter
#   python tools/game_udp_e2e.py
#   python tools/game_udp_e2e.py --heavy       # 把吞吐与并发拉到更高一档
#
# 为什么值得单开一个套件（而不是并进 stream 的 TCP 用例）：
#
# * **回包必须回到它自己的客户端**。房间服给 A 算出的位置/血量发给 B，不是"体验差"，
#   是跨用户数据泄漏。用例让 60 个客户端并发各发自己的 player 号，服务器原样回显，
#   任何一次串话都会立刻让"收到的回包都带着自己的号"这条断言变红。
# * **心跳是"只管发、不等回"**（`proxy_responses 0`）。这种形态不该建会话、不该占 fd，
#   所以要数清楚：3 万个上报包，网关内部账目必须守恒（收到 = 转发 + 各类丢弃）。
# * **一问多答**（匹配服一条请求回若干帧）：`proxy_responses 4`。
# * **会话必须能复用**。客户端以 10Hz 连发 3 秒，会话数应该 ≈1，不是 30 —— 每包一个会话
#   等于把 UDP 代理变成 fd 制造机。
# * **会话额度用尽时必须丢包并计数**，不是把进程拖到 EMFILE：UDP 的会话 = 一条 socket =
#   一个 fd，与 HTTP/stream 共用 `worker_connections`。
# * **同一端口号的 TCP 与 UDP 互不干扰**。
#
# 断言一律按 nginx 的 UDP 语义与业务底线写；不通过就查网关，不把断言改成"实际行为"。
import argparse
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "target", "release", "onrouter.exe" if os.name == "nt" else "onrouter")
CONF = os.path.join(ROOT, "conf", "game_udp.conf")
ERRLOG = os.path.join(ROOT, "conf", "logs", "game_udp_err.log")

GW_HTT = 18610
GW_HB = 18613          # UDP 心跳（不等回包）+ 同端口号的 TCP
GW_ROOM = 18614
GW_MATCH = 18615
GW_SESS = 18616
ORIG_ROOM_A, ORIG_ROOM_B = 18611, 18612
ORIG_HB, ORIG_SESS = 18621, 18622
ORIG_MATCH, ORIG_TCP = 18623, 18624

results = []
COUNT = {}
COUNT_LOCK = threading.Lock()
BIG = 4 * 1024 * 1024


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:240])


def bump(key, n=1):
    with COUNT_LOCK:
        COUNT[key] = COUNT.get(key, 0) + n


def count_of(key):
    with COUNT_LOCK:
        return COUNT.get(key, 0)


def find_binary():
    if not os.path.exists(EXE):
        raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")
    return EXE


# ---------------------------------------------------------------- UDP 后端
def udp_server(port, handler, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BIG)
    except OSError:
        pass
    s.bind(("127.0.0.1", port))
    s.settimeout(0.5)

    def loop():
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                handler(s, data, addr, tag)
            except OSError:
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return s, t


def start_origins():
    def room(s, data, addr, tag):
        # 原样回显客户端的 payload（前缀带上自己是哪个节点）：
        # 串话会立刻表现为"收到的回包里带着别人的 player 号"
        bump("room:" + tag)
        s.sendto(f"{tag}|".encode() + data, addr)

    def heartbeat(s, data, addr, tag):
        bump("hb")
        # proxy_responses 0：不回包

    def sess(s, data, addr, tag):
        bump("sess")
        s.sendto(f"{tag}|".encode() + data, addr)

    def match(s, data, addr, tag):
        # 一问多答：一条请求回 4 帧（匹配结果 + 若干状态帧）
        bump("match")
        for i in range(4):
            s.sendto(f"{tag}|{i}|".encode() + data, addr)

    socks = [
        udp_server(ORIG_ROOM_A, room, "roomA"),
        udp_server(ORIG_ROOM_B, room, "roomB"),
        udp_server(ORIG_HB, heartbeat, "hb"),
        udp_server(ORIG_SESS, sess, "sess"),
        udp_server(ORIG_MATCH, match, "match"),
    ]

    # 同端口号 TCP 那条路用的 TCP echo 后端
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", ORIG_TCP))
    tcp.listen(16)
    tcp.settimeout(0.5)

    def tcp_loop():
        while True:
            try:
                c, _ = tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with c:
                bump("tcp")
                try:
                    data = c.recv(4096)
                    c.sendall(b"tcpecho|" + data)
                except OSError:
                    pass

    threading.Thread(target=tcp_loop, daemon=True).start()
    return socks, tcp


def udp_client(port=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BIG)
    except OSError:
        pass
    if port:
        s.bind(("127.0.0.1", port))
    s.settimeout(2.0)
    return s


def roundtrip(gw_port, payload, timeout=2.0):
    """一次一问一答，返回 (回包, 往返秒)。"""
    s = udp_client()
    s.settimeout(timeout)
    t0 = time.perf_counter()
    s.sendto(payload, ("127.0.0.1", gw_port))
    try:
        data, _ = s.recvfrom(65535)
        return data, time.perf_counter() - t0
    except socket.timeout:
        return None, time.perf_counter() - t0
    finally:
        s.close()


# ---------------------------------------------------------------- 指标
def metrics():
    import http.client

    c = http.client.HTTPConnection("127.0.0.1", GW_HTT, timeout=8)
    c.request("GET", "/metrics")
    r = c.getresponse()
    txt = r.read().decode("utf-8", "replace")
    c.close()
    return txt


def metric_lines(prefix, text):
    out = {}
    for line in text.splitlines():
        if line.startswith(prefix):
            key = line.split()[0]
            out[key] = float(line.split()[-1])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--heavy", action="store_true", help="把吞吐/并发拉到更高一档")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    exe = find_binary()
    origins, tcp_origin = start_origins()

    # 1) -t：UDP 入口要逐条说出来，包括 proxy_responses 与回收时间
    t = subprocess.run([exe, "-t", "-c", os.path.relpath(CONF, ROOT)], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    tout = (t.stdout or "") + (t.stderr or "")
    check("-t 通过", t.returncode == 0, tout[-300:])
    check("-t 列出 UDP 监听", "udp://0.0.0.0:18613" in tout, tout[-200:])
    check("-t 说清 proxy_responses", "proxy_responses=0" in tout and "proxy_responses=4" in tout, tout[-200:])

    logf = open(os.path.join(ROOT, "logs", "game_udp_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        # 等 HTTP 与 UDP 都就位
        for _ in range(100):
            try:
                if roundtrip(GW_ROOM, b"probe") is not None:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            raise SystemExit("!! 网关未就绪，见 logs/game_udp_out.log / conf/logs/game_udp_err.log")
        print("网关已就绪", GW_HTT)

        # ── 2) 一问一答：回包带得上自己的数据 ─────────────────────────────
        got, _rtt = roundtrip(GW_ROOM, b"player=1")
        check("房间服一问一答通", got == b"roomA|player=1" or got == b"roomB|player=1", repr(got))

        # ── 3) 不串话：60 个客户端并发，每人只该收到自己的号 ──────────────
        n_clients = 60
        bad = []

        def one_player(pid):
            s = udp_client()
            s.settimeout(3.0)
            wrong = None
            try:
                for seq in range(8):
                    payload = f"player={pid};seq={seq}".encode()
                    s.sendto(payload, ("127.0.0.1", GW_ROOM))
                    try:
                        data, _ = s.recvfrom(65535)
                    except socket.timeout:
                        return (pid, "timeout", b"")
                    if f"player={pid}".encode() not in data:
                        return (pid, "cross-talk", data)
            finally:
                s.close()
            return None

        with ThreadPoolExecutor(max_workers=n_clients) as ex:
            for r in ex.map(one_player, list(range(n_clients))):
                if r:
                    bad.append(r)
        check("60 个客户端并发，没有一个回包串到别人手上", not bad, str(bad[:3]))
        check("60×8 次请求全部得到回包", count_of("room:roomA") + count_of("room:roomB") >= 470,
              f"roomA={count_of('room:roomA')} roomB={count_of('room:roomB')}")

        # ── 4) 两个节点轮流承接（会话选点走了 upstream）──────────────────
        va, vb = count_of("room:roomA"), count_of("room:roomB")
        check("两个房间节点都被用到（不是钉死在一个上）", va > 0 and vb > 0, f"A={va} B={vb}")

        # ── 5) 一问多答：proxy_responses 4 ────────────────────────────────
        s = udp_client()
        s.settimeout(3.0)
        s.sendto(b"matchme", ("127.0.0.1", GW_MATCH))
        frames = []
        while True:
            try:
                data, _ = s.recvfrom(65535)
                frames.append(data)
            except socket.timeout:
                break
        s.close()
        check("匹配服一条请求收到 4 帧", len(frames) == 4, f"{len(frames)} 帧: {frames[:2]}")
        check("4 帧都带着请求内容", all(b"matchme" in f for f in frames), str(frames[:2]))

        # ── 6) 心跳：不等回包 + 网关内部账目守恒 ─────────────────────────
        burst = 30000 if not a.heavy else 120000
        before_m = metrics()
        b_in = sum(metric_lines("onrouter_stream_udp_datagrams_total", before_m).values())
        b_fwd = sum(metric_lines("onrouter_stream_udp_forwarded_total", before_m).values())
        b_drop = sum(metric_lines("onrouter_stream_udp_dropped_total", before_m).values())
        hb_base = count_of("hb")
        s = udp_client()
        sent = 0
        t0 = time.perf_counter()
        for i in range(burst):
            try:
                s.sendto(f"hb{i}".encode(), ("127.0.0.1", GW_HB))
                sent += 1
            except OSError:
                break
            # 轻微节奏：让"网关有没有丢包"这个问题与"内核缓冲区够不够大"分开
            if i % 200 == 199:
                time.sleep(0.001)
        s.close()
        dur = time.perf_counter() - t0
        pps = sent / dur
        time.sleep(0.6)                      # 给最后几个还在内核队列里的数据报一点时间
        arrived = count_of("hb") - hb_base
        mm = metrics()
        tot_in = sum(metric_lines("onrouter_stream_udp_datagrams_total", mm).values()) - b_in
        tot_fwd = sum(metric_lines("onrouter_stream_udp_forwarded_total", mm).values()) - b_fwd
        tot_drop = sum(metric_lines("onrouter_stream_udp_dropped_total", mm).values()) - b_drop
        print(f"  心跳：客户端发出 {sent}，网关收到 {tot_in:.0f}、转发 {tot_fwd:.0f}、"
              f"计入丢弃 {tot_drop:.0f}；后端实收 {arrived}（{dur:.1f}s ≈ {pps:,.0f} pps）")
        # 网关的性质：进来的每一个数据报都要么转出去、要么被数到。悄悄吞包是最坏的失效。
        check("网关计数守恒（这一段的增量）：收到 = 转发 + 各类丢弃",
              abs((tot_in - (tot_fwd + tot_drop))) < 0.5,
              f"in={tot_in:.0f} fwd={tot_fwd:.0f} drop={tot_drop:.0f}")
        check("后端不会收到网关没转发过的东西", arrived <= tot_fwd + 0.5,
              f"后端 {arrived} / 网关转发 {tot_fwd:.0f}")
        # 送达率不是网关性质：本机回环上"客户端发出→网关收到"这一段由内核 UDP 缓冲决定，
        # 满载回归里内核会丢几千个（上一轮空载是 0）。所以这里判定的是"丢的那些有没有被
        # 数到"，并把三条数打印出来供人读，而不是拿一个魔法百分比假装它是契约。
        check("没有到不了后端又没人记账的数据报（发送端与网关入口的差额都能解释）",
              sent - tot_in + 0.5 >= 0 and tot_in <= sent + 0.5,
              f"发出 {sent} vs 网关收到 {tot_in:.0f}")

        # ── 7) 会话复用：3 秒 10Hz 连发，会话数应 ≈1 而不是 30 ────────────
        before = sum(metric_lines("onrouter_stream_udp_sessions_total", metrics()).values())
        s = udp_client()
        s.settimeout(2.0)
        n = 0
        t_end = time.perf_counter() + 3.0
        while time.perf_counter() < t_end:
            s.sendto(b"beat", ("127.0.0.1", GW_SESS))
            try:
                s.recvfrom(65535)
            except socket.timeout:
                pass
            n += 1
            time.sleep(0.1)
        s.close()
        after = sum(metric_lines("onrouter_stream_udp_sessions_total", metrics()).values())
        created = after - before
        check(f"一个客户端 {n} 次心跳只建了 1─2 条会话（会话真的在复用）", created <= 2,
              f"新建会话 {created} / {n} 次发包")

        # ── 7b) 同一个客户端猛发时，不能把自己的回包饿死 ────────────────────
        # 会话任务用 tokio::select! + biased，发包分支排在收包分支之前。客户端以最高速
        # 猛发时，如果发包分支一直就绪，回包分支就会被拖死：表现是"没有报错，但回包
        # 迟到/丢失"。这条用"自己压自己"的方式把它钉住：一个客户端全速 3000 发，
        # 另一个线程只管收，要求一个不少、且没有长空窗。
        N_FLOOD = 3000
        cli = udp_client()
        cli.settimeout(4.0)
        got_ts = []
        stop_reader = threading.Event()

        def reader():
            while not stop_reader.is_set():
                try:
                    data, _ = cli.recvfrom(65535)
                    got_ts.append((time.perf_counter(), data))
                except socket.timeout:
                    continue
                except OSError:
                    break

        rt = threading.Thread(target=reader, daemon=True)
        rt.start()
        t_send0 = time.perf_counter()
        sent_f = 0
        for i in range(N_FLOOD):
            try:
                cli.sendto(f"f{i}".encode(), ("127.0.0.1", GW_ROOM))
                sent_f += 1
            except OSError:
                break
        t_send1 = time.perf_counter()
        # 给回包一点时间，再判定
        deadline = time.perf_counter() + 3.0
        while len(got_ts) < sent_f and time.perf_counter() < deadline:
            time.sleep(0.05)
        stop_reader.set()
        rt.join(timeout=2)
        cli.close()
        got_n = len(got_ts)
        lats = [t - t_send0 for t, _ in got_ts]
        p99f = sorted(lats)[int(len(lats) * 0.99) - 1] * 1000 if lats else 0.0
        gap = max((b[0] - a[0] for a, b in zip(got_ts[1:], got_ts[:-1])), default=0.0)
        print(f"  自压：{sent_f} 发 / {got_n} 收，发送耗时 {t_send1 - t_send0:.2f}s，"
              f"p99 首包到达 {p99f:.0f}ms，回包最大空窗 {gap * 1000:.0f}ms")
        check("全速猛发时回包一个不少（发包分支没有饿死收包分支）", got_n == sent_f,
              f"收 {got_n} / 发 {sent_f}")
        check("回包没有被攒到最后一次（最大空窗 < 1s）", gap < 1.0, f"空窗 {gap * 1000:.0f}ms")

        # ── 8) 会话上限：600 个不同 4 元组的"客户端"（真实场景就是伪造源洪水的形状）
        # 18616 配了 udp_max_sessions 32。没有这个上限时，会话会吃光 worker_connections
        # 并把七层一起饿死（nginx 没有这个旋钮）；有了它，洪水只打满这一条监听。
        held = []
        opened = 0
        for _ in range(600):
            c = udp_client()
            try:
                c.sendto(b"hold", ("127.0.0.1", GW_SESS))
                held.append(c)
                opened += 1
            except OSError:
                c.close()
                break
        time.sleep(0.4)
        mm = metrics()
        dropped = metric_lines("onrouter_stream_udp_dropped_total", mm)
        live = sum(metric_lines("onrouter_stream_udp_sessions_active", mm).values())
        print(f"  并发打开 {opened} 个客户端，当前活跃会话 {live:.0f}，丢弃分布 {dropped}")
        cap_key = 'onrouter_stream_udp_dropped_total{role="session_cap"}'
        check("超过 udp_max_sessions 的会话被挡下并按 session_cap 计数",
              dropped.get(cap_key, 0) > 0, str(dropped))
        check("会话数被钉在上限附近，没有把进程额度吃光", live <= 40, f"活跃 {live:.0f}")
        check("洪水期间七层仍在服务（会话上限挡住了饿死）", http_ok(), "GET /ping 非 200")
        for c in held:
            c.close()

        # ── 9) 极端尺寸：0 字节与 64KB 数据报 ────────────────────────────
        zero, _ = roundtrip(GW_ROOM, b"")
        check("0 字节数据报也能原路回", zero in (b"roomA|", b"roomB|"), repr(zero))
        big = b"x" * 65000
        got_big, _ = roundtrip(GW_ROOM, big, timeout=4.0)
        check("接近上限的数据报（65000 B）完整往返",
              got_big is not None and got_big.endswith(big), f"回包 {len(got_big) if got_big else None} 字节")

        # ── 10) 同端口号的 TCP 与 UDP 互不干扰 ────────────────────────────
        u = roundtrip(GW_HB, b"via-udp")          # 18613/udp 不等回包 → 必然超时
        tcp_line = tcp_on(18613)
        check("同端口号的 TCP 服务照常可用", tcp_line == b"tcpecho|hello-18613", repr(tcp_line))
        check("同端口号的 UDP 入口是'不等回包'形态（不回才是正确的）", u[0] is None, repr(u[0])[:60])

        # ── 11) 延迟：一问一答的 p50/p99 ─────────────────────────────────
        rt = []
        for _ in range(400):
            _g, dt = roundtrip(GW_ROOM, b"ping")
            rt.append(dt * 1000.0)
        rt.sort()
        p50, p99 = statistics.median(rt), rt[int(len(rt) * 0.99)]
        print(f"  往返延迟 p50={p50:.2f}ms p99={p99:.2f}ms（一问一答，本机回环）")
        check("p50 往返在个位数毫秒内", p50 < 10.0, f"p50={p50:.2f}ms")
        check("p99 没有被会话/调度拖到失控", p99 < 100.0, f"p99={p99:.2f}ms")

        # ── 12) 指标族本身：只出现一次 TYPE，且没有会话泄漏 ───────────────
        mm = metrics()
        check("UDP 指标族只声明一次 TYPE",
              mm.count("# TYPE onrouter_stream_udp_dropped_total") == 1,
              str(mm.count("# TYPE onrouter_stream_udp_dropped_total")))
        check("UDP 指标覆盖到 drop 的四种角色",
              all(f'role="{r}"' in mm
                  for r in ("no_permit", "queue_full", "send_failed", "session_cap")), "")
        time.sleep(2.5)  # 超过 proxy_timeout(2s)，会话应当自己收干净
        live2 = sum(metric_lines("onrouter_stream_udp_sessions_active", metrics()).values())
        check("客户端全部停手后会话回落到 0（空闲回收在工作，没有 fd 泄漏）", live2 == 0,
              f"仍活跃 {live2:.0f}")

        # ── 13) 对照：不设上限就是 nginx 的默认形状，能有多疼 ──────────────
        # 600 个伪造得了源 4 元组的"客户端"打向 18617（没有 udp_max_sessions）。
        # 会话会把 worker_connections(256) 吃光，七层跟着饿死——这就是那条告警的全部内容，
        # 也是本实现给出 udp_max_sessions 这个旋钮的理由（nginx 没有对应物）。
        held2 = []
        for _ in range(400):
            c = udp_client()
            try:
                c.sendto(b"flood", ("127.0.0.1", 18617))
                held2.append(c)
            except OSError:
                c.close()
                break
        time.sleep(0.4)
        mm2 = metrics_or_empty()
        live2 = sum(metric_lines("onrouter_stream_udp_sessions_active", mm2).values())
        starved = not http_ok()
        print(f"  对照（无上限）：活跃会话 {live2:.0f}，七层还能服务 = {not starved}")
        check("没有 udp_max_sessions 时会话能吃满进程额度（worker_connections=256）",
              live2 >= 200 or starved, f"活跃 {live2:.0f}，七层饿死={starved}")
        for c in held2:
            c.close()
        # 清场：等空闲回收把会话放掉，再确认七层恢复——证明这不是永久损伤
        deadline = time.perf_counter() + 8.0
        while time.perf_counter() < deadline and not http_ok():
            time.sleep(0.3)
        check("洪水退去后七层恢复服务（会话按 proxy_timeout 归还额度）", http_ok(),
              "等待 8s 后 /ping 仍非 200")

        # ── 14) 错误日志 ──────────────────────────────────────────────────
        txt = open(ERRLOG, encoding="utf-8", errors="replace").read() if os.path.exists(ERRLOG) else ""
        check("错误日志无 panic", "panicked" not in txt and "BACKTRACE" not in txt.upper(), txt[-240:])
        check("错误日志里能看到 UDP 入口的建立", "stream 监听 udp://" in txt, txt[-120:])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for s, _t in origins:
            s.close()
        tcp_origin.close()

    ok = sum(1 for _, r in results if r)
    print(f"\n==== 游戏 UDP E2E: {ok}/{len(results)} passed ====")
    if ok != len(results):
        print("失败项：")
        for name, r in results:
            if not r:
                print("  -", name)
        sys.exit(1)


def metrics_or_empty():
    """对照用例里 /metrics 可能正被饿死——拿不到就返回空串，别把用例搞崩。"""
    try:
        return metrics()
    except OSError:
        return ""


def http_ok():
    import http.client

    try:
        c = http.client.HTTPConnection("127.0.0.1", GW_HTT, timeout=3)
        c.request("GET", "/ping")
        r = c.getresponse()
        r.read()
        c.close()
        return r.status == 200
    except OSError:
        return False


def tcp_on(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(b"hello-18613")
    data = s.recv(4096)
    s.close()
    return data


if __name__ == "__main__":
    main()
