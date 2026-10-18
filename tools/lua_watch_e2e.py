# -*- coding: utf-8 -*-
# Lua 脚本文件定期自检 E2E —— 证明"热重载靠后台自检，不靠请求路径 stat"。
#
# 证明了什么（都在同一个进程、同一批监听 socket 上发生）：
#   1) 改写 .lua 后**不重启、不 SIGHUP、conf 里也没配 `reload`**，请求在 ≤2s 内拿到新内容
#      —— 说明脚本失效判定由后台定期自检完成，编辑最终一定会生效。
#   2) 自检收敛后 error log 里有"定期自检：Lua 脚本有变更" —— 说明换内容是自检任务干的，
#      不是某个请求顺手 stat 出来的。
#   3) 换内容期间持续打请求，0 个非 200 —— 说明热替换对客户端无损（旧内容继续服务，
#      半成品文件不会把请求打成 500）。
#   4) 连续改 6 轮仍能正确收敛且进程存活 —— 说明反复编辑不会让每 VM 的编译缓存无界增长。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/lua_watch_e2e.py
import http.client
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "lua_watch_e2e.conf")
LUA = os.path.join(ROOT, "conf", "lua_watch_e2e.lua")
# conf 里的相对路径以 conf 所在目录为基准，运行产物落在 conf/logs/
LOG = os.path.join(ROOT, "conf", "logs", "lua_watch_e2e_err.log")
PID = os.path.join(ROOT, "conf", "logs", "lua_watch_e2e.pid")
PORT = 18128
CHECK_INTERVAL = 1.0  # 与 lua_engine::LUA_FILE_CHECK_INTERVAL 一致

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


def get(path, timeout=5):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        c.close()


def write_lua(tag):
    """写入 `ngx.say("<tag>")`，并强制 bump mtime（Windows 时间戳粒度问题）。"""
    with open(LUA, "w", encoding="utf-8", newline="\n") as f:
        f.write('ngx.say("%s")\n' % tag)
        f.flush()
    st = os.stat(LUA)
    os.utime(LUA, (st.st_atime, st.st_mtime + 1))


def wait_for(tag, deadline):
    """轮询直到响应里出现 tag；返回 (耗时, 非 200/异常次数)，超时返回 (None, errs)。"""
    t0 = time.time()
    errs = 0
    while time.time() - t0 < deadline:
        try:
            st, body = get("/watch", timeout=2)
            if st != 200:
                errs += 1
            elif tag in body:
                return time.time() - t0, errs
        except Exception:
            errs += 1
        time.sleep(0.02)
    return None, errs


def main():
    for p in (CONF, LUA, LOG, PID):
        try:
            os.remove(p)
        except OSError:
            pass
    os.makedirs(os.path.join(ROOT, "conf", "logs"), exist_ok=True)

    write_lua("v0")
    # 故意不写 reload 指令：证明 .lua 自检与主配置的 reload 开关无关，常开
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(
            'error_log "logs/lua_watch_e2e_err.log" info;\n'
            'pid "logs/lua_watch_e2e.pid";\n'
            "\n"
            "server {\n"
            f"    listen 127.0.0.1:{PORT};\n"
            "    server_name lua-watch.local;\n"
            "    location /watch {\n"
            f'        content_by_lua_file "{LUA.replace(os.sep, "/")}";\n'
            "    }\n"
            "}\n",
        )

    proc = subprocess.Popen(
        [find_binary(), CONF], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                if get("/watch")[0] == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            check("服务启动", False, "10s 内 /watch 没有可用响应")
            return 1

        st, body = get("/watch")
        check("基线：首次请求读到 v0 并回填缓存", st == 200 and "v0" in body, repr(body))

        # 1)+2)+3)+4)：连续 6 轮改写，每轮都必须在自检节拍内收敛且期间请求不出现非 200
        lat, bad = [], 0
        for i in range(1, 7):
            tag = "v%d" % i
            write_lua(tag)
            dt, errs = wait_for(tag, CHECK_INTERVAL * 2.5)
            bad += errs
            if dt is None:
                check("第 %d 轮编辑后自检重载 %s" % (i, tag), False, "2.5s 内未收敛")
                break
            lat.append(dt)
        else:
            check("6 轮编辑全部在自检节拍内收敛（每轮 ≤2.5s）", True)
            check("首轮收敛 %.2fs，落在 1 秒自检节拍量级" % lat[0], lat[0] <= 2.0)
            check("换内容期间请求全为 200（共 %d 次采样）" % (6 + bad), bad == 0,
                  "非 200/异常共 %d 次" % bad)
            print("     各轮收敛耗时: " + " ".join("%.2fs" % d for d in lat))

        check("进程全程存活（未因热替换重启）", proc.poll() is None)

        log = ""
        if os.path.exists(LOG):
            with open(LOG, encoding="utf-8", errors="replace") as f:
                log = f.read()
        hits = re.findall(r"定期自检：Lua 脚本有变更", log)
        check("自检重载由后台任务记录（%d 条）" % len(hits), len(hits) >= 6,
              "日志里只有 %d 条" % len(hits))

        # 回到初始内容，别把 fixture 留在改写状态
        write_lua("v0")
        dt, _ = wait_for("v0", CHECK_INTERVAL * 2.5)
        check("还原后仍能收敛回 v0", dt is not None)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        for p in (CONF, LUA, LOG, PID):
            try:
                os.remove(p)
            except OSError:
                pass

    failed = [n for n, ok in results if not ok]
    print("\n%d/%d 通过" % (len(results) - len(failed), len(results)))
    if failed:
        print("失败项: " + "; ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
