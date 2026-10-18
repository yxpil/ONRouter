# -*- coding: utf-8 -*-
# init_worker_by_lua* + lua_package_path 实跑 E2E
#   1) init_by_lua 先于 init_worker；init_worker 每 VM 恰好执行一次（共享字典计数 = VM 数）
#   2) lua_package_path 让 require 从磁盘加载模块
#   3) `;;` 保留 Lua 默认搜索路径；不写 `;;` 时默认路径被整体替换
#   4) init_worker 里注册的 ngx.timer.at 真正触发（说明调度器已就绪）
#   5) 请求不会重复执行 init_worker（连发多次计数不变）
#   6) init_worker_by_lua_file 形式
#   7) 脚本报错 -> 启动失败、进程非 0 退出、端口不被监听
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/init_worker_package_e2e.py
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = os.path.join(ROOT, "conf", ".tmp_init_worker")
LUALIB = os.path.join(TMP, "lualib")
LOG_DIR = os.path.join(ROOT, "logs")
HOST = "127.0.0.1"
PORT_INLINE = 18550
PORT_FILE = 18551
PORT_BAD = 18552

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if not ok else detail)


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def slash(p):
    return p.replace("\\", "/")


def wait_port(port, timeout=10.0, proc=None):
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection((HOST, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def port_free(port):
    try:
        with socket.create_connection((HOST, port), timeout=0.3):
            return False
    except OSError:
        return True


def get_json(port, path="/"):
    conn = http.client.HTTPConnection(HOST, port, timeout=8)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, json.loads(body.decode("utf-8"))


def start(conf, out_path):
    out = open(out_path, "wb")
    p = subprocess.Popen(
        [find_binary(), "-c", conf],
        cwd=ROOT,
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    p._out_file = out  # 防止 GC 提前关闭
    return p


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)
    getattr(p, "_out_file", None) and p._out_file.close()


def read_log(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


# ---------------- 夹具 ----------------

INLINE_CONF = os.path.join(TMP, "initw_inline.conf")
FILE_CONF = os.path.join(TMP, "initw_file.conf")
BAD_CONF = os.path.join(TMP, "initw_bad.conf")


def write_fixtures():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(LUALIB, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    with open(os.path.join(LUALIB, "myhelper.lua"), "w", encoding="utf-8") as f:
        f.write("return { greeting = 'from-disk' }\n")

    inline_err = slash(os.path.join(TMP, "inline_err.log"))
    file_err = slash(os.path.join(TMP, "file_err.log"))
    lualib = slash(LUALIB)
    rid = os.getpid()

    with open(INLINE_CONF, "w", encoding="utf-8") as f:
        f.write(
            f"""
error_log {inline_err} info;
pid {slash(os.path.join(TMP, 'inline.pid'))};
lua_shared_dict initw 1m;
lua_package_path "{lualib}/?.lua;;";

init_by_lua_block {{
    ngx.shared.initw:set("init", "by-init")
}}

init_worker_by_lua_block {{
    assert(ngx.shared.initw:get("init") == "by-init", "init_by_lua 必须先于 init_worker")
    local h = require("myhelper")
    ngx.shared.initw:set("mod", h.greeting)
    ngx.shared.initw:incr("runs", 1, 0)
    local ok, err = ngx.timer.at(0.05, function(premature)
        ngx.shared.initw:set("timer", premature and "premature" or "fired")
    end)
    assert(ok, err)
}}

server {{
    listen {HOST}:{PORT_INLINE};
    location / {{
        content_by_lua_block {{
            local d = ngx.shared.initw
            ngx.header["content-type"] = "application/json"
            ngx.say('{{"init":"' .. tostring(d:get("init"))
                .. '","mod":"' .. tostring(d:get("mod"))
                .. '","runs":' .. tostring(d:get("runs"))
                .. ',"timer":"' .. tostring(d:get("timer"))
                .. '","path":"' .. package.path:gsub("\\\\", "/") .. '"}}')
        }}
    }}
}}
"""
        )

    with open(os.path.join(TMP, "worker.lua"), "w", encoding="utf-8") as f:
        f.write(
            """
local h = require("myhelper")
ngx.shared.f:set("mod", h.greeting)
ngx.shared.f:incr("runs", 1, 0)
"""
        )

    with open(FILE_CONF, "w", encoding="utf-8") as f:
        f.write(
            f"""
error_log {file_err} info;
pid {slash(os.path.join(TMP, 'file.pid'))};
lua_shared_dict f 1m;
lua_package_path "{lualib}/?.lua";
init_worker_by_lua_file {slash(os.path.join(TMP, 'worker.lua'))};

server {{
    listen {HOST}:{PORT_FILE};
    location / {{
        content_by_lua_block {{
            local d = ngx.shared.f
            ngx.header["content-type"] = "application/json"
            ngx.say('{{"mod":"' .. tostring(d:get("mod"))
                .. '","runs":' .. tostring(d:get("runs"))
                .. ',"path":"' .. package.path:gsub("\\\\", "/") .. '","pid":{rid}}}')
        }}
    }}
}}
"""
        )

    with open(BAD_CONF, "w", encoding="utf-8") as f:
        f.write(
            f"""
error_log {slash(os.path.join(TMP, 'bad_err.log'))} info;
init_worker_by_lua_block {{
    error("boom-init-worker")
}}
server {{
    listen {HOST}:{PORT_BAD};
    location / {{
        content_by_rust echo ok;
    }}
}}
"""
        )


def main():
    if not find_binary():
        raise SystemExit("!! 先构建 onrouter")
    write_fixtures()

    # ---------- 1. inline + lua_package_path ----------
    out_inline = os.path.join(TMP, "inline_stdout.log")
    p = start(INLINE_CONF, out_inline)
    try:
        up = wait_port(PORT_INLINE, proc=p)
        if not up:
            print(read_log(out_inline))
        check("inline 配置启动并监听", up)
        if up:
            status, js = get_json(PORT_INLINE)
            check("内容端点返回 200/JSON", status == 200 and isinstance(js, dict), f"{status} {js}")
            check("init_by_lua 先于 init_worker 执行", js.get("init") == "by-init", js.get("init"))
            check("lua_package_path 让 require 从磁盘加载", js.get("mod") == "from-disk", js.get("mod"))

            out = read_log(out_inline)
            m = re.search(r"已执行 init_worker_by_lua（x(\d+) VM", out)
            vms = int(m.group(1)) if m else None
            check("日志报告 init_worker 每 VM 执行一次", vms is not None and vms >= 1, out[-2000:])
            runs = int(js.get("runs") or 0)
            check("共享字典计数 == VM 数（每 VM 恰好一次）", vms is not None and runs == vms, f"runs={runs} vms={vms}")

            # timer 50ms 触发；最多轮询 3s
            fired = False
            timer_val = None
            for _ in range(30):
                _, js2 = get_json(PORT_INLINE)
                timer_val = js2.get("timer")
                if timer_val == "fired":
                    fired = True
                    break
                time.sleep(0.1)
            check("init_worker 里注册的 ngx.timer.at 已触发", fired, f"timer={timer_val!r}")

            path = (js2 if fired else js).get("path", "")
            check("`;;` 保留 Lua 默认搜索路径", "share/lua/5.4" in path, path)
            check("package.path 包含配置的模块目录", f"{slash(LUALIB)}/?.lua" in path, path)
            check("启动日志记录 lua_package_path", "lua_package_path 已应用" in out, out[-1500:])

            # 连续请求不重复执行 init_worker
            counts = []
            for _ in range(5):
                _, r = get_json(PORT_INLINE)
                counts.append(int(r.get("runs") or 0))
            check("请求不重复执行 init_worker（计数不变）", len(set(counts)) == 1 and counts[0] == runs, counts)
    finally:
        stop(p)

    # ---------- 2. _file 形式 + 不带 ;; 替换默认路径 ----------
    out_file = os.path.join(TMP, "file_stdout.log")
    p = start(FILE_CONF, out_file)
    try:
        up = wait_port(PORT_FILE, proc=p)
        if not up:
            print(read_log(out_file))
        check("_file 配置启动并监听", up)
        if up:
            status, js = get_json(PORT_FILE)
            check("_file 内容端点返回 200/JSON", status == 200 and isinstance(js, dict), f"{status} {js}")
            check("_file init_worker 从磁盘加载模块", js.get("mod") == "from-disk", js.get("mod"))
            out = read_log(out_file)
            m = re.search(r"已执行 init_worker_by_lua_file（x(\d+) VM", out)
            vms = int(m.group(1)) if m else None
            check("日志报告 init_worker_by_lua_file 每 VM 执行一次", vms is not None, out[-2000:])
            check("_file 计数 == VM 数", vms is not None and int(js.get("runs") or 0) == vms, f"{js.get('runs')} vs {vms}")
            path = js.get("path", "")
            check("不写 `;;` 时默认路径被整体替换", "share/lua/5.4" not in path, path)
            check("替换后仍包含配置的模块目录", f"{slash(LUALIB)}/?.lua" in path, path)
    finally:
        stop(p)

    # ---------- 3. 脚本报错 -> 启动失败 ----------
    bad = subprocess.run(
        [find_binary(), "-c", BAD_CONF],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    bad_out = (bad.stdout + bad.stderr).decode("utf-8", "replace")
    check("init_worker 脚本报错时进程非 0 退出", bad.returncode != 0, f"rc={bad.returncode}")
    check("错误信息包含 VM 编号与原始错误", "init_worker_by_lua 在第 1 个 VM 执行失败" in bad_out and "boom-init-worker" in bad_out, bad_out[-1000:])
    check("失败后端口未被监听", port_free(PORT_BAD))

    total = len(results)
    passed = sum(1 for _, ok in results if ok)
    print(f"\n==== init_worker + lua_package_path E2E: {passed}/{total} passed ====")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
