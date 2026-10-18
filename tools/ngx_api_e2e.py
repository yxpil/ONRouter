# -*- coding: utf-8 -*-
# ngx.* 核心 API 补全 E2E —— 用真实流量证明 Batch 1 新增 API 面可用且语义对齐 OpenResty：
#   摘要/CRC 与 RFC1321/RFC2202/CRC32 已知向量逐字节一致；时间格式化/解析往返；
#   worker/config/get_phase/is_subrequest；req.* 体读写与方法读写与 POST 参数；resp.get_headers。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/ngx_api_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "ngx_api.conf")
HOST, PORT = "127.0.0.1", 18131
BASE = f"http://{HOST}:{PORT}"

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
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


def req(path, data=None, method=None):
    body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(BASE + path, data=body, method=method or ("POST" if body is not None else "GET"))
    if body is not None:
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        resp = _opener.open(r, timeout=8)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    # ngx.say 会在相邻参数间插入一个空格，故 "key= value"：剥掉值前的那一个空格即可
    m = {}
    for line in body.strip().splitlines():
        k, _, v = line.partition("=")
        if v.startswith(" "):
            v = v[1:]
        m[k.strip()] = v
    return m


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "ngx_api_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if req("/meta")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18131 被占用？看 logs/ngx_api_err.log）")

        # === 摘要 / CRC（与已知向量逐字节一致）===
        st, body = req("/digest")
        d = kv(body)
        check("/digest 200", st == 200, f"st={st}")
        check("ngx.md5('abc')", d.get("md5") == "900150983cd24fb0d6963f7d28e17f72", f"md5={d.get('md5')}")
        check("ngx.md5_bin('abc') 十六进制一致", d.get("md5_bin") == "900150983cd24fb0d6963f7d28e17f72", f"md5_bin={d.get('md5_bin')}")
        check("ngx.sha1_bin('abc',true)", d.get("sha1_hex") == "a9993e364706816aba3e25717850c26c9cd0d89d", f"sha1={d.get('sha1_hex')}")
        check("ngx.sha1_bin 原始 20 字节", d.get("sha1_bin_len") == "20", f"len={d.get('sha1_bin_len')}")
        check("ngx.hmac_sha1(RFC2202)", d.get("hmac") == "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", f"hmac={d.get('hmac')}")
        check("ngx.crc32_short('123456789')==0xCBF43926", d.get("crc32") == "3421780262", f"crc32={d.get('crc32')}")
        check("ngx.crc32_long 同值", d.get("crc32_long") == d.get("crc32"), f"long={d.get('crc32_long')}")

        # === 时间 ===
        st, body = req("/time")
        t = kv(body)
        check("/time 200", st == 200, f"st={st}")
        check("ngx.cookie_time(0)", t.get("cookie0") == "Thu, 01-Jan-1970 00:00:00 GMT", f"cookie0={t.get('cookie0')}")
        check("ngx.http_time(0)", t.get("http0") == "Thu, 01 Jan 1970 00:00:00 GMT", f"http0={t.get('http0')}")
        check("ngx.parse_http_time 命中", t.get("parsed") == "0", f"parsed={t.get('parsed')}")
        check("ngx.parse_http_time 失败→nil", t.get("bad") == "nil", f"bad={t.get('bad')}")
        check("ngx.today() 形如 YYYY-MM-DD", t.get("today_len") == "10", f"len={t.get('today_len')}")
        check("ngx.update_time() 存在（nil）", t.get("update_time") == "nil", f"ut={t.get('update_time')}")

        # === worker / config ===
        st, body = req("/meta")
        mt = kv(body)
        check("/meta 200", st == 200, f"st={st}")
        check("ngx.worker.pid()>0", mt.get("pid_positive") == "true", f"pid={mt.get('pid_positive')}")
        check("ngx.worker.id()==0（单进程反应器）", mt.get("wid") == "0", f"wid={mt.get('wid')}")
        check("ngx.worker.count()==1", mt.get("wcount") == "1", f"count={mt.get('wcount')}")
        check("ngx.config.subsystem=='http'", mt.get("subsystem") == "http", f"subsystem={mt.get('subsystem')}")
        check("ngx.config.server=='ONRouter'", mt.get("server") == "ONRouter", f"server={mt.get('server')}")
        check("ngx.config.prefix() 非空", mt.get("prefix_nonempty") == "true", f"prefix={mt.get('prefix_nonempty')}")

        # === 阶段 / 子请求 ===
        st, body = req("/phase")
        ph = kv(body)
        check("/phase 200", st == 200, f"st={st}")
        check("ngx.get_phase()=='content_by_lua'", ph.get("phase") == "content_by_lua", f"phase={ph.get('phase')}")
        check("顶层 ngx.is_subrequest==false", ph.get("sub") == "false", f"sub={ph.get('sub')}")

        # === req.*（POST 表单体）===
        st, body = req("/req", data="a=1&b=hello%20world")
        q = kv(body)
        check("/req 200", st == 200, f"st={st}")
        check("get_body_file()→nil（体在内存）", q.get("body_file") == "nil", f"bf={q.get('body_file')}")
        check("get_post_args a==1", q.get("a") == "1", f"a={q.get('a')}")
        check("get_post_args b 已 url 解码", q.get("b") == "hello world", f"b={q.get('b')}")
        check("get_method()==POST", q.get("method") == "POST", f"method={q.get('method')}")
        check("set_method('PUT') 生效", q.get("method2") == "PUT", f"method2={q.get('method2')}")
        check("raw_header 含原始方法", q.get("head_has_method") == "true", f"rh={q.get('head_has_method')}")
        check("set_body_data 覆盖请求体", q.get("after_set") == "replaced=1", f"after_set={q.get('after_set')}")
        check("discard_body 清空请求体", q.get("after_discard") == "nil", f"after_discard={q.get('after_discard')}")

        # === resp.get_headers ===
        st, body = req("/resp")
        rp = kv(body)
        check("/resp 200", st == 200, f"st={st}")
        check("resp.get_headers 读回 X-Test", rp.get("xtest") == "yes", f"xtest={rp.get('xtest')}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx API E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
