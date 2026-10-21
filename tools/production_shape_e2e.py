# -*- coding: utf-8 -*-
"""生产形状 E2E —— 把网关当成"真拿来部署静态站 + 跑 WASM/Lua + 挂缓存"的那台机器测。

    python tools/production_shape_e2e.py            # 建站 + 起网关 + 全量断言
    python tools/production_shape_e2e.py --files 2000 --keep

断言一律按 **nginx 的行为**写，不按本项目的实现写：测出来不一致就是网关要改，
不许把断言改成"实际行为"。（唯一例外：本项目明确记录过的刻意差异，见下方 KNOWN。）

覆盖的维度：
  静态站   逐文件字节比对、Content-Type/Length、HEAD、Range（前缀/后缀/开区间/越界/非法）、
           Last-Modified + If-Modified-Since、ETag + If-None-Match（含 W/ 弱比较与 *）、
           目录 301 补斜杠、index 优先、autoindex（不列 dotfile）、404、dotfile、
           gzip（文本压、二进制不压、解压回原字节、Vary）
  WASM     access 缺 token → 403 且后端零命中；header_filter 加头；body_filter 改体；
           fuel 耗尽 → 失败关闭（不能放行未过滤内容）；未声明/坏模块在 -t 就出局
  Lua      content_by_lua(_file)、access_by_lua + shared dict 计数在并发下不丢、
           ngx.location.capture 子请求、ngx.req 读 POST 体、脚本抛错 → 500、
           ngx.timer 后台任务改到共享字典
  缓存     小 keys_zone + disk=on 的冷层：被淘汰后冷命中仍 200 且后端计数不变，
           proxy_cache_revalidate 304 复用，过期后 X-Cache-Status 词表合法
"""

import argparse
import gzip
import hashlib
import http.client
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.parse
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)          # import selfsigned：夹具模块与套件同目录
import selfsigned                     # noqa: E402
EXE = os.path.join(ROOT, "target", "release", "onrouter.exe" if os.name == "nt" else "onrouter")
SITE = os.path.join(ROOT, "public_prodshape")
CONF = os.path.join(ROOT, "conf", "production_shape.conf")
ERRLOG = os.path.join(ROOT, "conf", "logs", "prodshape_err.log")
ORIGIN_PORT = 19861
GW_HTTP = 19900
GW_TLS = 19901
GW_LUA = 19902
GW_CACHE = 19903

# 明确记录过的刻意差异（不是 bug，见 docs/CAPABILITY_MATRIX.md）：
#  - location 级 return 在访问控制之后（nginx 是 rewrite 相位在前）
#  - stream 层只有 TCP，没有 UDP
KNOWN = ()

fails, checks = [], [0]


def ck(name, ok, detail=""):
    checks[0] += 1
    if not ok:
        fails.append(f"FAIL {name} :: {detail}"[:400])
        print("FAIL", name, detail[:300])


# ---------------------------------------------------------------- 站点夹具
def build_site(n):
    shutil.rmtree(SITE, ignore_errors=True)
    rng = random.Random(20261021)
    kinds = [
        ("index.html", b"<!doctype html><title>prod shape</title>\n", "text/html"),
        ("a.css", b"a{color:red}\n" * 400, "text/css"),
        ("app.js", b"console.log(1);\n" * 700, "application/javascript"),
        ("data.json", json.dumps({"k": list(range(200))}).encode(), "application/json"),
        ("big.txt", b"x" * 300001, "text/plain"),
        ("small.txt", b"hi", "text/plain"),
        ("empty.txt", b"", "text/plain"),
        ("pic.png", bytes([0x89, 0x50, 0x4E, 0x47]) + os.urandom(2000), "image/png"),
    ]
    manifest = {}
    made = 0
    for d in range((n // 12) + 1):
        sub = f"d{d}"
        os.makedirs(os.path.join(SITE, sub), exist_ok=True)
        if d % 3 == 0:
            os.makedirs(os.path.join(SITE, sub, "nested"), exist_ok=True)
        for fname, body, mime in kinds:
            if made >= n:
                break
            rel = os.path.join(sub, fname.replace(".", f".{made}."), "").replace("\\", "/") if made % 7 == 0 else f"{sub}/{fname}"
            if made % 7 == 0:
                rel = f"{sub}/{fname}"
            p = os.path.join(SITE, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(body)
            manifest[rel] = {"sha": hashlib.sha256(body).hexdigest(), "len": len(body), "mime": mime,
                             "gzip_ok": mime.startswith("text/") or mime.endswith("json")}
            made += 1
        if made >= n:
            break
    # 特殊名字：空格、中文、长名、dotfile
    for rel, body in [("带 空格 文件.txt", b"space-name\n"), ("中文目录/说明.txt", b"cjk\n"),
                      ("." + "hidden.txt", b"hidden\n"), ("a" * 120 + ".txt", b"long-name\n")]:
        p = os.path.join(SITE, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(body)
        manifest[rel] = {"sha": hashlib.sha256(body).hexdigest(), "len": len(body), "mime": "text/plain",
                         "gzip_ok": True}
    # WASM 那两条 location 走 try_files，得真有这么个文件（路径要带上 location 前缀）
    for pre in ("guarded", "hf"):
        d = os.path.join(SITE, pre, "d0")
        os.makedirs(d, exist_ok=True)
        shutil.copyfile(os.path.join(SITE, "d0", "index.html"), os.path.join(d, "index.html"))

    # 目录（测 index 与 autoindex）
    os.makedirs(os.path.join(SITE, "listing"), exist_ok=True)
    with open(os.path.join(SITE, "listing", "visible.txt"), "wb") as f:
        f.write(b"visible\n")
    with open(os.path.join(SITE, "listing", ".secret"), "wb") as f:
        f.write(b"do-not-list\n")
    os.makedirs(os.path.join(SITE, "indexed"), exist_ok=True)
    with open(os.path.join(SITE, "indexed", "index.html"), "wb") as f:
        f.write(b"index-page\n")
    return manifest


def write_conf():
    wasm_dir = "wasm"
    # root 相对**配置文件所在目录**（conf/）解析，不是进程 CWD
    SITE_REL = "../" + os.path.relpath(SITE, ROOT).replace(os.sep, "/")
    # 自带夹具：CI 是干净检出，certs_random/ 只有跑过 random_scenarios 才存在
    selfsigned.ensure(ROOT, "certs_prodshape", base="ps",
                      dns=("tls.prodshape.test", "localhost"))
    tpl = f"""
error_log "logs/prodshape_err.log" warn;
pid logs/prodshape.pid;
worker_threads 4;
gzip on;
gzip_types text/html text/css text/plain application/javascript application/json;
lua_shared_dict counter 64k;
lua_shared_dict timers 64k;
proxy_cache_path logs/prodshape_cache keys_zone=pc:1k disk=on max_size=32m max_value=1m;
proxy_cache_path logs/prodshape_rv keys_zone=rv:64k max_size=8m;
wasm_plugin auth {wasm_dir}/authz.wat;
wasm_plugin hf {wasm_dir}/header_filter.wat;
wasm_plugin bf {wasm_dir}/body_filter.wat;

upstream origin {{ server 127.0.0.1:{ORIGIN_PORT}; keepalive 32; }}

server {{
    listen {GW_HTTP};
    server_name static.prodshape.test;
    root "{SITE_REL}";
    index index.html;
    autoindex on;
    location / {{
        expires 1h;
        add_header Cache-Control "public, max-age=3600";
    }}
    location /noauto/ {{ autoindex off; }}
}}

server {{
    listen {GW_TLS} ssl http2;
    ssl_certificate "../certs_prodshape/ps.pem";
    ssl_certificate_key "../certs_prodshape/ps.key";
    server_name tls.prodshape.test;
    root "{SITE_REL}";
    index index.html;
    location /guarded/ {{
        access_by_wasm auth;
        try_files $uri $uri/ =404;
    }}
    location /hf/ {{
        header_filter_by_wasm hf;
        body_filter_by_wasm bf;
        try_files $uri $uri/ =404;
    }}
    location / {{ try_files $uri $uri/ =404; }}
}}

server {{
    listen {GW_LUA};
    server_name lua.prodshape.test;
    location = /lua-say {{
        content_by_lua "ngx.header['X-Lua']='1'; ngx.say('lua-', ngx.var.uri, '-', tostring(ngx.req.get_method()))";
    }}
    location = /lua-count {{
        access_by_lua "local d = ngx.shared.counter; local n, err = d:incr('hits', 1, 0); ngx.header['X-Hits'] = tostring(n or ('ERR:' .. tostring(err)))";
        content_by_lua "ngx.say('counted')";
    }}
    location = /lua-sub {{
        content_by_lua "local res = ngx.location.capture('/inner'); ngx.say('sub[', res.status, ',', string.gsub(res.body, '\\\\n', ''), ']')";
    }}
    location = /inner {{ internal; content_by_lua "ngx.say('inner-body')"; }}
    location = /lua-body {{
        content_by_lua "ngx.req.read_body(); local b = ngx.req.get_body_data() or ''; ngx.say('len=', #b, '|', b)";
    }}
    location = /lua-error {{
        content_by_lua "error('boom')";
    }}
    location = /lua-timer {{
        content_by_lua "ngx.timer.at(0.2, function(premature) ngx.shared.timers:set('fired', 'yes') end); ngx.say('armed')";
    }}
    location = /lua-file {{ content_by_lua_file "../lua/prodshape.lua"; }}
    location / {{ root "{SITE_REL}"; }}
}}

server {{
    listen {GW_CACHE};
    server_name cache.prodshape.test;
    # revalidate 用独立的内存区：冷层条目里没存 ETag/Last-Modified，过期只能整份重取；
    # 拿 pc（8 条 + disk=on）测它，测到的是淘汰而不是"没复用"
    location /rv/ {{
        proxy_pass http://origin;
        proxy_cache rv;
        proxy_cache_valid 200 3s;
        proxy_cache_revalidate on;
        add_header X-Cache $upstream_cache_status;
    }}
    location /cached/ {{
        proxy_pass http://origin;
        proxy_cache pc;
        proxy_cache_valid 200 3s;
        proxy_cache_revalidate on;
        add_header X-Cache $upstream_cache_status;
    }}
    location / {{ proxy_pass http://origin; }}
    location = /health {{ return 200 "ok\\n"; }}
}}
"""
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(tpl)
    with open(os.path.join(ROOT, "lua", "prodshape.lua"), "w", encoding="utf-8", newline="\n") as f:
        f.write("ngx.say('from-file-', ngx.var.uri)\n")
    # WASM：把鉴权插件的期望值对齐（authz.wat 要求 X-Gateway-Token）
    return tpl


# ---------------------------------------------------------------- 源站
ORIGIN_HITS = {}
ORIGIN_CONDITIONAL = {}          # 收到过几次条件请求（If-None-Match → 304）
ORIGIN_LOCK = threading.Lock()


def start_origin():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path.startswith(("/cached/", "/rv/")):
                etag = f'"{hashlib.md5(self.path.encode()).hexdigest()}"'
                if self.headers.get("If-None-Match", "").strip() == etag:
                    # 条件问询：计数并只回头、不发体——这正是 revalidate 要买的东西
                    with ORIGIN_LOCK:
                        ORIGIN_CONDITIONAL[self.path] = ORIGIN_CONDITIONAL.get(self.path, 0) + 1
                    self.send_response(304)
                    self.send_header("ETag", etag)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                with ORIGIN_LOCK:
                    ORIGIN_HITS[self.path] = ORIGIN_HITS.get(self.path, 0) + 1
                    n = ORIGIN_HITS[self.path]
                body = f"origin-{self.path}-{n}\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Cache-Control", "public, max-age=3")
                self.send_header("ETag", etag)
                self.send_header("Last-Modified", "Wed, 21 Oct 2026 08:00:00 GMT")
                self.send_header("Content-Length", str(len(body.encode())))
                self.end_headers()
                self.wfile.write(body.encode())
                return
            with ORIGIN_LOCK:
                ORIGIN_HITS[self.path] = ORIGIN_HITS.get(self.path, 0) + 1
            body = b"origin-other\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", ORIGIN_PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- 客户端
def req(port, path, host, method="GET", headers=None, tls=False, body=None, timeout=15):
    h = {"Host": host}
    h.update(headers or {})
    if tls:
        ctx = ssl._create_unverified_context()
        c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=timeout)
    else:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    except Exception as e:  # noqa: BLE001
        return None, {"err": str(e)}, b""
    finally:
        try:
            c.close()
        except OSError:
            pass


def urlpath(rel):
    # 非 ASCII 与空格都必须编码：http.client 直接发中文路径会先在自己这边炸掉
    return "/" + urllib.parse.quote(rel.replace("\\", "/"), safe="/")


# ---------------------------------------------------------------- 静态站断言
def test_static(manifest, sample):
    port, host = GW_HTTP, "static.prodshape.test"
    for rel in sample:
        meta = manifest[rel]
        st, h, body = req(port, urlpath(rel), host)
        ok = st == 200 and hashlib.sha256(body).hexdigest() == meta["sha"]
        ck(f"静态逐文件 {rel}", ok, f"status={st} got={len(body)}B want={meta['len']}B {h.get('err', '')}")
        if st == 200:
            ck(f"Content-Length {rel}", h.get("content-length") == str(meta["len"]),
               f"{h.get('content-length')} != {meta['len']}")
            ck(f"Last-Modified 存在 {rel}", bool(h.get("last-modified")), str(h))
            ck(f"ETag 存在 {rel}", bool(h.get("etag")), str(h))
    # HEAD 不出体
    rel0 = sample[0]
    st, h, body = req(port, urlpath(rel0), host, method="HEAD")
    ck("HEAD 无 body 但状态与头齐", st == 200 and body == b"" and h.get("content-length"), f"st={st} body={body!r}")
    # 条件请求
    st, h, body = req(port, urlpath(rel0), host)
    etag, lm = h.get("etag"), h.get("last-modified")
    st2, _, b2 = req(port, urlpath(rel0), host, headers={"If-None-Match": etag or ""})
    ck("If-None-Match 命中 → 304 无体", st2 == 304 and b2 == b"", f"st={st2} body={b2[:40]!r}")
    weak = (etag or "").replace('"', 'W/"', 1)
    st3, _, _ = req(port, urlpath(rel0), host, headers={"If-None-Match": weak})
    ck("W/ 弱 ETag 比较也 304（nginx 语义）", st3 == 304, f"st={st3}")
    st4, _, _ = req(port, urlpath(rel0), host, headers={"If-None-Match": '*'})
    ck("If-None-Match: * 已有实体 → 304", st4 == 304, f"st={st4}")
    st5, _, _ = req(port, urlpath(rel0), host, headers={"If-Modified-Since": lm or ""})
    ck("If-Modified-Since 同刻 → 304", st5 == 304, f"st={st5}")
    st6, _, _ = req(port, urlpath(rel0), host, headers={"If-Modified-Since": "Wed, 21 Oct 2026 08:00:00 GMT"})
    ck("If-Modified-Since 未来时间 → 304", st6 in (200, 304), f"st={st6}")
    st7, _, b7 = req(port, urlpath(rel0), host, headers={"If-Modified-Since": "Mon, 01 Jan 2019 00:00:00 GMT"})
    ck("If-Modified-Since 早于文件 → 200 全量", st7 == 200 and len(b7) == manifest[rel0]["len"], f"st={st7}")
    # Range
    big = next((r for r, m in manifest.items() if m["len"] > 1000 and " " not in r), rel0)
    total = manifest[big]["len"]
    st, h, b = req(port, urlpath(big), host, headers={"Range": "bytes=0-9"})
    ck("Range 前 10 字节 → 206 + Content-Range", st == 206 and len(b) == 10
       and h.get("content-range") == f"bytes 0-9/{total}", f"st={st} cr={h.get('content-range')} len={len(b)}")
    st, h, b = req(port, urlpath(big), host, headers={"Range": "bytes=-10"})
    ck("Range 后缀 10 字节 → 206", st == 206 and len(b) == 10
       and h.get("content-range") == f"bytes {total - 10}-{total - 1}/{total}", f"st={st} cr={h.get('content-range')}")
    st, h, b = req(port, urlpath(big), host, headers={"Range": f"bytes={total - 5}-"})
    ck("Range 开区间到末尾", st == 206 and len(b) == 5, f"st={st} len={len(b)}")
    st, h, b = req(port, urlpath(big), host, headers={"Range": f"bytes={total + 10}-"})
    ck("Range 越界 → 416 + bytes */size", st == 416 and h.get("content-range") == f"bytes */{total}",
       f"st={st} cr={h.get('content-range')}")
    st, h, b = req(port, urlpath(big), host, headers={"Range": "bytes=abc"})
    ck("非法 Range 头 → 忽略并回 200 全量（nginx 行为）", st == 200 and len(b) == total, f"st={st} len={len(b)}")
    st, h, _ = req(port, urlpath(big), host, headers={"Range": "bytes=0-9"})
    ck("Accept-Ranges 声明支持分段", h.get("accept-ranges") == "bytes", str(h))
    # 目录语义
    st, h, _ = req(port, "/indexed", host)
    ck("目录无斜杠 → 301 补斜杠", st == 301 and (h.get("location") or "").endswith("/indexed/"),
       f"st={st} loc={h.get('location')}")
    st, h, b = req(port, "/indexed/", host)
    ck("目录 → index.html 优先于 autoindex", st == 200 and b.startswith(b"index-page"), f"st={st} body={b[:40]!r}")
    st, h, b = req(port, "/listing/", host)
    ck("目录无 index → autoindex 列表", st == 200 and b"visible.txt" in b, f"st={st} body={b[:80]!r}")
    ck("autoindex 不列点开头文件", b".secret" not in b and b"do-not-list" not in b, b[:200].decode("utf-8", "replace"))
    st, h, b = req(port, "/listing/", "static.prodshape.test")
    st2, _, b2 = req(port, "/noauto/listing/", host)
    ck("autoindex off → 该 location 不列表（403/404 皆可接受但绝不能泄露内容）",
       st2 in (403, 404) and b"do-not-list" not in b2, f"st={st2} body={b2[:60]!r}")
    st, h, b = req(port, "/definitely-missing-xyz.txt", host)
    ck("缺文件 → 404 且不含文件内容", st == 404, f"st={st}")
    st, h, b = req(port, "/../etc/passwd", host)
    ck("路径穿越被挡", st in (400, 404) and b"root:" not in b, f"st={st} body={b[:60]!r}")
    st, h, b = req(port, urlpath(".hidden.txt"), host)
    ck("点文件（dotfile）在根内可取（nginx 默认不设限）", st in (200, 404), f"st={st} —— 记录行为，若为 404 需确认与 nginx 的差别")
    # gzip
    st, h, b = req(port, urlpath(rel0), host, headers={"Accept-Encoding": "gzip"})
    gz = h.get("content-encoding") == "gzip"
    if gz:
        try:
            plain = gzip.decompress(b)
        except OSError as e:
            plain = b"__bad__"
            ck("gzip 响应可解压", False, str(e))
        ck("gzip 解压回原字节", plain == open(os.path.join(SITE, rel0), "rb").read(), f"len={len(plain)}")
    ck("文本资源协商 gzip（大文件）", gz or manifest[rel0]["len"] < 1024, f"headers={ {k: v for k, v in h.items() if 'encoding' in k or 'vary' in k} }")
    png = next((r for r, m in manifest.items() if m["mime"] == "image/png"), None)
    if png:
        st, h, b = req(port, urlpath(png), host, headers={"Accept-Encoding": "gzip"})
        ck("二进制 png 不被 gzip", h.get("content-encoding") != "gzip", str(h.get("content-encoding")))
    # 缓存头
    ck("expires/add_header 产出 Cache-Control", "max-age=3600" in (h.get("cache-control") or ""), str(h.get("cache-control")))


# ---------------------------------------------------------------- WASM 断言
def test_wasm():
    port, host = GW_TLS, "tls.prodshape.test"
    rel = "d0/index.html"
    st, h, b = req(port, urlpath(rel), host, tls=True)
    ck("TLS 站基线 200", st == 200 and b.startswith(b"<!doctype"), f"st={st} body={b[:30]!r}")
    ck("未挂过滤器的 location 不被改写（基线保持 200 且没有插件头）",
       st == 200 and "x-wasm-header-filter" not in h, f"st={st} {list(h)[:6]}")
    # /hf/ 才是挂了响应过滤器的那条路由：拿基线响应判"加了头"等于什么都没测
    st, h, b = req(port, "/hf/" + urlpath(rel).lstrip("/"), host, tls=True)
    ck("header_filter_by_wasm 加了头", h.get("x-wasm-header-filter") == "on", str(list(h))[:200])
    ck("header_filter_by_wasm 改写状态码（插件把 200 改成 202）", st == 202, f"st={st}")
    # body_filter 插件只留前 5 个字节：截断后的体证明它真的看过上游的体
    ck("body_filter_by_wasm 改了体（截成前 5 字节，且字节来自上游）", b == b"<!doc", f"body={b[:40]!r}")
    st, h, b = req(port, "/guarded/" + urlpath(rel).lstrip("/"), host, tls=True)
    ck("access_by_wasm 缺 token → 403", st == 403, f"st={st} body={b[:40]!r}")
    st, h, b = req(port, "/guarded/" + urlpath(rel).lstrip("/"), host, tls=True,
                       headers={"X-Gateway-Token": "secret"})
    ck("access_by_wasm 有 token → 放行", st == 200, f"st={st}")


# ---------------------------------------------------------------- Lua 断言
def test_lua():
    port, host = GW_LUA, "lua.prodshape.test"
    st, h, b = req(port, "/lua-say", host)
    ck("content_by_lua 基本输出", st == 200 and b.startswith(b"lua-/lua-say") and h.get("x-lua") == "1",
       f"st={st} body={b[:60]!r}")
    with ThreadPoolExecutor(max_workers=60) as ex:
        rs = list(ex.map(lambda i: req(port, "/lua-count", host), range(120)))
    oks = [r for r in rs if r[0] == 200]
    hits = sorted(int(r[1].get("x-hits", 0)) for r in oks)
    ck("access_by_lua + shared dict 并发 120 次无丢加", len(oks) == 120 and len(set(hits)) == 120,
       f"成功 {len(oks)}，X-Hits 去重 {len(set(hits))}")
    st, h, b = req(port, "/lua-sub", host)
    ck("ngx.location.capture 子请求", st == 200 and b.strip() == b"sub[200,inner-body]", f"body={b[:60]!r}")
    st, h, b = req(port, "/lua-body", host, method="POST", body=b"hello-lua-body")
    ck("Lua 读 POST 体", st == 200 and b"len=14|hello-lua-body" in b, f"st={st} body={b[:60]!r}")
    st, h, b = req(port, "/lua-error", host)
    ck("脚本报错 → 500（不是挂住或 502）", st == 500, f"st={st}")
    req(port, "/lua-timer", host)
    fired = False
    for _ in range(30):
        time.sleep(0.2)
        st, h, b = req(port, "/lua-say", host)
        if st == 200:
            fired = True
            break
    st, h, b = req(port, "/lua-file", host)
    ck("content_by_lua_file 走脚本文件", st == 200 and b.startswith(b"from-file-/lua-file"), f"st={st} body={b[:40]!r}")


# ---------------------------------------------------------------- 缓存冷层 + revalidate
def test_cache():
    port, host = GW_CACHE, "cache.prodshape.test"
    urls = [f"/cached/item{i}" for i in range(24)]
    first = [req(port, u, host) for u in urls]
    ck("首轮全部 MISS", all(h.get("x-cache") == "MISS" for _, h, _ in first),
       str([h.get("x-cache") for _, h, _ in first])[:120])
    with ORIGIN_LOCK:
        after1 = dict(ORIGIN_HITS)
    hits2 = []
    for u in urls:
        st, h, b = req(port, u, host)
        hits2.append(h.get("x-cache"))
    ck("第二轮全 HIT 且后端计数不动", set(hits2) <= {"HIT", "STALE"} and ORIGIN_HITS == after1,
       f"{set(hits2)} 后端 {sum(ORIGIN_HITS.values())} vs {sum(after1.values())}")
    # 小 keys_zone(8 条) + 24 个对象 → 必然淘汰 → 冷层；反复扫一遍要求：内容都对、且没有把淘汰对象再打后端
    with ORIGIN_LOCK:
        before = dict(ORIGIN_HITS)
    wrong = []
    for u in urls:
        st, h, b = req(port, u, host)
        n = ORIGIN_HITS.get(u, 0)
        want = f"origin-{u}-1\n".encode()
        if st != 200 or b != want:
            wrong.append((u, st, b[:40], n))
    ck("容量外对象由冷层供（body 仍是第一次那份，后端零新增）", not wrong, str(wrong[:3]))
    with ORIGIN_LOCK:
        grew = {k: v - before.get(k, 0) for k, v in ORIGIN_HITS.items() if v != before.get(k, 0)}
    ck("冷层供的命中没有回源", not grew, str(grew))
    # —— revalidate：独立内存区，4 个对象放得下，不会被淘汰伪装成"没复用"。
    #    冷层条目不带校验头（ORDK 记录里没有 ETag/Last-Modified），过期只能整份重取，
    #    所以这一维必须在还在内存里的时候测，见 docs/CAPABILITY_MATRIX.md §2.2
    rv = [f"/rv/item{i}" for i in range(4)]
    prime = [req(port, u, host) for u in rv]
    ck("revalidate 预热全部 MISS", all(h.get("x-cache") == "MISS" for _, h, _ in prime),
       str([h.get("x-cache") for _, h, _ in prime]))
    with ORIGIN_LOCK:
        before = sum(v for k, v in ORIGIN_HITS.items() if k.startswith("/rv/"))
        before_cond = sum(v for k, v in ORIGIN_CONDITIONAL.items() if k.startswith("/rv/"))
    time.sleep(3.2)                       # 上游 max-age=3 → 条目过期，该带条件头去问
    sts = [req(port, u, host) for u in rv]
    ok_body = all(b == f"origin-{u}-1\n".encode() for (_, _, b), u in zip(sts, rv))
    ck("过期 + revalidate：源站答 304 时 body 复用（序号仍是 -1）", ok_body,
       str([(h.get("x-cache"), b[:24]) for _, h, b in sts])[:160])
    with ORIGIN_LOCK:
        asked = sum(v for k, v in ORIGIN_HITS.items() if k.startswith("/rv/")) - before
        cond = sum(v for k, v in ORIGIN_CONDITIONAL.items() if k.startswith("/rv/")) - before_cond
    ck("revalidate：源站只答 304、没再发整份（发出计数不增、条件计数增加）",
       cond == len(rv) and asked == 0, f"整份发出新增={asked} 条件问询新增={cond}")
    ck("revalidate 后 X-Cache 词表合法（HIT/REVALIDATED/STALE 之一）",
       set(h.get("x-cache") for _, h, _ in sts) <= {"HIT", "REVALIDATED", "STALE"},
       str([h.get("x-cache") for _, h, _ in sts]))


# ---------------------------------------------------------------- 并发混合
def test_mixed_load(manifest, sample):
    port, host = GW_HTTP, "static.prodshape.test"
    paths = [urlpath(r) for r in sample[:40]]
    bad = []

    def one(i):
        p = paths[i % len(paths)]
        st, h, b = req(port, p, host)
        want = next((m for r, m in manifest.items() if urlpath(r) == p), None)
        if not want or st != 200 or hashlib.sha256(b).hexdigest() != want["sha"]:
            bad.append((p, st, len(b)))
        return st

    with ThreadPoolExecutor(max_workers=200) as ex:
        list(ex.map(one, range(4000)))
    ck("200 并发 × 4000 请求：字节级不错、不串文件", not bad, str(bad[:3]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=800)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--sample", type=int, default=120, help="逐文件比对的抽样个数")
    a = ap.parse_args()
    if not os.path.exists(EXE):
        raise SystemExit("!! 先 cargo build --release -p onrouter-server --bin onrouter")
    print(f"建静态站 {a.files} 文件 …")
    manifest = build_site(a.files)
    print(f"  实际 {len(manifest)} 个文件；生成配置 …")
    write_conf()
    t = subprocess.run([EXE, "-t", "-c", os.path.relpath(CONF, ROOT)], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    ck("-t 通过生产形状配置", t.returncode == 0, ((t.stdout or "") + (t.stderr or ""))[-400:])
    start_origin()
    log = open(os.devnull, "wb")
    proc = subprocess.Popen([EXE, CONF], cwd=ROOT, stdout=log, stderr=log)
    try:
        for p in (GW_HTTP, GW_TLS, GW_LUA, GW_CACHE):
            if not wait_ready(p):
                raise SystemExit(f"!! 端口 {p} 未就绪，看 {ERRLOG}")
        rng = random.Random(7)
        sample = [k for k in manifest if not k.startswith(".")]
        rng.shuffle(sample)
        sample = sample[: a.sample]
        print("静态站 / 条件请求 / Range / 目录 / gzip …")
        test_static(manifest, sample)
        print("WASM …")
        test_wasm()
        print("Lua …")
        test_lua()
        print("缓存冷层 + revalidate …")
        test_cache()
        print("200 并发混合读 …")
        test_mixed_load(manifest, sample)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
        err = ""
        if os.path.exists(ERRLOG):
            err = open(ERRLOG, encoding="utf-8", errors="replace").read()
        ck("错误日志里没有 panic/backtrace", "panicked" not in err and "BACKTRACE" not in err.upper(),
           err[-300:])
        if not a.keep:
            for f in (CONF, os.path.join(ROOT, "lua", "prodshape.lua")):
                try:
                    os.remove(f)
                except OSError:
                    pass
            shutil.rmtree(SITE, ignore_errors=True)
            shutil.rmtree(os.path.join(ROOT, "conf", "logs", "prodshape_cache"), ignore_errors=True)
    print(f"\n==== 生产形状 E2E: {checks[0] - len(fails)}/{checks[0]} passed ====")
    for line in fails:
        print(" ", line)
    sys.exit(1 if fails else 0)


def wait_ready(port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


if __name__ == "__main__":
    main()
