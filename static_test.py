# -*- coding: utf-8 -*-
"""静态文件语义端到端验证：ETag/Last-Modified → 304、Range → 206/416、隐藏文件策略。

用裸 socket 而不是 urllib：条件请求与部分内容的响应必须逐字节核对（304 不能带 body，
206 的 Content-Range 与真实字节要一致），高层客户端会把这些细节抹平。
"""
import os
import socket
import subprocess
import sys
import time

ROOT = r"C:\Users\User\Desktop\LearnON"
CONF = os.path.join(ROOT, "conf", "smoke_static.conf")
HOST, PORT, SERVER_NAME = "127.0.0.1", 18093, "static.local"
BIG = bytes(range(256)) * 8  # 与 public_static/big.txt 的生成方式一致

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def http(method, path, headers=None):
    s = socket.create_connection((HOST, PORT), timeout=5)
    try:
        raw = f"{method} {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n"
        for k, v in (headers or {}).items():
            raw += f"{k}: {v}\r\n"
        s.sendall((raw + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    hdrs = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, body


def main():
    exe = "onrouter.exe" if os.name == "nt" else "onrouter"
    binary = os.path.join(ROOT, "target", "debug", exe)
    if not os.path.exists(binary):
        binary = os.path.join(ROOT, "target", "release", exe)
    gw = subprocess.Popen([binary, CONF], cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                http("GET", "/index.html")
                break
            except OSError:
                time.sleep(0.2)

        st, h, b = http("GET", "/big.txt")
        check("200 带 ETag/Last-Modified/Accept-Ranges",
              st == 200 and h.get("etag", "").startswith('"') and h.get("last-modified", "").endswith("GMT")
              and h.get("accept-ranges") == "bytes", f"{st} {h}")
        check("200 全量体与长度", st == 200 and b == BIG and h.get("content-length") == str(len(BIG)),
              f"{st} {len(b)}")
        check("静态响应也吃 add_header", h.get("x-static-added") == "yes", str(h))
        etag, lm = h["etag"], h["last-modified"]

        st, h, b = http("GET", "/big.txt", {"If-None-Match": etag})
        check("If-None-Match 命中 304", st == 304 and b == b"", f"{st} {len(b)}")
        check("304 回显 ETag 且无 body 头",
              h.get("etag") == etag and "content-length" not in h and "content-type" not in h, str(h))
        st, _, b = http("GET", "/big.txt", {"If-None-Match": '"deadbeef-0"'})
        check("ETag 不匹配照常 200", st == 200 and b == BIG, f"{st} {len(b)}")
        st, _, _ = http("GET", "/big.txt", {"If-None-Match": f'W/{etag}, "x"'})
        check("弱校验位与多值列表算命中", st == 304, f"{st}")

        st, _, _ = http("GET", "/big.txt", {"If-Modified-Since": "Mon, 01 Jan 2035 00:00:00 GMT"})
        check("If-Modified-Since 未来时间 → 304", st == 304, f"{st}")
        st, _, _ = http("GET", "/big.txt", {"If-Modified-Since": "Sun, 06 Nov 1994 08:49:37 GMT"})
        check("If-Modified-Since 过去时间 → 200", st == 200, f"{st}")
        st, _, _ = http("GET", "/big.txt", {"If-Modified-Since": "not a date"})
        check("非法日期不误判 304", st == 200, f"{st}")
        st, _, _ = http("GET", "/big.txt", {"If-None-Match": '"stale"', "If-Modified-Since": lm})
        check("ETag 与 IMS 同时存在时 ETag 优先", st == 200, f"{st}")

        st, h, b = http("GET", "/big.txt", {"Range": "bytes=0-99"})
        check("Range 首段 → 206", st == 206 and b == BIG[:100]
              and h.get("content-range") == f"bytes 0-99/{len(BIG)}"
              and h.get("content-length") == "100", f"{st} {h} {len(b)}")
        st, h, b = http("GET", "/big.txt", {"Range": f"bytes={len(BIG) - 100}-"})
        check("Range 开区间 → 206", st == 206 and b == BIG[-100:]
              and h.get("content-range") == f"bytes {len(BIG) - 100}-{len(BIG) - 1}/{len(BIG)}", f"{st} {h}")
        st, h, b = http("GET", "/big.txt", {"Range": "bytes=-64"})
        check("Range 后缀长度 → 206", st == 206 and b == BIG[-64:]
              and h.get("content-range") == f"bytes {len(BIG) - 64}-{len(BIG) - 1}/{len(BIG)}", f"{st} {h}")
        st, h, b = http("GET", "/big.txt", {"Range": "bytes=1000-999999"})
        check("结束值越界截到文件尾", st == 206 and b == BIG[1000:]
              and h.get("content-range") == f"bytes 1000-{len(BIG) - 1}/{len(BIG)}", f"{st} {h}")
        st, h, b = http("GET", "/big.txt", {"Range": f"bytes={len(BIG) + 5}-"})
        check("起点越界 → 416", st == 416 and b == b""
              and h.get("content-range") == f"bytes */{len(BIG)}", f"{st} {h}")
        st, h, b = http("GET", "/big.txt", {"Range": "bytes=0-1,5-6"})
        check("多段 Range 忽略，回整份 200", st == 200 and b == BIG, f"{st} {len(b)}")
        st, h, b = http("GET", "/big.txt", {"Range": "bytes=abc-def"})
        check("非法 Range 语法忽略", st == 200 and b == BIG, f"{st} {len(b)}")

        st, h, b = http("GET", "/big.txt", {"Range": "bytes=0-9", "If-Range": '"old-etag"'})
        check("If-Range 不匹配 → 整份 200", st == 200 and b == BIG, f"{st} {len(b)}")
        st, h, b = http("GET", "/big.txt", {"Range": "bytes=0-9", "If-Range": etag})
        check("If-Range 匹配 → 206", st == 206 and b == BIG[:10], f"{st} {len(b)}")

        st, h, b = http("HEAD", "/big.txt")
        check("HEAD 只回头不给体", st == 200 and b == b"" and h.get("content-length") == str(len(BIG)),
              f"{st} {h}")
        st, _, _ = http("HEAD", "/big.txt", {"If-None-Match": etag})
        check("HEAD + If-None-Match → 304", st == 304, f"{st}")

        for p in ["/.env", "/.hidden/config", "/.hidden/config", "/docs/../.env"]:
            st, _, b = http("GET", p)
            check(f"隐藏文件不放行 {p}", st == 404 and b"should-never" not in b and b"leak" not in b, f"{st}")
        st, _, b = http("GET", "/.well-known/probe.txt")
        check(".well-known 放行（ACME 需要）", st == 200 and b.strip() == b"acme-ok", f"{st} {b[:40]}")
        st, _, b = http("GET", "/backup.txt.bak")
        check("尾巴带点号的普通文件不受影响", st == 200, f"{st}")

        st, h, b = http("GET", "/docs/")
        check("autoindex 列表不泄露点文件，动态页无 ETag",
              st == 200 and b"note.txt" in b and b".env" not in b and "etag" not in h, f"{st} {h}")
        st, _, b = http("GET", "/")
        check("目录走 index 指令", st == 200 and b"static-root" in b, f"{st} {b[:60]}")

    finally:
        gw.kill()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n=== {passed}/{len(results)} 通过 ===")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
