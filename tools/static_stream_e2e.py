# -*- coding: utf-8 -*-
# 大静态文件流式 E2E —— 用真实流量证明超过 1MB 缓存阈值的文件按需从磁盘分块读出：
#   * 128MB 文件整份 GET / Range / 后缀 Range / HEAD / ETag 304 字节级正确；
#   * 客户端故意不读、让写缓冲填满时，服务端 RSS 不随文件大小增长
#     （改造前 std::fs::read 会把整份 128MB 装进响应体，RSS 至少 +128MB）；
#   * 大文件 + sub_filter 只在 MIME 命中时整份缓冲并改写；Range 切片不改写。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/static_stream_e2e.py
import ctypes
import ctypes.wintypes
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "static_stream_e2e.conf")
WEBROOT = os.path.join(ROOT, "public_static_stream_e2e")
HOST, PORT = "127.0.0.1", 18192
BASE = f"http://{HOST}:{PORT}"

BIG_SIZE = 128 * 1024 * 1024
HTML_SIZE = 2 * 1024 * 1024
RSS_LIMIT = 48 * 1024 * 1024  # 增量上限：远小于 128MB，旧实现必然超过

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


# ---------- 进程 RSS（活动工作集）----------
class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("PageFaultCount", ctypes.wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def proc_rss(pid):
    if sys.platform == "win32":
        # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        handle = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            return 0
        try:
            c = _ProcessMemoryCounters()
            c.cb = ctypes.sizeof(c)
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(c), ctypes.sizeof(c)
            )
            return int(c.WorkingSetSize) if ok else 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


# ---------- HTTP ----------
def fetch(path, method="GET", headers=None):
    """流式读取响应，返回 (状态码, 响应头, 字节数, sha256, 首字节)。"""
    req = urllib.request.Request(BASE + path, method=method, headers=headers or {})
    t0 = time.time()
    try:
        resp = _opener.open(req, timeout=120)
        h = hashlib.sha256()
        n = 0
        first = b""
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            if not first:
                first = chunk[:64]
            h.update(chunk)
            n += len(chunk)
        return resp.status, resp.headers, n, h.hexdigest(), first, time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.headers, 0, "", b"", time.time() - t0


def sha_slice(path, start, end):
    """[start, end] 闭区间的 sha256 与长度。"""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        f.seek(start)
        left = end - start + 1
        while left > 0:
            b = f.read(min(1 << 20, left))
            if not b:
                break
            h.update(b)
            n += len(b)
            left -= len(b)
    return h.hexdigest(), n


def build_files():
    os.makedirs(WEBROOT, exist_ok=True)
    big = os.path.join(WEBROOT, "big.bin")

    h = hashlib.sha256()
    pattern = bytes(range(256)) * 256  # 64KB 周期
    written = 0
    with open(big, "wb") as f:
        while written < BIG_SIZE:
            chunk = pattern[: min(len(pattern), BIG_SIZE - written)]
            f.write(chunk)
            h.update(chunk)
            written += len(chunk)
    big_hash = h.hexdigest()

    # 2MB 文本（超过缓存阈值 → 走磁盘 + sub_filter 整份缓冲）
    line = b"STATIC_TOKEN " + b"a" * 1000 + b"\n"
    raw = bytearray()
    while len(raw) < HTML_SIZE:
        raw.extend(line)
    del raw[HTML_SIZE:]
    with open(os.path.join(WEBROOT, "big.html"), "wb") as f:
        f.write(raw)
    expected = bytes(raw).replace(b"STATIC_TOKEN", b"S_DONE")

    with open(os.path.join(WEBROOT, "small.txt"), "wb") as f:
        f.write(b"small-cached-file")
    return big_hash, hashlib.sha256(expected).hexdigest(), len(expected)


def wait_ready():
    for _ in range(100):
        try:
            st, _, _, _, _, _ = fetch("/small.txt")
            if st == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def pause_download_peak_rss(pid, path, read_bytes=256 * 1024):
    """发 GET 读一小段后故意不读，服务端写缓冲会填满；此时采样 RSS。"""
    s = socket.create_connection((HOST, PORT), timeout=10)
    try:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: static-stream.local\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return 0, b""
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        got = len(rest)
        while got < read_bytes:
            chunk = s.recv(64 * 1024)
            if not chunk:
                break
            got += len(chunk)
        time.sleep(0.8)  # 让写路径完全阻塞在客户端不读的状态
        peak = max(proc_rss(pid) for _ in range(5))
        return peak, head
    finally:
        s.close()


def main():
    big_hash, filtered_hash, filtered_len = build_files()
    big_path = os.path.join(WEBROOT, "big.bin")
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "static_stream_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter 未就绪（端口 18192 被占用？看 logs/static_stream_out.log）")

        # 1) 整份大文件：字节数与哈希必须与磁盘完全一致
        st, hdrs, n, sha, _, el = fetch("/big.bin")
        check("/big.bin 200 + 字节数一致", st == 200 and n == BIG_SIZE, f"st={st} n={n}")
        check("/big.bin sha256 一致", sha == big_hash, f"sha={sha[:16]}…")
        check("/big.bin Content-Length 显式且正确",
              hdrs.get("content-length") == str(BIG_SIZE), f"cl={hdrs.get('content-length')}")
        check("/big.bin 定长分帧（非 chunked）",
              hdrs.get("transfer-encoding") is None, f"te={hdrs.get('transfer-encoding')}")
        print(f"   (整份 {BIG_SIZE // (1024 * 1024)}MB 耗时 {el:.2f}s)")

        # 2) 大文件 Range（跨过 1MB 缓存线）+ 后缀 Range
        start, end = 64 * 1024 * 1024, 64 * 1024 * 1024 + 65535
        want_sha, want_n = sha_slice(big_path, start, end)
        st, hdrs, n, sha, _, _ = fetch("/big.bin", headers={"Range": f"bytes={start}-{end}"})
        check("大文件 Range 206", st == 206, f"st={st}")
        check("大文件 Range Content-Range 正确",
              hdrs.get("content-range") == f"bytes {start}-{end}/{BIG_SIZE}",
              f"cr={hdrs.get('content-range')}")
        check("大文件 Range 字节一致", n == want_n and sha == want_sha, f"n={n}")

        tail_start = BIG_SIZE - 1024
        tail_sha, tail_n = sha_slice(big_path, tail_start, BIG_SIZE - 1)
        st, hdrs, n, sha, _, _ = fetch("/big.bin", headers={"Range": "bytes=-1024"})
        check("大文件后缀 Range 206 且末段一致",
              st == 206 and n == tail_n and sha == tail_sha,
              f"st={st} n={n} cr={hdrs.get('content-range')}")

        # 3) HEAD：只回头部，大文件不打开/不发送体
        st, hdrs, n, _, _, _ = fetch("/big.bin", method="HEAD")
        check("HEAD 大文件 200 + 空体 + Content-Length 正确",
              st == 200 and n == 0 and hdrs.get("content-length") == str(BIG_SIZE),
              f"st={st} n={n} cl={hdrs.get('content-length')}")

        # 4) ETag 304：校验位来自 (mtime,size)，无需读文件
        st, hdrs, n, _, _, _ = fetch("/big.bin")
        etag = hdrs.get("etag")
        st, hdrs, n, _, _, _ = fetch("/big.bin", headers={"If-None-Match": etag or ""})
        check("大文件 ETag 命中 304 + 空体", st == 304 and n == 0, f"st={st} n={n} etag={etag}")

        # 5) 越界 Range → 416
        st, hdrs, n, _, _, _ = fetch("/big.bin", headers={"Range": f"bytes={BIG_SIZE}-"})
        check("大文件越界 Range 416 + bytes */size",
              st == 416 and hdrs.get("content-range") == f"bytes */{BIG_SIZE}",
              f"st={st} cr={hdrs.get('content-range')}")

        # 6) 大文件 + sub_filter：整份缓冲改写，长度与哈希都按替换后计算
        st, hdrs, n, sha, first, _ = fetch("/filtered/big.html")
        check("大文件 sub_filter 200", st == 200, f"st={st}")
        check("大文件 sub_filter 全部替换且字节一致",
              n == filtered_len and sha == filtered_hash and first.startswith(b"S_DONE "),
              f"n={n} first={first[:16]!r}")
        check("大文件 sub_filter Content-Length = 改写后长度",
              hdrs.get("content-length") == str(filtered_len),
              f"cl={hdrs.get('content-length')}")

        # 7) Range 命中 sub_filter location 时仍返回原始切片（nginx 语义）
        st, hdrs, n, _, first, _ = fetch("/filtered/big.html", headers={"Range": "bytes=0-11"})
        check("sub_filter 大文件 Range 不改写",
              st == 206 and n == 12 and first == b"STATIC_TOKEN",
              f"st={st} n={n} first={first!r}")

        # 8) 内存：客户端暂停读取时，服务端 RSS 增量必须远小于文件大小
        base_rss = proc_rss(proc.pid)
        peak, head = pause_download_peak_rss(proc.pid, "/big.bin")
        check("暂停下载时响应头已返回 200 + CL",
              head.startswith(b"HTTP/1.1 200") and b"content-length: 134217728" in head.lower(),
              f"head={head[:120]!r}")
        delta = peak - base_rss
        check(
            f"暂停下载时 RSS 增量 < {RSS_LIMIT // (1024 * 1024)}MB（不整份驻留）",
            base_rss > 0 and peak > 0 and delta < RSS_LIMIT,
            f"base={base_rss / 1048576:.1f}MB peak={peak / 1048576:.1f}MB delta={delta / 1048576:.1f}MB",
        )
        print(
            f"   (RSS base={base_rss / 1048576:.1f}MB peak={peak / 1048576:.1f}MB "
            f"delta={delta / 1048576:.1f}MB，文件 {BIG_SIZE // (1024 * 1024)}MB)"
        )

        # 9) 小文件缓存路径仍正常（Bytes 缓存不回退）
        for i in range(2):
            st, _, n, _, first, _ = fetch("/small.txt")
            check(f"小文件第 {i + 1} 次读取正常", st == 200 and n == 17 and first == b"small-cached-file",
                  f"st={st} n={n} first={first!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        if os.environ.get("KEEP_WEBROOT") != "1":
            shutil.rmtree(WEBROOT, ignore_errors=True)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== static stream E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
