# -*- coding: utf-8 -*-
"""ONRouter nginx 语法兼容性测试：拉起网关（conf/compat_nginx.conf），验证新指令行为。"""
import subprocess, sys, time, os
import urllib.request, urllib.error

RUST = os.path.dirname(os.path.abspath(__file__))  # 仓库根：脚本与 conf/、target/ 同级
BASE = "http://127.0.0.1:8090"

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

_opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))

def req(method, path, headers=None, data=None, timeout=10, host=None):
    h = dict(headers or {})
    if host: h["Host"] = host
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        resp = _opener.open(r, timeout=timeout)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, detail if not ok else "")

def main():
    exe = os.path.join(RUST, "target", "release", "onrouter.exe")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "compat_nginx.conf")],
                          cwd=RUST, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try: req("GET", "/exact"); break
            except Exception: time.sleep(0.2)

        # 1. 精确匹配 + return URL 简写
        st, b = req("GET", "/exact")
        check("return 200 精确", st == 200 and b == b"exact", f"{st} {b[:60]}")
        st, b = req("GET", "/r302")
        check("return <URL> 302", st == 302, f"{st} {b[:60]}")

        # 2. location 匹配算法
        st, b = req("GET", "/photo.PNG")           # ~* 大小写不敏感
        check("~* 大小写不敏感", st == 200 and b == b"regex-i", f"{st} {b[:60]}")
        st, b = req("GET", "/regexfoo")            # ~ 普通正则
        check("~ 正则命中", st == 200 and b == b"regex", f"{st} {b[:60]}")
        st, b = req("GET", "/caretprefix/x")       # ^~ 赢过 ~ ^/care
        check("^~ 前缀赢过正则", st == 200 and b == b"caret", f"{st} {b[:60]}")

        # 3. server_name 通配符 + 多 server
        st, b = req("GET", "/nonexistent-page")    # 默认 server：无 Host 匹配 → 第一个 → 404 自定义页
        check("默认 server 兜底+error_page", st == 404 and b"custom-404" in b, f"{st} {b[:80]}")
        st, b = req("GET", "/", host="foo.wild.test")
        check("server_name 通配符路由到主 server", st in (200, 403), f"{st}")
        st, b = req("GET", "/x", host="other.site")
        check("server_name 精确二选一", st == 200 and b == b"other-site", f"{st} {b[:60]}")

        # 4. try_files
        st, b = req("GET", "/files/a.txt")
        check("try_files 文件命中", st == 200 and b == b"file-a\n", f"{st} {b[:60]}")
        st, b = req("GET", "/files/missing")
        check("try_files 兜底内部重定向", st == 200 and b"fallback" in b, f"{st} {b[:80]}")

        # 5. autoindex
        st, b = req("GET", "/docs/")
        check("autoindex 目录列表", st == 200 and b"Index of /docs/" in b and b"note.txt" in b, f"{st} {b[:120]}")

        # 6. alias
        st, b = req("GET", "/up/index.html")
        check("alias 映射", st == 200 and b"ONRouter" in b, f"{st} {b[:60]}")

        # 7. index 多值（/home/ 下只有 index.htm）
        st, b = req("GET", "/home/")
        check("index 多值", st == 200 and b"htm-index" in b, f"{st} {b[:60]}")

        # 8. error_page
        st, b = req("GET", "/nonexistent-page2")
        check("error_page 404", st == 404 and b"custom-404" in b, f"{st} {b[:80]}")

        # 9. client_max_body_size 413
        st, b = req("POST", "/exact", data=b"x" * 4096)
        check("client_max_body_size 413", st == 413, f"{st} {b[:80]}")
        st, b = req("POST", "/exact", data=b"ok")
        check("小请求体正常", st == 200, f"{st} {b[:60]}")

        # 10. 目录 301 补斜杠（nginx 行为）
        st, b = req("GET", "/docs")
        check("目录 301 补斜杠", st == 301, f"{st} {b[:60]}")

    finally:
        gw.kill()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n=== {passed}/{len(results)} 通过 ===")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
