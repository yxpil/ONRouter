#!/usr/bin/env python3
"""教程用后端：返回自己的名字与网关写下的请求头。

只服务 docs/TUTORIAL.md 的动手步骤，不是生产示例：

    python tools/tutorial_backend.py a 18601
    python tools/tutorial_backend.py b 18602
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = sys.argv[1] if len(sys.argv) > 1 else "a"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18601


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = (
            f"backend={NAME}\n"
            f"path={self.path}\n"
            f"x-split={self.headers.get('X-Split', '')}\n"
            f"x-split-served={self.headers.get('X-Split-Served', '')}\n"
            f"x-wasm-verified={self.headers.get('X-Wasm-Verified', '')}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # WASM header_filter 示例会删掉这个头，用来证明过滤器真的改写了上游响应
        self.send_header("X-Backend-Secret", "internal")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
