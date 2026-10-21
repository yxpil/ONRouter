# -*- coding: utf-8 -*-
"""测试夹具：需要 TLS 的套件自己将证书造出来。

每个证书目录都在 .gitignore 里。CI 是干净检出，开发机上却可能恰好留着别人生成的
一份，于是"只在 CI 红"的套件就是这么来的（1.0.2 的 production_shape 借了
random_scenarios 的 certs_random/，CI 上 -t 直接报"打开证书失败"）。约定：
一套件一个目录，入口先 ensure()。
"""
import os
import subprocess


def ensure(root, rel_dir, base="server", dns=("localhost",), ips=("127.0.0.1",), days=90):
    """在 <root>/<rel_dir>/<base>.pem|.key 造一张自签证书，已存在就原样返回。

    用 RSA 而不是 ECDSA：上游 mTLS 那侧的 Identity::from_pkcs8 只收 RSA，
    同一份夹具能被两类套件复用。SAN 要写全——QUIC 客户端强制校验服务器名。

    basicConstraints 必须显式写成 CA:FALSE。OpenSSL 的 `-x509` 默认给自签证书打上
    `CA:TRUE`，rustls 会把它当 CA 证书用在末端而拒绝握手（`CaUsedAsEndEntity`），
    而"把这张证书当自己的受信根"正是 h3 客户端的校验方式。
    """
    d = os.path.join(root, rel_dir)
    pem = os.path.join(d, base + ".pem")
    key = os.path.join(d, base + ".key")
    if os.path.exists(pem) and os.path.exists(key):
        return pem
    os.makedirs(d, exist_ok=True)
    san = ",".join([f"DNS:{n}" for n in dns] + [f"IP:{n}" for n in ips])
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", key, "-out", pem, "-days", str(days),
           "-subj", f"/CN={dns[0]}",
           "-addext", f"subjectAltName={san}",
           "-addext", "basicConstraints=critical,CA:FALSE",
           "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
           "-addext", "extendedKeyUsage=serverAuth"]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        raise SystemExit("!! openssl 自签夹具失败（%s）: %s" % (
            " ".join(cmd[:4]), p.stderr.decode("utf-8", "replace")[:300]))
    return pem
