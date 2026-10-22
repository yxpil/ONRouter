#!/usr/bin/env python3
"""被动打印入向 TLS ClientHello（Linux，root，AF_PACKET，不需要 libpcap/tcpdump）。

为什么要有它：握手失败的成因**全在客户端提供的曲线列表里**，而 CDN 报给用户的只有一句
"handshake failed"。源站这边如果既没有 tcpdump 也不该为了排障装包（生产机上很常见），
原始套接字镜像一份入向报文就够了——ClientHello 是明文，解出 supported_groups 就结案。
只镜像、不劫持：不占端口、不改路由、不动网关，Ctrl-C 或到点自己停。

    python3 tools/tls_hello_tap.py ens18 45      # 抓 45 秒
    # 同时从外部制造几条真实回源请求（带唯一 query 绕过 CDN 缓存，逼它新建连接）

输出每行一个 hello：对端、SNI、cipher 数、supported_versions、supported_groups（含名字）、
前几个 signature_algorithms。同一次抓取里正常站点与异常站点并排看，差别一目了然——
2026-10-22 那次 Cloudflare 525 就是这么定性的：坏 zone 的回源 hello 只给了
`0x11ec`(X25519MLKEM768) 与两个实验 codepoint，一条经典曲线都没有。
运维口径见 docs/OPERATIONS.md §5.6。
"""
import collections
import json
import socket
import struct
import sys
import time

IFACE = sys.argv[1] if len(sys.argv) > 1 else "ens18"
SECS = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0

GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001D: "x25519", 0x001E: "brainpoolP256r1", 0x001F: "brainpoolP384r1",
    0x0020: "brainpoolP512r1", 0x0021: "x448",
    0x0024: "secp256r1mlkem768", 0x0025: "x25519mlkem768", 0x0026: "mlkem512",
    0x0027: "mlkem768", 0x0028: "mlkem1024",
    0x0030: "ffdhe2048", 0x0031: "ffdhe3072", 0x0032: "ffdhe4096",
    0x11EC: "x25519kyber768draft00", 0x11ED: "x25519mlkem768draft",
    0x11EE: "p256mlkem768draft", 0x11EF: "p384mlkem1024draft",
    0x11F0: "p521mlkem1024draft", 0x11F1: "x25519ntrulpr768draft",
    0x11F2: "ntrulpr768sntrup761x25519draft",
    0xFF01: "second_pre_shared_key_draft",
}
TYPES = {0: "server_name", 10: "supported_groups", 11: "ec_point_formats",
         13: "signature_algorithms", 43: "supported_versions", 0x002B: "key_share",
         21: "padding", 17: "encrypted_client_hello", 5: "status_request",
         10: "supported_groups"}


def gname(g):
    return GROUPS.get(g, "0x%04x" % g)


def parse_hello(payload):
    """Return dict for a TLS record that starts with a ClientHello, else None."""
    if len(payload) < 45 or payload[0] != 0x16:
        return None
    reclen = struct.unpack("!H", payload[3:5])[0]
    body = payload[5:5 + reclen]
    if len(body) < 40 or body[0] != 0x01:
        return None
    hslen = int.from_bytes(body[1:4], "big")
    b = body[4:4 + hslen]
    o = 0
    o += 2                      # legacy version
    o += 32                     # random
    l = b[o]; o += 1 + l        # session id
    cslen = struct.unpack("!H", b[o:o + 2])[0]; o += 2 + cslen
    cl = b[o]; o += 1 + cl      # compression
    extlen = struct.unpack("!H", b[o:o + 2])[0]; o += 2
    out = {"groups": [], "versions": [], "sni": None, "sigalgs": [],
           "ciphers": cslen // 2, "exts": []}
    end = o + extlen
    while o + 4 <= end and o + 4 <= len(b):
        et, el = struct.unpack("!HH", b[o:o + 4])
        o += 4
        ev = b[o:o + el]
        o += el
        out["exts"].append(et)
        if et == 0 and len(ev) >= 5:          # server_name list
            out["sni"] = ev[3 + 2:].decode("ascii", "replace")
        elif et == 10:
            out["groups"] = [struct.unpack("!H", ev[i:i + 2])[0]
                             for i in range(2, min(len(ev), 2 + struct.unpack("!H", ev[0:2])[0]), 2)]
        elif et == 13:
            out["sigalgs"] = [struct.unpack("!H", ev[i:i + 2])[0]
                              for i in range(2, min(len(ev), 2 + struct.unpack("!H", ev[0:2])[0]), 2)]
        elif et == 43:
            out["versions"] = list(ev[1:ev[0] + 1])
    return out


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((IFACE, 0x0800))
    s.settimeout(2.0)
    seen = {}
    streams = {}          # (peer, sport) -> {seq: payload}
    stats = collections.Counter()
    t0 = time.time()
    while time.time() - t0 < SECS:
        try:
            pkt = s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        if eth_type == 0x8100:
            eth_type = struct.unpack("!H", pkt[16:18])[0]
            off = 18
        if eth_type != 0x0800:
            continue
        ip = pkt[off:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:
            continue
        if ip[5:6] != b"\x00\x00" and (ip[6] & 0x1F or ip[7]):
            continue  # fragmented: not our case
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[0:4])
        if dport != 443:
            continue
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if not payload:
            continue
        seq = struct.unpack("!I", tcp[16:20])[0]
        src = ".".join(str(x) for x in ip[12:16])
        stats["segments"] += 1
        st = streams.setdefault((src, sport), {})
        if seq in st:
            continue
        st[seq] = payload
        # 按 seq 排序拼接后，凑齐一条完整 TLS 记录再解析
        buf = b""
        for sq in sorted(st):
            buf += st[sq]
        if len(buf) < 5:
            continue
        reclen = struct.unpack("!H", buf[3:5])[0]
        if len(buf) < 5 + reclen:
            continue
        h = parse_hello(buf)
        if not h:
            stats["unparsed"] += 1
            if stats["unparsed"] <= 3:
                print("# unparsed %s:%d first=%s len=%d" %
                      (src, sport, buf[:8].hex(), len(buf)), flush=True)
            continue
        key = (src, h["sni"], tuple(h["groups"]))
        if key in seen:
            continue
        seen[key] = True
        print(json.dumps({
            "peer": src, "sni": h["sni"], "ciphers": h["ciphers"],
            "versions": h["versions"],
            "groups": [gname(g) for g in h["groups"]],
            "groups_raw": ["%04x" % g for g in h["groups"]],
            "sigalgs": ["%04x" % s2 for s2 in h["sigalgs"][:8]],
        }, ensure_ascii=False), flush=True)
    print("# segments_seen=%d unparsed=%d distinct_hellos=%d" %
          (stats["segments"], stats["unparsed"], len(seen)), flush=True)


main()
