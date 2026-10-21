// h2/h1 请求驱动 —— 与 orr-h3check 同一套输出词汇，好让套件能把"同一条业务在两种传输上
// 的表现"逐项对撞（状态、字节数、摘要、关键响应头、帧到达时刻）。
//
// 本机 libcurl 不带 HTTP/2，h2 侧用 Node 核心 http2；h1.1 over TLS 用 Node https。
//
// 用法: node h2_request_check.js <url> <mode> <path> [n]
//   detail | head | post | many <n> | streams <n> | sse | cancel <n> | h1
// 环境变量:
//   QBIZ_HDRS  额外请求头 `cookie:sid=A;range:bytes=0-99`（`;` 分隔，`:` 分键值）
//   QBIZ_BODY  post 模式的请求体文件路径
const http2 = require('node:http2');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');

const url = process.argv[2];
const mode = process.argv[3] || 'detail';
const path = process.argv[4] || '/';
const n = parseInt(process.argv[5] || '3', 10);

function headers() {
  const out = {};
  const raw = process.env.QBIZ_HDRS || '';
  for (const kv of raw.split(';')) {
    const i = kv.indexOf(':');
    if (i > 0) out[kv.slice(0, i).trim().toLowerCase()] = kv.slice(i + 1).trim();
  }
  return out;
}

function bodyToFile(name, buf) {
  const fs2 = require('node:fs');
  const os2 = require('node:os');
  const fp = require('node:path').join(fs2.mkdtempSync(os2.tmpdir() + '/qbiz-'), name);
  fs2.writeFileSync(fp, buf);
  return fp;
}

function sha(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function detail(status, proto, hdrs, body, trailers) {
  console.log(`STATUS=${status}`);
  console.log(`PROTO=${proto}`);
  console.log(`LEN=${body.length}`);
  console.log(`SHA=${sha(body)}`);
  console.log(`TRAILERS=${trailers ? 1 : 0}`);
  if (body.length) console.log(`FILE=${bodyToFile('resp.bin', body)}`);
  for (const k of Object.keys(hdrs || {}).sort()) console.log(`HDR=${k}: ${hdrs[k]}`);
}

// 一条 h2 会话上的一个请求
function request(session, p, method, body) {
  return new Promise((resolve) => {
    const hdrs = headers();
    // :path 与 :method 显式写进头里。之前用 `session.request(headers, { path })` 的写法，
    // 实测下来每个路径都拿到首页那份响应（LEN 与 content-type 全是 index.html 的），
    // 于是"h2 上 expires/gzip/Range/代理全都失效"这种假故障会被记到网关头上。
    // 没去查 Node 为什么这样处理 options.path；显式伪头之后每条路径各自正确，就够用。
    hdrs[':path'] = p;
    hdrs[':method'] = method || 'GET';
    const req = session.request(hdrs);
    if (body) req.write(body);
    req.end();
    let status = 0;
    let res = {};
    let trailersSeen = null;
    const chunks = [];
    req.on('response', (h) => { status = h[':status']; res = h; });
    req.on('data', (d) => chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
    req.on('trailers', (t) => { trailersSeen = t; });
    req.on('end', () => resolve({ status, hdrs: res, body: Buffer.concat(chunks), trailers: trailersSeen }));
    req.on('error', () => resolve({ status: 0, hdrs: {}, body: Buffer.alloc(0), trailers: null }));
    req.setTimeout(12000, () => { req.close(); resolve({ status: 0, hdrs: {}, body: Buffer.alloc(0), trailers: null }); });
  });
}

function connect() {
  const session = http2.connect(url, { rejectUnauthorized: false });
  session.on('error', (e) => { console.log(`ERROR=${e.message}`); });
  return session;
}

// h1.1 over TLS：与 h2 用同一个 vhost、同一个端口，只是不 advertised h2
function h1Request(p, method, body) {
  return new Promise((resolve) => {
    const u = new URL(url + p);
    const req = https.request({
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
      method: method || 'GET', headers: headers(),
      rejectUnauthorized: false, ALPNProtocols: ['http/1.1'],
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({
        status: res.statusCode, hdrs: res.headers, body: Buffer.concat(chunks),
        trailers: null, version: 'HTTP/' + res.httpVersion,
      }));
    });
    req.on('error', (e) => resolve({ status: 0, hdrs: {}, body: Buffer.alloc(0), trailers: null }));
    req.setTimeout(12000, () => { req.abort(); resolve({ status: 0, hdrs: {}, body: Buffer.alloc(0), trailers: null }); });
    if (body) req.write(body);
    req.end();
  });
}

(async () => {
  if (mode === 'h1') {
    const r = await h1Request(path, 'GET');
    detail(r.status, r.version || 'HTTP/1.1', r.hdrs, r.body, r.trailers);
    return;
  }
  const session = connect();
  try {
    if (mode === 'streams') {
      const rs = await Promise.all(Array.from({ length: n }, () => request(session, path)));
      console.log(`STREAMS=${rs.filter((r) => r.status === 200).length}`);
    } else if (mode === 'many') {
      let ok = 0;
      for (let i = 0; i < n; i++) {
        const r = await request(session, path);
        if (r.status === 200) ok += 1;
        console.log(`REQ=${i} STATUS=${r.status} LEN=${r.body.length} SHA=${sha(r.body)}`);
      }
      console.log(`SUMMARY=${ok}/${n}`);
    } else if (mode === 'sse') {
      const req = session.request({ ...headers(), ':method': 'GET', ':path': path });
      let frames = 0;
      const t0 = Date.now();
      req.on('data', (d) => {
        frames += 1;
        console.log(`FRAME=${frames} AT=${Date.now() - t0} BYTES=${d.length}`);
      });
      await new Promise((resolve) => {
        req.on('end', resolve);
        req.on('close', resolve);
        req.on('error', resolve);
        setTimeout(resolve, 12000);
      });
      console.log(`FRAMES=${frames}`);
    } else if (mode === 'cancel') {
      let opened = 0;
      for (let i = 0; i < n; i++) {
        const req = session.request({ ...headers(), ':method': 'GET', ':path': path });
        req.on('error', () => {});
        opened += 1;
        req.close();
      }
      const after = await request(session, path);
      console.log(`CANCELLED=${opened} THEN=${after.status}`);
    } else if (mode === 'head') {
      const r = await request(session, path, 'HEAD');
      detail(r.status, 'HTTP/2', r.hdrs, r.body, r.trailers);
    } else if (mode === 'post') {
      const body = fs.readFileSync(process.env.QBIZ_BODY || '', () => Buffer.alloc(0));
      const r = await request(session, path, 'POST', body);
      detail(r.status, 'HTTP/2', r.hdrs, r.body, r.trailers);
    } else {
      const r = await request(session, path);
      detail(r.status, 'HTTP/2', r.hdrs, r.body, r.trailers);
    }
  } finally {
    session.close();
  }
})();
