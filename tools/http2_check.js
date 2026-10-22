// HTTP/2 客户端探针（Node 核心 http2：既支持 TLS h2 也支持明文 h2c prior-knowledge）。
// 用法: node http2_check.mjs <url> <mode> [n]
//   mode=single  -> 发一个 GET /，打印 STATUS/VER/BODY
//   mode=streams -> 并发开 n 个流，打印 STREAMS=<成功数>
const http2 = require('node:http2');

const url = process.argv[2];
const mode = process.argv[3] || 'single';
const n = parseInt(process.argv[4] || '3', 10);

const session = http2.connect(url, { rejectUnauthorized: false });
session.on('error', (e) => {
  console.log('ERROR', e.message);
  process.exit(3);
});

function request(path) {
  return new Promise((resolve) => {
    const req = session.request({ ':path': path, ':method': 'GET' });
    let body = '';
    let status = 0;
    let location = '';
    req.on('response', (h) => { status = h[':status']; location = h['location'] || ''; });
    req.setEncoding('utf8');
    req.on('data', (d) => { body += d; });
    req.on('end', () => resolve({ status, body, location }));
    req.on('error', () => resolve({ status: 0, body: '', location: '' }));
    req.setTimeout(8000, () => { req.close(http2.errors?.CONNECT_ERROR ?? 2); resolve({ status: 0, body: '', location: '' }); });
  });
}

(async () => {
  if (mode === 'streams') {
    const results = await Promise.all(Array.from({ length: n }, () => request('/')));
    const ok = results.filter((r) => r.status === 200).length;
    console.log('STREAMS=' + ok);
  } else if (mode === 'redirect') {
    // 用真实 h2 流取 Location，验证服务端的 $request_uri 是 :path 而非绝对 URI
    const r = await request(process.argv[5] || '/redir?x=1');
    console.log('STATUS=' + r.status);
    console.log('LOCATION=' + r.location);
  } else {
    const r = await request('/');
    // Node 的 http2 客户端只有在服务端确实协商到 HTTP/2 时才能拿到 200，
    // 因此 STATUS/BODY 即证明这条连接走的是 h2。
    console.log('STATUS=' + r.status);
    console.log('BODY=' + r.body.replace(/\n$/, ''));
  }
  session.close();
  // 关闭后让事件循环自然退出
})();
