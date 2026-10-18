// h2 流式探针：报告 TTFB / 总耗时 / 字节数 / 分块数。
// 用法: node h2_stream_probe.js <https-url> <path> [servername]
const http2 = require('node:http2');

const url = process.argv[2];
const path = process.argv[3] || '/';
const servername = process.argv[4] || undefined;

const t0 = Date.now();
const opts = { rejectUnauthorized: false };
if (servername) opts.servername = servername;
const session = http2.connect(url, opts);
let status = 0;
let ttfb = -1;
let bytes = 0;
let chunks = 0;

session.on('error', (e) => {
  console.log('ERROR ' + e.message);
  process.exit(3);
});

const req = session.request({ ':path': path, ':method': 'GET' });
req.on('response', (h) => { status = h[':status']; });
req.on('data', (d) => {
  if (ttfb < 0) ttfb = Date.now() - t0;
  bytes += d.length;
  chunks += 1;
});
req.on('end', () => {
  console.log(JSON.stringify({
    status,
    ttfb_ms: ttfb,
    total_ms: Date.now() - t0,
    bytes,
    chunks,
  }));
  session.close();
});
req.on('error', (e) => {
  console.log('ERROR ' + e.message);
  session.close();
  process.exit(4);
});
req.setTimeout(8000, () => {
  console.log('ERROR timeout');
  session.close();
  process.exit(5);
});
req.end();
