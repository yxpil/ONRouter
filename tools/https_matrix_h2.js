// HTTPS 矩阵用的 h2 探针：可以同时指定 URL（连到哪个 IP:port）、SNI、:authority。
// 用法: node https_matrix_h2.js <url> [servername] [authority] [path]
// 输出: STATUS / BODY / ALPN / PEER_SHA256
// 现有 http2_check.js 只能从 URL 推导 SNI/Host，测不了「SNI 与 Host 不一致」「SNI 选证书」。
const http2 = require('node:http2');
const crypto = require('node:crypto');

const url = process.argv[2];
const servername = process.argv[3] || undefined;
const authority = process.argv[4] || undefined;
const path = process.argv[5] || '/';

const opts = { rejectUnauthorized: false };
if (servername) opts.servername = servername;

const session = http2.connect(url, opts);
session.on('error', (e) => {
  console.log('ERROR ' + e.message);
  process.exit(3);
});

session.on('connect', () => {
  const sock = session.socket;
  console.log('ALPN=' + (sock.alpnProtocol || ''));
  const cert = sock.getPeerCertificate();
  if (cert && cert.raw) {
    console.log('PEER_SHA256=' + crypto.createHash('sha256').update(cert.raw).digest('hex'));
  }
});

const headers = { ':path': path, ':method': 'GET' };
if (authority) headers[':authority'] = authority;

const req = session.request(headers);
let status = 0;
let body = '';
req.on('response', (h) => { status = h[':status']; });
req.setEncoding('utf8');
req.on('data', (d) => { body += d; });
req.on('end', () => {
  console.log('STATUS=' + status);
  console.log('BODY=' + body.replace(/\n$/, ''));
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
