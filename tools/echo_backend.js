// 演示后端：返回自身端口 + 收到的路径/UA，附带一个 1MB 二进制路由和一个慢路由
// 用于验证 ONRouter 转发的正确性（负载均衡、请求头保留、大响应完整性、超时/中断）
const http = require('http');
const crypto = require('crypto');
const port = Number(process.argv[2]);
const BLOB = crypto.randomBytes(1024 * 1024);

http.createServer((req, res) => {
  if (req.url.startsWith('/blob')) {
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'x-backend': String(port) });
    res.end(BLOB);
    return;
  }
  if (req.url.startsWith('/slow')) {
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`slow-ok from ${port}`);
    }, 1500);
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    res.writeHead(200, { 'content-type': 'application/json', 'x-backend': String(port) });
    res.end(JSON.stringify({
      backend: port,
      path: req.url,
      method: req.method,
      ua: req.headers['user-agent'] || null,
      xff: req.headers['x-forwarded-for'] || null,
      host: req.headers['host'] || null,
      body_len: body.length,
      body_sha256: crypto.createHash('sha256').update(body).digest('hex'),
    }));
  });
}).listen(port, '127.0.0.1', () => console.log(`backend ${port} up`));
