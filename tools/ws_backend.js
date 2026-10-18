// 最小 WebSocket 回显后端（RFC6455，无第三方依赖）
// 用途：验证 ONRouter 的 101 升级隧道端到端可用
const http = require('http');
const crypto = require('crypto');
const port = Number(process.argv[2] || 9301);
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function encodeFrame(payload, opcode = 0x1) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode; header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode; header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(`ws-backend ${port} (use upgrade)`);
});

server.on('upgrade', (req, socket, head) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  if (head && head.length) socket.emit('data', head);

  let buf = Buffer.alloc(0);
  socket.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      let mask = null;
      if (masked) { if (buf.length < off + 4) return; mask = buf.subarray(off, off + 4); off += 4; }
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (masked) {
        const un = Buffer.from(payload);
        for (let i = 0; i < un.length; i++) un[i] ^= mask[i % 4];
        payload = un;
      }
      buf = buf.subarray(off + len);
      if (opcode === 0x8) { socket.end(encodeFrame(Buffer.alloc(0), 0x8)); return; }
      if (opcode === 0x9) { socket.write(encodeFrame(payload, 0xA)); continue; }
      if (fin) socket.write(encodeFrame(Buffer.from('echo:' + payload.toString('utf8')), 0x1));
    }
  });
  socket.on('error', () => {});
  socket.on('close', () => {});
});

server.listen(port, '127.0.0.1', () => console.log(`ws backend ${port} up`));
