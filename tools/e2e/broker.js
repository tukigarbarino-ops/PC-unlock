'use strict';
// Broker MQTT local para pruebas (aedes): TCP 1883 (host y ESP falsa) y WebSocket 8888 (web app con cfg.testUrl).
// También sirve web/ en http://localhost:8000 (rpId "localhost" para el autenticador virtual).
// Exporta start() para usarlo desde las pruebas; con "node broker.js" queda corriendo.
const net = require('node:net');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const aedesLib = require('aedes');
const ws = require('websocket-stream');

const WEB = path.join(__dirname, '..', '..', 'web');
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };

async function start({ tcp = 1883, wsPort = 8888, web = 8000, log = false } = {}) {
  const aedes = aedesLib.createBroker ? aedesLib.createBroker() : aedesLib();
  const seen = [];
  aedes.on('publish', (p, c) => { if (c) { seen.push({ topic: p.topic, payload: p.payload.toString() }); if (log) console.log('[mqtt]', p.topic, p.payload.length); } });
  const tcpServer = net.createServer(aedes.handle);
  await new Promise((r) => tcpServer.listen(tcp, '127.0.0.1', r));
  const httpWs = http.createServer();
  ws.createServer({ server: httpWs }, aedes.handle);
  await new Promise((r) => httpWs.listen(wsPort, '127.0.0.1', r));
  const webServer = http.createServer((req, res) => {
    const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let f = path.normalize(path.join(WEB, u.endsWith('/') ? u + 'index.html' : u));
    if (!f.startsWith(WEB) || !fs.existsSync(f)) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream', 'cache-control': 'no-store' });
    fs.createReadStream(f).pipe(res);
  });
  await new Promise((r) => webServer.listen(web, '127.0.0.1', r));
  return {
    aedes, seen,
    close: async () => { webServer.close(); httpWs.close(); tcpServer.close(); await new Promise((r) => aedes.close(r)); },
  };
}

module.exports = { start };
if (require.main === module) start({ log: true }).then(() => console.log('broker 1883/8888, web http://localhost:8000'));
