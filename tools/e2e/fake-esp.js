'use strict';
// "ESP falsa" para las pruebas: habla MQTT como el firmware y usa la MISMA criptografía de sesión que la ESP
// (firmware/pc-unlock/session.cpp compilado en PC como session_test, ver firmware/test/session_test.cpp).
// La verificación de Face ID usa host/src/webauthn.js (probada contra los mismos fixtures que auth.cpp).
// Registra lo que mandaría por Bluetooth: "[esp] tecla abajo 0xe0", "[esp] mover 3 4", etc.
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const mqtt = require('../../host/node_modules/mqtt');
const { parsePairCode, verifyAssertion, ReplayGuard } = require('../../host/src/webauthn');
const { decode, OP } = require('../../host/src/protocol');

async function startFakeEsp({ code, bin, sessionSecs = 3600, log = () => {} }) {
  const pairing = parsePairCode(code);
  const t = `pcu/${pairing.topic}`;
  const proc = spawn(bin, [], { stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = [];
  let wake = null;
  createInterface({ input: proc.stdout }).on('line', (l) => { lines.push(l); if (wake) { wake(); wake = null; } });
  let chain = Promise.resolve();
  const ask = (cmd) => (chain = chain.then(async () => {
    proc.stdin.write(cmd + '\n');
    while (!lines.length) await new Promise((r) => (wake = r));
    return lines.shift();
  }));
  const [, pub, vcode] = (await ask('id')).split(' ');
  const events = [];
  const say = (m) => { events.push(m); log('[esp] ' + m); };
  const guard = new ReplayGuard();
  const client = mqtt.connect('mqtt://127.0.0.1:1883', { clientId: 'fake-esp',
    will: { topic: `${t}/state`, payload: '{"online":false}', retain: true, qos: 1 } });
  await new Promise((r) => client.on('connect', r));
  client.publish(`${t}/state`, JSON.stringify({ online: true, pc: true, v: '1.3.0', k: pub, in: 1, mac: true, pin: true }), { retain: true, qos: 1 });
  client.subscribe([`${t}/cmd`, `${t}/in`]);
  const opens = [];
  client.on('message', async (topic, buf) => {
    if (topic === `${t}/in`) {
      const r = await ask(`frame ${buf.toString('hex')} ${Math.floor(Date.now() / 1000)}`);
      if (!r.startsWith('OK ')) { say('mensaje rechazado'); return; }
      for (const c of decode(Buffer.from(r.slice(3), 'hex'))) {
        if (c.op === OP.KEY_DOWN || c.op === OP.KEY_UP) say(`tecla ${c.op === OP.KEY_DOWN ? 'abajo' : 'arriba'} 0x${c.usage.toString(16)}`);
        else if (c.op === OP.MOVE) say(`mover ${c.dx} ${c.dy}`);
        else if (c.op === OP.BTN_DOWN || c.op === OP.BTN_UP) say(`botón ${c.mask} ${c.op === OP.BTN_DOWN ? 'abajo' : 'arriba'}`);
        else if (c.op === OP.WHEEL) say(`rueda ${c.v} ${c.h}`);
        else if (c.op === OP.CONSUMER) say(`multimedia 0x${c.usage.toString(16)}`);
        else if (c.op === OP.RELEASE_ALL) say('soltar todo');
      }
      return;
    }
    let m, cmd;
    try { m = JSON.parse(buf); } catch { return; }
    const resp = (o) => client.publish(`${t}/resp`, JSON.stringify({ pc: true, ...o }));
    try {
      cmd = verifyAssertion(pairing.key, m.ad, m.cd, m.sig);
      guard.check(cmd);
    } catch (e) { say('orden rechazada: ' + e.message); return; }
    if (cmd.c === 'rs' || cmd.c === 'rr') {
      if (!cmd.e) return resp({ n: cmd.n, c: cmd.c, ok: false, msg: 'Falta la clave de sesión' });
      const exp = Math.floor(Date.now() / 1000) + sessionSecs;
      const r = (await ask(`open ${cmd.e} ${cmd.n} ${exp}`)).split(' ');
      if (r[0] !== 'OPEN') return resp({ n: cmd.n, c: cmd.c, ok: false, msg: r.slice(1).join(' ') });
      opens.push(cmd);
      say(`sesión abierta (${cmd.c}${cmd.f ? ', con fingerprint del host' : ''})`);
      resp({ n: cmd.n, c: cmd.c, ok: true, e: r[1], s: r[2], exp });
    } else {
      say(`orden ${cmd.c}`);
      resp({ n: cmd.n, c: cmd.c, ok: true });
    }
  });
  return {
    code: vcode, pub, events, opens,
    has: (re) => events.some((e) => re.test(e)),
    async waitFor(re, ms = 10000) {
      const t0 = Date.now();
      while (Date.now() - t0 < ms) { if (events.some((e) => re.test(e))) return; await new Promise((r) => setTimeout(r, 100)); }
      throw new Error(`la ESP falsa no registró ${re}`);
    },
    async stop() {
      client.publish(`${t}/state`, '{"online":false}', { retain: true });
      await new Promise((r) => client.end(false, r));
      proc.stdin.end();
    },
  };
}

module.exports = { startFakeEsp };
