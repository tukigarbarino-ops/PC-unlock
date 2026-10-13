'use strict';
// Prueba de punta a punta del respaldo por la ESP (fase 2):
//   web app (Playwright + Face ID virtual) <-> broker local <-> ESP falsa con la cripto real del firmware
//   (+ PC Unlock Host real para probar el cambio automático host <-> ESP).
// Necesita session_test compilado (ver firmware/test/session_test.cpp):  E2E_SESSION_BIN=<ruta> node esp.e2e.js
const assert = require('node:assert');
const { chromium } = require('playwright');
const mqtt = require('../../host/node_modules/mqtt');
const { start } = require('./broker');
const { launchHost } = require('./host');
const { startFakeEsp } = require('./fake-esp');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let step = 0;
const ok = (msg) => console.log(`  ✔ ${++step}. ${msg}`);
async function until(fn, ms = 15000, what = 'condición') {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timeout esperando ${what}`);
    await sleep(150);
  }
}

async function main() {
  const bin = process.env.E2E_SESSION_BIN;
  if (!bin) throw new Error('Falta E2E_SESSION_BIN (session_test compilado)');
  const verbose = !!process.env.E2E_VERBOSE;
  const broker = await start();
  const browser = await chromium.launch({ channel: process.env.E2E_CHANNEL ?? 'msedge' });
  const ctx = await browser.newContext({ hasTouch: true, viewport: { width: 390, height: 844 }, deviceScaleFactor: 3 });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  let esp = null, host = null;
  try {
    await page.goto('http://localhost:8000/');
    await page.evaluate(() => localStorage.setItem('pcu-config-v1', JSON.stringify({ host: 'localhost', user: 'u', pass: 'p', testUrl: 'ws://127.0.0.1:8888' })));
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.reload();
    await page.evaluate(() => window.PCU.createKey());
    const code = await page.evaluate(() => window.PCU.pairCode());
    esp = await startFakeEsp({ code, bin, sessionSecs: 60, log: verbose ? (m) => console.log('   ', m) : undefined });
    ok(`ESP falsa con la cripto del firmware (código ${esp.code})`);

    // ---------- emparejar la ESP comparando códigos
    await page.evaluate(() => window.PCU.connect());
    if (await page.isHidden('#settings')) await page.click('#btnSettings');
    await until(() => page.isVisible('#espCodeBox'), 15000, 'código de la ESP');
    assert.equal(await page.textContent('#espCode'), esp.code);
    await page.click('#btnEspMatch');
    await until(async () => (await page.textContent('#espPairState')).includes('Emparejada'));
    ok('el código de la ESP en la app es igual al del firmware; ESP emparejada');

    // ---------- sin host: teclado y mouse por la ESP
    await page.click('#btnBack');
    await page.click('#btnRemote');
    await until(async () => (await page.textContent('#rConnect')).includes('ESP') && page.isVisible('#rConnect') && page.evaluate(() => !!window.PCU.R.ecdh), 10000, 'botón de conectar por la ESP');
    ok('sin el programa de la compu, la vista Remoto ofrece conectar por la ESP (clave ECDH lista antes del toque)');
    await page.click('#rConnect');
    await esp.waitFor(/sesión abierta \(rs\)/);
    await until(() => page.evaluate(() => window.PCU.espActive()), 10000, 'sesión con la ESP');
    assert.match(await page.textContent('#rStatus'), /ESP/);
    ok('un Face ID abre la sesión con la ESP (firma de la ESP verificada, clave AES derivada)');

    const touch = (type, pts) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints: pts.map(([x, y, id]) => ({ x, y, id })) });
    if (await page.isHidden('#panel-kbd')) await page.click('[data-panel="kbd"]');
    if (await page.isVisible('#panel-pad')) await page.click('[data-panel="pad"]');
    await page.$eval('#kbd', (e) => e.scrollIntoView({ block: 'end' }));
    const kc = async (u) => { const b = await (await page.$(`.key[data-u="${u}"]`)).boundingBox(); return [b.x + b.width / 2, b.y + b.height / 2]; };
    let [cx, cy] = await kc(0xe0), [lx, ly] = await kc(0x06);
    await touch('touchStart', [[cx, cy, 1]]);
    await touch('touchStart', [[cx, cy, 1], [lx, ly, 2]]);
    await touch('touchEnd', [[lx, ly, 2]]);
    await touch('touchEnd', [[cx, cy, 1]]);
    await esp.waitFor(/tecla arriba 0xe0/);
    const keys = esp.events.filter((e) => /^tecla (abajo|arriba) 0x(e0|6)$/.test(e));
    assert.deepEqual(keys.slice(-4), ['tecla abajo 0xe0', 'tecla abajo 0x6', 'tecla arriba 0x6', 'tecla arriba 0xe0']);
    ok('Ctrl+C multitouch llega cifrado a la ESP y se descifra con el código del firmware');

    // mantener una tecla: por la ESP NO se repite en la app (Windows repite solo las de un teclado Bluetooth)
    const [ax, ay] = await kc(0x04);
    const before = esp.events.filter((e) => e === 'tecla abajo 0x4').length;
    await touch('touchStart', [[ax, ay, 3]]);
    await sleep(1200);
    await touch('touchEnd', [[ax, ay, 3]]);
    await esp.waitFor(/tecla arriba 0x4/);
    assert.equal(esp.events.filter((e) => e === 'tecla abajo 0x4').length - before, 1);
    ok('mantener una tecla por la ESP manda un solo "abajo" (la repetición la hace Windows)');

    await page.click('[data-panel="kbd"]');
    await page.click('[data-panel="pad"]');
    await page.$eval('#pad', (e) => e.scrollIntoView({ block: 'center' }));
    const pb = await (await page.$('#pad')).boundingBox();
    await touch('touchStart', [[pb.x + 100, pb.y + 100, 4]]);
    for (let i = 1; i <= 10; i++) { await touch('touchMove', [[pb.x + 100 + i * 8, pb.y + 100 + i * 4, 4]]); await sleep(16); }
    await touch('touchEnd', [[pb.x + 180, pb.y + 140, 4]]);
    await esp.waitFor(/mover \d+ \d+/);
    const moves = esp.events.filter((e) => e.startsWith('mover')).length;
    assert.ok(moves <= 8, `demasiados mensajes de mouse por la ESP: ${moves}`);
    await sleep(350);
    await touch('touchStart', [[pb.x + 40, pb.y + 200, 5]]); await touch('touchEnd', [[pb.x + 40, pb.y + 200, 5]]);
    await esp.waitFor(/botón 1 arriba/);
    ok(`touchpad por la ESP (movimiento agrupado: ${moves} mensajes, clic izquierdo)`);

    await page.click('[data-panel="media"]');
    await page.dispatchEvent('[data-media="e9"]', 'pointerdown', { pointerId: 20 });
    await page.dispatchEvent('[data-media="e9"]', 'pointerup', { pointerId: 20 });
    await esp.waitFor(/multimedia 0xe9/);
    ok('multimedia (volumen +) por la ESP');

    // ---------- renovar la sesión con la ESP (en la prueba dura 60 s, así "Renovar" ya aparece)
    await until(() => page.isVisible('#rRenew'), 5000, 'botón Renovar');
    await until(() => page.evaluate(() => !!window.PCU.R.ecdh), 5000, 'clave ECDH nueva');
    await page.click('#rRenew');
    await esp.waitFor(/sesión abierta \(rr\)/);
    await until(() => page.evaluate(() => window.PCU.R.esp && window.PCU.R.esp.seq === 0), 5000, 'sesión renovada');
    await page.dispatchEvent('[data-media="cd"]', 'pointerdown', { pointerId: 21 });
    await page.dispatchEvent('[data-media="cd"]', 'pointerup', { pointerId: 21 });
    await esp.waitFor(/multimedia 0xcd/);
    assert.ok(!esp.has(/mensaje rechazado/));
    ok('renovar con Face ID abre una sesión nueva con la ESP (clave nueva) y sigue andando');

    // ---------- alguien en el broker cambia la clave efímera de la ESP: la app no la acepta
    await page.click('#rBack');
    await page.click('#btnRemote');
    broker.aedes.authorizeForward = (client, packet) => {
      if (!packet.topic.endsWith('/resp')) return packet;
      const m = JSON.parse(packet.payload.toString());
      if (m.e) m.e = m.e.slice(0, 10) + (m.e[10] === 'A' ? 'B' : 'A') + m.e.slice(11);
      return { ...packet, payload: Buffer.from(JSON.stringify(m)) };
    };
    await until(() => page.evaluate(() => !!window.PCU.R.ecdh) && page.isVisible('#rConnect'), 10000, 'botón conectar');
    await page.click('#rConnect');
    const txt = await until(async () => { const t = await page.textContent('#rOvText'); return /firmada por tu ESP/.test(t) && t; }, 15000, 'rechazo');
    assert.equal(await page.evaluate(() => window.PCU.espActive()), false);
    broker.aedes.authorizeForward = (c, p) => p;
    ok(`clave efímera de la ESP cambiada en el broker: la app no la usa ("${txt.trim()}")`);

    // ---------- host + ESP con un solo Face ID; la entrada cambia sola de camino
    host = launchHost({ code, env: { PCU_TEST_HOOKS: '1' } });
    const hostCode = (await host.waitFor(/código (\S+)$/)).match(/código (\S+)$/)[1];
    await page.click('#rBack');
    await page.click('#btnSettings');
    await until(() => page.isVisible('#hostCodeBox'), 15000, 'código del host');
    assert.equal(await page.textContent('#hostCode'), hostCode);
    await page.click('#btnHostMatch');
    await page.click('#btnBack');
    await page.click('#btnRemote');
    await until(() => page.evaluate(() => !!window.PCU.R.prepared && !!window.PCU.R.ecdh), 10000, 'oferta y clave ECDH');
    const opensBefore = esp.opens.length;
    await page.click('#rConnect');
    await until(() => page.evaluate(() => document.querySelector('#rVideo').videoWidth > 0), 20000, 'video');
    await until(() => esp.opens.length > opensBefore, 10000, 'sesión con la ESP');
    assert.ok(esp.opens.at(-1).f, 'el mismo Face ID trae el fingerprint del host y la clave para la ESP');
    await until(() => page.evaluate(() => window.PCU.espActive() && window.PCU.viaHost()), 10000, 'ambas sesiones');
    ok('un solo Face ID abre la pantalla (host) y el respaldo (ESP)');

    const pressMedia = async (u, id) => {
      await page.dispatchEvent(`[data-media="${u}"]`, 'pointerdown', { pointerId: id });
      await page.dispatchEvent(`[data-media="${u}"]`, 'pointerup', { pointerId: id });
    };
    const espCount = () => esp.events.filter((e) => e === 'multimedia 0xb5').length;
    const hostCount = () => host.lines.filter((l) => /multimedia 0xb5$/.test(l)).length;
    await pressMedia('b5', 30);
    await host.waitFor(/multimedia 0xb5$/);
    await sleep(300);
    assert.equal(espCount(), 0);
    ok('con el host conectado, la entrada va por el host (DataChannel), no por la ESP');

    const pub = mqtt.connect('mqtt://127.0.0.1:1883');
    await new Promise((r) => pub.on('connect', r));
    const topic = await page.evaluate(() => window.PCU.cfg().topic);
    pub.publish(`pcu/${topic}/host/in/test`, JSON.stringify({ locked: true }));
    await until(() => page.isVisible('#rLocked'), 5000, 'aviso de bloqueo');
    assert.ok(await page.isVisible('#rLockEsp'));
    await pressMedia('b5', 31);
    await esp.waitFor(/multimedia 0xb5/);
    assert.equal(hostCount(), 1);
    ok('compu bloqueada: la entrada pasa sola a la ESP (que sí llega a la pantalla de bloqueo)');
    pub.publish(`pcu/${topic}/host/in/test`, JSON.stringify({ locked: false }));
    await until(() => page.isHidden('#rLocked'), 5000, 'fin del bloqueo');
    await pressMedia('b5', 32);
    await until(() => hostCount() === 2, 5000, 'entrada por el host');
    assert.equal(espCount(), 1);
    ok('al desbloquear vuelve a ir por el host');

    await host.kill();
    host = null;
    await until(() => page.evaluate(() => !window.PCU.R.live), 20000, 'fin de la sesión con el host');
    await pressMedia('b5', 33);
    await until(() => espCount() === 2, 5000, 'entrada por la ESP');
    ok('si el programa de la compu se cierra, teclado/mouse/multimedia siguen por la ESP');
    pub.end();

    assert.deepEqual(errors.filter((e) => !/favicon|ERR_|WebSocket/.test(e)), []);
    ok('sin errores de JavaScript en la página');
    console.log(`\nOK: ${step} verificaciones`);
  } finally {
    if (host) await host.kill().catch(() => {});
    if (esp) await esp.stop().catch(() => {});
    await browser.close();
    await broker.close();
  }
}

main().catch((e) => { console.error('\nFALLÓ:', e.stack || e.message); process.exit(1); });
