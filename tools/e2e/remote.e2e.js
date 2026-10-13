'use strict';
// Prueba de punta a punta de la vista Remoto:
//   web app (Playwright + autenticador WebAuthn virtual)  <->  broker local  <->  PC Unlock Host real (Electron)
// La entrada en el host va en modo simulado (registra en vez de mover el mouse de esta compu).
// Uso: node remote.e2e.js            (E2E_VERBOSE=1 para ver el log del host)
const assert = require('node:assert');
const { chromium } = require('playwright');
const mqtt = require('../../host/node_modules/mqtt');
const { start } = require('./broker');
const { launchHost } = require('./host');

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
  const broker = await start();
  const channel = process.env.E2E_CHANNEL ?? 'msedge'; // Edge trae H.264; con "" usa el Chromium de Playwright
  const browser = await chromium.launch({ channel: channel || undefined, headless: !process.env.E2E_HEADED });
  const ctx = await browser.newContext({ hasTouch: true, viewport: { width: 390, height: 844 }, deviceScaleFactor: 3 });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  let host = null;
  const hosts = [];
  try {
    // ---------- web app configurada contra el broker local, con passkey virtual
    await page.goto('http://localhost:8000/');
    await page.evaluate(() => localStorage.setItem('pcu-config-v1', JSON.stringify({ host: 'localhost', user: 'u', pass: 'p', testUrl: 'ws://127.0.0.1:8888' })));
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.reload();
    await page.evaluate(() => window.PCU.createKey());
    const code = await page.evaluate(() => window.PCU.pairCode());
    assert.match(code, /^PCU1\./);
    ok('passkey virtual creada y código PCU1 generado');

    // ---------- host real
    const launch = (env = {}) => { const h = launchHost({ code, env: { PCU_TEST_HOOKS: '1', ...env } }); hosts.push(h); return h; };
    host = launch({ PCU_SESSION_SECS: '45', PCU_LOG_STATS: '1' });
    const line = await host.waitFor(/código ([0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})/);
    const hostCode = line.match(/código (\S+)$/)[1];
    ok(`host arrancó (código ${hostCode})`);

    // ---------- emparejar: el código de la app tiene que ser el mismo que muestra el host
    await page.evaluate(() => window.PCU.connect());
    if (await page.isHidden('#settings')) await page.click('#btnSettings');
    await until(() => page.isVisible('#hostCodeBox'), 15000, 'código del host en Ajustes');
    assert.equal(await page.textContent('#hostCode'), hostCode);
    await page.click('#btnHostMatch');
    await until(async () => (await page.textContent('#hostPairState')).includes('Emparejada'));
    ok('códigos de verificación iguales en app y host; compu emparejada');

    // ---------- conectar: la oferta ya está lista antes del toque
    await page.click('#btnBack');
    await page.click('#btnRemote');
    await until(() => page.evaluate(() => !!window.PCU.R.prepared), 10000, 'oferta preparada');
    assert.equal(await page.isDisabled('#rConnect'), false);
    ok('oferta WebRTC + candidatos ICE preparados al abrir la vista (antes del toque)');
    await page.click('#rConnect');
    await until(() => page.evaluate(() => document.querySelector('#rVideo').videoWidth > 0), 20000, 'video');
    const vw = await page.evaluate(() => [document.querySelector('#rVideo').videoWidth, document.querySelector('#rVideo').videoHeight]);
    ok(`video en vivo ${vw[0]}×${vw[1]}`);
    const stats = await until(async () => { const t = await page.textContent('#rStats'); return /fps/.test(t) && t; }, 10000, 'estadísticas');
    ok(`estadísticas: ${stats}`);
    assert.ok(await page.isHidden('#rOverlay'));
    const attrs = await page.evaluate(() => { const v = document.querySelector('#rVideo'); return [v.playsInline, v.muted]; });
    assert.deepEqual(attrs, [true, true]);
    ok('video con playsinline y muted');

    // ---------- touchpad
    const pad = await page.$('#pad');
    if (await pad.isHidden()) await page.click('[data-panel="pad"]');
    const pb = await pad.boundingBox();
    const touch = (type, pts) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints: pts.map(([x, y, id]) => ({ x, y, id })) });
    // arrastrar un dedo
    await touch('touchStart', [[pb.x + 100, pb.y + 100, 1]]);
    for (let i = 1; i <= 10; i++) { await touch('touchMove', [[pb.x + 100 + i * 8, pb.y + 100 + i * 4, 1]]); await sleep(16); }
    await touch('touchEnd', []);
    await host.waitFor(/mover \d+ \d+/);
    ok('arrastrar mueve el puntero (con aceleración)');
    await sleep(350);
    await touch('touchStart', [[pb.x + 40, pb.y + 200, 2]]); await touch('touchEnd', []);
    await host.waitFor(/botón 1 abajo/); await host.waitFor(/botón 1 arriba/);
    await sleep(350);
    await touch('touchStart', [[pb.x + pb.width - 40, pb.y + 200, 3]]); await touch('touchEnd', []);
    await host.waitFor(/botón 2 abajo/); await host.waitFor(/botón 2 arriba/);
    ok('tocar mitad izquierda = clic izquierdo; mitad derecha = clic derecho');
    await touch('touchStart', [[pb.x + 100, pb.y + 200, 4], [pb.x + 160, pb.y + 200, 5]]);
    for (let i = 1; i <= 8; i++) { await touch('touchMove', [[pb.x + 100, pb.y + 200 - i * 10, 4], [pb.x + 160, pb.y + 200 - i * 10, 5]]); await sleep(16); }
    await touch('touchEnd', []);
    await host.waitFor(/rueda -\d+ 0/);
    ok('dos dedos hacia arriba = scroll hacia abajo (natural)');

    // ---------- teclado multitouch: Ctrl apretado con un dedo + C con otro
    await page.click('[data-panel="pad"]'); // cerrar touchpad
    await page.click('[data-panel="kbd"]');
    await page.$eval('#kbd', (e) => e.scrollIntoView({ block: 'end' }));
    const kc = async (u) => { const b = await (await page.$(`.key[data-u="${u}"]`)).boundingBox(); return [b.x + b.width / 2, b.y + b.height / 2]; };
    const [cx, cy] = await kc(0xe0), [lx, ly] = await kc(0x06);
    await touch('touchStart', [[cx, cy, 10]]);
    await touch('touchStart', [[cx, cy, 10], [lx, ly, 11]]);
    await sleep(60);
    await touch('touchEnd', [[lx, ly, 11]]); // en CDP, touchEnd lleva el punto que se levanta: primero la C
    await sleep(60);
    await touch('touchEnd', [[cx, cy, 10]]);
    await host.waitFor(/tecla arriba 0xe0/);
    const seq = host.lines.filter((l) => /tecla (abajo|arriba) 0x(e0|6)$/.test(l)).map((l) => l.replace(/^.*tecla /, ''));
    assert.deepEqual(seq.slice(-4), ['abajo 0xe0', 'abajo 0x6', 'arriba 0x6', 'arriba 0xe0']);
    ok('Ctrl se mantiene solo mientras el dedo está encima (Ctrl+C), nada queda pegado');
    // AltGr + Q = @ en Latinoamérica: se manda la tecla física, Windows pone el símbolo
    const [ax, ay] = await kc(0xe6), [qx, qy] = await kc(0x14);
    await touch('touchStart', [[ax, ay, 12]]); await touch('touchStart', [[ax, ay, 12], [qx, qy, 13]]);
    await touch('touchEnd', [[qx, qy, 13]]); await touch('touchEnd', [[ax, ay, 12]]);
    await host.waitFor(/tecla arriba 0xe6/);
    ok('AltGr+Q (@) llega como teclas físicas');

    // ---------- multimedia
    await page.click('[data-panel="media"]');
    await page.$eval('#panel-media', (e) => e.scrollIntoView({ block: 'end' }));
    await page.dispatchEvent('[data-media="cd"]', 'pointerdown', { pointerId: 20 });
    await page.dispatchEvent('[data-media="cd"]', 'pointerup', { pointerId: 20 });
    await host.waitFor(/multimedia 0xcd/);
    ok('multimedia play/pausa');

    if (process.env.E2E_SHOTS) {
      const shot = async (name) => page.screenshot({ path: `${process.env.E2E_SHOTS}/${name}.png`, fullPage: true });
      await page.evaluate(() => scrollTo(0, 0));
      await shot('1-vertical-teclado-multimedia');
      await page.click('[data-panel="media"]'); await page.click('[data-panel="kbd"]'); await page.click('[data-panel="pad"]');
      await shot('2-vertical-touchpad');
      await page.click('[data-panel="kbd"]');
      await page.setViewportSize({ width: 844, height: 390 });
      await page.evaluate(() => scrollTo(0, 0));
      await shot('3-horizontal');
      await page.click('#rFull');
      await page.screenshot({ path: `${process.env.E2E_SHOTS}/4-pantalla-completa.png` });
      await page.click('#rFull');
      await page.setViewportSize({ width: 390, height: 844 });
      await page.click('[data-panel="pad"]');
    }

    // ---------- se pierde la conexión con una tecla apretada: el host suelta a los ~2 s
    await page.$eval('#kbd', (e) => e.scrollIntoView({ block: 'end' }));
    const [cx2, cy2] = await kc(0xe0);
    await touch('touchStart', [[cx2, cy2, 30]]);
    await host.waitFor(/tecla abajo 0xe0/);
    await page.evaluate(() => { clearInterval(window.PCU.R.pingTimer); }); // sin latidos = como si se cortara
    const t0 = Date.now();
    await host.waitFor(/soltar todo \(sin mensajes por 2 s\)/, 5000);
    const dt = Date.now() - t0;
    assert.ok(dt > 1500 && dt < 3500, `soltó a los ${dt} ms`);
    await touch('touchEnd', []);
    ok(`sin mensajes con Ctrl apretado: el host soltó todo a los ${(dt / 1000).toFixed(1)} s`);

    // ---------- compu bloqueada: aviso con botón Desbloquear
    const pub = mqtt.connect('mqtt://127.0.0.1:1883');
    await new Promise((r) => pub.on('connect', r));
    const topic = (await page.evaluate(() => window.PCU.cfg().topic));
    pub.publish(`pcu/${topic}/host/in/test`, JSON.stringify({ locked: true }));
    await until(() => page.isVisible('#rLocked'), 5000, 'aviso de bloqueo');
    assert.ok(await page.isVisible('#rLockUnlock'));
    pub.publish(`pcu/${topic}/host/in/test`, JSON.stringify({ locked: false }));
    await until(() => page.isHidden('#rLocked'), 5000, 'fin del aviso');
    ok('compu bloqueada muestra el aviso con "Desbloquear" y se va al desbloquear');

    // ---------- renovar con Face ID antes de que venza (en la prueba la sesión dura 45 s)
    await until(() => page.isVisible('#rRenew'), 5000, 'botón Renovar');
    const expBefore = await page.evaluate(() => window.PCU.R.live.exp);
    await sleep(1200);
    await page.click('#rRenew');
    await until(() => page.evaluate((e) => window.PCU.R.live && window.PCU.R.live.exp > e && !window.PCU.R.live.renewing, expBefore), 8000, 'renovación');
    await host.waitFor(/sesión renovada/);
    ok('renovación con Face ID verificada por el host y firma del host verificada por la app');

    // ---------- vencimiento: a la hora (acá 45 s) el host corta y la app pide Face ID de nuevo
    await host.waitFor(/fin de sesión: venció la hora/, 60000);
    await until(async () => (await page.textContent('#rOvText')).includes('Pasó la hora'), 5000, 'aviso de vencimiento');
    ok('la sesión vence y la app vuelve a pedir Face ID');

    // ---------- ataques desde el broker (alguien que controla EMQX)
    await until(() => page.evaluate(() => !!window.PCU.R.prepared), 10000, 'oferta nueva');
    const attack = async (mutate) => page.evaluate(async (mut) => {
      const P = window.PCU, cfg = P.cfg(), prep = P.R.prepared;
      const extra = { f: prep.fp, h: cfg.hostId, m: null, q: 'auto' };
      if (mut === 'host') extra.h = 'deadbeefdeadbeef';
      if (mut === 'old') extra.t = Math.floor(Date.now() / 1000) - 200;
      const s = await P.signCommand('rs', extra);
      let sdp = prep.sdp;
      if (mut === 'fp') sdp = sdp.replace(/(a=fingerprint:sha-256 )([0-9A-F]{2})/g, (_, a, b) => a + (b === '00' ? '11' : '00'));
      const msg = JSON.stringify({ type: 'open', sdp, ...s.msg });
      const topic = `pcu/${cfg.topic}/host`;
      const c = window.mqtt.connect(cfg.testUrl, { username: 'u', password: 'p' });
      await new Promise((r) => c.on('connect', r));
      c.subscribe(topic + '/out');
      const send = () => new Promise((resolve) => {
        const h = (_t, b) => { const m = JSON.parse(b); if (m.n === s.nonce) { c.removeListener('message', h); resolve(m); } };
        c.on('message', h);
        c.publish(topic + '/in', msg);
        setTimeout(() => resolve(null), 8000);
      });
      const first = await send();
      const second = mut === 'replay' ? await send() : null;
      c.end();
      return { first, second };
    }, mutate);
    let r = await attack('fp');
    assert.equal(r.first.type, 'error'); assert.match(r.first.msg, /fingerprint/i);
    ok(`SDP con otro fingerprint DTLS: rechazado ("${r.first.msg}")`);
    r = await attack('host');
    assert.equal(r.first.type, 'error'); assert.match(r.first.msg, /otra compu/);
    ok('challenge para otra compu: rechazado');
    r = await attack('old');
    assert.equal(r.first.type, 'error'); assert.match(r.first.msg, /Hora/);
    ok('aserción vieja (200 s): rechazada');
    r = await attack('replay');
    assert.equal(r.first.type, 'answer');
    assert.equal(r.second.type, 'error'); assert.match(r.second.msg, /repetida/);
    ok('la misma aserción repetida: rechazada (nonce)');

    // ---------- hombre en el medio en el broker: cambia la respuesta del host -> la app no se conecta
    const tamper = async (mode) => {
      broker.aedes.authorizeForward = (client, packet) => {
        if (!packet.topic.endsWith('/host/out')) return packet;
        const m = JSON.parse(packet.payload.toString());
        if (m.type !== 'answer') return packet;
        if (mode === 'sig') m.hs = (m.hs[0] === 'A' ? 'B' : 'A') + m.hs.slice(1);
        if (mode === 'sdp') m.sdp = m.sdp.replace(/(a=fingerprint:sha-256 )([0-9A-F]{2})/g, (_, a, b) => a + (b === '00' ? '11' : '00'));
        if (mode === 'exp') m.exp += 3600;
        return { ...packet, payload: Buffer.from(JSON.stringify(m)) };
      };
      await until(() => page.evaluate(() => !!window.PCU.R.prepared), 10000, 'oferta');
      await page.click('#rConnect');
      const txt = await until(async () => { const t = await page.textContent('#rOvText'); return /firmada/.test(t) && t; }, 15000, 'rechazo de la respuesta');
      assert.equal(await page.evaluate(() => window.PCU.R.live), null);
      broker.aedes.authorizeForward = (c, p) => p;
      return txt;
    };
    if (await page.isHidden('#remote')) { await page.click('#btnRemote'); }
    for (const mode of ['sig', 'sdp', 'exp']) {
      const txt = await tamper(mode);
      ok(`respuesta del host alterada en el broker (${mode}): la app no se conecta ("${txt}")`);
    }

    // ---------- un impostor del host (otra clave): la app no se conecta
    await host.kill();
    const impostor = launch();
    await impostor.waitFor(/código/);
    await page.click('#rBack');
    await page.click('#btnSettings');
    await until(async () => (await page.textContent('#hostPairState')).includes('OTRA clave'), 10000, 'aviso de clave distinta');
    ok('si la compu cambia de clave, Ajustes avisa y no la acepta sola');
    await page.click('#btnBack');
    await page.click('#btnRemote');
    assert.match(await page.textContent('#rOvText'), /otra clave/);
    assert.ok(await page.isHidden('#rConnect'));
    // aunque la app intentara conectarse igual, la firma de la respuesta no verifica con la clave fijada
    const forged = await page.evaluate(async () => {
      const P = window.PCU;
      return P.verifyCode(new Uint8Array(65), 'host');
    });
    assert.match(forged, /^[0-9A-Z-]{19}$/);
    ok('con otra clave la vista Remoto no ofrece conectar');

    await impostor.kill();
    assert.deepEqual(errors.filter((e) => !/favicon|ERR_|WebSocket/.test(e)), []);
    ok('sin errores de JavaScript en la página');
    console.log(`\nOK: ${step} verificaciones`);
  } finally {
    for (const h of hosts) { try { if (h.proc.exitCode === null) await h.kill(); } catch { /* ya cerrado */ } }
    await browser.close();
    await broker.close();
  }
}

main().catch((e) => { console.error('\nFALLÓ:', e.stack || e.message); process.exit(1); });
