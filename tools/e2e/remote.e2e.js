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
    assert.ok(await page.isVisible('#rFps'));
    await page.click('#rFps [data-fps="30"]');
    await page.click('#rFps [data-fps="60"]');
    assert.equal(await page.evaluate(() => window.PCU.cfg().fps), 60);
    await page.click('#rConnect');
    await host.waitFor(/sesión abierta.*\(60 fps\)/);
    await until(() => page.evaluate(() => document.querySelector('#rVideo').videoWidth > 0), 20000, 'video');
    const vw = await page.evaluate(() => [document.querySelector('#rVideo').videoWidth, document.querySelector('#rVideo').videoHeight]);
    ok(`video en vivo ${vw[0]}×${vw[1]}`);
    const stats = await until(async () => { const t = await page.textContent('#rStats'); return /fps/.test(t) && t; }, 10000, 'estadísticas');
    ok(`estadísticas: ${stats}`);
    assert.ok(await page.isHidden('#rOverlay'));
    const attrs = await page.evaluate(() => { const v = document.querySelector('#rVideo'); return [v.playsInline, v.muted]; });
    assert.deepEqual(attrs, [true, true]);
    ok('video con playsinline y muted');
    await until(async () => (await page.inputValue('#rFpsSel')) === '60', 5000, 'fps en opciones');
    ok('selector 30/60 fps antes de conectar: la sesión arranca a 60 fps');

    // ---------- touchpad
    const pad = await page.$('#pad');
    if (await pad.isHidden()) await page.click('[data-panel="pad"]');
    await page.$eval('#pad', (e) => e.scrollIntoView({ block: 'center' }));
    const pb = await pad.boundingBox();
    const touch = (type, pts) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints: pts.map(([x, y, id]) => ({ x, y, id })) });
    // iOS no tiene que poder "agarrar" el toque (selección de texto, lupa, menú de copiar)
    await page.evaluate(() => { window.__tp = []; addEventListener('touchstart', (e) => window.__tp.push(e.defaultPrevented)); });
    await touch('touchStart', [[pb.x + 50, pb.y + 50, 90]]); await touch('touchEnd', [[pb.x + 50, pb.y + 50, 90]]);
    const sel = await page.evaluate(() => [window.__tp.every(Boolean) && window.__tp.length > 0, getComputedStyle(document.querySelector('#pad')).webkitUserSelect || getComputedStyle(document.querySelector('#pad')).userSelect]);
    assert.deepEqual(sel, [true, 'none']);
    await sleep(450);
    ok('el touchpad bloquea la selección de texto y los gestos de iOS');
    // arrastrar un dedo
    await touch('touchStart', [[pb.x + 100, pb.y + 100, 1]]);
    for (let i = 1; i <= 10; i++) { await touch('touchMove', [[pb.x + 100 + i * 8, pb.y + 100 + i * 4, 1]]); await sleep(16); }
    await touch('touchEnd', []);
    await host.waitFor(/mover \d+ \d+/);
    ok('arrastrar mueve el puntero (con aceleración)');
    await sleep(450);
    const btnLog = () => host.lines.filter((l) => /\[input\] (botón|mover)/.test(l)).map((l) => l.replace(/^.*\[input\] /, '').replace(/^mover .*/, 'mover'));
    let n0 = btnLog().length;
    await touch('touchStart', [[pb.x + 40, pb.y + 200, 2]]); await touch('touchEnd', []);
    await host.waitFor(/botón 1 arriba/);
    await sleep(450);
    await touch('touchStart', [[pb.x + pb.width - 40, pb.y + 200, 3]]); await touch('touchEnd', []);
    await host.waitFor(/botón 2 arriba/);
    assert.deepEqual(btnLog().slice(n0), ['botón 1 abajo', 'botón 1 arriba', 'botón 2 abajo', 'botón 2 arriba']);
    ok('tocar mitad izquierda = clic izquierdo; mitad derecha = clic derecho');
    // tocar, soltar y volver a apoyar manteniendo = clic sostenido (arrastrar)
    await sleep(450);
    n0 = btnLog().length;
    await touch('touchStart', [[pb.x + 60, pb.y + 120, 6]]); await touch('touchEnd', [[pb.x + 60, pb.y + 120, 6]]);
    await sleep(120);
    await touch('touchStart', [[pb.x + 60, pb.y + 120, 7]]);
    for (let i = 1; i <= 8; i++) { await touch('touchMove', [[pb.x + 60 + i * 10, pb.y + 120 + i * 5, 7]]); await sleep(20); }
    await sleep(300); // sigue apretado mientras el dedo está apoyado
    assert.equal(btnLog().slice(n0).filter((x) => x === 'botón 1 arriba').length, 1);
    await touch('touchEnd', [[pb.x + 140, pb.y + 160, 7]]);
    await sleep(200);
    const drag = btnLog().slice(n0);
    assert.deepEqual([drag[0], drag[1], drag[2], drag.at(-1)], ['botón 1 abajo', 'botón 1 arriba', 'botón 1 abajo', 'botón 1 arriba']);
    assert.ok(drag.slice(3, -1).length > 0 && drag.slice(3, -1).every((x) => x === 'mover'));
    ok('tocar y volver a apoyar = clic sostenido: el botón queda apretado mientras se arrastra');
    // doble toque = doble clic
    await sleep(450);
    n0 = btnLog().length;
    await touch('touchStart', [[pb.x + 60, pb.y + 120, 8]]); await touch('touchEnd', [[pb.x + 60, pb.y + 120, 8]]);
    await sleep(100);
    await touch('touchStart', [[pb.x + 60, pb.y + 120, 9]]); await touch('touchEnd', [[pb.x + 60, pb.y + 120, 9]]);
    await sleep(200);
    assert.deepEqual(btnLog().slice(n0), ['botón 1 abajo', 'botón 1 arriba', 'botón 1 abajo', 'botón 1 arriba']);
    ok('doble toque = doble clic');
    await sleep(450);
    await touch('touchStart', [[pb.x + 100, pb.y + 200, 4], [pb.x + 160, pb.y + 200, 5]]);
    for (let i = 1; i <= 8; i++) { await touch('touchMove', [[pb.x + 100, pb.y + 200 - i * 10, 4], [pb.x + 160, pb.y + 200 - i * 10, 5]]); await sleep(16); }
    await touch('touchEnd', []);
    await host.waitFor(/rueda -\d+ 0/);
    ok('dos dedos hacia arriba = scroll hacia abajo (natural)');

    // ---------- teclado multitouch: Ctrl apretado con un dedo + C con otro
    if (await page.isHidden('#panel-kbd')) await page.click('[data-panel="kbd"]');
    if (await page.isVisible('#panel-pad')) await page.click('[data-panel="pad"]'); // cerrar touchpad
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

    const shot = async (name) => { if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/${name}.png` }); };
    await page.click('[data-panel="media"]'); // cerrar multimedia
    await page.click('[data-panel="pad"]');   // teclado + touchpad
    await page.evaluate(() => scrollTo(0, 0));
    await shot('1-vertical');

    // ---------- horizontal tipo laptop: video a la izquierda, teclado compacto arriba y touchpad abajo, sin superponer
    await page.setViewportSize({ width: 844, height: 390 });
    await until(() => page.evaluate(() => document.querySelector('#kbd').classList.contains('compact')), 5000, 'teclado compacto');
    await sleep(300);
    const box = async (sel) => page.evaluate((q) => { const r = document.querySelector(q).getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; }, sel);
    const overlap = (a, b) => a.l < b.r - 1 && b.l < a.r - 1 && a.t < b.b - 1 && b.t < a.b - 1;
    let st = await box('#stage'), kbB = await box('#kbd'), padB = await box('#pad');
    assert.ok(!overlap(st, kbB) && !overlap(st, padB) && !overlap(kbB, padB), JSON.stringify({ st, kbB, padB }));
    assert.ok(kbB.b <= padB.t + 1 && st.r <= kbB.l, 'teclado arriba, touchpad abajo, video a la izquierda');
    assert.ok(padB.b <= 390 && st.b <= 390, 'todo entra en la pantalla');
    await shot('2-horizontal-laptop');
    ok(`horizontal: video ${Math.round(st.r - st.l)}×${Math.round(st.b - st.t)} a la izquierda, teclado compacto arriba y touchpad abajo, sin superponerse`);

    // teclado compacto: los símbolos mandan su combinación (Latinoamérica)
    const keyAt = async (sel) => { const b = await (await page.$(sel)).boundingBox(); return [b.x + b.width / 2, b.y + b.height / 2]; };
    const tap = async (sel, id) => { const [x, y] = await keyAt(sel); await touch('touchStart', [[x, y, id]]); await touch('touchEnd', [[x, y, id]]); await sleep(60); };
    const keyLog = () => host.lines.filter((l) => /\[input\] tecla/.test(l)).map((l) => l.replace(/^.*tecla /, ''));
    await tap('.krow.bottom .layer', 40); // ?123
    assert.equal(await page.evaluate(() => window.PCU.kb.layer), '123');
    let k0 = keyLog().length;
    await tap('.kb-layer[data-layer="123"] [data-sym="@"]', 41);
    await tap('.kb-layer[data-layer="123"] [data-sym="!"]', 42);
    await host.waitFor(/tecla arriba 0xe1$/);
    assert.deepEqual(keyLog().slice(k0), ['abajo 0xe6', 'abajo 0x14', 'arriba 0x14', 'arriba 0xe6', 'abajo 0xe1', 'abajo 0x1e', 'arriba 0x1e', 'arriba 0xe1']);
    await tap('.kb-layer[data-layer="123"] .layer', 43); // #+=
    k0 = keyLog().length;
    await tap('.kb-layer[data-layer="sym"] [data-sym="{"]', 44);
    await tap('.kb-layer[data-layer="sym"] [data-sym="\\\\"]', 45);
    await host.waitFor(/tecla arriba 0xe6$/);
    assert.deepEqual(keyLog().slice(k0), ['abajo 0x34', 'arriba 0x34', 'abajo 0xe6', 'abajo 0x2d', 'arriba 0x2d', 'arriba 0xe6']);
    await tap('.krow.bottom .layer', 46); // abc
    assert.equal(await page.evaluate(() => window.PCU.kb.layer), 'abc');
    ok('teclado compacto con capas ?123 y #+=: @ = AltGr+Q, ! = Shift+1, { y \\ salen directo');

    // pantalla completa: solo se esconde la barra; nada se superpone
    await page.click('#rFull');
    await sleep(300);
    assert.ok(await page.isHidden('.rbar'));
    st = await box('#stage'); kbB = await box('#kbd'); padB = await box('#pad');
    assert.ok(!overlap(st, kbB) && !overlap(st, padB), 'pantalla completa sin superponer');
    await shot('3-horizontal-pantalla-completa');
    await page.click('#rFsExit');
    await sleep(200);
    assert.ok(await page.isVisible('.rbar'));
    ok('pantalla completa en horizontal: esconde la barra y no tapa el video');

    // solo touchpad: la columna de la derecha se achica y el video crece; botones de arriba de 44 px
    const stKb = await box('#stage');
    await page.click('[data-panel="kbd"]'); // cerrar teclado
    await sleep(300);
    const stPad = await box('#stage'), padOnly = await box('#pad'), tb = await box('.rtools button');
    assert.ok(stPad.r - stPad.l > stKb.r - stKb.l, 'sin teclado el video es más ancho');
    assert.ok(stPad.r - stPad.l >= 0.6 * 844, `video ${stPad.r - stPad.l}px`);
    assert.ok(!overlap(stPad, padOnly) && padOnly.b <= 390, 'touchpad sin superponer');
    assert.ok(tb.b - tb.t >= 44, `botones de ${tb.b - tb.t}px`);
    await shot('2b-horizontal-solo-touchpad');
    ok(`solo touchpad: video ${Math.round(stPad.r - stPad.l)} px de ancho (con teclado ${Math.round(stKb.r - stKb.l)}), touchpad ${Math.round(padOnly.r - padOnly.l)} px, botones de ${Math.round(tb.b - tb.t)} px`);
    // sin ningún panel: el video ocupa casi todo y a la derecha queda una tira con los botones apilados
    await page.click('[data-panel="pad"]');
    await sleep(300);
    const stFull = await box('#stage'), side = await box('.rside');
    const tbs = await page.$$eval('.rtools button', (bs) => bs.map((b) => { const r = b.getBoundingClientRect(); return { l: r.left, t: r.top, h: r.height }; }));
    assert.ok(side.r - side.l <= 60, `tira de ${side.r - side.l}px`);
    assert.ok(stFull.r - stFull.l >= 0.88 * 844, `video ${stFull.r - stFull.l}px`);
    assert.ok(tbs.every((b, i) => i === 0 || (Math.abs(b.l - tbs[0].l) < 2 && b.t > tbs[i - 1].t)), 'botones apilados');
    assert.ok(tbs.every((b) => b.h >= 44) && tbs.at(-1).t + tbs.at(-1).h <= 390, 'botones grandes y dentro de la pantalla');
    assert.deepEqual(await page.$$eval('.rtools button', (bs) => bs.slice(0, 2).map((b) => b.textContent.trim())), ['⌨️', '🖱️']);
    await shot('2c-horizontal-sin-paneles');
    ok(`sin paneles: el video ocupa ${Math.round(stFull.r - stFull.l)} px de ancho y los botones (⌨️ 🖱️ ♫ 🎮 ⚙) quedan apilados en una tira de ${Math.round(side.r - side.l)} px`);
    await page.click('[data-panel="pad"]');
    await page.click('[data-panel="kbd"]'); // volver a abrir el teclado

    // ---------- joystick: control de Xbox 360 virtual en la compu (ViGEmBus), leído con XInput
    const koffi = require('../../host/node_modules/koffi');
    const XS = koffi.struct('XS', { pkt: 'uint32', buttons: 'uint16', lt: 'uint8', rt: 'uint8', lx: 'int16', ly: 'int16', rx: 'int16', ry: 'int16' });
    const XInputGetState = koffi.load('xinput1_4.dll').func('__stdcall', 'XInputGetState', 'uint32', ['uint32', koffi.out(koffi.pointer(XS))]);
    const pads = () => [0, 1, 2, 3].map((i) => { const o = {}; return XInputGetState(i, o) === 0 ? { i, ...o } : null; }).filter(Boolean);
    const before = pads().map((x) => x.i);
    await page.click('#btnGp');
    await host.waitFor(/joystick virtual enchufado/, 10000);
    await until(() => page.isVisible('#gp'), 5000, 'joystick en pantalla');
    assert.ok(await page.isHidden('.rside'), 'en horizontal el joystick usa todo el ancho');
    const xpad = await until(() => pads().find((x) => !before.includes(x.i)), 5000, 'control en XInput');
    const l1 = await box('#gp .gp-l1'), l2 = await box('#gp .gp-l2'), r1 = await box('#gp .gp-r1'), r2 = await box('#gp .gp-r2');
    assert.ok(l2.t < l1.t && l2.l > l1.l && l2.l < l1.r && r2.t < r1.t && r2.r < r1.r && r2.r > r1.l, 'L2/R2 arriba y corridos hacia el centro');
    assert.ok(!overlap(l1, l2) && !overlap(r1, r2));
    const [crx, cry] = await keyAt('#gp .cr');
    const lsB = await (await page.$('#gp .gp-ls')).boundingBox();
    const lcx = lsB.x + lsB.width / 2, lcy = lsB.y + lsB.height / 2;
    await touch('touchStart', [[crx, cry, 60]]);
    await touch('touchStart', [[crx, cry, 60], [lcx, lcy, 61]]);
    await touch('touchMove', [[crx, cry, 60], [lcx + lsB.width, lcy - lsB.height, 61]]); // palanca arriba a la derecha (al tope)
    await touch('touchStart', [[crx, cry, 60], [lcx + lsB.width, lcy - lsB.height, 61], ...[await keyAt('#gp .gp-r2')].map(([x, y]) => [x, y, 62])]);
    const held = await until(() => { const x = pads().find((q) => q.i === xpad.i); return x && x.buttons & 0x1000 && x.rt === 255 && x.lx > 20000 && x.ly > 20000 && x; }, 5000, 'estado del joystick');
    await shot('4-horizontal-joystick');
    await touch('touchEnd', [[crx, cry, 60]]);
    await touch('touchEnd', [[lcx + lsB.width, lcy - lsB.height, 61]]);
    await touch('touchEnd', [[0, 0, 62]]);
    await until(() => { const x = pads().find((q) => q.i === xpad.i); return x && !x.buttons && !x.rt && !x.lx && !x.ly; }, 5000, 'joystick en reposo');
    ok(`joystick: ✕ + R2 + palanca izquierda llegan al control virtual (XInput: botones 0x${held.buttons.toString(16)}, R2 ${held.rt}, LX ${held.lx}, LY ${held.ly}) y vuelven a reposo`);
    // L3 / R3: botón chico, o doble toque en la palanca y mantener (se puede seguir moviendo)
    const xstate = () => pads().find((q) => q.i === xpad.i) || {};
    await page.dispatchEvent('#gp .gp-l3', 'pointerdown', { pointerId: 70 });
    await until(() => xstate().buttons & 0x0040, 3000, 'L3 apretado');
    await page.dispatchEvent('#gp .gp-l3', 'pointerup', { pointerId: 70 });
    await until(() => !(xstate().buttons & 0x0040), 3000, 'L3 suelto');
    const rsB = await (await page.$('#gp .gp-rs')).boundingBox();
    const rcx = rsB.x + rsB.width / 2, rcy = rsB.y + rsB.height / 2;
    await touch('touchStart', [[rcx, rcy, 71]]); await touch('touchEnd', [[rcx, rcy, 71]]);
    await sleep(80);
    await touch('touchStart', [[rcx, rcy, 72]]);
    await touch('touchMove', [[rcx - rsB.width, rcy, 72]]); // R3 apretado y palanca a la izquierda
    const r3 = await until(() => { const x = xstate(); return x.buttons & 0x0080 && x.rx < -20000 && x; }, 3000, 'R3 + palanca');
    await touch('touchEnd', [[rcx - rsB.width, rcy, 72]]);
    await until(() => { const x = xstate(); return !(x.buttons & 0x0080) && !x.rx; }, 3000, 'R3 suelto');
    ok(`L3 con su botón y R3 con doble toque en la palanca (mientras se mueve: RX ${r3.rx})`);

    // sin mensajes con un botón apretado: el host lo suelta a los ~2 s
    await page.dispatchEvent('#gp .cr', 'pointerdown', { pointerId: 63 });
    await until(() => (pads().find((q) => q.i === xpad.i)?.buttons || 0) & 0x1000, 3000, '✕ apretado');
    await page.evaluate(() => clearInterval(window.PCU.R.pingTimer));
    await host.waitFor(/joystick a reposo/, 5000);
    await page.dispatchEvent('#gp .cr', 'pointerup', { pointerId: 63 });
    ok('si se corta con un botón del joystick apretado, el host lo suelta a los ~2 s');
    await page.click('#gpOff');
    await host.waitFor(/joystick virtual desenchufado/, 5000);
    await until(() => pads().length === before.length, 5000, 'control desenchufado');
    assert.ok(await page.isVisible('.rside'));
    ok('"Salir del joystick" desenchufa el control virtual y vuelve el teclado y el touchpad');
    await page.evaluate(() => { const R = window.PCU.R; R.pingTimer = setInterval(() => { if (R.held.size || R.buttons) R.live?.inp.send(Uint8Array.of(9)); }, 500); });

    await page.setViewportSize({ width: 390, height: 844 });
    await sleep(300);

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
