'use strict';
// PC Unlock Host: queda en la bandeja, escucha pedidos de sesión por MQTT y, si vienen firmados con la passkey
// (Face ID) y atados al fingerprint DTLS de la oferta, transmite la pantalla por WebRTC y recibe mouse/teclado.
const { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain, safeStorage, desktopCapturer, screen,
  powerMonitor, Notification, session: electronSession } = require('electron');
const path = require('node:path');
const crypto = require('node:crypto');
const mqtt = require('mqtt');
const { Config } = require('./config');
const { parsePairCode, verifyAssertion, ReplayGuard, sdpFingerprint, b64u } = require('./webauthn');
const identity = require('./identity');
const { decode } = require('./protocol');
const { Injector } = require('./input');
const { Gamepad } = require('./gamepad');

const VERSION = app.getVersion();
const SESSION_SECS = Number(process.env.PCU_SESSION_SECS) || 3600; // máximo 1 hora por Face ID
const MAX_SDP = 32 * 1024;
const ICON = path.join(__dirname, '..', 'build', 'icon.png');

if (process.env.PCU_USERDATA) app.setPath('userData', process.env.PCU_USERDATA);
if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0); }
app.setAppUserModelId('io.github.pcunlock.host');

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

let cfg, tray, settingsWin = null, rtcWin = null, client = null;
let pairing = null;           // { topic, key, mqtt }
let idPem = null, idPub = null, hostId = '';
let mqttState = 'sin configurar';
let locked = false;
let sess = null;              // sesión activa: { n, fo, fa, exp, timer, monitor, quality, connected, stats }
const guard = new ReplayGuard();
const gamepad = new Gamepad({ log: (m) => log(m) });
const injector = new Injector({ simulate: process.env.PCU_SIMULATE_INPUT === '1', log: process.env.PCU_LOG_INPUT ? (m) => log('[input]', m) : null });

const T = () => {
  const base = `pcu/${pairing.topic}/host`;
  return { state: `${base}/state`, in: `${base}/in`, out: `${base}/out` };
};

// ------------------------------------------------------------ identidad y configuración

function loadIdentity() {
  idPem = cfg.getSecret('identity');
  if (!idPem) { idPem = identity.generate(); cfg.setSecret('identity', idPem); log('clave de identidad nueva'); }
  idPub = identity.publicRaw(idPem);
  hostId = identity.deviceId(idPub);
}

function loadPairing() {
  const code = cfg.getSecret('pair');
  pairing = null;
  if (!code) return;
  try { pairing = parsePairCode(code); } catch (e) { log('código guardado inválido:', e.message); }
}

function savePairCode(code) {
  const p = parsePairCode(code); // tira error con mensaje para mostrar
  cfg.setSecret('pair', code.replace(/\s+/g, ''));
  pairing = p;
  endSession('cambió la configuración');
  connectMqtt();
}

// ------------------------------------------------------------ MQTT

function publishState() {
  if (!client?.connected || !pairing) return;
  const s = { online: true, v: VERSION, id: hostId, k: b64u.enc(idPub), locked, sess: !!sess, t: Math.floor(Date.now() / 1000) };
  client.publish(T().state, JSON.stringify(s), { qos: 1, retain: true });
}

function connectMqtt() {
  if (client) { client.end(true); client = null; }
  if (!pairing) { setMqttState('sin configurar'); return; }
  const m = pairing.mqtt;
  const url = process.env.PCU_MQTT_URL || `mqtts://${m.host}:${m.port}`;
  setMqttState('conectando');
  client = mqtt.connect(url, {
    username: m.user, password: m.pass,
    clientId: 'pcu-host-' + crypto.randomBytes(4).toString('hex'),
    protocolVersion: 4, clean: true, keepalive: 60, reconnectPeriod: 5000, connectTimeout: 15000,
    will: { topic: T().state, payload: '{"online":false}', qos: 1, retain: true },
  });
  client.on('connect', () => {
    setMqttState('conectado');
    client.subscribe(T().in, { qos: 1 });
    if (process.env.PCU_TEST_HOOKS === '1') client.subscribe(T().in + '/test'); // solo en pruebas automáticas
    publishState();
  });
  client.on('reconnect', () => setMqttState('reconectando'));
  client.on('offline', () => setMqttState('sin conexión'));
  client.on('error', (e) => { log('mqtt:', e.message); setMqttState('error: ' + e.message); });
  client.on('message', (topic, buf) => {
    if (process.env.PCU_TEST_HOOKS === '1' && topic === T().in + '/test') {
      try { const t = JSON.parse(buf); if ('locked' in t) setLocked(!!t.locked); } catch { /* nada */ }
      return;
    }
    if (topic !== T().in || buf.length > MAX_SDP + 4096) return;
    let msg;
    try { msg = JSON.parse(buf.toString('utf8')); } catch { return; }
    if (msg.type === 'open') handleOpen(msg).catch((e) => log('open:', e.message));
  });
}

function reply(obj) {
  if (client?.connected) client.publish(T().out, JSON.stringify(obj), { qos: 1 });
}

// Nonce del challenge sin verificar nada, solo para poder contestar el error.
function peekNonce(cdB64) {
  try { return JSON.parse(b64u.dec(JSON.parse(b64u.dec(cdB64)).challenge)).n; } catch { return undefined; }
}

// ------------------------------------------------------------ sesión

async function handleOpen(msg) {
  let cmd, fo;
  try {
    if (typeof msg.sdp !== 'string' || msg.sdp.length > MAX_SDP) throw new Error('Oferta inválida');
    cmd = verifyAssertion(pairing.key, msg.ad, msg.cd, msg.sig);
    if (cmd.c !== 'rs') throw new Error('Orden inesperada');
    if (cmd.h !== hostId) throw new Error('El pedido es para otra compu (¿volviste a emparejar?)');
    fo = sdpFingerprint(msg.sdp);
    if (cmd.f !== fo) throw new Error('El fingerprint DTLS no coincide con el firmado');
    guard.check(cmd);
  } catch (e) {
    log('sesión rechazada:', e.message);
    reply({ type: 'error', n: peekNonce(msg.cd), msg: e.message });
    return;
  }
  endSession('nueva sesión');
  const exp = Math.floor(Date.now() / 1000) + SESSION_SECS;
  sess = { n: cmd.n, fo, fa: null, exp, connected: false, monitor: cmd.m ?? cfg.get('monitor', null), quality: cmd.q === 'saver' ? 'saver' : 'auto',
    fps: cmd.r === 60 ? 60 : 30 };
  armExpiry();
  const mine = sess;
  setTimeout(() => { if (sess === mine && !sess.connected) endSession('no se pudo conectar en 30 s'); }, 30000);
  log('sesión abierta, vence', new Date(exp * 1000).toLocaleTimeString(), `(${sess.fps} fps)`);
  try {
    const src = await pickSource(sess.monitor);
    const ice = sanitizeIce(msg.ice);
    const answer = await rtcStart({ offer: msg.sdp, ice, source: src, quality: sess.quality, fps: sess.fps });
    const fa = sdpFingerprint(answer);
    sess.fa = fa;
    reply({ type: 'answer', n: cmd.n, sdp: answer, exp, hs: identity.sign(idPem, identity.answerPayload(cmd.n, fo, fa, exp)) });
    notify('Sesión remota abierta', 'Alguien con tu Face ID abrió la pantalla remota. Podés cortarla desde la bandeja.');
  } catch (e) {
    log('no se pudo iniciar:', e.message);
    reply({ type: 'error', n: cmd.n, msg: 'La compu no pudo iniciar la transmisión: ' + e.message });
    endSession('error');
  }
  refreshUi();
}

function armExpiry() {
  clearTimeout(sess.timer);
  sess.timer = setTimeout(() => {
    sess.endReason = 'venció la hora';
    rtcSend('ctl', { t: 'bye', why: 'expired' });
    setTimeout(() => endSession('venció la hora'), 300);
  }, Math.max(0, sess.exp * 1000 - Date.now()));
}

function handleRenew(m) {
  try {
    const cmd = verifyAssertion(pairing.key, m.ad, m.cd, m.sig);
    if (cmd.c !== 'rr' || cmd.h !== hostId || cmd.f !== sess.fo) throw new Error('Renovación inválida');
    guard.check(cmd);
    sess.exp = Math.floor(Date.now() / 1000) + SESSION_SECS;
    armExpiry();
    rtcSend('ctl', { t: 'renewed', n: cmd.n, exp: sess.exp, hs: identity.sign(idPem, identity.renewPayload(cmd.n, sess.fo, sess.fa, sess.exp)) });
    log('sesión renovada');
  } catch (e) {
    rtcSend('ctl', { t: 'error', msg: e.message });
  }
}

function endSession(why) {
  if (!sess) return;
  log('fin de sesión:', sess.endReason || why);
  clearTimeout(sess.timer);
  sess = null;
  injector.releaseAll();
  gamepad.unplug();
  if (rtcWin && !rtcWin.isDestroyed()) rtcWin.destroy();
  rtcWin = null;
  publishState();
  refreshUi();
}

function sanitizeIce(ice) {
  const def = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
  if (!Array.isArray(ice)) return def;
  const out = [];
  for (const s of ice.slice(0, 4)) {
    const urls = [].concat(s?.urls || []).filter((u) => typeof u === 'string' && /^(stun|turns?):[^\s]{3,200}$/.test(u)).slice(0, 4);
    if (!urls.length) continue;
    const e = { urls };
    if (typeof s.username === 'string') e.username = s.username.slice(0, 256);
    if (typeof s.credential === 'string') e.credential = s.credential.slice(0, 256);
    out.push(e);
  }
  return out.length ? out : def;
}

// ------------------------------------------------------------ monitores

async function monitors() {
  const displays = screen.getAllDisplays();
  const primary = screen.getPrimaryDisplay().id;
  return displays.map((d, i) => ({
    id: String(d.id),
    name: `Pantalla ${i + 1}${d.id === primary ? ' (principal)' : ''}`,
    w: Math.round(d.bounds.width * d.scaleFactor),
    h: Math.round(d.bounds.height * d.scaleFactor),
    primary: d.id === primary,
  }));
}

async function pickSource(monitorId) {
  const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 0, height: 0 } });
  if (!sources.length) throw new Error('Windows no dejó capturar la pantalla');
  const displays = screen.getAllDisplays();
  const want = monitorId ? String(monitorId) : String(screen.getPrimaryDisplay().id);
  const src = sources.find((s) => s.display_id === want) || sources.find((s) => s.display_id === String(screen.getPrimaryDisplay().id)) || sources[0];
  const d = displays.find((x) => String(x.id) === src.display_id) || screen.getPrimaryDisplay();
  return { id: src.id, displayId: String(d.id), w: Math.round(d.bounds.width * d.scaleFactor), h: Math.round(d.bounds.height * d.scaleFactor), bounds: d.bounds };
}

// Si el puntero está en otro monitor, lo lleva al centro del que se está mirando.
function bringCursorTo(src) {
  try {
    const c = screen.getCursorScreenPoint();
    const b = src.bounds;
    if (c.x >= b.x && c.x < b.x + b.width && c.y >= b.y && c.y < b.y + b.height) return;
    const p = screen.dipToScreenPoint({ x: b.x + b.width / 2, y: b.y + b.height / 2 });
    injector.moveTo(p.x, p.y);
  } catch (e) { log('cursor:', e.message); }
}

// ------------------------------------------------------------ WebRTC (ventana oculta)

function rtcSend(ch, data) { if (rtcWin && !rtcWin.isDestroyed()) rtcWin.webContents.send(ch, data); }

function rtcStart(opts) {
  if (rtcWin && !rtcWin.isDestroyed()) rtcWin.destroy();
  rtcWin = new BrowserWindow({
    show: false, width: 320, height: 240,
    webPreferences: { preload: path.join(__dirname, 'rtc', 'preload.js'), contextIsolation: true, sandbox: true, backgroundThrottling: false },
  });
  const win = rtcWin;
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('tiempo agotado armando la respuesta')), 20000);
    win.webContents.once('did-finish-load', () => win.webContents.send('start', opts));
    win.webContents.ipc.once('answer', (_e, r) => { clearTimeout(to); r.error ? reject(new Error(r.error)) : resolve(r.sdp); });
    win.webContents.on('render-process-gone', () => endSession('se cerró el proceso de video'));
    win.loadFile(path.join(__dirname, 'rtc', 'rtc.html'));
    bringCursorTo(opts.source);
    if (sess) sess.source = opts.source;
  });
}

function setupRtcIpc() {
  ipcMain.on('rtc-input', (e, data) => {
    if (!sess || e.sender !== rtcWin?.webContents) return;
    try {
      const cmds = decode(Buffer.from(data));
      for (const c of cmds) if (c.op === 10) gamepad.set(c.pad); else if (c.op === 9) gamepad.touch();
      injector.apply(cmds.filter((c) => c.op !== 10));
    } catch (err) { log(err.message); }
  });
  ipcMain.on('rtc-ctl', async (e, m) => {
    if (!sess || e.sender !== rtcWin?.webContents || !m || typeof m !== 'object') return;
    switch (m.t) {
      case 'hello':
        rtcSend('ctl', { t: 'hello', v: VERSION, exp: sess.exp, locked, monitors: await monitors(), monitor: sess.source?.displayId,
          fps: sess.fps, pad: Gamepad.available() });
        break;
      case 'monitor': {
        const src = await pickSource(m.id);
        sess.monitor = src.displayId;
        sess.source = src;
        cfg.set('monitor', src.displayId);
        rtcSend('source', src);
        bringCursorTo(src);
        rtcSend('ctl', { t: 'monitor', id: src.displayId });
        break;
      }
      case 'quality':
        sess.quality = m.mode === 'saver' ? 'saver' : 'auto';
        rtcSend('quality', sess.quality);
        break;
      case 'renew': handleRenew(m); break;
      case 'fps':
        sess.fps = m.v === 60 ? 60 : 30;
        rtcSend('fps', sess.fps);
        break;
      case 'pad': {
        const err = m.on ? gamepad.plug() : (gamepad.unplug(), '');
        rtcSend('ctl', { t: 'pad', on: !!m.on && !err, err });
        break;
      }
      case 'bye': endSession('la app cerró la sesión'); break;
      default: break;
    }
  });
  ipcMain.on('rtc-state', (e, st) => {
    if (!sess || e.sender !== rtcWin?.webContents) return;
    log('webrtc:', st);
    if (st === 'connected') { sess.connected = true; refreshUi(); }
    if (st === 'failed' || st === 'closed' || st === 'gone') endSession('se cortó la conexión');
  });
  ipcMain.on('rtc-stats', (e, s) => { if (sess && e.sender === rtcWin?.webContents) { sess.stats = s; if (process.env.PCU_LOG_STATS) log('stats', JSON.stringify(s)); } });
  ipcMain.on('rtc-log', (_e, m) => log('[rtc]', m));
}

// ------------------------------------------------------------ bloqueo de Windows

function setLocked(v) {
  if (v === locked) return;
  locked = v;
  log(v ? 'compu bloqueada' : 'compu desbloqueada');
  publishState();
  rtcSend('ctl', { t: 'locked', v });
  refreshUi();
}

// ------------------------------------------------------------ interfaz (bandeja y ventana)

function notify(title, body) {
  try { if (Notification.isSupported()) new Notification({ title, body, icon: ICON, silent: true }).show(); } catch { /* sin notificaciones */ }
}

function setMqttState(s) { mqttState = s; refreshUi(); }

function uiState() {
  return {
    version: VERSION,
    paired: !!pairing,
    mqtt: mqttState,
    code: identity.verificationCode(idPub, 'host'),
    locked,
    session: sess ? { exp: sess.exp, connected: sess.connected, stats: sess.stats || null } : null,
    startAtLogin: cfg.get('startAtLogin', true),
    canAutostart: app.isPackaged,
  };
}

function refreshUi() {
  if (tray) {
    const st = sess ? 'sesión remota activa' : mqttState;
    tray.setToolTip(`PC Unlock Host — ${st}`);
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: 'Abrir PC Unlock Host', click: showSettings },
      { label: 'Cortar sesión remota', enabled: !!sess, click: () => { rtcSend('ctl', { t: 'bye', why: 'host' }); setTimeout(() => endSession('cortada desde la bandeja'), 200); } },
      { type: 'separator' },
      { label: 'Salir', click: () => { app.isQuitting = true; app.quit(); } },
    ]));
  }
  if (settingsWin && !settingsWin.isDestroyed()) settingsWin.webContents.send('state', uiState());
}

function showSettings() {
  if (settingsWin && !settingsWin.isDestroyed()) { settingsWin.show(); settingsWin.focus(); return; }
  settingsWin = new BrowserWindow({
    width: 520, height: 720, resizable: true, title: 'PC Unlock Host', icon: ICON, autoHideMenuBar: true,
    backgroundColor: '#0f1115',
    webPreferences: { preload: path.join(__dirname, 'ui', 'preload.js'), contextIsolation: true, sandbox: true },
  });
  settingsWin.loadFile(path.join(__dirname, 'ui', 'settings.html'));
  settingsWin.on('closed', () => { settingsWin = null; });
}

function setupUiIpc() {
  ipcMain.handle('ui-state', () => uiState());
  ipcMain.handle('ui-save-pair', (_e, code) => {
    try { savePairCode(String(code || '')); return { ok: true }; } catch (e) { return { ok: false, msg: e.message }; }
  });
  ipcMain.handle('ui-option', (_e, k, v) => {
    if (k === 'startAtLogin') { cfg.set('startAtLogin', !!v); applyAutostart(); }
    refreshUi();
  });
  ipcMain.handle('ui-end-session', () => { rtcSend('ctl', { t: 'bye', why: 'host' }); setTimeout(() => endSession('cortada desde la ventana'), 200); });
}

function applyAutostart() {
  if (!app.isPackaged) return;
  app.setLoginItemSettings({ openAtLogin: cfg.get('startAtLogin', true), args: ['--hidden'] });
}

// ------------------------------------------------------------ inicio

app.on('second-instance', showSettings);
app.on('window-all-closed', () => { /* sigue en la bandeja */ });

app.whenReady().then(() => {
  cfg = new Config(app.getPath('userData'), safeStorage);
  loadIdentity();
  if (process.env.PCU_PAIR_CODE) cfg.setSecret('pair', process.env.PCU_PAIR_CODE); // solo para pruebas
  loadPairing();

  // Solo la ventana de WebRTC puede capturar la pantalla; nada más pide permisos.
  electronSession.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(perm === 'media' && wc === rtcWin?.webContents));

  setupRtcIpc();
  setupUiIpc();
  applyAutostart();

  tray = new Tray(nativeImage.createFromPath(ICON).resize({ width: 16, height: 16 }));
  tray.on('click', showSettings);
  refreshUi();

  powerMonitor.on('lock-screen', () => setLocked(true));
  powerMonitor.on('unlock-screen', () => setLocked(false));
  setLocked(powerMonitor.getSystemIdleState(1) === 'locked');
  setInterval(() => setLocked(powerMonitor.getSystemIdleState(1) === 'locked'), 5000);

  log(`PC Unlock Host ${VERSION} — id ${hostId} — código ${identity.verificationCode(idPub, 'host')}`);
  try { const vd = injector.virtualDesktop(); log(`escritorio virtual ${vd.w}×${vd.h} en (${vd.x},${vd.y})${injector.simulate ? ' (entrada simulada)' : ''}`); }
  catch (e) { log('ERROR: no se pudo cargar la inyección de entrada:', e.message); }
  connectMqtt();
  if (!pairing || !process.argv.includes('--hidden')) { if (!process.env.PCU_NO_WINDOW) showSettings(); }
});

app.on('before-quit', () => {
  injector.close();
  gamepad.close();
  if (client?.connected && pairing) client.publish(T().state, '{"online":false}', { qos: 1, retain: true });
  client?.end();
});
