'use strict';
/* PC Unlock — web app.
 * Cada orden se firma con una passkey (Face ID) y se manda por MQTT a la ESP32,
 * que verifica la firma antes de prender / desbloquear / bloquear la compu. */

const $ = (s) => document.querySelector(s);
const STORE = 'pcu-config-v1';
const WSS_PORT = 8084;
const TLS_PORT = 8883;

let cfg = loadCfg();
let client = null;
const waiting = new Map(); // nonce -> resolve

// ------------------------------------------------------------ utilidades

function loadCfg() {
  try { return JSON.parse(localStorage.getItem(STORE)) || {}; } catch { return {}; }
}
function saveCfg() {
  try { localStorage.setItem(STORE, JSON.stringify(cfg)); return true; }
  catch (e) { showResult('No se pudo guardar la configuración: ' + e.message, false); return false; }
}
function randHex(bytes) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, '0')).join('');
}
const b64u = {
  enc(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  },
};
const topics = () => ({
  cmd: `pcu/${cfg.topic}/cmd`,
  resp: `pcu/${cfg.topic}/resp`,
  state: `pcu/${cfg.topic}/state`,
  hostState: `pcu/${cfg.topic}/host/state`, // programa PC Unlock Host en la compu
  hostIn: `pcu/${cfg.topic}/host/in`,
  hostOut: `pcu/${cfg.topic}/host/out`,
});
const subTopics = () => [topics().state, topics().resp, topics().hostState, topics().hostOut];

// CBOR mínimo (solo lo necesario para leer la clave pública de la passkey)
function cborDecode(bytes, pos = 0) {
  const ib = bytes[pos++];
  const major = ib >> 5;
  let info = ib & 0x1f;
  let len = info;
  if (info === 24) len = bytes[pos++];
  else if (info === 25) { len = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; }
  else if (info === 26) { len = ((bytes[pos] << 24) >>> 0) + (bytes[pos + 1] << 16) + (bytes[pos + 2] << 8) + bytes[pos + 3]; pos += 4; }
  else if (info > 26) throw new Error('CBOR no soportado');
  switch (major) {
    case 0: return [len, pos];
    case 1: return [-1 - len, pos];
    case 2: return [bytes.slice(pos, pos + len), pos + len];
    case 3: return [new TextDecoder().decode(bytes.slice(pos, pos + len)), pos + len];
    case 4: { const a = []; for (let i = 0; i < len; i++) { let v; [v, pos] = cborDecode(bytes, pos); a.push(v); } return [a, pos]; }
    case 5: { const m = new Map(); for (let i = 0; i < len; i++) { let k, v; [k, pos] = cborDecode(bytes, pos); [v, pos] = cborDecode(bytes, pos); m.set(k, v); } return [m, pos]; }
    case 7: return [info === 21 ? true : info === 20 ? false : null, pos];
    default: throw new Error('CBOR no soportado');
  }
}
function pubKeyFromAttestation(attObj) {
  const [ao] = cborDecode(attObj);
  const ad = ao.get('authData');
  if (!(ad[32] & 0x40)) throw new Error('La passkey no trajo clave pública');
  const credLen = (ad[53] << 8) | ad[54];
  const [cose] = cborDecode(ad, 55 + credLen);
  const x = cose.get(-2), y = cose.get(-3);
  if (cose.get(3) !== -7 || !x || !y) throw new Error('Tipo de clave no soportado');
  const pub = new Uint8Array(65);
  pub[0] = 4; pub.set(x, 1); pub.set(y, 33);
  return pub;
}

// ------------------------------------------------------------ passkey

async function createKey() {
  if (!window.PublicKeyCredential) throw new Error('Este navegador no soporta passkeys');
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: location.hostname, name: 'PC Unlock' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'PC Unlock', displayName: 'PC Unlock' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
      attestation: 'none',
      timeout: 60000,
    },
  });
  let pub = null;
  try {
    if (cred.response.getPublicKey && cred.response.getPublicKeyAlgorithm?.() === -7) {
      const spki = new Uint8Array(cred.response.getPublicKey());
      pub = spki.slice(spki.length - 65);
    }
  } catch { /* se usa el plan B */ }
  if (!pub || pub[0] !== 4) pub = pubKeyFromAttestation(new Uint8Array(cred.response.attestationObject));
  cfg.topic = cfg.topic || randHex(8);
  cfg.credId = b64u.enc(cred.rawId);
  cfg.rpId = location.hostname;
  cfg.origin = location.origin;
  cfg.pub = b64u.enc(pub);
  saveCfg();
}

// Firma una orden con Face ID y devuelve el mensaje a publicar.
// extra: campos adicionales del challenge (sesión remota: fingerprint DTLS, id del host, etc.).
// Ojo iOS: credentials.get tiene que ser lo primero que se espera después del toque.
async function signCommand(cmd, extra = {}) {
  const payload = { c: cmd, t: Math.floor(Date.now() / 1000), n: randHex(12), ...extra };
  const challenge = new TextEncoder().encode(JSON.stringify(payload));
  const a = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: cfg.rpId,
      allowCredentials: [{ type: 'public-key', id: b64u.dec(cfg.credId) }],
      userVerification: 'required',
      timeout: 60000,
    },
  });
  return {
    nonce: payload.n,
    msg: {
      ad: b64u.enc(a.response.authenticatorData),
      cd: b64u.enc(a.response.clientDataJSON),
      sig: b64u.enc(a.response.signature),
      id: cfg.credId,
    },
  };
}

function pairCode() {
  if (!cfg.pub || !cfg.host || !cfg.user || !cfg.pass) return '';
  const data = {
    t: cfg.topic, r: cfg.rpId, o: cfg.origin, k: cfg.pub, i: cfg.credId,
    h: cfg.host, p: TLS_PORT, u: cfg.user, w: cfg.pass,
  };
  return 'PCU1.' + b64u.enc(new TextEncoder().encode(JSON.stringify(data)));
}

// ------------------------------------------------------------ MQTT

function connect() {
  if (client) { client.end(true); client = null; }
  if (!cfg.host || !cfg.user || !cfg.pass) { setConn('Sin configurar', ''); return; }
  setConn('Conectando…', '');
  const url = cfg.testUrl || `wss://${cfg.host}:${WSS_PORT}/mqtt`; // testUrl: solo para pruebas locales
  client = mqtt.connect(url, {
    username: cfg.user,
    password: cfg.pass,
    clientId: 'pcu-app-' + randHex(6),
    protocolVersion: 4,
    clean: true,
    reconnectPeriod: 3000,
    connectTimeout: 10000,
    keepalive: 30,
  });
  client.on('connect', () => {
    setConn('Conectado', 'on');
    if (cfg.topic) client.subscribe(subTopics(), { qos: 1 });
    $('#mqttMsg').textContent = '✔ Conectado al servidor';
    $('#mqttMsg').className = 'hint ok';
  });
  client.on('reconnect', () => setConn('Reconectando…', ''));
  client.on('offline', () => setConn('Sin conexión', 'off'));
  client.on('error', (e) => {
    setConn('Error de conexión', 'off');
    $('#mqttMsg').textContent = 'No se pudo conectar: ' + (e?.message || e);
    $('#mqttMsg').className = 'hint err';
  });
  client.on('message', (topic, buf) => {
    let m;
    try { m = JSON.parse(buf.toString()); } catch { return; }
    if (topic === topics().state) renderState(m);
    else if (topic === topics().resp && waiting.has(m.n)) { waiting.get(m.n)(m); waiting.delete(m.n); }
    else if (topic === topics().hostState || topic === topics().hostOut) onHostMessage(topic, m); // remote.js
  });
}

function waitConnected(ms) {
  return new Promise((resolve) => {
    if (client?.connected) return resolve(true);
    const t = setTimeout(() => resolve(false), ms);
    client?.once('connect', () => { clearTimeout(t); resolve(true); });
  });
}

function waitResponse(nonce, ms, map = waiting) {
  return new Promise((resolve) => {
    const t = setTimeout(() => { map.delete(nonce); resolve(null); }, ms);
    map.set(nonce, (m) => { clearTimeout(t); resolve(m); });
  });
}

// Manda una orden ya firmada a la ESP y espera la respuesta.
async function sendToEsp(signed, cmd) {
  if (!(await waitConnected(8000))) return { ok: false, msg: 'No hay conexión con el servidor MQTT.' };
  client.publish(topics().cmd, JSON.stringify(signed.msg), { qos: 1 });
  const r = await waitResponse(signed.nonce, cmd === 'unlock' ? 20000 : 12000);
  return r || { ok: false, msg: 'La ESP no respondió. ¿Está enchufada y con WiFi?' };
}

// ------------------------------------------------------------ interfaz

function setConn(text, cls) {
  const el = $('#conn');
  el.textContent = text;
  el.className = 'conn ' + cls;
}

function renderState(s) {
  const vis = $('#pcVisual');
  if (!s.online) {
    $('#pcState').textContent = 'ESP desconectada';
    $('#espState').textContent = 'La ESP no está conectada a internet';
    vis.dataset.state = 'unknown';
    return;
  }
  $('#pcState').textContent = s.pc ? 'Compu prendida' : 'Compu apagada';
  vis.dataset.state = s.pc ? 'on' : 'off';
  const extra = [];
  if (s.ssid) extra.push(`ESP en “${s.ssid}”`);
  if (!s.pc) extra.push('sin Bluetooth');
  if (s.mac === false) extra.push('falta MAC');
  if (s.pin === false) extra.push('falta PIN');
  $('#espState').textContent = extra.join(' · ');
}

function showResult(text, ok) {
  const el = $('#result');
  el.hidden = false;
  el.textContent = text;
  el.className = 'result ' + (ok === true ? 'ok' : ok === false ? 'err' : '');
}

const OK_TEXT = {
  wake: 'Listo. La compu debería arrancar en unos segundos.',
  unlock: 'Listo. PIN enviado.',
  lock: 'Compu bloqueada.',
  shutdown: 'Apagando la compu.',
};

async function runCommand(cmd, btn) {
  if (!cfg.credId || !cfg.topic) { showSettings(); return; }
  document.querySelectorAll('.action').forEach((b) => (b.disabled = true));
  btn.classList.add('busy');
  try {
    let signed;
    try {
      signed = await signCommand(cmd); // tiene que ser lo primero tras el toque (Face ID)
    } catch (e) {
      showResult(e?.name === 'NotAllowedError' ? 'Cancelado.' : 'Error de Face ID: ' + e.message, false);
      return;
    }
    showResult('Enviando…');
    const r = await sendToEsp(signed, cmd);
    if (r.ok) showResult(OK_TEXT[cmd] || 'Listo.', true);
    else showResult(r.msg || 'Error', false);
  } finally {
    btn.classList.remove('busy');
    document.querySelectorAll('.action').forEach((b) => (b.disabled = false));
  }
}

function refreshSettings() {
  $('#mqHost').value = cfg.host || '';
  $('#mqUser').value = cfg.user || '';
  $('#mqPass').value = cfg.pass || '';
  const ks = $('#keyState');
  if (cfg.credId) {
    ks.textContent = '✔ Llave creada para ' + cfg.rpId;
    ks.className = 'hint ok';
    $('#btnCreateKey').textContent = 'Crear una llave nueva';
  } else {
    ks.textContent = 'Todavía no hay llave.';
    ks.className = 'hint';
    $('#btnCreateKey').textContent = 'Crear llave con Face ID';
  }
  $('#pairCode').value = pairCode();
  refreshHostSettings(); // remote.js
}

function showSettings() {
  leaveRemote(); // remote.js
  $('#home').hidden = true;
  $('#settings').hidden = false;
  const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const standalone = navigator.standalone || matchMedia('(display-mode: standalone)').matches;
  $('#standaloneHint').hidden = !(isIOS && !standalone);
  refreshSettings();
  scrollTo(0, 0);
}
function showHome() {
  leaveRemote(); // remote.js
  $('#settings').hidden = true;
  $('#home').hidden = false;
}

// ------------------------------------------------------------ eventos

// Los botones con data-confirm piden un segundo toque (así Face ID sigue siendo lo primero tras el toque).
document.querySelectorAll('.action').forEach((btn) => {
  const label = btn.querySelector('span');
  const original = label.textContent;
  let timer = null;
  const disarm = () => { btn.classList.remove('armed'); label.textContent = original; clearTimeout(timer); timer = null; };
  btn.addEventListener('click', () => {
    if (btn.dataset.confirm && !btn.classList.contains('armed')) {
      btn.classList.add('armed');
      label.textContent = btn.dataset.confirm;
      timer = setTimeout(disarm, 4000);
      return;
    }
    disarm();
    runCommand(btn.dataset.cmd, btn);
  });
});

$('#btnSettings').addEventListener('click', () => ($('#settings').hidden ? showSettings() : showHome()));
$('#btnBack').addEventListener('click', showHome);

$('#btnSaveMqtt').addEventListener('click', () => {
  cfg.host = $('#mqHost').value.trim().replace(/^[a-z]+:\/\//i, '').replace(/[:/].*$/, '');
  cfg.user = $('#mqUser').value.trim();
  cfg.pass = $('#mqPass').value;
  if (!cfg.host || !cfg.user || !cfg.pass) {
    $('#mqttMsg').textContent = 'Completá los tres campos.';
    $('#mqttMsg').className = 'hint err';
    return;
  }
  saveCfg();
  $('#mqttMsg').textContent = 'Probando…';
  $('#mqttMsg').className = 'hint';
  connect();
  refreshSettings();
});

$('#btnCreateKey').addEventListener('click', async () => {
  if (cfg.credId && !confirm('Vas a crear una llave nueva. Después tenés que pegar el código nuevo en la ESP. ¿Seguir?')) return;
  try {
    await createKey();
    refreshSettings();
    if (client?.connected) client.subscribe(subTopics(), { qos: 1 });
  } catch (e) {
    $('#keyState').textContent = e?.name === 'NotAllowedError' ? 'Cancelado.' : 'Error: ' + e.message;
    $('#keyState').className = 'hint err';
  }
});

$('#btnCopy').addEventListener('click', async () => {
  const code = $('#pairCode').value;
  if (!code) return;
  try {
    await navigator.clipboard.writeText(code);
  } catch {
    $('#pairCode').select();
    document.execCommand('copy');
  }
  $('#btnCopy').textContent = '✔ Copiado';
  setTimeout(() => ($('#btnCopy').textContent = 'Copiar código'), 2000);
});

$('#btnReset').addEventListener('click', () => {
  if (!confirm('¿Borrar la configuración de esta app? (La passkey queda en tu llavero de iCloud.)')) return;
  localStorage.removeItem(STORE);
  location.reload();
});

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && client && !client.connected) client.reconnect();
});

// ------------------------------------------------------------ inicio

window.PCU = { signCommand, pairCode, createKey, cfg: () => cfg, saveCfg, connect }; // para pruebas
// El inicio está al final de remote.js (se carga después de este archivo).
