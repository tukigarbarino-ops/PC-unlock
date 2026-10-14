'use strict';
/* PC Unlock — vista "Remoto": pantalla de la compu en vivo (WebRTC con PC Unlock Host), touchpad,
 * teclado propio (Español Latinoamérica) y multimedia.
 * Seguridad: la sesión se abre con Face ID (challenge "rs" que incluye el fingerprint DTLS de la oferta) y
 * la respuesta del host viene firmada con su clave de identidad, que se fijó al emparejar comparando códigos.
 * Usa lo definido en app.js ($, cfg, client, b64u, signCommand, topics, sendToEsp…). */

const STUN_DEFAULT = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
const OFFER_MAX_AGE = 60000;     // la oferta preparada se renueva si no se usa en 1 min
const RENEW_BEFORE = 5 * 60;     // ofrecer "Renovar" 5 min antes de que venza la hora

let hostState = null;            // último pcu/<t>/host/state
let espState = null;             // último pcu/<t>/state (la ESP)
const waitingHost = new Map();   // nonce -> resolve (respuestas del host)
const R = {
  visible: false,
  prepared: null,                // { pc, sdp, fp, at, ctl, inp, video }
  preparing: null,
  live: null,                    // sesión activa con el host: { pc, ctl, inp, fo, fa, exp, n }
  esp: null,                     // sesión activa con la ESP: { key (AES-GCM), seq, exp, q (cola de envíos) }
  ecdh: null,                    // clave ECDH efímera lista para el próximo Face ID: { priv, pubB64 }
  locked: false,                 // la compu está en la pantalla de bloqueo (SendInput no llega; la ESP sí)
  notice: null,                  // aviso que queda arriba del estado (por qué se cortó, error al conectar)
  quality: 'auto',
  held: new Set(),               // teclas apretadas (uso HID)
  buttons: 0,
  refreshTimer: null,
  tickTimer: null,
  pingTimer: null,
};

// ------------------------------------------------------------ utilidades criptográficas

async function verifyCode(pub, kind) {
  const pre = new TextEncoder().encode(`PCU-ID|${kind}|`);
  const buf = new Uint8Array(pre.length + pub.length);
  buf.set(pre); buf.set(pub, pre.length);
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let bits = 0, acc = 0, out = '';
  for (const b of h) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5 && out.length < 16) { bits -= 5; out += A[(acc >> bits) & 31]; }
    if (out.length >= 16) break;
  }
  return out.match(/.{4}/g).join('-');
}

async function deviceId(pub) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', pub));
  return Array.from(h.slice(0, 8), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifySig(pubB64, text, sigB64) {
  try {
    const key = await crypto.subtle.importKey('raw', b64u.dec(pubB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64u.dec(sigB64), new TextEncoder().encode(text));
  } catch { return false; }
}

function sdpFingerprint(sdp) {
  const fps = new Set();
  for (const m of String(sdp).matchAll(/^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/gm)) {
    if (m[1].toLowerCase() !== 'sha-256') return null;
    fps.add(m[2].toUpperCase());
  }
  return fps.size === 1 ? [...fps][0] : null;
}

function iceServers() {
  const list = [...STUN_DEFAULT];
  if (cfg.turnUrl) list.push({ urls: cfg.turnUrl.split(/[\s,]+/).filter(Boolean), username: cfg.turnUser || undefined, credential: cfg.turnPass || undefined });
  return list;
}

// ------------------------------------------------------------ mensajes del host por MQTT

function onHostMessage(topic, m) {
  if (topic === topics().hostState) {
    hostState = m;
    refreshHostSettings();
    if (R.visible && !R.live && !R.prepared && hostUsable()) prepareOffer();
    refreshRemoteOverlay();
  } else if (topic === topics().hostOut && m && waitingHost.has(m.n)) {
    waitingHost.get(m.n)(m);
    waitingHost.delete(m.n);
  }
}

const hostPaired = () => !!(cfg.hostKey && cfg.hostId);
const hostOnline = () => !!(hostState && hostState.online && hostState.k);
const hostKeyChanged = () => hostPaired() && hostOnline() && hostState.k !== cfg.hostKey;
const espPaired = () => !!cfg.espKey;
const espOnline = () => !!(espState && espState.online && espState.k && espState.in);
const espKeyChanged = () => espPaired() && espOnline() && espState.k !== cfg.espKey;
const hostUsable = () => hostPaired() && hostOnline() && !hostKeyChanged();
const espUsable = () => espPaired() && espOnline() && !espKeyChanged();

function onEspState(m) {
  espState = m;
  refreshEspSettings();
  refreshRemoteOverlay();
}

// Ajustes: emparejar la ESP (mismo esquema que la compu: comparar códigos)
async function refreshEspSettings() {
  const st = $('#espPairState');
  if (!st) return;
  $('#espCodeBox').hidden = true;
  $('#btnEspForget').hidden = !espPaired();
  if (!cfg.topic) { st.textContent = 'Primero completá los pasos de arriba.'; st.className = 'hint'; return; }
  if (!espState || !espState.online) {
    st.textContent = espPaired() ? '✔ Emparejada. La ESP ahora no está conectada.' : 'La ESP no está conectada.';
    st.className = 'hint' + (espPaired() ? ' ok' : '');
    return;
  }
  if (!espState.k) { st.textContent = `La ESP tiene la versión ${espState.v || 'vieja'}: actualizala a la 1.3.0 o más nueva.`; st.className = 'hint err'; return; }
  const code = await verifyCode(b64u.dec(espState.k), 'esp');
  if (espPaired() && !espKeyChanged()) { st.textContent = `✔ Emparejada (código ${code}).`; st.className = 'hint ok'; return; }
  st.textContent = espKeyChanged()
    ? '⚠ La ESP se presenta con OTRA clave (¿la borraste o le cargaste otra configuración?). Compará el código nuevo; si no coincide, no confirmes.'
    : 'Compará este código con el de la página de configuración de la ESP:';
  st.className = 'hint' + (espKeyChanged() ? ' err' : '');
  $('#espCode').textContent = code;
  $('#espCodeBox').hidden = false;
  $('#espCodeBox').dataset.key = espState.k;
}

// Clave ECDH efímera para la sesión con la ESP. Se crea ANTES del toque (WebCrypto es asíncrono y
// Face ID tiene que ser lo primero tras el toque). La privada no se puede exportar.
async function prepareEcdh() {
  if (R.ecdh || !espPaired()) return;
  const k = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  R.ecdh = { priv: k.privateKey, pubB64: b64u.enc(await crypto.subtle.exportKey('raw', k.publicKey)) };
}

// Respuesta de la ESP a "rs"/"rr": verifica la firma con la clave fijada y deriva la clave AES-256-GCM.
async function espDerive(r, nonce, ecdh) {
  if (!r || !r.ok || !r.e || !r.s) throw new Error(r?.msg || 'La ESP no respondió.');
  const payload = `PCU-ESP-SESSION|${nonce}|${ecdh.pubB64}|${r.e}|${r.exp}`;
  if (!(await verifySig(cfg.espKey, payload, r.s))) throw new Error('La respuesta no está firmada por tu ESP.');
  const espPub = await crypto.subtle.importKey('raw', b64u.dec(r.e), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const z = await crypto.subtle.deriveBits({ name: 'ECDH', public: espPub }, ecdh.priv, 256);
  const ikm = await crypto.subtle.importKey('raw', z, 'HKDF', false, ['deriveKey']);
  const te = new TextEncoder();
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(nonce), info: te.encode('PCU-ESP-SESSION') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  return { key, seq: 0, exp: r.exp, pc: !!r.pc, q: Promise.resolve() };
}

// Manda la orden firmada a la ESP y arma la sesión (o tira un error).
async function espOpen(signed, ecdh) {
  if (!(await waitConnected(8000))) throw new Error('No hay conexión con el servidor MQTT.');
  client.publish(topics().cmd, JSON.stringify(signed.msg), { qos: 1 });
  const r = await waitResponse(signed.nonce, 15000);
  return espDerive(r, signed.nonce, ecdh);
}

// Mensaje de entrada cifrado para la ESP: seq (u32 LE) || AES-256-GCM(texto || tag), IV = "PCUI" || seq || 0000.
function espSend(bytes) {
  const E = R.esp;
  const seq = ++E.seq;
  E.q = E.q.then(async () => {
    const iv = new Uint8Array(12);
    iv.set([0x50, 0x43, 0x55, 0x49]);
    new DataView(iv.buffer).setUint32(4, seq, true);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, E.key, bytes));
    const out = new Uint8Array(4 + ct.length);
    new DataView(out.buffer).setUint32(0, seq, true);
    out.set(ct, 4);
    if (client?.connected) client.publish(topics().in, out, { qos: 0 });
  }).catch(() => {});
}

const espActive = () => !!(R.esp && R.esp.exp > Date.now() / 1000);
// ¿Esta entrada va por el host (DataChannel)? Si la compu está bloqueada, va por la ESP (teclado Bluetooth de verdad).
const viaHost = () => !!(R.live && R.live.connected && R.live.inp.readyState === 'open' && !(R.locked && espActive()));

// ------------------------------------------------------------ Ajustes: emparejar la compu

async function refreshHostSettings() {
  const st = $('#hostPairState');
  if (!st) return;
  const box = $('#hostCodeBox');
  box.hidden = true;
  $('#btnHostForget').hidden = !hostPaired();
  const link = $('#hostDownload');
  if (link && location.hostname.endsWith('.github.io')) link.href = `https://github.com/${location.hostname.split('.')[0]}/PC-unlock/releases/latest`;
  if (!cfg.topic) { st.textContent = 'Primero completá los pasos de arriba.'; st.className = 'hint'; return; }
  if (!hostOnline()) {
    st.textContent = hostPaired() ? '✔ Emparejada. El programa de la compu ahora no está conectado.' : 'No se detecta PC Unlock Host. Instalalo en la compu y pegale el código del paso 3.';
    st.className = 'hint' + (hostPaired() ? ' ok' : '');
    return;
  }
  const code = await verifyCode(b64u.dec(hostState.k), 'host');
  if (hostPaired() && !hostKeyChanged()) {
    st.textContent = `✔ Emparejada (código ${code}).`;
    st.className = 'hint ok';
    return;
  }
  st.textContent = hostKeyChanged()
    ? '⚠ La compu se presenta con OTRA clave. Si reinstalaste el programa, compará el código nuevo. Si no, alguien podría estar haciéndose pasar por tu compu: no confirmes.'
    : 'Compará este código con el que muestra PC Unlock Host en la compu:';
  st.className = 'hint' + (hostKeyChanged() ? ' err' : '');
  $('#hostCode').textContent = code;
  box.hidden = false;
  box.dataset.key = hostState.k;
}

async function confirmHost() {
  const k = $('#hostCodeBox').dataset.key;
  if (!k) return;
  cfg.hostKey = k;
  cfg.hostId = await deviceId(b64u.dec(k));
  saveCfg();
  refreshHostSettings();
}

// ------------------------------------------------------------ vista Remoto

function showRemote() {
  if (!cfg.credId || !cfg.topic) { showSettings(); return; }
  $('#home').hidden = true;
  $('#settings').hidden = true;
  $('#remote').hidden = false;
  document.body.classList.add('remote-on');
  R.visible = true;
  refreshRemoteOverlay();
  prepareOffer();
  prepareEcdh().then(refreshRemoteOverlay).catch(() => {});
  clearInterval(R.tickTimer);
  R.tickTimer = setInterval(tick, 1000);
}

function leaveRemote() {
  if (!R.visible) return;
  R.visible = false;
  endLive('salir');
  if (R.esp) { releaseAllLocal(); R.esp = null; }
  discardPrepared();
  clearInterval(R.tickTimer);
  clearTimeout(R.refreshTimer);
  document.body.classList.remove('remote-on', 'fs');
  $('#remote').hidden = true;
}

function setOverlay(text, { connect = false, unlock = false, busy = false } = {}) {
  const ov = $('#rOverlay');
  ov.hidden = false;
  $('#rOvText').textContent = text;
  $('#rConnect').hidden = !connect;
  $('#rConnect').disabled = busy;
  $('#rFps').hidden = !connect || !hostUsable();
  document.querySelectorAll('#rFps [data-fps]').forEach((b) => b.classList.toggle('on', Number(b.dataset.fps) === (cfg.fps || 60)));
  $('#rOvUnlock').hidden = !unlock;
}

function refreshRemoteOverlay() {
  if (!R.visible || R.live) return;
  const say = (t, o) => setOverlay((R.notice ? R.notice + ' ' : '') + t, o);
  const espReady = espUsable() && !!R.ecdh;
  const espNote = espActive() ? ' Teclado, touchpad y multimedia siguen andando por la ESP (Bluetooth).' : '';
  $('#rConnect').textContent = hostUsable() ? 'Conectar con Face ID' : 'Conectar teclado y mouse (ESP) con Face ID';
  if (hostKeyChanged()) return say('La compu se presenta con otra clave. Revisalo en Ajustes antes de conectar.');
  if (espKeyChanged() && !hostUsable()) return say('La ESP se presenta con otra clave. Revisalo en Ajustes antes de conectar.');
  if (!hostPaired() && !espPaired()) return say('Primero emparejá la compu (o la ESP) en Ajustes.');
  if (!hostUsable()) {
    const why = !hostPaired() ? 'La compu no está emparejada para ver la pantalla.' : 'El programa de la compu no está conectado (¿bloqueada, recién prendida o cerrado?).';
    if (espActive()) return say(`Sin video. ${why}${espNote}`, { unlock: true });
    if (espReady) return say(`${why} Podés manejarla sin video por la ESP (teclado y mouse Bluetooth).`, { connect: true, unlock: true });
    return say(why + (espPaired() && !espOnline() ? ' La ESP tampoco está conectada.' : ''), { unlock: true });
  }
  if (!R.prepared) return say('Preparando la conexión…', { connect: true, busy: true });
  say((hostState.locked ? 'La compu está bloqueada: podés conectarte igual, pero Windows no deja ver la pantalla de bloqueo.' : 'Listo para conectar.') + espNote,
    { connect: true, unlock: !!hostState.locked });
}

// Crea la oferta WebRTC (y junta los candidatos ICE) ANTES del toque, para que el toque llame a Face ID enseguida.
async function prepareOffer() {
  if (R.preparing || R.live || !R.visible) return;
  if (!hostPaired() || hostKeyChanged()) return;
  discardPrepared();
  R.preparing = (async () => {
    const pc = new RTCPeerConnection({ iceServers: iceServers(), bundlePolicy: 'max-bundle' });
    const tr = pc.addTransceiver('video', { direction: 'recvonly' });
    try {
      const caps = RTCRtpReceiver.getCapabilities('video').codecs;
      const h264 = caps.filter((c) => /h264/i.test(c.mimeType));
      if (h264.length) tr.setCodecPreferences([...h264, ...caps.filter((c) => !/h264/i.test(c.mimeType))]);
    } catch { /* el navegador elige */ }
    const ctl = pc.createDataChannel('ctl', { ordered: true });
    const inp = pc.createDataChannel('in', { ordered: true });
    inp.binaryType = 'arraybuffer';
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') return resolve();
      const to = setTimeout(resolve, 4000);
      pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(to); resolve(); } });
    });
    const sdp = pc.localDescription.sdp;
    const fp = sdpFingerprint(sdp);
    if (!fp) throw new Error('No se pudo leer el fingerprint DTLS');
    return { pc, tr, ctl, inp, sdp, fp, at: Date.now() };
  })();
  try {
    const p = await R.preparing;
    if (!R.visible || R.live) { p.pc.close(); return; }
    R.prepared = p;
    clearTimeout(R.refreshTimer);
    R.refreshTimer = setTimeout(() => { if (R.visible && !R.live) prepareOffer(); }, OFFER_MAX_AGE);
  } catch (e) {
    setOverlay('Error preparando la conexión: ' + e.message);
  } finally {
    R.preparing = null;
    refreshRemoteOverlay();
  }
}

function discardPrepared() {
  if (R.prepared) { try { R.prepared.pc.close(); } catch { /* ya cerrada */ } }
  R.prepared = null;
}

// Un solo Face ID abre la sesión con el host (video + entrada) y, si está emparejada, con la ESP (respaldo).
async function connectRemote() {
  const p = hostUsable() ? R.prepared : null;
  const ecdh = espUsable() && !espActive() ? R.ecdh : null;
  if ((!p && !ecdh) || R.live) return;
  R.notice = null;
  if (p) { R.prepared = null; clearTimeout(R.refreshTimer); }
  if (ecdh) R.ecdh = null;
  const extra = {};
  if (p) Object.assign(extra, { f: p.fp, h: cfg.hostId, m: cfg.monitor || null, q: R.quality, r: cfg.fps || 60 });
  if (ecdh) extra.e = ecdh.pubB64;
  let signed;
  try {
    // Lo primero tras el toque: Face ID. El challenge ata la sesión a ESTA oferta (fingerprint DTLS), a ESTA compu
    // y a la clave efímera de la app para la ESP.
    signed = await signCommand('rs', extra);
  } catch (e) {
    if (p) p.pc.close();
    setOverlay(e?.name === 'NotAllowedError' ? 'Cancelado.' : 'Error de Face ID: ' + e.message);
    prepareOffer();
    prepareEcdh().then(refreshRemoteOverlay).catch(() => {});
    return;
  }
  setOverlay('Conectando…', { connect: true, busy: true });
  const espP = ecdh ? espOpen(signed, ecdh) : null;
  const hostP = p ? openHost(p, signed) : null;
  let espErr = null, hostErr = null;
  if (espP) {
    try { R.esp = await espP; if (!R.esp.pc) espErr = 'La ESP no está conectada por Bluetooth a la compu.'; }
    catch (e) { espErr = e.message; }
  }
  if (hostP) { try { await hostP; } catch (e) { hostErr = e.message; } }
  prepareEcdh().catch(() => {});
  if (hostErr || !p) {
    if (p) prepareOffer();
    R.notice = [hostErr, espErr].filter(Boolean).join(' ') || null;
    if (espActive()) setStatus('Por la ESP · sin video');
    refreshRemoteOverlay();
    tick();
  } else if (espErr) {
    setStatus('Conectado (sin respaldo por la ESP: ' + espErr + ')');
  }
}

async function openHost(p, signed) {
  try {
    if (!(await waitConnected(8000))) throw new Error('No hay conexión con el servidor MQTT.');
    client.publish(topics().hostIn, JSON.stringify({ type: 'open', sdp: p.sdp, ice: iceServers(), ...signed.msg }), { qos: 1 });
    const r = await waitResponse(signed.nonce, 25000, waitingHost);
    if (!r) throw new Error('La compu no respondió.');
    if (r.type === 'error') throw new Error(r.msg || 'La compu rechazó la sesión.');
    const fa = sdpFingerprint(r.sdp);
    if (!fa || !(await verifySig(cfg.hostKey, `PCU-HOST-ANSWER|${signed.nonce}|${p.fp}|${fa}|${r.exp}`, r.hs)))
      throw new Error('La respuesta no está firmada por tu compu. No se conecta.');
    R.live = { ...p, fo: p.fp, fa, exp: r.exp, n: signed.nonce, connected: false };
    wireLive(R.live);
    await p.pc.setRemoteDescription({ type: 'answer', sdp: r.sdp });
  } catch (e) {
    p.pc.close();
    R.live = null;
    throw e;
  }
}

function wireLive(L) {
  const video = $('#rVideo');
  L.pc.addEventListener('track', (ev) => {
    video.srcObject = ev.streams[0] || new MediaStream([ev.track]);
    video.play().catch(() => {});
    applyLowLatency();
  });
  L.pc.addEventListener('connectionstatechange', () => {
    const st = L.pc.connectionState;
    if (st === 'connected') { L.connected = true; $('#rOverlay').hidden = true; setStatus('Conectado'); }
    if (st === 'disconnected') setStatus('Reconectando…');
    if (st === 'failed' || st === 'closed') endLive('Se cortó la conexión.');
  });
  L.ctl.onmessage = (ev) => { try { onCtl(JSON.parse(ev.data)); } catch { /* mensaje inválido */ } };
  L.ctl.onclose = () => endLive('La compu cerró la sesión.');
  clearInterval(D.timer);
  D.host = null; D.rx = null; D.last = null;
  D.timer = setInterval(() => rxStats().catch(() => {}), 2000);
  clearInterval(R.pingTimer);
  R.pingTimer = setInterval(() => {
    if (R.held.size || R.buttons) sendInput(enc.ping());
    if (GP.on && !padNeutral() && viaHost()) R.live.inp.send(enc.pad(GP.st)); // el host vuelve el joystick a reposo a los 2 s sin mensajes
  }, 500);
}

function onCtl(m) {
  const L = R.live;
  if (!L) return;
  switch (m.t) {
    case 'hello':
      L.exp = m.exp;
      if (m.fps) $('#rFpsSel').value = String(m.fps);
      GP.avail = m.pad === undefined ? null : !!m.pad;
      fillMonitors(m.monitors || [], m.monitor);
      setLocked(!!m.locked);
      break;
    case 'locked': setLocked(!!m.v); break;
    case 'monitor': cfg.monitor = m.id; saveCfg(); break;
    case 'stats':
      D.host = m;
      renderDiag();
      break;
    case 'renewed':
      if (L.renewing && m.n === L.renewing) {
        verifySig(cfg.hostKey, `PCU-HOST-RENEW|${m.n}|${L.fo}|${L.fa}|${m.exp}`, m.hs).then((ok) => {
          if (ok) L.exp = m.exp; else setStatus('Renovación con firma inválida');
          L.renewing = null;
          tick();
        });
      }
      break;
    case 'bye': endLive(m.why === 'expired' ? 'Pasó la hora: volvé a conectar con Face ID.' : 'La compu cortó la sesión.', true); break;
    case 'error': setStatus(m.msg || 'Error'); break;
    case 'pad':
      clearTimeout(GP.waiting);
      setStatus(m.err || 'Conectado');
      showGamepad(!!m.on);
      break;
    default: break;
  }
}

function endLive(why, fromHost = false) {
  const L = R.live;
  if (!L) return;
  R.live = null;
  clearInterval(R.pingTimer);
  clearInterval(D.timer);
  releaseAllLocal();
  showGamepad(false);
  try { if (!fromHost && L.ctl.readyState === 'open') L.ctl.send(JSON.stringify({ t: 'bye' })); } catch { /* cerrada */ }
  try { L.pc.close(); } catch { /* cerrada */ }
  $('#rVideo').srcObject = null;
  $('#rStats').textContent = '';
  $('#rSession').hidden = true;
  setLocked(false);
  setStatus(espActive() ? 'Por la ESP · sin video' : '');
  if (R.visible) {
    R.notice = why === 'salir' ? null : why;
    refreshRemoteOverlay();
    prepareOffer();
  }
  tick();
}

function setStatus(t) { $('#rStatus').textContent = t; }

function setLocked(v) {
  if (v !== R.locked && (R.held.size || R.buttons)) releaseAllLocal(); // cambia el camino de la entrada
  R.locked = v;
  $('#rLocked').hidden = !v || !R.live;
  $('#rLockEsp').hidden = !espActive();
}

function fillMonitors(list, current) {
  const sel = $('#rMonitor');
  sel.innerHTML = '';
  for (const m of list) {
    const o = document.createElement('option');
    o.value = m.id;
    o.textContent = `${m.name} · ${m.w}×${m.h}`;
    sel.appendChild(o);
  }
  sel.value = current || '';
  sel.hidden = list.length < 2;
}

function tick() {
  const L = R.live;
  const exp = L?.exp || (R.esp ? R.esp.exp : 0);
  if (!exp) { $('#rSession').hidden = true; return; }
  const left = exp - Math.floor(Date.now() / 1000);
  if (!L && left <= 0) {
    R.esp = null;
    $('#rSession').hidden = true;
    setStatus('');
    R.notice = 'Pasó la hora: volvé a conectar con Face ID.';
    refreshRemoteOverlay();
    return;
  }
  $('#rSession').hidden = false;
  $('#rLeft').textContent = left > 60 ? `${Math.ceil(left / 60)} min` : `${Math.max(0, left)} s`;
  $('#rRenew').hidden = left > RENEW_BEFORE || !!L?.renewing || !!R.renewing;
}

async function renewSession() {
  const L = R.live;
  const ecdh = espUsable() ? R.ecdh : null; // la sesión con la ESP se renueva con una clave efímera nueva
  if (!L && !(espActive() && ecdh)) return;
  if (ecdh) R.ecdh = null;
  const extra = {};
  if (L) Object.assign(extra, { f: L.fo, h: cfg.hostId });
  if (ecdh) extra.e = ecdh.pubB64;
  let signed;
  try {
    signed = await signCommand('rr', extra); // Face ID primero
  } catch (e) {
    setStatus(e?.name === 'NotAllowedError' ? 'Cancelado.' : e.message);
    prepareEcdh().catch(() => {});
    return;
  }
  if (L) { L.renewing = signed.nonce; L.ctl.send(JSON.stringify({ t: 'renew', ...signed.msg })); }
  if (ecdh) {
    R.renewing = true;
    tick();
    try {
      const E = await espOpen(signed, ecdh);
      releaseAllLocal();
      R.esp = E;
    } catch (e) { setStatus('ESP: ' + e.message); }
    R.renewing = false;
    prepareEcdh().catch(() => {});
  }
  tick();
}

function sendCtl(m) { if (R.live?.ctl.readyState === 'open') R.live.ctl.send(JSON.stringify(m)); }

// ------------------------------------------------------------ diagnóstico de fluidez: ¿dónde se pierden los cuadros?
// La compu manda cada 2 s lo que envía (fps, Mb/s y qué la limita según WebRTC); el iPhone mide lo que muestra.

const D = { host: null, rx: null, last: null, timer: 0 };

async function rxStats() {
  const L = R.live;
  if (!L || !L.connected) return;
  const r = await L.pc.getStats();
  let inb = null, pair = null;
  r.forEach((s) => {
    if (s.type === 'inbound-rtp' && s.kind === 'video') inb = s;
    if (s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') pair = s;
  });
  if (!inb) return;
  const prev = D.last;
  D.last = { t: inb.timestamp, dec: inb.framesDecoded || 0, lost: inb.packetsLost || 0, pk: inb.packetsReceived || 0,
    drop: inb.framesDropped || 0, frz: inb.totalFreezesDuration || 0,
    jbd: inb.jitterBufferDelay || 0, jbe: inb.jitterBufferEmittedCount || 0, tdt: inb.totalDecodeTime || 0 };
  if (!prev) return;
  const dt = (D.last.t - prev.t) / 1000;
  if (dt <= 0) return;
  const pk = D.last.pk - prev.pk, lost = Math.max(0, D.last.lost - prev.lost);
  D.rx = {
    fps: Math.round((D.last.dec - prev.dec) / dt),
    loss: pk + lost ? (100 * lost) / (pk + lost) : 0,
    drop: Math.max(0, D.last.drop - prev.drop),
    freeze: Math.max(0, D.last.frz - prev.frz),
    rtt: pair && pair.currentRoundTripTime != null ? Math.round(pair.currentRoundTripTime * 1000) : null,
    jitter: inb.jitter != null ? Math.round(inb.jitter * 1000) : null,
  };
  // Retardo: cuánto espera cada cuadro en el búfer del iPhone y cuánto tarda en decodificarse (promedio de los últimos 2 s)
  const dJb = D.last.jbe - prev.jbe, dDec = D.last.dec - prev.dec;
  D.rx.buffer = dJb > 0 ? Math.round(((D.last.jbd - prev.jbd) / dJb) * 1000) : null;
  D.rx.decode = dDec > 0 ? Math.round(((D.last.tdt - prev.tdt) / dDec) * 1000) : null;
  // Estimado de punta a punta: captura (~1 cuadro) + codificar (~8 ms) + ida por la red + búfer + decodificar + mostrar (~1 cuadro de 60 Hz)
  if (D.rx.buffer != null && D.rx.rtt != null) {
    const frame = 1000 / Math.max(15, D.host?.fps || 30);
    D.rx.total = Math.round(frame + 8 + D.rx.rtt / 2 + D.rx.buffer + (D.rx.decode || 0) + 17);
  }
  renderDiag();
}

function renderDiag() {
  const h = D.host, x = D.rx;
  if (!h) return;
  const parts = [`${h.codec || '?'}${h.hw ? ' hw' : ''} · ${h.w}×${h.h}`, x ? `compu ${h.fps} → iPhone ${x.fps} fps` : `${h.fps} fps`,
    `${(h.kbps / 1000).toFixed(1)} Mb/s`, h.route];
  if (x && x.loss >= 1) parts.push(`pérdida ${x.loss.toFixed(0)}%`);
  if (x && x.total) parts.push(`retardo ~${x.total} ms`);
  $('#rStats').textContent = parts.join(' · ');
  let msg, warn = true;
  if (h.limit === 'bandwidth') msg = `Cuello de botella: la RED. La compu manda menos cuadros porque la conexión no da más (${(h.kbps / 1000).toFixed(1)} Mb/s).`;
  else if (h.limit === 'cpu') msg = 'Cuello de botella: el codificador de la COMPU (CPU).';
  else if (x && h.fps >= 40 && x.fps < h.fps * 0.75)
    msg = `Cuello de botella: entre la red y el iPhone. La compu manda ${h.fps} fps y en el iPhone se muestran ${x.fps}` +
      (x.loss >= 1 ? ` (se pierde el ${x.loss.toFixed(0)} % de los paquetes: es la red).` : '.');
  else if (h.fps < 40) msg = `La compu está mandando ${h.fps} fps. Si la pantalla se mueve (un juego), el límite está en la CAPTURA de la compu; con la pantalla quieta es normal.`;
  else { msg = 'Sin cuello de botella: en el iPhone se ven los cuadros que manda la compu.'; warn = false; }
  if (x && x.total) {
    const biggest = [['el búfer del iPhone', x.buffer], ['la red (ida)', Math.round(x.rtt / 2)], ['decodificar en el iPhone', x.decode || 0]]
      .sort((a, b) => b[1] - a[1])[0];
    msg += ` Retardo estimado ~${x.total} ms; lo que más suma: ${biggest[0]} (${biggest[1]} ms).`;
  }
  $('#rDiag').textContent = msg;
  $('#rDiag').classList.toggle('warn', warn);
  const lim = { none: 'ninguno', bandwidth: 'red', cpu: 'CPU', other: 'otro' }[h.limit] || h.limit || '—';
  $('#rDiagNum').textContent = [`compu ${h.fps} fps`, x ? `iPhone ${x.fps} fps` : '', x && x.rtt != null ? `latencia ${x.rtt} ms` : '',
    x && x.jitter != null ? `jitter ${x.jitter} ms` : '', x ? `pérdida ${x.loss.toFixed(1)} %` : '', x && x.drop ? `${x.drop} cuadros descartados` : '',
    x && x.freeze ? `congelado ${x.freeze.toFixed(1)} s` : '', `límite según la compu: ${lim}`,
    x && x.buffer != null ? `búfer del iPhone ${x.buffer} ms` : '', x && x.decode != null ? `decodificar ${x.decode} ms` : '',
    `baja latencia: ${!lowLatSupported() ? 'no disponible' : lowLatOn() ? 'sí' : 'no'}`].filter(Boolean).join(' · ');
}

// "Baja latencia": le pide al navegador que use el búfer mínimo antes de mostrar cada cuadro (si lo permite).
// Activada por defecto: probado el 14/10 en el iPhone, sin ella el retardo era muy alto.
const lowLatOn = () => cfg.lowLat !== false;
const lowLatSupported = () => typeof RTCRtpReceiver !== 'undefined' &&
  ('playoutDelayHint' in RTCRtpReceiver.prototype || 'jitterBufferTarget' in RTCRtpReceiver.prototype);
function applyLowLatency() {
  const L = R.live;
  if (!L) return;
  for (const r of L.pc.getReceivers()) {
    if (r.track?.kind !== 'video') continue;
    try {
      if ('playoutDelayHint' in r) r.playoutDelayHint = lowLatOn() ? 0 : null;
      if ('jitterBufferTarget' in r) r.jitterBufferTarget = lowLatOn() ? 0 : null;
    } catch { /* el navegador no lo acepta */ }
  }
}

// ------------------------------------------------------------ protocolo de entrada (igual que host/src/protocol.js)

const enc = {
  key: (u, down) => Uint8Array.of(down ? 1 : 2, u),
  move(dx, dy) { const b = new Uint8Array(5); const v = new DataView(b.buffer); b[0] = 3; v.setInt16(1, clamp16(dx), true); v.setInt16(3, clamp16(dy), true); return b; },
  btn: (mask, down) => Uint8Array.of(down ? 4 : 5, mask),
  wheel(vv, h) { const b = new Uint8Array(5); const v = new DataView(b.buffer); b[0] = 6; v.setInt16(1, clamp16(vv), true); v.setInt16(3, clamp16(h), true); return b; },
  consumer(u) { const b = new Uint8Array(3); b[0] = 7; b[1] = u & 0xff; b[2] = u >> 8; return b; },
  release: () => Uint8Array.of(8),
  ping: () => Uint8Array.of(9),
};
const clamp16 = (x) => Math.max(-32768, Math.min(32767, Math.round(x)));

function sendInput(bytes) {
  if (viaHost()) { R.live.inp.send(bytes); return true; }
  if (espActive()) { espSend(bytes); return true; }
  return false;
}

function keyEvent(u, down) {
  if (down) R.held.add(u); else R.held.delete(u);
  sendInput(enc.key(u, down));
}

function buttonEvent(mask, down) {
  R.buttons = down ? R.buttons | mask : R.buttons & ~mask;
  sendInput(enc.btn(mask, down));
}

function releaseAllLocal() {
  if (R.held.size || R.buttons) sendInput(enc.release());
  R.held.clear();
  R.buttons = 0;
  document.querySelectorAll('.key.down').forEach((k) => k.classList.remove('down'));
  document.body.classList.remove('shift-on');
}

// ------------------------------------------------------------ touchpad

const pad = { pts: new Map(), acc: { x: 0, y: 0 }, wheel: { v: 0, h: 0 }, raf: 0, tap: null, lastTap: 0, lastMask: 0, dragging: 0, two: null };
const DRAG_WINDOW = 350; // ms entre soltar y volver a apoyar para que sea "clic sostenido" (o doble clic)

function flushPad() {
  pad.raf = 0;
  const dx = Math.trunc(pad.acc.x), dy = Math.trunc(pad.acc.y);
  if (dx || dy) { sendInput(enc.move(dx, dy)); pad.acc.x -= dx; pad.acc.y -= dy; }
  const v = Math.trunc(pad.wheel.v), h = Math.trunc(pad.wheel.h);
  if (v || h) { sendInput(enc.wheel(v, h)); pad.wheel.v -= v; pad.wheel.h -= h; }
}
// Por la ESP: ~25 mensajes por segundo (cada uno viaja por MQTT y Bluetooth).
const schedulePad = () => {
  if (pad.raf) return;
  pad.raf = viaHost() ? requestAnimationFrame(flushPad) : setTimeout(flushPad, 40);
};

function setupPad() {
  const el = $('#pad');
  el.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    el.setPointerCapture(e.pointerId);
    const now = performance.now();
    pad.pts.set(e.pointerId, { x: e.clientX, y: e.clientY, x0: e.clientX, y0: e.clientY, t: now, moved: 0 });
    if (pad.pts.size === 1) {
      const r = el.getBoundingClientRect();
      const x = e.clientX - r.left;
      // Tocar, soltar y volver a apoyar enseguida = el mismo botón queda APRETADO mientras el dedo está apoyado
      // (arrastrar ventanas, seleccionar). Si se suelta enseguida, Windows lo ve como doble clic.
      if (now - pad.lastTap < DRAG_WINDOW && pad.lastMask) { pad.dragging = pad.lastMask; buttonEvent(pad.lastMask, true); }
      pad.tap = { t: now, x, w: r.width };
      pad.two = null;
    } else if (pad.pts.size === 2) {
      pad.tap = null;
      pad.two = { t: now, moved: false };
    }
  });
  el.addEventListener('pointermove', (e) => {
    const p = pad.pts.get(e.pointerId);
    if (!p) return;
    e.preventDefault();
    const dx = e.clientX - p.x, dy = e.clientY - p.y;
    const dt = Math.max(1, e.timeStamp - (p.ts || p.t));
    p.x = e.clientX; p.y = e.clientY; p.ts = e.timeStamp;
    p.moved += Math.abs(dx) + Math.abs(dy);
    if (pad.pts.size === 1) {
      if (p.moved > 8) pad.tap = null;
      // Aceleración: lento = preciso, rápido = cruza la pantalla.
      const v = Math.hypot(dx, dy) / dt; // px/ms
      // por la ESP es un mouse Bluetooth y Windows le suma su propia aceleración
      const gain = (cfg.ptrSpeed || 1) * (1.3 + Math.min(v, 3) * 1.8) * (viaHost() ? 1 : 0.6);
      pad.acc.x += dx * gain; pad.acc.y += dy * gain;
      schedulePad();
    } else if (pad.pts.size === 2) {
      if (p.moved > 10 && pad.two) pad.two.moved = true;
      // Scroll "natural" como en el iPhone: el contenido sigue a los dedos. 120 = un paso de rueda.
      pad.wheel.v += dy * 2; pad.wheel.h -= dx * 2; // cada dedo aporta la mitad
      schedulePad();
    }
  });
  const up = (e) => {
    const p = pad.pts.get(e.pointerId);
    if (!p) return;
    pad.pts.delete(e.pointerId);
    const now = performance.now();
    if (pad.pts.size === 0) {
      if (pad.dragging) { buttonEvent(pad.dragging, false); pad.dragging = 0; pad.lastTap = 0; }
      else if (pad.two && !pad.two.moved && now - pad.two.t < 300) { buttonEvent(2, true); buttonEvent(2, false); } // dos dedos = clic derecho
      else if (pad.tap && now - pad.tap.t < 280 && e.type === 'pointerup') {
        const mask = pad.tap.x < pad.tap.w / 2 ? 1 : 2; // mitad izquierda = clic izq., mitad derecha = clic der.
        buttonEvent(mask, true); buttonEvent(mask, false);
        pad.lastTap = now; pad.lastMask = mask;
      }
      pad.tap = null;
      pad.two = null;
    }
  };
  el.addEventListener('pointerup', up);
  el.addEventListener('pointercancel', up);
}

// ------------------------------------------------------------ teclado (Español Latinoamérica)

// Teclado completo: [uso HID, etiqueta, con Shift, con AltGr, ancho]
const K = (u, l, s = '', a = '', w = 1) => ({ u, l, s, a, w });
const M = (u, l, w = 1.3) => ({ u, l, w, mod: true });
const KEYBOARD = [
  [K(0x29, 'Esc'), ...Array.from({ length: 12 }, (_, i) => K(0x3a + i, 'F' + (i + 1)))],
  [K(0x35, '|', '°', '¬'), K(0x1e, '1', '!'), K(0x1f, '2', '"'), K(0x20, '3', '#'), K(0x21, '4', '$'), K(0x22, '5', '%'),
    K(0x23, '6', '&'), K(0x24, '7', '/'), K(0x25, '8', '('), K(0x26, '9', ')'), K(0x27, '0', '='), K(0x2d, "'", '?', '\\'),
    K(0x2e, '¿', '¡'), K(0x2a, '⌫', '', '', 1.5)],
  [K(0x2b, 'Tab', '', '', 1.5), K(0x14, 'q', '', '@'), ...'wertyuiop'.split('').map((c) => K(0x04 + c.charCodeAt(0) - 97, c)),
    K(0x2f, '´', '¨'), K(0x30, '+', '*', '~')],
  [...'asdfghjkl'.split('').map((c) => K(0x04 + c.charCodeAt(0) - 97, c)), K(0x33, 'ñ'), K(0x34, '{', '[', '^'),
    K(0x32, '}', ']', '`'), K(0x28, 'Enter', '', '', 1.7)],
  [M(0xe1, 'Shift', 1.4), K(0x64, '<', '>'), ...'zxcvbnm'.split('').map((c) => K(0x04 + c.charCodeAt(0) - 97, c)),
    K(0x36, ',', ';'), K(0x37, '.', ':'), K(0x38, '-', '_'), M(0xe5, 'Shift', 1.4)],
  [M(0xe0, 'Ctrl'), M(0xe3, 'Win'), M(0xe2, 'Alt'), K(0x2c, 'Espacio', '', '', 4), M(0xe6, 'AltGr'),
    K(0x50, '←'), K(0x52, '↑'), K(0x51, '↓'), K(0x4f, '→')],
  [K(0x49, 'Ins'), K(0x4c, 'Supr'), K(0x4a, 'Inicio'), K(0x4d, 'Fin'), K(0x4b, 'RePág'), K(0x4e, 'AvPág'), K(0x46, 'ImpPnt')],
];

// Teclado compacto (como el del celular): letras + capas "?123" y "#+=". Cada símbolo manda la combinación de su
// tecla en la distribución latinoamericana (por ejemplo @ = AltGr+Q, ! = Shift+1): se escribe el símbolo directo.
const SH = 0xe1, AG = 0xe6;
const SYM = { '-': [0x38], '/': [0x24, SH], ':': [0x37, SH], ';': [0x36, SH], '(': [0x25, SH], ')': [0x26, SH], $: [0x21, SH],
  '&': [0x23, SH], '@': [0x14, AG], '"': [0x1f, SH], '.': [0x37], ',': [0x36], '?': [0x2d, SH], '!': [0x1e, SH], "'": [0x2d],
  '[': [0x34, SH], ']': [0x32, SH], '{': [0x34], '}': [0x32], '#': [0x20, SH], '%': [0x22, SH], '^': [0x34, AG], '*': [0x30, SH],
  '+': [0x30], '=': [0x27, SH], _: [0x38, SH], '\\': [0x2d, AG], '|': [0x35], '~': [0x30, AG], '<': [0x64], '>': [0x64, SH],
  '¿': [0x2e], '¡': [0x2e, SH], '°': [0x35, SH], '¬': [0x35, AG], '´': [0x2f], '¨': [0x2f, SH], '`': [0x32, AG] };
const S = (ch) => ({ u: SYM[ch][0], l: ch, m: SYM[ch].slice(1), w: 1 });
const LY = (layer, l, w = 1.4) => ({ layer, l, w });
const letters = (str) => str.split('').map((c) => K(c === 'ñ' ? 0x33 : 0x04 + c.charCodeAt(0) - 97, c));
const COMPACT = {
  abc: [letters('qwertyuiop'), letters('asdfghjklñ'), [M(0xe1, '⇧', 1.4), ...letters('zxcvbnm'), K(0x2a, '⌫', '', '', 1.4)]],
  123: ['1234567890'.split('').map((c) => K(c === '0' ? 0x27 : 0x1d + Number(c), c)), '-/:;()$&@"'.split('').map(S),
    [LY('sym', '#+='), K(0x2b, 'Tab', '', '', 1.2), K(0x29, 'Esc', '', '', 1.2), ...".,?!'".split('').map(S), K(0x2a, '⌫', '', '', 1.4)]],
  sym: ['[]{}#%^*+='.split('').map(S), '_\\|~<>¿¡°¬'.split('').map(S),
    [LY('123', '123'), ...'´¨`'.split('').map(S), K(0x4c, 'Supr', '', '', 1.2), K(0x4a, 'Inicio', '', '', 1.3), K(0x4d, 'Fin', '', '', 1.1), K(0x2a, '⌫', '', '', 1.4)]],
};
const COMPACT_BOTTOM = [LY('switch', '?123'), M(0xe0, 'Ctrl', 1.1), M(0xe3, '⊞', 1), M(0xe2, 'Alt', 1.1), K(0x2c, 'espacio', '', '', 3),
  K(0x50, '←'), K(0x52, '↑'), K(0x51, '↓'), K(0x4f, '→'), K(0x28, '↵', '', '', 1.3)];

const landscapeMQ = matchMedia('(orientation: landscape) and (max-height: 600px)');
const kbIsCompact = () => (landscapeMQ.matches ? (cfg.kbLand || 'compact') : (cfg.kbPort || 'full')) === 'compact';
const kb = { layer: 'abc' };

function makeKey(k) {
  const b = document.createElement('div');
  b.className = 'key' + (k.mod ? ' mod' : '') + (k.layer ? ' mod layer' : '') + (k.l.length > 2 ? ' wide-label' : '');
  b.style.flexGrow = k.w;
  if (k.u !== undefined) b.dataset.u = k.u;
  if (k.m) b.dataset.sym = k.l;
  b.setAttribute('role', 'button');
  b.setAttribute('aria-label', k.l);
  const main = document.createElement('span');
  main.className = 'kl';
  main.textContent = k.l;
  b.appendChild(main);
  if (k.s) { const e = document.createElement('span'); e.className = 'ks'; e.textContent = k.s; b.appendChild(e); }
  if (k.a) { const e = document.createElement('span'); e.className = 'ka'; e.textContent = k.a; b.appendChild(e); }
  if (k.layer) setupLayerKey(b, k); else setupKey(b, k);
  return b;
}

function row(keys, cls = '') {
  const r = document.createElement('div');
  r.className = 'krow' + cls;
  for (const k of keys) r.appendChild(makeKey(k));
  return r;
}

function buildKeyboard() {
  releaseAllLocal();
  const el = $('#kbd');
  el.innerHTML = '';
  const compact = kbIsCompact();
  el.classList.toggle('compact', compact);
  $('#kbMode').textContent = compact ? 'Teclado completo' : 'Teclado compacto';
  $('#rKbSel').value = compact ? 'compact' : 'full';
  if (!compact) {
    KEYBOARD.forEach((r, i) => el.appendChild(row(r, (i === 0 ? ' fn' : '') + (i === KEYBOARD.length - 1 ? ' nav' : ''))));
    return;
  }
  // Las tres capas quedan armadas (solo se ve una): así un dedo que ya está apretando una tecla no se pierde.
  for (const [name, rows] of Object.entries(COMPACT)) {
    const layer = document.createElement('div');
    layer.className = 'kb-layer';
    layer.dataset.layer = name;
    layer.hidden = name !== kb.layer;
    rows.forEach((r) => layer.appendChild(row(r)));
    el.appendChild(layer);
  }
  el.appendChild(row(COMPACT_BOTTOM, ' bottom'));
  showLayer(kb.layer);
}

function showLayer(name) {
  kb.layer = name;
  document.querySelectorAll('.kb-layer').forEach((l) => { l.hidden = l.dataset.layer !== name; });
  const sw = document.querySelector('.krow.bottom .layer .kl');
  if (sw) sw.textContent = name === 'abc' ? '?123' : 'abc';
}

// Cambiar de capa es un toque (queda en esa capa, como en el iPhone). Ctrl/Shift/Alt/Win siguen siendo "mientras el dedo está".
function setupLayerKey(el, k) {
  el.addEventListener('pointerdown', (e) => { e.preventDefault(); el.classList.add('down'); });
  el.addEventListener('pointerup', () => {
    el.classList.remove('down');
    if (k.layer === 'switch') showLayer(kb.layer === 'abc' ? '123' : 'abc');
    else showLayer(k.layer);
  });
  el.addEventListener('pointercancel', () => el.classList.remove('down'));
}

// Cada tecla sigue a SU dedo (multitouch): apretada mientras el dedo está encima, nada queda pegado.
function setupKey(el, k) {
  let pid = null, repeat = null, extra = [];
  const isShift = k.mod && (k.u === 0xe1 || k.u === 0xe5);
  const down = (e) => {
    e.preventDefault();
    if (pid !== null) return;
    pid = e.pointerId;
    try { el.setPointerCapture(pid); } catch { /* sin captura */ }
    el.classList.add('down');
    // símbolos del teclado compacto: aprieta Shift/AltGr si hace falta (y los suelta al final)
    extra = (k.m || []).filter((m) => !R.held.has(m));
    for (const m of extra) keyEvent(m, true);
    keyEvent(k.u, true);
    if (isShift) document.body.classList.add('shift-on');
    // Repetición al mantener (Windows no repite las teclas de SendInput)
    // (por la ESP no hace falta: Windows repite solo las teclas de un teclado Bluetooth)
    if (!k.mod) repeat = setTimeout(function rep() { if (pid !== null && viaHost()) { sendInput(enc.key(k.u, true)); repeat = setTimeout(rep, 40); } }, 450);
  };
  const up = (e) => {
    if (e.pointerId !== pid) return;
    pid = null;
    clearTimeout(repeat);
    el.classList.remove('down');
    keyEvent(k.u, false);
    for (const m of extra.reverse()) keyEvent(m, false);
    extra = [];
    if (isShift && !R.held.has(0xe1) && !R.held.has(0xe5)) document.body.classList.remove('shift-on');
  };
  el.addEventListener('pointerdown', down);
  el.addEventListener('pointerup', up);
  el.addEventListener('pointercancel', up);
  el.addEventListener('lostpointercapture', up);
}

// ------------------------------------------------------------ multimedia

function setupMedia() {
  document.querySelectorAll('[data-media]').forEach((b) => {
    const u = parseInt(b.dataset.media, 16);
    let rep = null;
    b.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      b.classList.add('down');
      sendInput(enc.consumer(u));
      if (b.dataset.repeat) rep = setInterval(() => sendInput(enc.consumer(u)), 180);
    });
    const stop = () => { b.classList.remove('down'); clearInterval(rep); rep = null; };
    b.addEventListener('pointerup', stop);
    b.addEventListener('pointercancel', stop);
    b.addEventListener('pointerleave', stop);
  });
}

// ------------------------------------------------------------ joystick (control de Xbox 360 virtual en la compu)
// Dibujado como un DualSense. Solo por el host (necesita el driver ViGEmBus en Windows).

const GP = { on: false, avail: null, st: { buttons: 0, lt: 0, rt: 0, lx: 0, ly: 0, rx: 0, ry: 0 }, raf: 0, waiting: null };
enc.pad = (st) => {
  const b = new Uint8Array(13);
  const v = new DataView(b.buffer);
  b[0] = 10;
  v.setUint16(1, st.buttons, true);
  b[3] = st.lt; b[4] = st.rt;
  v.setInt16(5, st.lx, true); v.setInt16(7, st.ly, true); v.setInt16(9, st.rx, true); v.setInt16(11, st.ry, true);
  return b;
};
const padNeutral = () => { const t = GP.st; return !t.buttons && !t.lt && !t.rt && !t.lx && !t.ly && !t.rx && !t.ry; };
function padSend() {
  if (GP.raf) return;
  GP.raf = requestAnimationFrame(() => { GP.raf = 0; if (viaHost()) R.live.inp.send(enc.pad(GP.st)); });
}

function setupGamepad() {
  const root = $('#gp');
  root.querySelectorAll('[data-gb]').forEach((el) => {
    const bit = parseInt(el.dataset.gb, 16);
    const pids = new Set();
    const set = () => { GP.st.buttons = pids.size ? GP.st.buttons | bit : GP.st.buttons & ~bit; el.classList.toggle('down', pids.size > 0); padSend(); };
    el.addEventListener('pointerdown', (e) => { e.preventDefault(); try { el.setPointerCapture(e.pointerId); } catch { /* nada */ } pids.add(e.pointerId); set(); });
    const up = (e) => { if (pids.delete(e.pointerId)) set(); };
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  });
  root.querySelectorAll('[data-gt]').forEach((el) => {
    const key = el.dataset.gt;
    const pids = new Set();
    const set = () => { GP.st[key] = pids.size ? 255 : 0; el.classList.toggle('down', pids.size > 0); padSend(); };
    el.addEventListener('pointerdown', (e) => { e.preventDefault(); try { el.setPointerCapture(e.pointerId); } catch { /* nada */ } pids.add(e.pointerId); set(); });
    const up = (e) => { if (pids.delete(e.pointerId)) set(); };
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  });
  root.querySelectorAll('[data-stick]').forEach((el) => {
    const [kx, ky] = el.dataset.stick === 'l' ? ['lx', 'ly'] : ['rx', 'ry'];
    const click = el.dataset.stick === 'l' ? 0x0040 : 0x0080; // L3 / R3
    const knob = el.querySelector('.knob');
    let pid = null, lastUp = 0, clicking = false;
    // Sensible: llega al tope con el dedo al 60 % del radio (con un poquito de zona muerta en el centro).
    // El botón de la palanca se puede estirar más allá del borde para que se vea hacia dónde va.
    const FULL = 0.6, DEAD = 0.06, TRAVEL = 0.95;
    const move = (e) => {
      const r = el.getBoundingClientRect();
      const rad = r.width / 2;
      const fx = (e.clientX - (r.left + rad)) / rad, fy = (e.clientY - (r.top + rad)) / rad;
      const m = Math.hypot(fx, fy);
      const v = m <= DEAD ? 0 : Math.min(1, (m - DEAD) / (FULL - DEAD)); // 0..1
      const ux = m ? fx / m : 0, uy = m ? fy / m : 0;
      const vis = Math.min(m, 1.4) / 1.4 * TRAVEL;
      knob.style.transform = `translate(${ux * vis * rad}px, ${uy * vis * rad}px)`;
      GP.st[kx] = clamp16(ux * v * 32767);
      GP.st[ky] = clamp16(-uy * v * 32767); // en XInput, arriba es positivo
      padSend();
    };
    el.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      if (pid !== null) return;
      pid = e.pointerId;
      try { el.setPointerCapture(pid); } catch { /* nada */ }
      el.classList.add('down');
      // doble toque y mantener = L3/R3 apretado mientras el dedo sigue en la palanca (se puede seguir moviendo)
      clicking = performance.now() - lastUp < 300;
      if (clicking) { GP.st.buttons |= click; el.classList.add('click'); }
      move(e);
    });
    el.addEventListener('pointermove', (e) => { if (e.pointerId === pid) move(e); });
    const up = (e) => {
      if (e.pointerId !== pid) return;
      pid = null;
      el.classList.remove('down', 'click');
      knob.style.transform = '';
      GP.st[kx] = 0; GP.st[ky] = 0;
      if (clicking) { GP.st.buttons &= ~click; clicking = false; lastUp = 0; } else lastUp = performance.now();
      padSend();
    };
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  });
  $('#btnGp').addEventListener('click', () => setGamepad(!GP.on));
  $('#gpOff').addEventListener('click', () => setGamepad(false));
}

function resetGamepad() {
  GP.st = { buttons: 0, lt: 0, rt: 0, lx: 0, ly: 0, rx: 0, ry: 0 };
  document.querySelectorAll('#gp .down').forEach((e) => e.classList.remove('down'));
  document.querySelectorAll('#gp .knob').forEach((k) => { k.style.transform = ''; });
}

function showGamepad(on) {
  GP.on = on;
  $('#gp').hidden = !on;
  document.body.classList.toggle('gp-on', on);
  $('#btnGp').classList.toggle('on', on);
  if (!on) resetGamepad();
  setTimeout(applyZoom, 50);
}

function setGamepad(on) {
  if (!on) { if (GP.on && viaHost()) { R.live.inp.send(enc.pad({ buttons: 0, lt: 0, rt: 0, lx: 0, ly: 0, rx: 0, ry: 0 })); sendCtl({ t: 'pad', on: false }); } showGamepad(false); return; }
  if (!R.live || !R.live.connected) { setStatus('El joystick necesita la pantalla conectada (programa de la compu).'); return; }
  if (GP.avail === false) { setStatus('Para el joystick, la compu necesita el driver ViGEmBus (ver README).'); return; }
  setStatus('Conectando el joystick…');
  sendCtl({ t: 'pad', on: true });
  clearTimeout(GP.waiting);
  GP.waiting = setTimeout(() => setStatus('La compu no respondió. ¿PC Unlock Host está actualizado (1.1.0 o más nuevo)?'), 4000);
}

// ------------------------------------------------------------ zoom y desplazamiento del video

const zoom = { s: 1, x: 0, y: 0, pts: new Map(), start: null, lastTap: 0 };

function applyZoom() {
  const st = $('#stage');
  const w = st.clientWidth, h = st.clientHeight;
  zoom.s = Math.min(6, Math.max(1, zoom.s));
  zoom.x = Math.min(0, Math.max(w - w * zoom.s, zoom.x));
  zoom.y = Math.min(0, Math.max(h - h * zoom.s, zoom.y));
  $('#rVideo').style.transform = `translate(${zoom.x}px, ${zoom.y}px) scale(${zoom.s})`;
}

function setupZoom() {
  const st = $('#stage');
  const pts = zoom.pts;
  const snapshot = () => {
    const a = [...pts.values()];
    const r = st.getBoundingClientRect();
    if (a.length >= 2) {
      const mx = (a[0].x + a[1].x) / 2 - r.left, my = (a[0].y + a[1].y) / 2 - r.top;
      zoom.start = { d: Math.hypot(a[0].x - a[1].x, a[0].y - a[1].y), mx, my, s: zoom.s, x: zoom.x, y: zoom.y };
    } else if (a.length === 1) {
      zoom.start = { px: a[0].x, py: a[0].y, x: zoom.x, y: zoom.y };
    }
  };
  st.addEventListener('pointerdown', (e) => {
    if (e.target.closest('button, .overlay, .gp-c')) return;
    e.preventDefault();
    st.setPointerCapture(e.pointerId);
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    snapshot();
    const now = performance.now();
    if (pts.size === 1 && now - zoom.lastTap < 300) { zoom.s = 1; zoom.x = 0; zoom.y = 0; applyZoom(); } // doble toque = sin zoom
    zoom.lastTap = now;
  });
  st.addEventListener('pointermove', (e) => {
    if (!pts.has(e.pointerId)) return;
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    const a = [...pts.values()], s0 = zoom.start;
    if (!s0) return;
    if (a.length >= 2 && s0.d) {
      const r = st.getBoundingClientRect();
      const d = Math.hypot(a[0].x - a[1].x, a[0].y - a[1].y);
      const mx = (a[0].x + a[1].x) / 2 - r.left, my = (a[0].y + a[1].y) / 2 - r.top;
      const s = Math.min(6, Math.max(1, s0.s * (d / s0.d)));
      // el punto que estaba bajo los dedos queda bajo los dedos
      zoom.x = mx - ((s0.mx - s0.x) / s0.s) * s;
      zoom.y = my - ((s0.my - s0.y) / s0.s) * s;
      zoom.s = s;
      applyZoom();
    } else if (a.length === 1 && s0.px !== undefined && zoom.s > 1) {
      zoom.x = s0.x + (a[0].x - s0.px);
      zoom.y = s0.y + (a[0].y - s0.py);
      applyZoom();
    }
  });
  const up = (e) => { pts.delete(e.pointerId); snapshot(); };
  st.addEventListener('pointerup', up);
  st.addEventListener('pointercancel', up);
  $('#rVideo').addEventListener('loadedmetadata', () => {
    const v = $('#rVideo');
    if (v.videoWidth) st.style.setProperty('--ar', `${v.videoWidth} / ${v.videoHeight}`);
    applyZoom();
  });
  $('#rVideo').addEventListener('resize', () => {
    const v = $('#rVideo');
    if (v.videoWidth) st.style.setProperty('--ar', `${v.videoWidth} / ${v.videoHeight}`);
  });
  addEventListener('resize', applyZoom);
}

// ------------------------------------------------------------ desbloquear (por la ESP) desde la vista Remoto

async function remoteUnlock(btn) {
  btn.disabled = true;
  try {
    let signed;
    try { signed = await signCommand('unlock'); } // Face ID primero
    catch (e) { setStatus(e?.name === 'NotAllowedError' ? 'Cancelado.' : 'Error de Face ID: ' + e.message); return; }
    setStatus('Desbloqueando…');
    const r = await sendToEsp(signed, 'unlock');
    setStatus(r.ok ? 'PIN enviado.' : r.msg || 'Error');
  } finally { btn.disabled = false; }
}

// ------------------------------------------------------------ eventos

// En horizontal la columna de la derecha se ensancha solo si el teclado está abierto
function panelLayout() {
  document.body.classList.toggle('kb-open', !$('#panel-kbd').hidden);
  document.body.classList.toggle('no-panels', [...document.querySelectorAll('.panel')].every((p) => p.hidden));
  setTimeout(applyZoom, 60);
}

function togglePanel(name) {
  const p = $('#panel-' + name);
  p.hidden = !p.hidden;
  document.querySelector(`[data-panel="${name}"]`).classList.toggle('on', !p.hidden);
  panelLayout();
  const open = [...document.querySelectorAll('.panel')].filter((x) => !x.hidden).map((x) => x.id.slice(6));
  cfg.panels = open;
  saveCfg();
}

function setupRemote() {
  buildKeyboard();
  setupPad();
  setupMedia();
  setupZoom();
  setupGamepad();
  landscapeMQ.addEventListener('change', () => { buildKeyboard(); setTimeout(applyZoom, 100); });
  const setKbMode = (mode) => {
    if (landscapeMQ.matches) cfg.kbLand = mode; else cfg.kbPort = mode;
    saveCfg();
    buildKeyboard();
  };
  $('#kbMode').addEventListener('click', () => setKbMode(kbIsCompact() ? 'full' : 'compact'));
  $('#rKbSel').addEventListener('change', (e) => setKbMode(e.target.value));
  document.querySelectorAll('#rFps [data-fps]').forEach((b) => b.addEventListener('click', () => {
    cfg.fps = Number(b.dataset.fps);
    saveCfg();
    document.querySelectorAll('#rFps [data-fps]').forEach((x) => x.classList.toggle('on', x === b));
    $('#rFpsSel').value = String(cfg.fps);
  }));
  $('#rFpsSel').value = String(cfg.fps || 60);
  $('#rLowLat').checked = lowLatOn();
  if (!lowLatSupported()) { $('#rLowLat').disabled = true; $('#rLowLatNote').textContent = '(este navegador no lo permite)'; }
  $('#rLowLat').addEventListener('change', (e) => { cfg.lowLat = e.target.checked; saveCfg(); applyLowLatency(); D.last = null; });
  $('#rFpsSel').addEventListener('change', (e) => {
    cfg.fps = Number(e.target.value);
    saveCfg();
    sendCtl({ t: 'fps', v: cfg.fps });
  });
  // Que iOS no "agarre" los toques: sin selección de texto, lupa, menú de copiar ni zoom de la página.
  const NO_GESTURE = '#pad, #kbd, .media, #stage';
  document.addEventListener('touchstart', (e) => {
    if (!R.visible) return;
    const t = e.target;
    if (t.closest('.overlay button, .seg button, #rFsExit, #gpOff, select, input, label')) return;
    if (t.closest(NO_GESTURE)) e.preventDefault();
  }, { passive: false });
  for (const ev of ['contextmenu', 'selectstart', 'gesturestart']) document.addEventListener(ev, (e) => { if (R.visible) e.preventDefault(); });
  for (const name of cfg.panels || ['kbd', 'pad']) { const p = $('#panel-' + name); if (p) { p.hidden = false; document.querySelector(`[data-panel="${name}"]`)?.classList.add('on'); } }
  document.querySelectorAll('[data-panel]').forEach((b) => b.addEventListener('click', () => togglePanel(b.dataset.panel)));
  panelLayout();
  $('#btnRemote').addEventListener('click', showRemote);
  $('#rBack').addEventListener('click', showHome);
  $('#rConnect').addEventListener('click', connectRemote);
  $('#rOvUnlock').addEventListener('click', (e) => remoteUnlock(e.currentTarget));
  $('#rLockUnlock').addEventListener('click', (e) => remoteUnlock(e.currentTarget));
  $('#rRenew').addEventListener('click', renewSession);
  $('#rEnd').addEventListener('click', () => endLive('Sesión cortada.'));
  // Pantalla completa: solo esconde la barra de arriba para ganar lugar. Nada se superpone al video.
  const setFs = (on) => {
    document.body.classList.toggle('fs', on);
    if (on && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(() => {});
    if (!on && document.fullscreenElement) document.exitFullscreen().catch(() => {});
    setTimeout(applyZoom, 80);
  };
  $('#rFull').addEventListener('click', () => setFs(true));
  $('#rFsExit').addEventListener('click', () => setFs(false));
  R.quality = cfg.saver ? 'saver' : 'auto';
  $('#rSaver').checked = !!cfg.saver;
  $('#rSaver').addEventListener('change', (e) => {
    cfg.saver = e.target.checked; saveCfg();
    R.quality = cfg.saver ? 'saver' : 'auto';
    sendCtl({ t: 'quality', mode: R.quality });
  });
  $('#rMonitor').addEventListener('change', (e) => sendCtl({ t: 'monitor', id: e.target.value }));

  // Ajustes: compu y TURN
  $('#btnHostMatch').addEventListener('click', confirmHost);
  $('#btnHostNoMatch').addEventListener('click', () => {
    $('#hostCodeBox').hidden = true;
    $('#hostPairState').textContent = 'No se emparejó. Si el código no coincide, alguien podría estar en el medio: revisá que el programa de la compu use tu código.';
    $('#hostPairState').className = 'hint err';
  });
  $('#btnHostForget').addEventListener('click', () => {
    if (!confirm('¿Olvidar esta compu? Para volver a usar la pantalla remota vas a tener que comparar el código otra vez.')) return;
    delete cfg.hostKey; delete cfg.hostId; saveCfg(); refreshHostSettings();
  });
  $('#btnEspMatch').addEventListener('click', () => {
    const k = $('#espCodeBox').dataset.key;
    if (!k) return;
    cfg.espKey = k;
    saveCfg();
    refreshEspSettings();
  });
  $('#btnEspNoMatch').addEventListener('click', () => {
    $('#espCodeBox').hidden = true;
    $('#espPairState').textContent = 'No se emparejó. Si el código no coincide, no la uses como respaldo y revisá la ESP.';
    $('#espPairState').className = 'hint err';
  });
  $('#btnEspForget').addEventListener('click', () => {
    if (!confirm('¿Olvidar esta ESP como teclado/mouse de respaldo?')) return;
    delete cfg.espKey;
    saveCfg();
    refreshEspSettings();
  });
  $('#turnUrl').value = cfg.turnUrl || '';
  $('#turnUser').value = cfg.turnUser || '';
  $('#turnPass').value = cfg.turnPass || '';
  $('#btnSaveTurn').addEventListener('click', () => {
    const url = $('#turnUrl').value.trim();
    if (url && !/^turns?:/i.test(url.split(/[\s,]+/)[0])) { $('#turnMsg').textContent = 'Tiene que empezar con turn: o turns:'; $('#turnMsg').className = 'hint err'; return; }
    cfg.turnUrl = url; cfg.turnUser = $('#turnUser').value.trim(); cfg.turnPass = $('#turnPass').value;
    saveCfg();
    $('#turnMsg').textContent = url ? '✔ Guardado. Se usa en la próxima conexión.' : '✔ Sin TURN (solo STUN).';
    $('#turnMsg').className = 'hint ok';
  });

  // App en segundo plano: soltar todo y pausar el video (casi no gasta datos). Al volver, sigue.
  document.addEventListener('visibilitychange', () => {
    if (!R.live) return;
    if (document.visibilityState === 'hidden') { releaseAllLocal(); sendCtl({ t: 'pause' }); }
    else sendCtl({ t: 'resume' });
  });
  addEventListener('pagehide', releaseAllLocal);
}

// ------------------------------------------------------------ inicio

setupRemote();
Object.assign(window.PCU, { verifyCode, R, showRemote, sdpFingerprint, enc, viaHost, espActive, GP, kb, buildKeyboard, D });
if (!cfg.credId || !cfg.host) showSettings();
connect();
