'use strict';
/* global host */
// Ventana oculta: captura el monitor y responde la oferta WebRTC de la app.
// Video H.264 (aceleración por hardware si Windows la ofrece) + DataChannels "in" (binario) y "ctl" (JSON).

let pc = null, sender = null, track = null, source = null, quality = 'auto', fps = 30, ctl = null;
// Modo juego: se captura y se manda a 720p o 1080p, priorizando los fps. Medido el 14/10 en el iPhone: a 2560×1440 casi
// todo el retardo (~190 ms) era lo que tarda en llegar cada cuadro completo; con cuadros más chicos baja.
let game = { on: false, h: 720 };

// Tamaño de captura: completo, o escalado al alto del modo juego (sin agrandar si el monitor es más chico)
function captureSize(src) {
  if (!game.on || src.h <= game.h) return { w: src.w, h: src.h };
  return { w: Math.round((src.w * game.h) / src.h / 2) * 2, h: game.h };
}
let lastBytes = 0, lastTs = 0, discTimer = null;

async function capture(src) {
  const size = captureSize(src);
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: { mandatory: { chromeMediaSource: 'desktop', chromeMediaSourceId: src.id,
      maxWidth: size.w, maxHeight: size.h, maxFrameRate: fps } },
  });
  const t = stream.getVideoTracks()[0];
  t.contentHint = game.on ? 'motion' : 'detail'; // juego: priorizar fluidez; escritorio: nitidez del texto
  return t;
}

// Vuelve a abrir la captura con la configuración actual (fps, modo juego, monitor) sin renegociar
async function recapture() {
  const t = await capture(source);
  await sender.replaceTrack(t);
  if (track) track.stop();
  track = t;
  applyQuality();
}

// El iPhone (Safari) ofrece H.264 "Constrained Baseline" (42e0xx) y "Constrained High" (640cxx). Con Constrained Baseline,
// Chromium NO usa el codificador por hardware (NVENC vía Media Foundation) sino OpenH264 por software: a 2560×1440 da
// 10-25 fps. Con "Baseline" (4200xx) sí usa NVENC (55+ fps). Así que la oferta se negocia internamente como Baseline y en
// la respuesta se vuelve a poner el perfil original de cada payload type. Es compatible: NVENC no usa FMO/ASO ni slices
// redundantes (lo único que distingue Baseline de Constrained Baseline). La seguridad no cambia: lo firmado es el fingerprint DTLS.
function fmtpProfiles(sdp) {
  const m = new Map();
  for (const x of sdp.matchAll(/^a=fmtp:(\d+) .*profile-level-id=([0-9a-fA-F]{6})/gm)) m.set(x[1], x[2]);
  return m;
}
function offerForHwEncoder(sdp) {
  return sdp.replace(/(profile-level-id=)42e0([0-9a-fA-F]{2})/gi, '$14200$2');
}
function restoreProfiles(answer, offerProfiles) {
  return answer.replace(/^(a=fmtp:(\d+) .*profile-level-id=)([0-9a-fA-F]{6})/gm, (all, pre, pt) =>
    (offerProfiles.has(pt) ? pre + offerProfiles.get(pt) : all));
}

function iceDone(ms) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve();
    const to = setTimeout(resolve, ms);
    pc.addEventListener('icegatheringstatechange', () => {
      if (pc.iceGatheringState === 'complete') { clearTimeout(to); resolve(); }
    });
  });
}

async function applyQuality() {
  if (!sender || !source) return;
  const p = sender.getParameters();
  if (!p.encodings || !p.encodings.length) return;
  const e = p.encodings[0];
  const cw = captureSize(source).w;
  if (quality === 'saver') {
    e.maxBitrate = 350_000; e.maxFramerate = 12; e.scaleResolutionDownBy = Math.max(1, cw / 1280);
  } else if (game.on) {
    // modo juego: la resolución ya viene chica de la captura; bitrate suficiente para movimiento a 60 fps
    e.maxBitrate = game.h >= 1080 ? (fps === 60 ? 12_000_000 : 8_000_000) : (fps === 60 ? 6_000_000 : 4_000_000);
    e.maxFramerate = fps; e.scaleResolutionDownBy = 1;
  } else {
    // 60 fps: más bitrate para que el movimiento no se vea borroso (igual se adapta solo si la conexión no da)
    e.maxBitrate = fps === 60 ? 15_000_000 : 8_000_000; e.maxFramerate = fps; e.scaleResolutionDownBy = Math.max(1, cw / 2560);
  }
  p.degradationPreference = quality === 'saver' ? 'maintain-resolution' : game.on ? 'maintain-framerate' : 'balanced';
  try { await sender.setParameters(p); } catch (err) { host.log('setParameters: ' + err.message); }
}

function sendCtl(m) { if (ctl && ctl.readyState === 'open') ctl.send(JSON.stringify(m)); }

function onCtl(ev) {
  let m;
  try { m = JSON.parse(ev.data); } catch { return; }
  if (!m || typeof m.t !== 'string') return;
  if (m.t === 'pause') { if (track) track.enabled = false; return; }  // app en segundo plano: casi sin datos
  if (m.t === 'resume') { if (track) track.enabled = true; return; }
  host.ctl(m);
}

async function stats() {
  if (!pc) return;
  const r = await pc.getStats();
  let out = null, codec = '', pair = null;
  const byId = new Map();
  r.forEach((s) => byId.set(s.id, s));
  r.forEach((s) => {
    if (s.type === 'outbound-rtp' && s.kind === 'video') out = s;
    if (s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') pair = s;
  });
  if (!out) { host.log('stats: sin outbound-rtp (' + [...byId.values()].map((s) => s.type).join(',') + ')'); return; }
  if (out.codecId && byId.get(out.codecId)) codec = byId.get(out.codecId).mimeType.replace('video/', '');
  const now = out.timestamp;
  const kbps = lastTs ? Math.round(((out.bytesSent - lastBytes) * 8) / (now - lastTs)) : 0;
  lastBytes = out.bytesSent; lastTs = now;
  let route = '';
  if (pair) {
    const l = byId.get(pair.localCandidateId), rm = byId.get(pair.remoteCandidateId);
    route = (l && l.candidateType === 'relay') || (rm && rm.candidateType === 'relay') ? 'relay' : 'directo';
  }
  const s = { codec, hw: !!out.powerEfficientEncoder, impl: out.encoderImplementation || '', w: out.frameWidth || 0,
    h: out.frameHeight || 0, fps: Math.round(out.framesPerSecond || 0), kbps, route, limit: out.qualityLimitationReason || '' };
  host.stats(s);
  sendCtl({ t: 'stats', ...s });
}

host.onStart(async (o) => {
  try {
    source = o.source;
    quality = o.quality;
    fps = o.fps === 60 ? 60 : 30;
    if (o.game) game = { on: !!o.game.on, h: o.game.h === 1080 ? 1080 : 720 };
    track = await capture(source);
    pc = new RTCPeerConnection({ iceServers: o.ice, bundlePolicy: 'max-bundle' });
    pc.addEventListener('datachannel', (ev) => {
      const dc = ev.channel;
      dc.binaryType = 'arraybuffer';
      if (dc.label === 'in') dc.onmessage = (m) => { if (m.data instanceof ArrayBuffer) host.input(new Uint8Array(m.data)); };
      if (dc.label === 'ctl') {
        ctl = dc;
        dc.onmessage = onCtl;
        dc.onopen = () => host.ctl({ t: 'hello' });
        dc.onclose = () => host.state('closed');
      }
    });
    pc.addEventListener('connectionstatechange', () => {
      const st = pc.connectionState;
      host.state(st);
      clearTimeout(discTimer);
      if (st === 'connected') applyQuality();
      // "disconnected" puede volver solo; si dura más de 10 s se da por cortada
      if (st === 'disconnected') discTimer = setTimeout(() => host.state('failed'), 10000);
    });
    const offerProfiles = fmtpProfiles(o.offer);
    host.log('H.264 que ofrece el cliente: ' + ([...new Set(offerProfiles.values())].join(', ') || 'ninguno'));
    await pc.setRemoteDescription({ type: 'offer', sdp: offerForHwEncoder(o.offer) });
    const tr = pc.getTransceivers().find((t) => t.receiver.track && t.receiver.track.kind === 'video');
    if (!tr) throw new Error('La oferta no trae video');
    tr.direction = 'sendonly';
    await tr.sender.replaceTrack(track);
    sender = tr.sender;
    try {
      const caps = RTCRtpSender.getCapabilities('video').codecs;
      const h264 = caps.filter((c) => /h264/i.test(c.mimeType));
      if (h264.length) tr.setCodecPreferences([...h264, ...caps.filter((c) => !/h264/i.test(c.mimeType))]);
    } catch (err) { host.log('codecs: ' + err.message); }
    await pc.setLocalDescription(await pc.createAnswer());
    await iceDone(4000);
    host.answer({ sdp: restoreProfiles(pc.localDescription.sdp, offerProfiles) });
    setInterval(() => stats().catch((e) => host.log('stats: ' + e.message)), 2000);
  } catch (err) {
    host.answer({ error: err.message || String(err) });
  }
});

host.onCtl((m) => sendCtl(m));
host.onQuality((q) => { quality = q; applyQuality(); });
// Cambiar los fps vuelve a abrir la captura con el tope nuevo (sin renegociar)
host.onGame(async (g) => {
  game = { on: !!g.on, h: g.h === 1080 ? 1080 : 720 };
  try { await recapture(); } catch (err) { host.log('modo juego: ' + err.message); }
});

host.onFps(async (f) => {
  fps = f === 60 ? 60 : 30;
  try {
    const t = await capture(source);
    await sender.replaceTrack(t);
    if (track) track.stop();
    track = t;
    applyQuality();
  } catch (err) { host.log('cambio de fps: ' + err.message); }
});

host.onSource(async (src) => {
  try {
    const t = await capture(src);
    await sender.replaceTrack(t);
    if (track) track.stop();
    track = t;
    source = src;
    applyQuality();
  } catch (err) { host.log('cambio de monitor: ' + err.message); }
});
