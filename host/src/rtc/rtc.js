'use strict';
/* global host */
// Ventana oculta: captura el monitor y responde la oferta WebRTC de la app.
// Video H.264 (aceleración por hardware si Windows la ofrece) + DataChannels "in" (binario) y "ctl" (JSON).

let pc = null, sender = null, track = null, source = null, quality = 'auto', fps = 30, ctl = null;
let lastBytes = 0, lastTs = 0, discTimer = null;

async function capture(src) {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: { mandatory: { chromeMediaSource: 'desktop', chromeMediaSourceId: src.id,
      maxWidth: src.w, maxHeight: src.h, maxFrameRate: fps } },
  });
  const t = stream.getVideoTracks()[0];
  t.contentHint = 'detail'; // escritorio: priorizar nitidez del texto
  return t;
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
  if (quality === 'saver') {
    e.maxBitrate = 350_000; e.maxFramerate = 12; e.scaleResolutionDownBy = Math.max(1, source.w / 1280);
  } else {
    // 60 fps: más bitrate para que el movimiento no se vea borroso (igual se adapta solo si la conexión no da)
    e.maxBitrate = fps === 60 ? 15_000_000 : 8_000_000; e.maxFramerate = fps; e.scaleResolutionDownBy = Math.max(1, source.w / 2560);
  }
  p.degradationPreference = quality === 'saver' ? 'maintain-resolution' : 'balanced';
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
    await pc.setRemoteDescription({ type: 'offer', sdp: o.offer });
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
    host.answer({ sdp: pc.localDescription.sdp });
    setInterval(() => stats().catch((e) => host.log('stats: ' + e.message)), 2000);
  } catch (err) {
    host.answer({ error: err.message || String(err) });
  }
});

host.onCtl((m) => sendCtl(m));
host.onQuality((q) => { quality = q; applyQuality(); });
// Cambiar los fps vuelve a abrir la captura con el tope nuevo (sin renegociar)
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
