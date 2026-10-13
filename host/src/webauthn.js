'use strict';
// Verificación de aserciones WebAuthn (ES256 / P-256), igual que firmware/pc-unlock/auth.cpp.
// No depende de Electron: se prueba con node --test contra los mismos fixtures del firmware.
const crypto = require('node:crypto');

const b64u = {
  enc: (buf) => Buffer.from(buf).toString('base64url'),
  dec: (str) => {
    if (typeof str !== 'string' || !/^[A-Za-z0-9_\-+/]*=*$/.test(str)) throw new Error('base64 inválido');
    return Buffer.from(str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url');
  },
};

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

// Punto P-256 sin comprimir (65 B) -> KeyObject
function p256PublicKey(raw) {
  if (!raw || raw.length !== 65 || raw[0] !== 4) throw new Error('Clave pública inválida');
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u.enc(raw.subarray(1, 33)), y: b64u.enc(raw.subarray(33)) },
    format: 'jwk',
  });
}

// Código de emparejamiento "PCU1.<base64url(json)>" que genera la web app.
function parsePairCode(codeIn) {
  const code = String(codeIn || '').replace(/\s+/g, '');
  if (!code.startsWith('PCU1.')) throw new Error('El código tiene que empezar con PCU1.');
  let d;
  try { d = JSON.parse(b64u.dec(code.slice(5)).toString('utf8')); } catch { throw new Error('Código mal copiado'); }
  for (const f of ['t', 'r', 'o', 'k', 'i']) if (typeof d[f] !== 'string' || !d[f]) throw new Error('Al código le faltan datos');
  if (!/^[a-z0-9]{8,40}$/.test(d.t)) throw new Error('Tema MQTT inválido');
  const pub = b64u.dec(d.k);
  p256PublicKey(pub); // valida que sea un punto de la curva
  if (!d.h || !d.u || !d.w) throw new Error('Al código le faltan los datos del servidor MQTT');
  return {
    topic: d.t,
    key: { rpId: d.r, origin: d.o, credId: d.i, pub: d.k },
    mqtt: { host: d.h, port: Number.isInteger(d.p) ? d.p : 8883, user: d.u, pass: d.w },
  };
}

// Verifica una aserción y devuelve el contenido del challenge (la orden firmada).
// Tira un Error con un mensaje para el usuario si algo no cuadra.
// key = { rpId, origin, pub (b64url, 65 B) }
function verifyAssertion(key, adB64, cdB64, sigB64) {
  let ad, cd, sig;
  try { ad = b64u.dec(adB64); cd = b64u.dec(cdB64); sig = b64u.dec(sigB64); } catch { throw new Error('Mensaje mal formado'); }
  if (ad.length < 37) throw new Error('authenticatorData corto');
  if (cd.length > 2048 || sig.length > 80) throw new Error('Mensaje demasiado largo');

  let client;
  try { client = JSON.parse(cd.toString('utf8')); } catch { throw new Error('clientData inválido'); }
  if (client.type !== 'webauthn.get') throw new Error('Tipo inválido');
  if (client.origin !== key.origin) throw new Error('Origen inválido');
  if (typeof client.challenge !== 'string') throw new Error('Falta challenge');

  let cmd;
  try { cmd = JSON.parse(b64u.dec(client.challenge).toString('utf8')); } catch { throw new Error('Orden inválida'); }
  if (!cmd || typeof cmd.c !== 'string' || typeof cmd.n !== 'string' || !Number.isInteger(cmd.t)) throw new Error('Orden incompleta');
  if (cmd.n.length < 8 || cmd.n.length > 64) throw new Error('Nonce inválido');

  if (!ad.subarray(0, 32).equals(sha256(Buffer.from(key.rpId, 'utf8')))) throw new Error('rpId distinto');
  const flags = ad[32];
  if (!(flags & 0x01)) throw new Error('Falta presencia del usuario');
  if (!(flags & 0x04)) throw new Error('Falta verificación (Face ID)');

  const signed = Buffer.concat([ad, sha256(cd)]);
  let ok = false;
  try {
    ok = crypto.verify('sha256', signed, { key: p256PublicKey(b64u.dec(key.pub)), dsaEncoding: 'der' }, sig);
  } catch { throw new Error('Firma mal formada'); }
  if (!ok) throw new Error('Firma inválida');
  return cmd;
}

// Hora (±90 s) y nonce no repetido, como la ESP.
class ReplayGuard {
  constructor(windowSec = 90) { this.windowSec = windowSec; this.seen = new Map(); }
  check(cmd, nowSec = Math.floor(Date.now() / 1000)) {
    if (Math.abs(nowSec - cmd.t) > this.windowSec) throw new Error('Hora fuera de rango (¿reloj del iPhone o de la compu?)');
    for (const [n, t] of this.seen) if (nowSec - t > this.windowSec * 2) this.seen.delete(n);
    if (this.seen.has(cmd.n)) throw new Error('Orden repetida');
    this.seen.set(cmd.n, nowSec);
  }
}

// a=fingerprint del SDP. Tiene que haber exactamente uno (sha-256), como en una oferta con BUNDLE.
function sdpFingerprint(sdp) {
  const fps = new Set();
  for (const m of String(sdp).matchAll(/^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/gm)) {
    if (m[1].toLowerCase() !== 'sha-256') throw new Error('Fingerprint DTLS no es sha-256');
    fps.add(m[2].toUpperCase());
  }
  if (fps.size !== 1) throw new Error('El SDP tiene que tener un único fingerprint DTLS');
  return [...fps][0];
}

module.exports = { b64u, sha256, p256PublicKey, parsePairCode, verifyAssertion, ReplayGuard, sdpFingerprint };
