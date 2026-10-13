'use strict';
// Clave de identidad del host (P-256). La app la fija al emparejar comparando un código de verificación
// y después verifica con ella la respuesta firmada de cada sesión.
const crypto = require('node:crypto');
const { b64u, sha256 } = require('./webauthn');

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function generate() {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return privateKey.export({ format: 'pem', type: 'pkcs8' });
}

function publicRaw(privPem) {
  const jwk = crypto.createPublicKey(privPem).export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), b64u.dec(jwk.x), b64u.dec(jwk.y)]);
}

const deviceId = (pubRaw) => sha256(pubRaw).toString('hex').slice(0, 16);

// 80 bits del hash de la clave en base32 (Crockford): "K7F2-9QXA-3M8D-T1VW".
// La web app calcula lo mismo (verifyCode en app.js); kind = "host" o "esp".
function verificationCode(pubRaw, kind) {
  const h = sha256(Buffer.concat([Buffer.from(`PCU-ID|${kind}|`), pubRaw]));
  let bits = 0, acc = 0, out = '';
  for (const b of h) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5 && out.length < 16) { bits -= 5; out += CROCKFORD[(acc >> bits) & 31]; }
    if (out.length >= 16) break;
  }
  return out.match(/.{4}/g).join('-');
}

const answerPayload = (n, fo, fa, exp) => `PCU-HOST-ANSWER|${n}|${fo}|${fa}|${exp}`;
const renewPayload = (n, fo, fa, exp) => `PCU-HOST-RENEW|${n}|${fo}|${fa}|${exp}`;

// Firma ECDSA P-256/SHA-256 en formato r||s (el que usa WebCrypto).
function sign(privPem, text) {
  return b64u.enc(crypto.sign('sha256', Buffer.from(text, 'utf8'), { key: privPem, dsaEncoding: 'ieee-p1363' }));
}

module.exports = { generate, publicRaw, deviceId, verificationCode, answerPayload, renewPayload, sign };
