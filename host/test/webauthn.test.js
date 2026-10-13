'use strict';
// Mismas aserciones reales que usa firmware/test/verify_test.cpp: el host tiene que dar el mismo resultado que la ESP.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { parsePairCode, verifyAssertion, ReplayGuard, sdpFingerprint, b64u } = require('../src/webauthn');
const identity = require('../src/identity');

const FIX = path.join(__dirname, '..', '..', 'firmware', 'test', 'fixtures');
const code = fs.readFileSync(path.join(FIX, 'code.txt'), 'utf8').trim();
const msgs = fs.readFileSync(path.join(FIX, 'msgs.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

test('lee el código PCU1', () => {
  const p = parsePairCode(code);
  assert.match(p.topic, /^[a-z0-9]{16}$/);
  assert.equal(p.key.rpId, 'localhost');
  assert.equal(p.mqtt.port, 8883);
  assert.throws(() => parsePairCode('PCU2.xxx'), /PCU1/);
  assert.throws(() => parsePairCode(code.slice(0, 40)), /mal copiado|faltan/);
});

test('aserciones de los fixtures dan lo mismo que en la ESP', () => {
  const { key } = parsePairCode(code);
  for (const m of msgs) {
    let ok = true, err = '';
    try { verifyAssertion(key, m.ad, m.cd, m.sig); } catch (e) { ok = false; err = e.message; }
    assert.equal(ok, m.expect === 'ok', `esperaba ${m.expect}, dio ${ok ? 'ok' : err}`);
  }
});

test('rechaza flags sin UV, rpId distinto y firma alterada', () => {
  const { key } = parsePairCode(code);
  const m = msgs[0];
  const ad = b64u.dec(m.ad);
  const noUv = Buffer.from(ad); noUv[32] &= ~0x04;
  assert.throws(() => verifyAssertion(key, b64u.enc(noUv), m.cd, m.sig), /Face ID/);
  assert.throws(() => verifyAssertion({ ...key, rpId: 'otro.example' }, m.ad, m.cd, m.sig), /rpId/);
  const sig = b64u.dec(m.sig); sig[sig.length - 1] ^= 1;
  assert.throws(() => verifyAssertion(key, m.ad, m.cd, b64u.enc(sig)), /Firma/);
});

test('hora y nonce', () => {
  const g = new ReplayGuard();
  const now = 1_800_000_000;
  g.check({ t: now, n: 'aaaaaaaa' }, now);
  assert.throws(() => g.check({ t: now, n: 'aaaaaaaa' }, now + 1), /repetida/);
  assert.throws(() => g.check({ t: now - 91, n: 'bbbbbbbb' }, now), /Hora/);
  assert.throws(() => g.check({ t: now + 91, n: 'cccccccc' }, now), /Hora/);
});

test('fingerprint DTLS del SDP', () => {
  const fp = 'AB:CD:' + 'EF:'.repeat(29) + '01';
  const sdp = `v=0\r\na=fingerprint:sha-256 ${fp.toLowerCase()}\r\nm=video\r\na=fingerprint:sha-256 ${fp}\r\n`;
  assert.equal(sdpFingerprint(sdp), fp);
  assert.throws(() => sdpFingerprint(sdp + `a=fingerprint:sha-256 ${fp.replace('AB', '00')}\r\n`), /único/);
  assert.throws(() => sdpFingerprint('v=0\r\n'), /único/);
});

test('identidad: firma verificable con WebCrypto y código estable', async () => {
  const pem = identity.generate();
  const pub = identity.publicRaw(pem);
  assert.equal(pub.length, 65);
  const text = identity.answerPayload('n123456789', 'AA', 'BB', 1800000000);
  const sig = b64u.dec(identity.sign(pem, text));
  assert.equal(sig.length, 64);
  const k = await crypto.webcrypto.subtle.importKey('raw', pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  assert.ok(await crypto.webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sig, Buffer.from(text)));
  const c = identity.verificationCode(pub, 'host');
  assert.match(c, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
  assert.notEqual(c, identity.verificationCode(pub, 'esp'));
  // vector fijo para comparar con la implementación de la web app
  const fixed = Buffer.alloc(65, 7); fixed[0] = 4;
  assert.equal(identity.verificationCode(fixed, 'host'), identity.verificationCode(Buffer.from(fixed), 'host'));
});
