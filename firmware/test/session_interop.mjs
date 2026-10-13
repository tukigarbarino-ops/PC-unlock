// Interoperabilidad de la sesión ESP: el lado "app" usa WebCrypto (igual que web/remote.js) y el lado "ESP"
// es session.cpp compilado en PC (session_test). Uso: node session_interop.mjs <ruta a session_test>
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import assert from 'node:assert';

const { subtle } = globalThis.crypto;
const p = spawn(process.argv[2], [], { stdio: ['pipe', 'pipe', 'inherit'] });
const lines = [];
let wake = null;
createInterface({ input: p.stdout }).on('line', (l) => { lines.push(l); if (wake) { wake(); wake = null; } });
async function ask(cmd) {
  p.stdin.write(cmd + '\n');
  while (!lines.length) await new Promise((r) => (wake = r));
  return lines.shift();
}
const b64u = (b) => Buffer.from(b).toString('base64url');
const hex = (b) => Buffer.from(b).toString('hex');
const now = () => Math.floor(Date.now() / 1000);
const enc = new TextEncoder();
let fails = 0;
const check = (name, cond) => { console.log(`[${cond ? 'PASS' : 'FAIL'}] ${name}`); if (!cond) fails++; };

// Código de verificación (mismo algoritmo que web/remote.js y host/src/identity.js)
async function verifyCode(pub, kind) {
  const pre = enc.encode(`PCU-ID|${kind}|`);
  const buf = new Uint8Array(pre.length + pub.length);
  buf.set(pre); buf.set(pub, pre.length);
  const h = new Uint8Array(await subtle.digest('SHA-256', buf));
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let bits = 0, acc = 0, out = '';
  for (const b of h) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5 && out.length < 16) { bits -= 5; out += A[(acc >> bits) & 31]; }
    if (out.length >= 16) break;
  }
  return out.match(/.{4}/g).join('-');
}

const [, idB64, code] = (await ask('id')).split(' ');
const idPub = Buffer.from(idB64, 'base64url');
check('código de verificación igual en ESP y app', code === (await verifyCode(idPub, 'esp')));
const idKey = await subtle.importKey('raw', idPub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

// Lo mismo que hace la app (web/remote.js: espOpen / espDerive)
async function openSession() {
  const app = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const appPub = new Uint8Array(await subtle.exportKey('raw', app.publicKey));
  const n = hex(globalThis.crypto.getRandomValues(new Uint8Array(12)));
  const exp = now() + 3600;
  const r = (await ask(`open ${b64u(appPub)} ${n} ${exp}`)).split(' ');
  assert.equal(r[0], 'OPEN', r.join(' '));
  const [espB64, sigB64] = [r[1], r[2]];
  const payload = `PCU-ESP-SESSION|${n}|${b64u(appPub)}|${espB64}|${exp}`;
  const sigOk = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, idKey, Buffer.from(sigB64, 'base64url'), enc.encode(payload));
  const espKey = await subtle.importKey('raw', Buffer.from(espB64, 'base64url'), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const z = await subtle.deriveBits({ name: 'ECDH', public: espKey }, app.privateKey, 256);
  const ikm = await subtle.importKey('raw', z, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode(n), info: enc.encode('PCU-ESP-SESSION') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  return { key, sigOk, exp, payload, sigB64 };
}
async function frame(key, seq, plain) {
  const iv = new Uint8Array(12);
  iv.set(enc.encode('PCUI'));
  new DataView(iv.buffer).setUint32(4, seq, true);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const out = new Uint8Array(4 + ct.length);
  new DataView(out.buffer).setUint32(0, seq, true);
  out.set(ct, 4);
  return out;
}

const s = await openSession();
check('la firma de la clave efímera verifica con la identidad de la ESP', s.sigOk);
const forged = s.payload.replace(/\|[^|]+\|(\d+)$/, '|' + b64u(new Uint8Array(65).fill(4)) + '|$1');
check('la firma NO verifica si alguien cambia la clave efímera',
  !(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, idKey, Buffer.from(s.sigB64, 'base64url'), enc.encode(forged))));

const msg1 = new Uint8Array([0x01, 0xe0, 0x01, 0x06, 0x02, 0x06, 0x02, 0xe0]);
const f1 = await frame(s.key, 1, msg1);
check('descifra un mensaje (Ctrl+C)', (await ask(`frame ${hex(f1)} ${now()}`)) === `OK ${hex(msg1)}`);
check('rechaza el mismo mensaje repetido', (await ask(`frame ${hex(f1)} ${now()}`)) === 'ERR');
const f2 = await frame(s.key, 5, new Uint8Array([0x09]));
check('acepta un seq mayor (con QoS 0 se pueden perder mensajes)', (await ask(`frame ${hex(f2)} ${now()}`)) === 'OK 09');
const f3 = await frame(s.key, 4, new Uint8Array([0x09]));
check('rechaza un seq viejo', (await ask(`frame ${hex(f3)} ${now()}`)) === 'ERR');
const f4 = await frame(s.key, 6, new Uint8Array([0x08]));
f4[6] ^= 1;
check('rechaza un mensaje alterado', (await ask(`frame ${hex(f4)} ${now()}`)) === 'ERR');
const f5 = await frame(s.key, 7, new Uint8Array([0x08]));
check('rechaza después de vencida la sesión', (await ask(`frame ${hex(f5)} ${s.exp + 1}`)) === 'ERR');

const s2 = await openSession();
const old = await frame(s.key, 100, new Uint8Array([0x09]));
check('una clave de la sesión anterior no sirve en la nueva', (await ask(`frame ${hex(old)} ${now()}`)) === 'ERR');
const g = await frame(s2.key, 1, new Uint8Array([0x07, 0xcd, 0x00]));
check('la sesión nueva funciona', (await ask(`frame ${hex(g)} ${now()}`)) === 'OK 07cd00');
const bad = await ask(`open ${b64u(new Uint8Array(65).fill(4))} 0123456789ab ${now() + 60}`);
check('rechaza una clave de app que no está en la curva', bad.startsWith('ERR'));

p.stdin.end();
console.log(fails ? `${fails} FALLAS` : 'session interop OK');
process.exit(fails ? 1 : 0);
