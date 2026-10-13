'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { decode, OP } = require('../src/protocol');
const { Injector, SCAN } = require('../src/input');

test('decodifica varias órdenes en un mensaje', () => {
  const b = Buffer.from([0x01, 0xe0, 0x03, 0xfb, 0xff, 0x0a, 0x00, 0x06, 0x88, 0xff, 0, 0, 0x07, 0xcd, 0x00, 0x09]);
  assert.deepEqual(decode(b), [
    { op: OP.KEY_DOWN, usage: 0xe0 },
    { op: OP.MOVE, dx: -5, dy: 10 },
    { op: OP.WHEEL, v: -120, h: 0 },
    { op: OP.CONSUMER, usage: 0xcd },
    { op: OP.PING },
  ]);
  assert.throws(() => decode(Buffer.from([0x03, 1])), /inválido/);
  assert.throws(() => decode(Buffer.from([0x55])), /inválido/);
});

test('todas las teclas del teclado de la app tienen scancode', () => {
  const needed = [];
  for (let u = 0x04; u <= 0x45; u++) needed.push(u); // letras, números, Enter..F12
  needed.push(0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x64, 0xe0, 0xe1, 0xe2, 0xe3, 0xe6);
  for (const u of needed) assert.ok(SCAN[u] !== undefined, `falta 0x${u.toString(16)}`);
});

test('suelta todo a los 2 s sin mensajes', async () => {
  const log = [];
  const inj = new Injector({ simulate: true, log: (m) => log.push(m), releaseAfterMs: 300 });
  inj.apply([{ op: OP.KEY_DOWN, usage: 0xe0 }, { op: OP.BTN_DOWN, mask: 1 }]);
  assert.ok(inj.holding);
  await new Promise((r) => setTimeout(r, 700));
  assert.ok(!inj.holding);
  assert.ok(log.some((m) => m.startsWith('soltar todo')));
  inj.close();
});

test('el latido evita que se suelte', async () => {
  const inj = new Injector({ simulate: true, releaseAfterMs: 300 });
  inj.apply([{ op: OP.KEY_DOWN, usage: 0x04 }]);
  for (let i = 0; i < 5; i++) { await new Promise((r) => setTimeout(r, 120)); inj.apply([{ op: OP.PING }]); }
  assert.ok(inj.holding);
  inj.close();
  assert.ok(!inj.holding);
});

test('mouse relativo se limita al escritorio virtual', () => {
  const inj = new Injector({ simulate: true });
  inj.apply([{ op: OP.MOVE, dx: -5000, dy: 30 }]);
  assert.deepEqual(inj.cursor(), { x: 0, y: 130 });
  inj.close();
});
