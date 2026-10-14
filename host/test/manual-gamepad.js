'use strict';
// Prueba REAL del joystick virtual (no corre en CI): enchufa un control de Xbox 360 con ViGEmBus, manda un estado,
// lo lee de vuelta con XInput y lo desenchufa. Uso: node test/manual-gamepad.js
const koffi = require('koffi');
const { Gamepad, BTN } = require('../src/gamepad');

const xinput = koffi.load('xinput1_4.dll');
const XINPUT_STATE = koffi.struct('XINPUT_STATE', { dwPacketNumber: 'uint32', wButtons: 'uint16', bLeftTrigger: 'uint8',
  bRightTrigger: 'uint8', sThumbLX: 'int16', sThumbLY: 'int16', sThumbRX: 'int16', sThumbRY: 'int16' });
const XInputGetState = xinput.func('__stdcall', 'XInputGetState', 'uint32', ['uint32', koffi.out(koffi.pointer(XINPUT_STATE))]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  console.log('driver ViGEmBus disponible:', Gamepad.available());
  const before = [0, 1, 2, 3].filter((i) => XInputGetState(i, {}) === 0);
  const pad = new Gamepad({ log: console.log });
  const err = pad.plug();
  if (err) { console.log('ERROR:', err); process.exit(1); }
  await sleep(1500);
  const want = { buttons: BTN.A | BTN.LB | BTN.UP, lt: 200, rt: 0, lx: 12345, ly: -20000, rx: 0, ry: 32767 };
  pad.set(want);
  await sleep(300);
  let found = null;
  for (let i = 0; i < 4; i++) {
    if (before.includes(i)) continue;
    const st = {};
    if (XInputGetState(i, st) === 0) { found = { i, st }; break; }
  }
  let fails = 0;
  if (!found) { console.log('FALLA: XInput no ve el control nuevo'); fails++; }
  else {
    const s = found.st;
    const ok = s.wButtons === want.buttons && s.bLeftTrigger === 200 && s.sThumbLX === 12345 && s.sThumbLY === -20000 && s.sThumbRY === 32767;
    console.log(`${ok ? 'OK  ' : (fails++, 'FALLA')} XInput #${found.i}: botones 0x${s.wButtons.toString(16)} LT ${s.bLeftTrigger} LX ${s.sThumbLX} LY ${s.sThumbLY} RY ${s.sThumbRY}`);
  }
  pad.close();
  await sleep(500);
  const after = [0, 1, 2, 3].filter((i) => XInputGetState(i, {}) === 0);
  console.log(`${after.length === before.length ? 'OK  ' : (fails++, 'FALLA')} desenchufado (controles antes ${before.length}, después ${after.length})`);
  process.exit(fails ? 1 : 0);
})();
