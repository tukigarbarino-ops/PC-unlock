'use strict';
// Inyección de mouse, teclado y multimedia en Windows con SendInput (vía koffi, sin compilar nada).
// Las teclas llegan como usos HID de posición física y se mandan como scancodes: Windows aplica la
// distribución instalada (Español Latinoamérica), igual que con un teclado de verdad.
// El mouse se mueve en coordenadas absolutas del escritorio virtual (varios monitores, cualquier escalado).
const { OP } = require('./protocol');

// Uso HID -> scancode (set 1). 0xE0xx = tecla extendida.
const SCAN = {
  0x04: 0x1e, 0x05: 0x30, 0x06: 0x2e, 0x07: 0x20, 0x08: 0x12, 0x09: 0x21, 0x0a: 0x22, 0x0b: 0x23, 0x0c: 0x17,
  0x0d: 0x24, 0x0e: 0x25, 0x0f: 0x26, 0x10: 0x32, 0x11: 0x31, 0x12: 0x18, 0x13: 0x19, 0x14: 0x10, 0x15: 0x13,
  0x16: 0x1f, 0x17: 0x14, 0x18: 0x16, 0x19: 0x2f, 0x1a: 0x11, 0x1b: 0x2d, 0x1c: 0x15, 0x1d: 0x2c,
  0x1e: 0x02, 0x1f: 0x03, 0x20: 0x04, 0x21: 0x05, 0x22: 0x06, 0x23: 0x07, 0x24: 0x08, 0x25: 0x09, 0x26: 0x0a, 0x27: 0x0b,
  0x28: 0x1c, 0x29: 0x01, 0x2a: 0x0e, 0x2b: 0x0f, 0x2c: 0x39, 0x2d: 0x0c, 0x2e: 0x0d, 0x2f: 0x1a, 0x30: 0x1b,
  0x31: 0x2b, 0x32: 0x2b, 0x33: 0x27, 0x34: 0x28, 0x35: 0x29, 0x36: 0x33, 0x37: 0x34, 0x38: 0x35, 0x39: 0x3a,
  0x3a: 0x3b, 0x3b: 0x3c, 0x3c: 0x3d, 0x3d: 0x3e, 0x3e: 0x3f, 0x3f: 0x40, 0x40: 0x41, 0x41: 0x42, 0x42: 0x43,
  0x43: 0x44, 0x44: 0x57, 0x45: 0x58, 0x46: 0xe037, 0x47: 0x46,
  0x49: 0xe052, 0x4a: 0xe047, 0x4b: 0xe049, 0x4c: 0xe053, 0x4d: 0xe04f, 0x4e: 0xe051,
  0x4f: 0xe04d, 0x50: 0xe04b, 0x51: 0xe050, 0x52: 0xe048, 0x64: 0x56, 0x65: 0xe05d,
  0xe0: 0x1d, 0xe1: 0x2a, 0xe2: 0x38, 0xe3: 0xe05b, 0xe4: 0xe01d, 0xe5: 0x36, 0xe6: 0xe038, 0xe7: 0xe05c,
};
// Uso HID Consumer -> tecla virtual de Windows
const MEDIA_VK = { 0xcd: 0xb3, 0xb5: 0xb0, 0xb6: 0xb1, 0xb7: 0xb2, 0xe2: 0xad, 0xe9: 0xaf, 0xea: 0xae };

const INPUT_MOUSE = 0, INPUT_KEYBOARD = 1;
const KEYEVENTF_EXTENDEDKEY = 0x1, KEYEVENTF_KEYUP = 0x2, KEYEVENTF_SCANCODE = 0x8;
const MOUSEEVENTF = { MOVE: 0x1, LEFTDOWN: 0x2, LEFTUP: 0x4, RIGHTDOWN: 0x8, RIGHTUP: 0x10, MIDDLEDOWN: 0x20,
  MIDDLEUP: 0x40, WHEEL: 0x800, HWHEEL: 0x1000, VIRTUALDESK: 0x4000, ABSOLUTE: 0x8000 };
const BTN_FLAGS = { 1: [MOUSEEVENTF.LEFTDOWN, MOUSEEVENTF.LEFTUP], 2: [MOUSEEVENTF.RIGHTDOWN, MOUSEEVENTF.RIGHTUP],
  4: [MOUSEEVENTF.MIDDLEDOWN, MOUSEEVENTF.MIDDLEUP] };
const SM = { XVIRTUAL: 76, YVIRTUAL: 77, CXVIRTUAL: 78, CYVIRTUAL: 79 };

let win = null;
function win32() {
  if (win) return win;
  const koffi = require('koffi');
  const user32 = koffi.load('user32.dll');
  const MOUSEINPUT = koffi.struct('MOUSEINPUT', { dx: 'long', dy: 'long', mouseData: 'int32', dwFlags: 'uint32', time: 'uint32', dwExtraInfo: 'uintptr_t' });
  const KEYBDINPUT = koffi.struct('KEYBDINPUT', { wVk: 'uint16', wScan: 'uint16', dwFlags: 'uint32', time: 'uint32', dwExtraInfo: 'uintptr_t' });
  const HARDWAREINPUT = koffi.struct('HARDWAREINPUT', { uMsg: 'uint32', wParamL: 'uint16', wParamH: 'uint16' });
  const INPUT = koffi.struct('INPUT', { type: 'uint32', u: koffi.union('INPUT_U', { mi: MOUSEINPUT, ki: KEYBDINPUT, hi: HARDWAREINPUT }) });
  const POINT = koffi.struct('POINT', { x: 'long', y: 'long' });
  win = {
    INPUT_SIZE: koffi.sizeof(INPUT),
    SendInput: user32.func('__stdcall', 'SendInput', 'uint32', ['uint32', koffi.pointer(INPUT), 'int']),
    GetCursorPos: user32.func('__stdcall', 'GetCursorPos', 'bool', [koffi.out(koffi.pointer(POINT))]),
    GetSystemMetrics: user32.func('__stdcall', 'GetSystemMetrics', 'int', ['int']),
    SetThreadDpiAwarenessContext: user32.func('__stdcall', 'SetThreadDpiAwarenessContext', 'intptr_t', ['intptr_t']),
    GetAsyncKeyState: user32.func('__stdcall', 'GetAsyncKeyState', 'int16', ['int']),
  };
  // Coordenadas en píxeles físicos aunque haya escalado 125/150 % (DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2).
  win.SetThreadDpiAwarenessContext(-4);
  return win;
}

class Injector {
  // simulate: no toca Windows, solo registra (para pruebas). log: función opcional.
  constructor({ simulate = false, log = null, releaseAfterMs = 2000 } = {}) {
    this.simulate = simulate;
    this.log = log || (() => {});
    this.keys = new Set();
    this.buttons = 0;
    this.last = Date.now();
    this.releaseAfterMs = releaseAfterMs;
    this.simCursor = { x: 100, y: 100 };
    this.timer = setInterval(() => this.watchdog(), 250);
    this.timer.unref?.();
  }

  get holding() { return this.keys.size > 0 || this.buttons !== 0; }

  // Si se corta la conexión con algo apretado, se suelta todo a los ~2 s sin mensajes.
  watchdog() {
    if (this.holding && Date.now() - this.last > this.releaseAfterMs) {
      this.log('soltar todo (sin mensajes por 2 s)');
      this.releaseAll();
    }
  }

  send(inputs) {
    if (this.simulate || !inputs.length) return;
    const w = win32();
    w.SendInput(inputs.length, inputs, w.INPUT_SIZE);
  }

  key(usage, down) {
    const sc = SCAN[usage];
    if (sc === undefined) return;
    if (down) this.keys.add(usage); else this.keys.delete(usage);
    this.log(`tecla ${down ? 'abajo' : 'arriba'} 0x${usage.toString(16)}`);
    let flags = KEYEVENTF_SCANCODE | (down ? 0 : KEYEVENTF_KEYUP);
    if (sc > 0xff) flags |= KEYEVENTF_EXTENDEDKEY;
    this.send([{ type: INPUT_KEYBOARD, u: { ki: { wVk: 0, wScan: sc & 0xff, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }]);
  }

  media(usage) {
    const vk = MEDIA_VK[usage];
    if (!vk) return;
    this.log(`multimedia 0x${usage.toString(16)}`);
    const ki = (up) => ({ type: INPUT_KEYBOARD, u: { ki: { wVk: vk, wScan: 0, dwFlags: KEYEVENTF_EXTENDEDKEY | (up ? KEYEVENTF_KEYUP : 0), time: 0, dwExtraInfo: 0 } } });
    this.send([ki(false), ki(true)]);
  }

  mouse(dwFlags, dx = 0, dy = 0, mouseData = 0) {
    this.send([{ type: INPUT_MOUSE, u: { mi: { dx, dy, mouseData, dwFlags, time: 0, dwExtraInfo: 0 } } }]);
  }

  virtualDesktop() {
    if (this.simulate) return { x: 0, y: 0, w: 1920, h: 1080 };
    const w = win32();
    return { x: w.GetSystemMetrics(SM.XVIRTUAL), y: w.GetSystemMetrics(SM.YVIRTUAL),
      w: w.GetSystemMetrics(SM.CXVIRTUAL), h: w.GetSystemMetrics(SM.CYVIRTUAL) };
  }

  cursor() {
    if (this.simulate) return { ...this.simCursor };
    const p = {};
    win32().GetCursorPos(p);
    return p;
  }

  // Lleva el puntero a (x, y) en píxeles físicos del escritorio virtual.
  moveTo(x, y) {
    const vd = this.virtualDesktop();
    x = Math.min(Math.max(Math.round(x), vd.x), vd.x + vd.w - 1);
    y = Math.min(Math.max(Math.round(y), vd.y), vd.y + vd.h - 1);
    if (this.simulate) { this.simCursor = { x, y }; return { x, y }; }
    // Normalizado a 0..65535; con ceil, Windows vuelve exactamente al mismo píxel.
    const nx = Math.ceil(((x - vd.x) * 65536) / vd.w);
    const ny = Math.ceil(((y - vd.y) * 65536) / vd.h);
    this.mouse(MOUSEEVENTF.MOVE | MOUSEEVENTF.ABSOLUTE | MOUSEEVENTF.VIRTUALDESK, nx, ny);
    return { x, y };
  }

  moveBy(dx, dy) {
    this.log(`mover ${dx} ${dy}`);
    const c = this.cursor();
    return this.moveTo(c.x + dx, c.y + dy);
  }

  button(mask, down) {
    for (const bit of [1, 2, 4]) {
      if (!(mask & bit)) continue;
      if (down === !!(this.buttons & bit)) continue;
      this.buttons = down ? this.buttons | bit : this.buttons & ~bit;
      this.log(`botón ${bit} ${down ? 'abajo' : 'arriba'}`);
      this.mouse(BTN_FLAGS[bit][down ? 0 : 1]);
    }
  }

  wheel(v, h) {
    this.log(`rueda ${v} ${h}`);
    if (v) this.mouse(MOUSEEVENTF.WHEEL, 0, 0, v);
    if (h) this.mouse(MOUSEEVENTF.HWHEEL, 0, 0, h);
  }

  releaseAll() {
    for (const u of [...this.keys]) this.key(u, false);
    if (this.buttons) this.button(this.buttons, false);
  }

  apply(cmds) {
    this.last = Date.now();
    for (const c of cmds) {
      switch (c.op) {
        case OP.KEY_DOWN: this.key(c.usage, true); break;
        case OP.KEY_UP: this.key(c.usage, false); break;
        case OP.MOVE: this.moveBy(c.dx, c.dy); break;
        case OP.BTN_DOWN: this.button(c.mask, true); break;
        case OP.BTN_UP: this.button(c.mask, false); break;
        case OP.WHEEL: this.wheel(c.v, c.h); break;
        case OP.CONSUMER: this.media(c.usage); break;
        case OP.RELEASE_ALL: this.releaseAll(); break;
        default: break;
      }
    }
  }

  close() { this.releaseAll(); clearInterval(this.timer); }
}

module.exports = { Injector, SCAN, MEDIA_VK, win32 };
