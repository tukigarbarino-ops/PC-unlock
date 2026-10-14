'use strict';
// Control virtual de Xbox 360 con el driver ViGEmBus (https://github.com/nefarius/ViGEmBus), hablándole directo
// con DeviceIoControl vía koffi (mismo protocolo que ViGEmClient, MIT). Si el driver no está instalado, no hay joystick.
// En la app se dibuja como un DualSense: ✕=A, ○=B, □=X, △=Y, L1=LB, R1=RB, L2/R2=gatillos, Share=Back,
// Options=Start, PS=Guide.

// Botones (mismos bits que XUSB_REPORT.wButtons; la app manda estos valores)
const BTN = { UP: 0x0001, DOWN: 0x0002, LEFT: 0x0004, RIGHT: 0x0008, START: 0x0010, BACK: 0x0020, L3: 0x0040, R3: 0x0080,
  LB: 0x0100, RB: 0x0200, GUIDE: 0x0400, A: 0x1000, B: 0x2000, X: 0x4000, Y: 0x8000 };

const CTL = (fn, access) => ((0x2a << 16) | (access << 14) | (fn << 2)) >>> 0; // FILE_DEVICE_BUS_EXTENDER, METHOD_BUFFERED
const IOCTL = { PLUGIN: CTL(0x801, 2), UNPLUG: CTL(0x802, 2), CHECK_VERSION: CTL(0x803, 2), WAIT_READY: CTL(0x804, 2), XUSB_SUBMIT: CTL(0xa02, 2) };
// {96E42B22-F5E9-42F8-B043-ED0F932F014F}
const GUID_VIGEM = Buffer.from([0x22, 0x2b, 0xe4, 0x96, 0xe9, 0xf5, 0xf8, 0x42, 0xb0, 0x43, 0xed, 0x0f, 0x93, 0x2f, 0x01, 0x4f]);

let api = null;
function win() {
  if (api) return api;
  const koffi = require('koffi');
  const setupapi = koffi.load('setupapi.dll');
  const kernel32 = koffi.load('kernel32.dll');
  api = {
    SetupDiGetClassDevsW: setupapi.func('__stdcall', 'SetupDiGetClassDevsW', 'intptr_t', ['void *', 'void *', 'void *', 'uint32']),
    SetupDiEnumDeviceInterfaces: setupapi.func('__stdcall', 'SetupDiEnumDeviceInterfaces', 'bool', ['intptr_t', 'void *', 'void *', 'uint32', 'void *']),
    SetupDiGetDeviceInterfaceDetailW: setupapi.func('__stdcall', 'SetupDiGetDeviceInterfaceDetailW', 'bool', ['intptr_t', 'void *', 'void *', 'uint32', koffi.inout(koffi.pointer('uint32')), 'void *']),
    SetupDiDestroyDeviceInfoList: setupapi.func('__stdcall', 'SetupDiDestroyDeviceInfoList', 'bool', ['intptr_t']),
    CreateFileW: kernel32.func('__stdcall', 'CreateFileW', 'intptr_t', ['str16', 'uint32', 'uint32', 'void *', 'uint32', 'uint32', 'void *']),
    DeviceIoControl: kernel32.func('__stdcall', 'DeviceIoControl', 'bool', ['intptr_t', 'uint32', 'void *', 'uint32', 'void *', 'uint32', koffi.inout(koffi.pointer('uint32')), 'void *']),
    CloseHandle: kernel32.func('__stdcall', 'CloseHandle', 'bool', ['intptr_t']),
    GetLastError: kernel32.func('__stdcall', 'GetLastError', 'uint32', []),
  };
  return api;
}

// Ruta del dispositivo del bus ViGEm (o null si el driver no está).
function busPath() {
  const w = win();
  const DIGCF_PRESENT = 0x2, DIGCF_DEVICEINTERFACE = 0x10;
  const set = w.SetupDiGetClassDevsW(GUID_VIGEM, null, null, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (set === -1 || set === 0) return null;
  try {
    const ifd = Buffer.alloc(32); // SP_DEVICE_INTERFACE_DATA (x64)
    ifd.writeUInt32LE(32, 0);
    if (!w.SetupDiEnumDeviceInterfaces(set, null, GUID_VIGEM, 0, ifd)) return null;
    const need = [0];
    w.SetupDiGetDeviceInterfaceDetailW(set, ifd, null, 0, need, null);
    if (!need[0]) return null;
    const det = Buffer.alloc(need[0] + 8);
    det.writeUInt32LE(8, 0); // cbSize de SP_DEVICE_INTERFACE_DETAIL_DATA_W en x64
    if (!w.SetupDiGetDeviceInterfaceDetailW(set, ifd, det, det.length, need, null)) return null;
    return det.toString('utf16le', 4).replace(/\0.*$/s, '');
  } finally {
    w.SetupDiDestroyDeviceInfoList(set);
  }
}

class Gamepad {
  constructor({ log = null, releaseAfterMs = 2000 } = {}) {
    this.log = log || (() => {});
    this.handle = null;
    this.serial = 0;
    this.state = { buttons: 0, lt: 0, rt: 0, lx: 0, ly: 0, rx: 0, ry: 0 };
    this.last = 0;
    this.releaseAfterMs = releaseAfterMs;
    this.timer = setInterval(() => this.watchdog(), 250);
    this.timer.unref?.();
  }

  static available() {
    try { return !!busPath(); } catch { return false; }
  }

  ioctl(code, buf) {
    const w = win();
    const n = [0];
    const ok = w.DeviceIoControl(this.handle, code, buf, buf.length, null, 0, n, null);
    return ok ? 0 : w.GetLastError();
  }

  // Enchufa un control de Xbox 360 virtual. Devuelve "" o un error.
  plug() {
    if (this.serial) return '';
    let path;
    try { path = busPath(); } catch (e) { return 'No se pudo usar el driver de joystick: ' + e.message; }
    if (!path) return 'Falta el driver ViGEmBus (ver README → Joystick).';
    const w = win();
    if (!this.handle) {
      const GENERIC_RW = 0xc0000000, SHARE_RW = 3, OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
      const h = w.CreateFileW(path, GENERIC_RW, SHARE_RW, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
      if (h === -1 || h === 0) return 'No se pudo abrir el driver de joystick';
      this.handle = h;
      const ver = Buffer.alloc(8);
      ver.writeUInt32LE(8, 0);
      ver.writeUInt32LE(1, 4); // VIGEM_COMMON_VERSION
      if (this.ioctl(IOCTL.CHECK_VERSION, ver)) { this.closeHandle(); return 'Versión del driver ViGEmBus incompatible'; }
    }
    for (let serial = 1; serial <= 16; serial++) {
      const p = Buffer.alloc(16); // VIGEM_PLUGIN_TARGET
      p.writeUInt32LE(16, 0);
      p.writeUInt32LE(serial, 4);
      p.writeUInt32LE(0, 8); // Xbox360Wired
      if (this.ioctl(IOCTL.PLUGIN, p)) continue;
      const r = Buffer.alloc(8);
      r.writeUInt32LE(8, 0);
      r.writeUInt32LE(serial, 4);
      this.ioctl(IOCTL.WAIT_READY, r); // en drivers viejos no existe: igual queda enchufado
      this.serial = serial;
      this.log(`joystick virtual enchufado (#${serial})`);
      this.submit();
      return '';
    }
    return 'El driver de joystick no tiene lugar libre';
  }

  unplug() {
    if (!this.serial) return;
    this.state = { buttons: 0, lt: 0, rt: 0, lx: 0, ly: 0, rx: 0, ry: 0 };
    this.submit();
    const u = Buffer.alloc(8);
    u.writeUInt32LE(8, 0);
    u.writeUInt32LE(this.serial, 4);
    this.ioctl(IOCTL.UNPLUG, u);
    this.log(`joystick virtual desenchufado (#${this.serial})`);
    this.serial = 0;
    this.closeHandle();
  }

  closeHandle() {
    if (this.handle) win().CloseHandle(this.handle);
    this.handle = null;
  }

  submit() {
    if (!this.serial) return;
    const s = this.state;
    const b = Buffer.alloc(20); // XUSB_SUBMIT_REPORT
    b.writeUInt32LE(20, 0);
    b.writeUInt32LE(this.serial, 4);
    b.writeUInt16LE(s.buttons & 0xffff, 8);
    b.writeUInt8(s.lt, 10);
    b.writeUInt8(s.rt, 11);
    b.writeInt16LE(s.lx, 12);
    b.writeInt16LE(s.ly, 14);
    b.writeInt16LE(s.rx, 16);
    b.writeInt16LE(s.ry, 18);
    this.ioctl(IOCTL.XUSB_SUBMIT, b);
  }

  set(st) {
    this.last = Date.now();
    this.state = st;
    this.submit();
  }

  touch() { this.last = Date.now(); }

  get neutral() {
    const s = this.state;
    return !s.buttons && !s.lt && !s.rt && !s.lx && !s.ly && !s.rx && !s.ry;
  }

  // Igual que el teclado: si se corta la conexión con algo apretado, todo vuelve a reposo a los ~2 s.
  watchdog() {
    if (this.serial && !this.neutral && Date.now() - this.last > this.releaseAfterMs) {
      this.log('joystick a reposo (sin mensajes por 2 s)');
      this.set({ buttons: 0, lt: 0, rt: 0, lx: 0, ly: 0, rx: 0, ry: 0 });
    }
  }

  close() { this.unplug(); clearInterval(this.timer); }
}

module.exports = { Gamepad, BTN, IOCTL };
