'use strict';
// Protocolo binario de entrada: es el mismo para el host (DataChannel) y para la ESP (MQTT cifrado, fase 2).
// Un mensaje puede traer varias órdenes seguidas. Enteros little-endian.
//   0x01 tecla abajo   u8 uso HID (página Keyboard)     0x02 tecla arriba  u8
//   0x03 mover mouse   i16 dx, i16 dy                    0x04 botón abajo   u8 máscara (1 izq, 2 der, 4 medio)
//   0x05 botón arriba  u8 máscara                        0x06 rueda         i16 vertical, i16 horizontal (120 = un paso)
//   0x07 multimedia    u16 uso HID (página Consumer)     0x08 soltar todo
//   0x09 latido (no hace nada; mantiene vivo el "soltar a los 2 s")

const OP = { KEY_DOWN: 1, KEY_UP: 2, MOVE: 3, BTN_DOWN: 4, BTN_UP: 5, WHEEL: 6, CONSUMER: 7, RELEASE_ALL: 8, PING: 9 };
const LEN = { 1: 2, 2: 2, 3: 5, 4: 2, 5: 2, 6: 5, 7: 3, 8: 1, 9: 1 };

function decode(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const out = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i];
    const len = LEN[op];
    if (!len || i + len > b.length) throw new Error(`Mensaje de entrada inválido (op ${op})`);
    switch (op) {
      case OP.KEY_DOWN: case OP.KEY_UP: out.push({ op, usage: b[i + 1] }); break;
      case OP.BTN_DOWN: case OP.BTN_UP: out.push({ op, mask: b[i + 1] & 7 }); break;
      case OP.MOVE: out.push({ op, dx: b.readInt16LE(i + 1), dy: b.readInt16LE(i + 3) }); break;
      case OP.WHEEL: out.push({ op, v: b.readInt16LE(i + 1), h: b.readInt16LE(i + 3) }); break;
      case OP.CONSUMER: out.push({ op, usage: b.readUInt16LE(i + 1) }); break;
      default: out.push({ op });
    }
    i += len;
  }
  return out;
}

module.exports = { OP, decode };
