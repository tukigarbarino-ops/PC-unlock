'use strict';
// Prueba REAL e inofensiva de SendInput en esta compu (no corre en CI):
// mueve el puntero a varios puntos del escritorio virtual y lo devuelve; aprieta y suelta Shift.
// Uso: node test/manual-input.js
const { Injector, win32 } = require('../src/input');

const inj = new Injector();
const w = win32();
console.log('sizeof(INPUT) =', w.INPUT_SIZE, '(tiene que ser 40 en x64)');
const vd = inj.virtualDesktop();
console.log('escritorio virtual (px físicos):', vd);
const start = inj.cursor();
let fails = 0;
const targets = [[vd.x, vd.y], [vd.x + vd.w - 1, vd.y + vd.h - 1], [vd.x + 123, vd.y + 457], [vd.x + Math.floor(vd.w / 2) + 1, vd.y + 333]];
for (const [x, y] of targets) {
  inj.moveTo(x, y);
  const p = inj.cursor();
  const ok = p.x === x && p.y === y;
  if (!ok) fails++;
  console.log(`${ok ? 'OK  ' : 'FALLA'} pedido (${x},${y}) -> quedó (${p.x},${p.y})`);
}
// 200 pasos relativos de +1: no tiene que acumular error
inj.moveTo(vd.x + 200, vd.y + 200);
for (let i = 0; i < 200; i++) inj.moveBy(1, 1);
const r = inj.cursor();
console.log(`${r.x === vd.x + 400 && r.y === vd.y + 400 ? 'OK  ' : (fails++, 'FALLA')} 200 pasos de +1 -> (${r.x},${r.y})`);
inj.moveTo(start.x, start.y);

inj.key(0xe1, true); // Shift izquierdo
const down = (w.GetAsyncKeyState(0x10) & 0x8000) !== 0;
inj.key(0xe1, false);
const up = (w.GetAsyncKeyState(0x10) & 0x8000) === 0;
console.log(`${down && up ? 'OK  ' : (fails++, 'FALLA')} Shift abajo=${down} arriba=${up}`);
inj.close();
process.exit(fails ? 1 : 0);
