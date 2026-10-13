'use strict';
// Lanza el host (Electron) en modo prueba: perfil temporal, broker local, entrada simulada.
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const HOST = path.join(__dirname, '..', '..', 'host');

function launchHost({ code, env = {}, userData } = {}) {
  // E2E_HOST_EXE: probar el ejecutable empaquetado (dist/win-unpacked/PC Unlock Host.exe) en vez de "electron ."
  const exe = process.env.E2E_HOST_EXE;
  const electron = exe || require(path.join(HOST, 'node_modules', 'electron'));
  const dir = userData || fs.mkdtempSync(path.join(os.tmpdir(), 'pcu-host-'));
  const lines = [];
  const proc = spawn(electron, exe ? ['--hidden'] : [HOST, '--hidden'], {
    env: { ...process.env, PCU_USERDATA: dir, PCU_MQTT_URL: 'mqtt://127.0.0.1:1883', PCU_SIMULATE_INPUT: '1', PCU_LOG_INPUT: '1',
      PCU_NO_WINDOW: '1', PCU_PAIR_CODE: code || '', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const waiters = [];
  const onLine = (l) => {
    lines.push(l);
    if (process.env.E2E_VERBOSE) console.log('  [host]', l);
    for (const w of [...waiters]) if (w.re.test(l)) { waiters.splice(waiters.indexOf(w), 1); w.resolve(l); }
  };
  for (const s of [proc.stdout, proc.stderr]) {
    let buf = '';
    s.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { onLine(buf.slice(0, i).trimEnd()); buf = buf.slice(i + 1); } });
  }
  return {
    proc, lines, dir,
    waitFor(re, ms = 15000) {
      const hit = lines.find((l) => re.test(l));
      if (hit) return Promise.resolve(hit);
      return new Promise((resolve, reject) => {
        const w = { re, resolve };
        waiters.push(w);
        setTimeout(() => { const i = waiters.indexOf(w); if (i >= 0) { waiters.splice(i, 1); reject(new Error(`el host no mostró ${re} en ${ms} ms`)); } }, ms);
      });
    },
    has: (re) => lines.some((l) => re.test(l)),
    kill: () => new Promise((r) => { proc.once('exit', r); proc.kill(); }),
  };
}

module.exports = { launchHost };
