'use strict';
// Configuración del host en %APPDATA%\PC Unlock Host\config.json.
// Lo sensible (código PCU1 con la contraseña MQTT y la clave de identidad) va cifrado con DPAPI (safeStorage).
const fs = require('node:fs');
const path = require('node:path');

class Config {
  constructor(dir, safeStorage) {
    this.file = path.join(dir, 'config.json');
    this.safe = safeStorage;
    try { this.data = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { this.data = {}; }
  }
  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    fs.renameSync(tmp, this.file);
  }
  getSecret(name) {
    const v = this.data[name];
    if (!v) return null;
    try { return this.safe.decryptString(Buffer.from(v, 'base64')); } catch { return null; }
  }
  setSecret(name, value) {
    this.data[name] = value == null ? undefined : this.safe.encryptString(value).toString('base64');
    this.save();
  }
  get(name, def) { return this.data[name] === undefined ? def : this.data[name]; }
  set(name, value) { this.data[name] = value; this.save(); }
}

module.exports = { Config };
