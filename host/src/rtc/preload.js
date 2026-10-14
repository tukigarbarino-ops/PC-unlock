'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('host', {
  onStart: (cb) => ipcRenderer.once('start', (_e, o) => cb(o)),
  onCtl: (cb) => ipcRenderer.on('ctl', (_e, m) => cb(m)),
  onSource: (cb) => ipcRenderer.on('source', (_e, s) => cb(s)),
  onQuality: (cb) => ipcRenderer.on('quality', (_e, q) => cb(q)),
  onFps: (cb) => ipcRenderer.on('fps', (_e, f) => cb(f)),
  answer: (r) => ipcRenderer.send('answer', r),
  input: (u8) => ipcRenderer.send('rtc-input', u8),
  ctl: (m) => ipcRenderer.send('rtc-ctl', m),
  state: (s) => ipcRenderer.send('rtc-state', s),
  stats: (s) => ipcRenderer.send('rtc-stats', s),
  log: (m) => ipcRenderer.send('rtc-log', String(m)),
});
