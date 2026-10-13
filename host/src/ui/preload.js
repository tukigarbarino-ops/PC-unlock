'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pcu', {
  state: () => ipcRenderer.invoke('ui-state'),
  savePair: (code) => ipcRenderer.invoke('ui-save-pair', code),
  option: (k, v) => ipcRenderer.invoke('ui-option', k, v),
  endSession: () => ipcRenderer.invoke('ui-end-session'),
  onState: (cb) => ipcRenderer.on('state', (_e, s) => cb(s)),
});
