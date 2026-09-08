'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// ─── Expose safe API to renderer ──────────────────────────────────────────────
// Renderer (index.html) calls window.silentEye.xxx()
// NO direct Node.js access — fully sandboxed via contextBridge

contextBridge.exposeInMainWorld('silentEye', {

  // ── Window controls (custom titlebar) ──
  minimize:    ()  => ipcRenderer.send('win-minimize'),
  maximize:    ()  => ipcRenderer.send('win-maximize'),
  close:       ()  => ipcRenderer.send('win-close'),
  quit:        ()  => ipcRenderer.send('win-quit'),
  isMaximized: ()  => ipcRenderer.invoke('win-is-maximized'),

  // ── File dialogs ──
  openFiles:   ()           => ipcRenderer.invoke('dialog-open-files'),
  openFolder:  ()           => ipcRenderer.invoke('dialog-open-folder'),

  // ── File system ──
  readFile:    (path)       => ipcRenderer.invoke('read-file', path),
  listFolder:  (path)       => ipcRenderer.invoke('list-folder', path),

  // ── Quarantine ──
  quarantineFile:   (path)  => ipcRenderer.invoke('quarantine-file', path),
  quarantineList:   ()      => ipcRenderer.invoke('quarantine-list'),
  quarantineClear:  ()      => ipcRenderer.invoke('quarantine-clear'),
  quarantinePath:   ()      => ipcRenderer.invoke('quarantine-path'),
  openQuarantineFolder: ()  => ipcRenderer.invoke('open-quarantine-folder'),

  // ── API status ──
  getApiStatus: ()          => ipcRenderer.invoke('get-api-status'),

  // ── Events from main process ──
  onApiStatus:  (cb)        => ipcRenderer.on('api-status',   (_, data) => cb(data)),
  onTriggerScan:(cb)        => ipcRenderer.on('trigger-scan', ()        => cb()),

  // ── Splash done signal ──
  splashDone:  ()           => ipcRenderer.send('splash-done'),

  // ── Auto Launch (startup with Windows) ──
  getAutoLaunch: ()         => ipcRenderer.invoke('get-autolaunch'),
  setAutoLaunch: (enable)   => ipcRenderer.invoke('set-autolaunch', enable),
});
