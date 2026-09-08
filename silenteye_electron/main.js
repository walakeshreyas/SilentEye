'use strict';

const { app, BrowserWindow, ipcMain, Tray, Menu, dialog, shell, nativeImage } = require('electron');
const path   = require('path');
const fs     = require('fs');
const { spawn, exec } = require('child_process');

// ─── Dev mode flag ────────────────────────────────────────────────────────────
const IS_DEV = process.argv.includes('--dev');

// ─── Paths ────────────────────────────────────────────────────────────────────
// When packaged: resources are in process.resourcesPath/silenteye1.1
// When dev:      resources are sibling folders on disk
const RESOURCES = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..');

const SILENTEYE_DIR = path.join(RESOURCES, 'silenteye1.1');
const ML_DIR        = path.join(RESOURCES, 'silenteye_ml1');
const API_SCRIPT    = path.join(SILENTEYE_DIR, 'api.py');
const ICON_PATH     = path.join(__dirname, 'assets', 'icon.png');

// ─── State ────────────────────────────────────────────────────────────────────
let mainWindow   = null;
let splashWindow = null;
let tray         = null;
let apiProcess   = null;
let apiPort      = 5000;
let apiReady     = false;

// ─── Single instance lock ─────────────────────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SPLASH WINDOW
// ─────────────────────────────────────────────────────────────────────────────
function createSplash() {
  splashWindow = new BrowserWindow({
    width:  480,
    height: 520,
    frame:           false,
    transparent:     true,
    resizable:       false,
    skipTaskbar:     true,
    alwaysOnTop:     true,
    hasShadow:       true,
    webPreferences:  { contextIsolation: true },
    icon: ICON_PATH,
  });
  splashWindow.loadFile(path.join(__dirname, 'renderer', 'splash.html'));
  splashWindow.center();

  // Fade in
  splashWindow.once('ready-to-show', () => splashWindow.show());
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN WINDOW
// ─────────────────────────────────────────────────────────────────────────────
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width:      1280,
    height:     800,
    minWidth:   960,
    minHeight:  600,
    frame:      false,        // Custom titlebar in HTML
    show:       false,        // Show only after splash
    hasShadow:  true,
    backgroundColor: '#080c10',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
      sandbox:          false,
    },
    icon: ICON_PATH,
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Dev tools in dev mode
  if (IS_DEV) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  // X button = destroy tray + kill Python + fully quit
  mainWindow.on('close', () => {
    app.isQuitting = true;

    // Destroy tray so Electron has no reason to stay alive
    if (tray) {
      tray.destroy();
      tray = null;
    }

    // Kill Python backend
    if (apiProcess) {
      try { apiProcess.kill('SIGTERM'); } catch {}
      if (process.platform === 'win32') {
        try { require('child_process').execSync('taskkill /F /IM python.exe /T', { stdio: 'ignore' }); } catch {}
        try { require('child_process').execSync('taskkill /F /IM python3.exe /T', { stdio: 'ignore' }); } catch {}
      }
      apiProcess = null;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    app.quit();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM TRAY
// ─────────────────────────────────────────────────────────────────────────────
function createTray() {
  const icon = fs.existsSync(ICON_PATH)
    ? nativeImage.createFromPath(ICON_PATH).resize({ width:16, height:16 })
    : nativeImage.createEmpty();

  tray = new Tray(icon);
  tray.setToolTip('SilentEye — Media Malware Scanner');

  const menu = Menu.buildFromTemplate([
    { label: 'SilentEye v1.0', enabled: false },
    { type: 'separator' },
    { label: 'Open',   click: () => { mainWindow?.show(); mainWindow?.focus(); } },
    { label: 'Scan Files...', click: () => { mainWindow?.show(); mainWindow?.webContents.send('trigger-scan'); } },
    { type: 'separator' },
    { label: 'Quit SilentEye', click: () => { app.isQuitting = true; app.quit(); } },
  ]);

  tray.setContextMenu(menu);
  tray.on('double-click', () => { mainWindow?.show(); mainWindow?.focus(); });
}

// ─────────────────────────────────────────────────────────────────────────────
// PYTHON API LAUNCHER
// ─────────────────────────────────────────────────────────────────────────────
function launchPythonAPI() {
  return new Promise((resolve) => {
    // Find Python executable
    const pythonCmds = process.platform === 'win32'
      ? ['python', 'python3', 'py']
      : ['python3', 'python'];

    let pythonExe = 'python';
    for (const cmd of pythonCmds) {
      try {
        const result = require('child_process').spawnSync(cmd, ['--version']);
        if (result.status === 0) { pythonExe = cmd; break; }
      } catch {}
    }

    // Check if api.py exists
    if (!fs.existsSync(API_SCRIPT)) {
      console.warn('[API] api.py not found at:', API_SCRIPT);
      console.warn('[API] Running in UI-only demo mode');
      apiReady = false;
      resolve(false);
      return;
    }

    console.log('[API] Launching:', pythonExe, API_SCRIPT);
    apiProcess = spawn(pythonExe, [API_SCRIPT, '--port', String(apiPort)], {
      cwd:      SILENTEYE_DIR,
      env: {
        ...process.env,
        SILENTEYE_ML_ROOT: ML_DIR,
        PYTHONUNBUFFERED:  '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Capture stdout to detect when API is ready
    apiProcess.stdout.on('data', (data) => {
      const msg = data.toString();
      console.log('[PY]', msg.trim());
      if ((msg.includes('Running on') || msg.includes('Serving on') || msg.includes('* Running'))
          && !apiReady) {
        apiReady = true;
        console.log('[API] Ready on port', apiPort);
        resolve(true);
      }
    });

    apiProcess.stderr.on('data', (data) => {
      const msg = data.toString();
      console.log('[PY-ERR]', msg.trim());
      // Flask writes startup message to stderr
      if ((msg.includes('Running on') || msg.includes('Serving on'))
          && !apiReady) {
        apiReady = true;
        resolve(true);
      }
    });

    apiProcess.on('error', (err) => {
      console.error('[API] Failed to start:', err);
      apiReady = false;
      resolve(false);
    });

    apiProcess.on('exit', (code) => {
      console.log('[API] Exited with code', code);
      apiReady = false;
    });

    // Timeout: if not ready in 12s, proceed anyway in demo mode
    setTimeout(() => {
      if (!apiReady) {
        console.warn('[API] Timeout — running in demo mode');
        resolve(false);
      }
    }, 12000);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// APP STARTUP SEQUENCE
// ─────────────────────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  // 1. Show splash immediately
  createSplash();

  // 2. Create main window in background (hidden)
  createMainWindow();

  // 3. Create tray
  createTray();

  // 4. Launch Python API (parallel to splash)
  const apiStarted = await launchPythonAPI();
  console.log('[APP] API started:', apiStarted);

  // 5. Wait for main window to be ready
  await new Promise((resolve) => {
    if (mainWindow.webContents.isLoading()) {
      mainWindow.webContents.once('did-finish-load', resolve);
    } else {
      resolve();
    }
  });

  // 6. Send API status to renderer
  mainWindow.webContents.send('api-status', {
    ready:   apiReady,
    port:    apiPort,
    demoMode: !apiReady,
  });

  // 7. Splash shows for minimum 5s, then transition
  // Splash html has its own 5s timer — it sends 'splash-done' IPC
  // Fallback: force transition after 6s
  setTimeout(() => {
    transitionToMain();
  }, 6000);
});

function transitionToMain() {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  mainWindow.show();
  mainWindow.focus();

  if (splashWindow && !splashWindow.isDestroyed()) {
    splashWindow.close();
    splashWindow = null;
  }
}

// IPC: splash signals it's done
ipcMain.on('splash-done', () => transitionToMain());

// ─────────────────────────────────────────────────────────────────────────────
// IPC HANDLERS — Window controls (custom titlebar)
// ─────────────────────────────────────────────────────────────────────────────
ipcMain.on('win-minimize',  () => mainWindow?.minimize());
ipcMain.on('win-maximize',  () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.on('win-close', () => {
  app.isQuitting = true;
  if (tray) { tray.destroy(); tray = null; }
  if (apiProcess) {
    try { apiProcess.kill('SIGTERM'); } catch {}
    if (process.platform === 'win32') {
      try { require('child_process').execSync('taskkill /F /IM python.exe /T', { stdio: 'ignore' }); } catch {}
      try { require('child_process').execSync('taskkill /F /IM python3.exe /T', { stdio: 'ignore' }); } catch {}
    }
    apiProcess = null;
  }
  app.quit();
});
ipcMain.on('win-quit', () => {
  app.isQuitting = true;
  app.quit();
});

// IPC: maximize state query
ipcMain.handle('win-is-maximized', () => mainWindow?.isMaximized() ?? false);

// ─────────────────────────────────────────────────────────────────────────────
// IPC HANDLERS — File system dialogs
// ─────────────────────────────────────────────────────────────────────────────
ipcMain.handle('dialog-open-files', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title:      'Select Files to Scan',
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Media Files', extensions: ['jpg','jpeg','png','gif','bmp','webp','heic','tiff','tif','mp4','mkv','avi','mov','wmv','flv','mpeg','3gp','webm','mp3','wav','flac','ogg','aac','m4a','svg','svgz','pdf','doc','docx','xls','xlsx','ppt','pptx','odt','ods','odp'] },
      { name: 'Images',      extensions: ['jpg','jpeg','png','gif','bmp','webp','heic','tiff'] },
      { name: 'Videos',      extensions: ['mp4','mkv','avi','mov','wmv','flv','mpeg','3gp','webm'] },
      { name: 'Audio',       extensions: ['mp3','wav','flac','ogg','aac','m4a'] },
      { name: 'Documents',   extensions: ['pdf','doc','docx','xls','xlsx','ppt','pptx','odt','ods','odp'] },
      { name: 'All Files',   extensions: ['*'] },
    ],
  });
  return result.canceled ? [] : result.filePaths;
});

ipcMain.handle('dialog-open-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title:      'Select Folder to Scan',
    properties: ['openDirectory'],
  });
  return result.canceled ? null : result.filePaths[0];
});

// ─────────────────────────────────────────────────────────────────────────────
// IPC HANDLERS — File reading (for scan)
// ─────────────────────────────────────────────────────────────────────────────
ipcMain.handle('read-file', async (_, filePath) => {
  try {
    const data = fs.readFileSync(filePath);
    return { ok: true, data: data.toString('base64'), size: data.length };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('list-folder', async (_, folderPath) => {
  try {
    const entries = fs.readdirSync(folderPath, { withFileTypes: true });
    const files = entries
      .filter(e => e.isFile())
      .map(e => ({
        name: e.name,
        path: path.join(folderPath, e.name),
        size: fs.statSync(path.join(folderPath, e.name)).size,
      }));
    return { ok: true, files };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// IPC HANDLERS — Quarantine (dedicated read-only folder)
// ─────────────────────────────────────────────────────────────────────────────
const QUARANTINE_DIR = path.join(app.getPath('userData'), 'quarantine');

ipcMain.handle('quarantine-file', async (_, filePath) => {
  try {
    if (!fs.existsSync(QUARANTINE_DIR)) {
      fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
    }
    const fname  = path.basename(filePath);
    const dest   = path.join(QUARANTINE_DIR, fname + '.quarantined');
    fs.copyFileSync(filePath, dest);

    // Strip all execute permissions — read-only
    fs.chmodSync(dest, 0o444);

    return { ok: true, quarantinePath: dest };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('quarantine-list', async () => {
  try {
    if (!fs.existsSync(QUARANTINE_DIR)) return { ok: true, files: [] };
    const files = fs.readdirSync(QUARANTINE_DIR).map(f => ({
      name:    f.replace('.quarantined', ''),
      path:    path.join(QUARANTINE_DIR, f),
      size:    fs.statSync(path.join(QUARANTINE_DIR, f)).size,
      readOnly: true,
    }));
    return { ok: true, files };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('quarantine-clear', async () => {
  try {
    if (fs.existsSync(QUARANTINE_DIR)) {
      fs.readdirSync(QUARANTINE_DIR).forEach(f => {
        const fp = path.join(QUARANTINE_DIR, f);
        fs.chmodSync(fp, 0o644);   // restore write permission to delete
        fs.unlinkSync(fp);
      });
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('quarantine-path', () => QUARANTINE_DIR);

ipcMain.handle('open-quarantine-folder', () => {
  if (!fs.existsSync(QUARANTINE_DIR)) fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  shell.openPath(QUARANTINE_DIR);
});

// ─────────────────────────────────────────────────────────────────────────────
// IPC — API status
// ─────────────────────────────────────────────────────────────────────────────
ipcMain.handle('get-api-status', () => ({
  ready:    apiReady,
  port:     apiPort,
  demoMode: !apiReady,
}));

// ─────────────────────────────────────────────────────────────────────────────
// CLEANUP
// ─────────────────────────────────────────────────────────────────────────────
app.on('before-quit', () => {
  app.isQuitting = true;
  if (apiProcess) {
    try { apiProcess.kill('SIGTERM'); } catch {}
    // On Windows, SIGTERM may not work — force kill python processes
    if (process.platform === 'win32') {
      try { require('child_process').execSync('taskkill /F /IM python.exe /T', { stdio: 'ignore' }); } catch {}
      try { require('child_process').execSync('taskkill /F /IM python3.exe /T', { stdio: 'ignore' }); } catch {}
    }
    apiProcess = null;
  }
});

app.on('will-quit', () => {
  if (apiProcess) {
    apiProcess.kill('SIGTERM');
  }
});

app.on('window-all-closed', () => {
  // Kill Python backend
  if (apiProcess) {
    try { apiProcess.kill('SIGTERM'); } catch {}
    apiProcess = null;
  }
  app.quit();
});

app.on('activate', () => {
  if (!mainWindow) createMainWindow();
  else mainWindow.show();
});
