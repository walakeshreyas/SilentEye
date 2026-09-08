# SilentEye — Electron App Setup Guide

## Folder Structure Required

```
Desktop/
  SilentEye/
    silenteye1.1/          ← your existing heuristic project
    silenteye_ml1/         ← your existing ML project
    silenteye_electron/    ← THIS FOLDER (the Electron app)
      main.js
      preload.js
      package.json
      renderer/
        index.html
        splash.html
      assets/
        icon.png           ← add your app icon here (256x256 PNG)
        icon.ico           ← add your app icon here (256x256 ICO)
```

---

## Step 1 — Prerequisites

Install these once on your system:

1. **Node.js** (v18 or v20 LTS)
   Download: https://nodejs.org/en/download
   After install, verify: `node --version`

2. **Python 3.10+** (you already have this)
   Verify: `python --version`

3. **Python packages** (if not already installed):
   ```
   pip install flask flask-cors
   ```

---

## Step 2 — Install Electron dependencies

Open terminal in `silenteye_electron/` folder:

```bash
cd Desktop/SilentEye/silenteye_electron
npm install
```

This downloads Electron and electron-builder (~200MB, one time only).

---

## Step 3 — Add app icon (important for .exe)

Place these two files in `silenteye_electron/assets/`:
- `icon.png` — 256×256 PNG (use your SilentEye logo)
- `icon.ico` — Windows ICO format (convert using: https://convertio.co)

If you skip this step, Electron uses its default icon.

---

## Step 4 — Run in development mode (test first)

```bash
cd Desktop/SilentEye/silenteye_electron
npm run dev
```

This opens the app with DevTools. Check the console for any errors.
The Python API (`silenteye1.1/api.py`) is launched automatically.

---

## Step 5 — Build Windows .exe

```bash
cd Desktop/SilentEye/silenteye_electron
npm run build
```

This creates two files in `silenteye_electron/dist/`:
- `SilentEye Setup 1.0.0.exe` — NSIS installer (for distribution)
- `SilentEye 1.0.0.exe`       — Portable .exe (runs without install)

Build takes 3-5 minutes first time.

---

## What happens when the app starts

1. Electron launches
2. **Splash screen** appears (5 seconds) with loading animation
3. In background: Python Flask API (`api.py`) is started on `localhost:5000`
4. After 5s: splash fades, main window slides in
5. UI connects to Python backend via HTTP
6. If Python not found → app runs in **demo mode** (simulated scan results)

---

## CPU / Memory expectations

| State          | CPU    | RAM     |
|----------------|--------|---------|
| App idle       | ~1%    | ~100MB  |
| Scanning file  | ~5-15% | ~150MB  |
| Python idle    | ~0%    | ~30MB   |
| Python scanning| ~20-60%| ~200MB  |

Heavy lifting is all Python. Electron just shows the UI.

---

## Minimize to Tray

- Clicking **X** hides the window to system tray (does NOT quit)
- Double-click tray icon to reopen
- Right-click tray → **Quit SilentEye** to fully exit

---

## Quarantine Vault location

Quarantined files are stored at:
```
C:\Users\<YourName>\AppData\Roaming\silenteye\quarantine\
```
- Files are copied here with `.quarantined` extension
- Permissions set to **read-only (444)** — cannot be executed
- Clear quarantine button removes all files from vault

---

## Troubleshooting

**Python API not starting:**
- Make sure `api.py` exists in `silenteye1.1/`
- Run `python silenteye1.1/api.py` manually to see errors
- App will run in demo mode if API fails

**npm install fails:**
- Check Node.js version: `node --version` (need v18+)
- Try: `npm install --legacy-peer-deps`

**Build fails — icon error:**
- Make sure `assets/icon.ico` exists
- Or remove the icon lines from package.json temporarily

**App opens blank:**
- Run `npm run dev` and check DevTools console for errors
- Usually a path issue — verify folder structure above
