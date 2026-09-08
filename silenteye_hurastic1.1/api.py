import os
import sys
import json
import base64
import argparse
import tempfile
import threading
from pathlib import Path

# ── Flask ──────────────────────────────────────────────────────────────────────
try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError:
    print("[API] ERROR: Flask not installed.")
    print("[API] Run: pip install flask flask-cors")
    sys.exit(1)

# ── Add silenteye1.1 root to path ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Import SilentEye pipeline ─────────────────────────────────────────────────
try:
    from preprocessing    import preprocess_file
    from heuristic.engine import run_heuristic_scan, load_yara_rules
    from main import scan_file

    THREAT_FLAGS = {
        "double_extension",
        "magic_byte_mismatch",
        "integrity_fail",
        "svg_script_injection",
}
    PIPELINE_OK = True
    print("[API] SilentEye pipeline loaded OK")
except ImportError as e:
    PIPELINE_OK = False
    print(f"[API] WARNING: Pipeline import failed: {e}")
    print("[API] Running in demo mode")

# ── ML integration (optional) ────────────────────────────────────────────────
try:
    from ml_integration import run_ml_scan, combine_verdicts, ml_status, ML_CATEGORIES
    ML_OK = True
    print("[API] ML integration loaded OK")
except ImportError:
    ML_OK = False
    print("[API] ML integration not found — heuristic only")

# ── Load YARA rules ───────────────────────────────────────────────────────────
YARA_PATH = os.path.join(BASE_DIR, "rules", "silenteye.yar")
if PIPELINE_OK and os.path.exists(YARA_PATH):
    load_yara_rules(YARA_PATH)
    print(f"[API] YARA rules loaded from {YARA_PATH}")
else:
    print(f"[API] YARA rules not found at {YARA_PATH} — skipping")

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=["http://localhost:*", "file://*"])

# Scan lock — one scan at a time
_scan_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _serialise(result: dict) -> dict:
    
    def clean(obj):
        if isinstance(obj, dict):
            return {k: clean(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [clean(i) for i in obj]
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, Path):
            return str(obj)
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)
    return clean(result)


def _run_full_pipeline(file_path: str) -> dict:
    
    if not PIPELINE_OK:
        return _demo_result(file_path)

    # Stage 1
    s1 = preprocess_file(file_path)

    if s1.get("status") in ("skip", "error"):
        return {
            "file":          os.path.basename(file_path),
            "file_path":     file_path,
            "final_verdict": s1["status"],
            "final_score":   0,
            "summary":       s1.get("reason", ""),
            "stage1":        s1,
            "stage2":        {},
            "stage2b_ml":    None,
            "ml_applied":    False,
        }

    # Stage 2A
    s2 = run_heuristic_scan(file_path, s1)

    # Stage 2B + Decision
    if ML_OK:
        category  = s1.get("file_type", "unknown")
        ml_result = None
        if category in ML_CATEGORIES:
            ml_result = run_ml_scan(file_path)
        combined = combine_verdicts(s1, s2, ml_result, category)
        combined["file"]      = os.path.basename(file_path)
        combined["file_path"] = file_path
        combined["ml_applied"] = ml_result is not None and not ml_result.get("skipped")
        return combined
    else:
        # Heuristic only — replicate main.py verdict logic
        return _heuristic_verdict(file_path, s1, s2)


def _heuristic_verdict(file_path, s1, s2) -> dict:
    """Identical to main.py verdict logic when ML is not available."""
    real_threat = [f for f in s1.get("flags", []) if f in THREAT_FLAGS]
    h_verdict   = s2.get("verdict", "clean")
    h_score     = s2.get("final_score", 0)

    if h_verdict == "malicious":
        fv, fs, summary = "malicious", h_score, s2.get("summary", "")
    elif real_threat and h_verdict == "suspicious":
        fv, fs, summary = "malicious", h_score, f"Stage1 {real_threat} + suspicious"
    elif h_verdict == "suspicious":
        fv, fs, summary = "suspicious", h_score, s2.get("summary", "")
    elif real_threat:
        fv, fs, summary = "suspicious", 25, f"Stage1 threat flags: {real_threat}"
    else:
        fv, fs, summary = "clean", max(h_score, 0), "File passed all checks"

    return {
        "file":          os.path.basename(file_path),
        "file_path":     file_path,
        "final_verdict": fv,
        "final_score":   fs,
        "summary":       summary,
        "stage1":        s1,
        "stage2":        s2,
        "stage2b_ml":    None,
        "ml_applied":    False,
    }


def _demo_result(file_path: str) -> dict:
    """Demo result when pipeline not loaded."""
    import random
    name = os.path.basename(file_path)
    seed = sum(ord(c) for c in name)
    r    = (seed * 7919 + 13) % 100
    verdict = "malicious" if r < 5 else "suspicious" if r < 15 else "clean"
    score   = 80 + random.randint(0,15) if verdict == "malicious" else \
              30 + random.randint(0,25) if verdict == "suspicious" else \
              random.randint(0,8)
    return {
        "file":          name,
        "file_path":     file_path,
        "final_verdict": verdict,
        "final_score":   score,
        "summary":       "Demo mode — pipeline not loaded",
        "stage1":        {"file_type": "unknown", "flags": [], "file_hash": "demo"},
        "stage2":        {"verdict": verdict, "final_score": score, "detections": []},
        "stage2b_ml":    None,
        "ml_applied":    False,
        "demo":          True,
    }


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/status", methods=["GET"])
def status():
    """Health check — Electron polls this to confirm API is up."""
    ml_stat = ml_status() if ML_OK else {"available": False, "reason": "Not loaded", "models": {}}
    return jsonify({
        "ok":           True,
        "version":      "1.0",
        "pipeline":     PIPELINE_OK,
        "ml":           ML_OK,
        "ml_models":    ml_stat.get("models", {}),
        "yara":         os.path.exists(YARA_PATH),
        "demo_mode":    not PIPELINE_OK,
    })


@app.route("/scan/file", methods=["POST"])
def scan_file_route():
    """
    Scan a single file by path.
    Body: { "path": "C:\\Users\\...\\file.jpg" }
    """
    data = request.get_json(force=True, silent=True) or {}
    file_path = data.get("path", "").strip()

    if not file_path:
        return jsonify({"ok": False, "error": "path required"}), 400

    if not os.path.exists(file_path):
        return jsonify({"ok": False, "error": f"File not found: {file_path}"}), 404

    if not os.path.isfile(file_path):
        return jsonify({"ok": False, "error": "Path is not a file"}), 400

    with _scan_lock:
        try:
            result = _run_full_pipeline(file_path)
            return jsonify({"ok": True, "result": _serialise(result)})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/scan/bytes", methods=["POST"])
def scan_bytes_route():
    """
    Scan file from base64 bytes (used when file is dragged into app).
    Body: { "name": "photo.jpg", "data": "<base64 string>" }
    """
    data = request.get_json(force=True, silent=True) or {}
    name    = data.get("name", "unknown")
    b64data = data.get("data", "")

    if not b64data:
        return jsonify({"ok": False, "error": "data required"}), 400

    try:
        file_bytes = base64.b64decode(b64data)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid base64 data"}), 400

    # Write to temp file so pipeline can read it normally
    ext  = os.path.splitext(name)[1] or ".bin"
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    with _scan_lock:
        try:
            result = _run_full_pipeline(tmp_path)
            result["file"]      = name           # restore original name
            result["file_path"] = name
            return jsonify({"ok": True, "result": _serialise(result)})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


@app.route("/scan/folder", methods=["POST"])
def scan_folder_route():
    """
    Scan all supported files in a folder.
    Body: { "path": "C:\\Users\\...\\folder" }
    Returns list of per-file results.
    """
    data        = request.get_json(force=True, silent=True) or {}
    folder_path = data.get("path", "").strip()

    if not folder_path:
        return jsonify({"ok": False, "error": "path required"}), 400

    if not os.path.isdir(folder_path):
        return jsonify({"ok": False, "error": f"Folder not found: {folder_path}"}), 404

    SUPPORTED_EXTS = {
        ".jpg",".jpeg",".png",".gif",".bmp",".webp",".heic",".tiff",".tif",
        ".mp4",".mkv",".avi",".mov",".wmv",".flv",".mpeg",".3gp",".webm",
        ".mp3",".wav",".flac",".ogg",".aac",".m4a",
        ".svg",".svgz",
        ".pdf",
        ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".odt",".ods",".odp",
    }

    all_files = [
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
        and os.path.splitext(f)[1].lower() in SUPPORTED_EXTS
    ]

    if not all_files:
        return jsonify({"ok": True, "results": [], "total": 0,
                        "message": "No supported files found in folder"})

    results = []
    with _scan_lock:
        for file_path in all_files:
            try:
                r = _run_full_pipeline(file_path)
                results.append(_serialise(r))
            except Exception as e:
                results.append({
                    "file":          os.path.basename(file_path),
                    "file_path":     file_path,
                    "final_verdict": "error",
                    "final_score":   0,
                    "summary":       str(e),
                })

    counts = {
        "total":     len(results),
        "clean":     sum(1 for r in results if r.get("final_verdict") == "clean"),
        "suspicious":sum(1 for r in results if r.get("final_verdict") == "suspicious"),
        "malicious": sum(1 for r in results if r.get("final_verdict") == "malicious"),
        "errors":    sum(1 for r in results if r.get("final_verdict") == "error"),
    }

    return jsonify({"ok": True, "results": results, **counts})


@app.route("/quarantine/add", methods=["POST"])
def quarantine_add():
    """Copy a file into quarantine folder with read-only permissions."""
    data      = request.get_json(force=True, silent=True) or {}
    file_path = data.get("path", "").strip()
    name      = data.get("name", os.path.basename(file_path))

    if not file_path or not os.path.exists(file_path):
        return jsonify({"ok": False, "error": "File not found"}), 404

    try:
        import shutil
        q_dir = os.path.join(BASE_DIR, "quarantine")
        os.makedirs(q_dir, exist_ok=True)          # create once, reused always
        dest  = os.path.join(q_dir, name + ".quarantined")
        shutil.copy2(file_path, dest)
        os.chmod(dest, 0o444)                       # read-only, non-executable
        return jsonify({"ok": True, "quarantinePath": dest})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/quarantine/list", methods=["GET"])
def quarantine_list():
    """List files in quarantine folder."""
    q_dir = os.path.join(BASE_DIR, "quarantine")
    if not os.path.exists(q_dir):
        return jsonify({"ok": True, "files": []})
    files = []
    for f in os.listdir(q_dir):
        fp = os.path.join(q_dir, f)
        if os.path.isfile(fp):
            files.append({
                "name":     f.replace(".quarantined", ""),
                "path":     fp,
                "size":     os.path.getsize(fp),
                "readOnly": True,
            })
    return jsonify({"ok": True, "files": files})


@app.route("/quarantine/clear", methods=["POST"])
def quarantine_clear():
    """Remove all files from quarantine folder."""
    q_dir = os.path.join(BASE_DIR, "quarantine")
    if not os.path.exists(q_dir):
        return jsonify({"ok": True, "deleted": 0})
    deleted = 0
    for f in os.listdir(q_dir):
        fp = os.path.join(q_dir, f)
        try:
            os.chmod(fp, 0o644)
            os.unlink(fp)
            deleted += 1
        except Exception:
            pass
    return jsonify({"ok": True, "deleted": deleted})


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SilentEye Flask API")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    args = parser.parse_args()

    print(f"[API] SilentEye API starting on http://{args.host}:{args.port}")
    print(f"[API] Pipeline: {'OK' if PIPELINE_OK else 'DEMO MODE'}")
    print(f"[API] ML:       {'OK' if ML_OK else 'Not available'}")

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        threaded=False,   # one scan at a time — prevents race conditions
        use_reloader=False,
    )
