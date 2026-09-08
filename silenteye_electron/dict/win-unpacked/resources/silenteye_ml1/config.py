"""
SilentEye ML — Config  (FINAL v11 — Portable)
================================================
ALL PATHS ARE RELATIVE OR CONFIGURABLE.
No hardcoded system paths — works on any OS.

Dataset path resolution order:
  1. SILENTEYE_DATASET env variable (highest priority)
  2. ./data/  subfolder next to this config.py
  3. ../ml_dataset1/  one level up from this config.py

Usage:
  # Option A — set env variable (recommended for testing)
  set SILENTEYE_DATASET=C:\\path\\to\\ml_dataset1   (Windows)
  export SILENTEYE_DATASET=/path/to/ml_dataset1     (Linux/Mac)

  # Option B — place dataset in ./data/ next to config.py
  silenteye_ml1/
    config.py
    data/
      alaska/
      bossbase/
      ...

  # Option C — place dataset one level up
  Desktop/
    silenteye_ml1/
      config.py
    ml_dataset1/
      alaska/
      ...
"""

import os

# ── BASE PATHS ────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "trained_models")

MODEL_PATHS = {
    "image_jpg":       os.path.join(MODELS_DIR, "image_jpg_model.pkl"),
    "image_png_alpha": os.path.join(MODELS_DIR, "image_png_alpha_model.pkl"),
    "video":           os.path.join(MODELS_DIR, "video_model.pkl"),
    "svg":             os.path.join(MODELS_DIR, "svg_model.pkl"),
}

# ── DATASET PATH RESOLUTION ───────────────────────────────────────────────────
def _resolve_dataset_base() -> str:
    """
    Resolve dataset base path — no hardcoded paths.
    Tries multiple locations in priority order.
    """
    # Priority 1: environment variable
    env_path = os.environ.get("SILENTEYE_DATASET", "")
    if env_path and os.path.exists(env_path):
        print(f"[config] Dataset: {env_path}  (from SILENTEYE_DATASET env)")
        return env_path

    # Priority 2: ./data/ subfolder next to config.py
    data_dir = os.path.join(BASE_DIR, "data")
    if os.path.exists(data_dir):
        print(f"[config] Dataset: {data_dir}  (from ./data/)")
        return data_dir

    # Priority 3: ../ml_dataset1/ one level up
    parent_ds = os.path.join(os.path.dirname(BASE_DIR), "ml_dataset1")
    if os.path.exists(parent_ds):
        print(f"[config] Dataset: {parent_ds}  (from ../ml_dataset1/)")
        return parent_ds

    # Priority 4: ../ml_dataset/ (old name)
    parent_ds2 = os.path.join(os.path.dirname(BASE_DIR), "ml_dataset")
    if os.path.exists(parent_ds2):
        print(f"[config] Dataset: {parent_ds2}  (from ../ml_dataset/)")
        return parent_ds2

    # Fallback: return ./data/ and let trainer warn about missing dirs
    fallback = data_dir
    print(f"[config] WARNING: Dataset not found. Set SILENTEYE_DATASET env variable.")
    print(f"[config] Expected locations:")
    print(f"[config]   {data_dir}")
    print(f"[config]   {parent_ds}")
    print(f"[config]   or set: SILENTEYE_DATASET=/path/to/dataset")
    return fallback


BASE1 = _resolve_dataset_base()

# ── DATASET PATHS ─────────────────────────────────────────────────────────────
# Image uses multiple source datasets — lists of paths
TRAIN_DIRS = {
    "image": {
        "clean": [
            os.path.join(BASE1, "alaska",    "train", "clean"),
            os.path.join(BASE1, "bossbase",  "train", "clean"),
            os.path.join(BASE1, "div2k",     "train", "clean"),
            os.path.join(BASE1, "flatfield", "train", "clean"),
        ],
        "malicious": [
            os.path.join(BASE1, "alaska",    "train", "malicious"),
            os.path.join(BASE1, "bossbase",  "train", "malicious"),
            os.path.join(BASE1, "div2k",     "train", "malicious"),
            os.path.join(BASE1, "flatfield", "train", "malicious"),
        ],
    },
    "video": {
        "clean":     os.path.join(BASE1, "video", "train", "clean"),
        "malicious": os.path.join(BASE1, "video", "train", "malicious"),
    },
    "svg": {
        "clean":     os.path.join(BASE1, "svg", "train", "clean"),
        "malicious": os.path.join(BASE1, "svg", "train", "malicious"),
    },
}

TEST_DIRS = {
    "image": {
        "clean": [
            os.path.join(BASE1, "alaska",    "test", "clean"),
            os.path.join(BASE1, "bossbase",  "test", "clean"),
            os.path.join(BASE1, "div2k",     "test", "clean"),
            os.path.join(BASE1, "flatfield", "test", "clean"),
        ],
        "malicious": [
            os.path.join(BASE1, "alaska",    "test", "malicious"),
            os.path.join(BASE1, "bossbase",  "test", "malicious"),
            os.path.join(BASE1, "div2k",     "test", "malicious"),
            os.path.join(BASE1, "flatfield", "test", "malicious"),
        ],
    },
    "video": {
        "clean":     os.path.join(BASE1, "video", "test", "clean"),
        "malicious": os.path.join(BASE1, "video", "test", "malicious"),
    },
    "svg": {
        "clean":     os.path.join(BASE1, "svg", "test", "clean"),
        "malicious": os.path.join(BASE1, "svg", "test", "malicious"),
    },
}

# ── FILE CATEGORIES ───────────────────────────────────────────────────────────
JPEG_EXTS  = {".jpg", ".jpeg"}
PNG_EXTS   = {".png", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".heic"}
IMAGE_EXTS = JPEG_EXTS | PNG_EXTS
VIDEO_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mpeg", ".3gp", ".webm"}
SVG_EXTS   = {".svg", ".svgz"}
ALL_EXTS   = IMAGE_EXTS | VIDEO_EXTS | SVG_EXTS

# ── ML THRESHOLDS ─────────────────────────────────────────────────────────────
THRESHOLDS = {
    "image_jpg": {
        "malicious": 0.40,
        "clean":     0.20,
    },
    "image_png_alpha": {
        "malicious": 0.45,
        "clean":     0.20,
    },
    "video": {
        "malicious": 0.70,
        "clean":     0.40,
    },
    "svg": {
        "malicious": 0.40,
        "clean":     0.20,
    },
}

# ── IMAGE PARAMETERS ──────────────────────────────────────────────────────────
IMAGE_MAX_DIM       = 1024
IMAGE_MIN_PIXELS    = 500
LSB_CHI_THRESHOLD   = 8.0
LSB_RATIO_TOLERANCE = 0.006
RS_RATIO_THRESHOLD  = -0.04
RS_EMBED_THRESHOLD  = 0.10
ALPHA_MID_THRESHOLD = 0.25
ALPHA_BIN_THRESHOLD = 0.70
CORR_RG_THRESHOLD   = 0.70
CORR_GB_THRESHOLD   = 0.68

DCT_PM1_CHI_THRESHOLD = 0.15
DCT_AC_ZERO_THRESHOLD = 0.55
DCT_DC_VAR_THRESHOLD  = 0.60

# ── VIDEO PARAMETERS ──────────────────────────────────────────────────────────
VIDEO_HEAD_BYTES = 5 * 1024 * 1024
VIDEO_TAIL_BYTES = 256 * 1024

# ── TRAINING PARAMETERS ───────────────────────────────────────────────────────
TRAIN_N_ESTIMATORS = 100
TRAIN_MAX_DEPTH    = 6
TRAIN_SYNTHETIC_N  = 400

# ── Constants required by ml_integration.py ──────────────────────────────────
IMAGE_MAX_DIM    = 1024
IMAGE_MIN_PIXELS = 500

# MODEL_PATHS is already defined above in silenteye_ml1/config.py
# If it's missing, add this:
import os as _os
_BASE = _os.path.dirname(_os.path.abspath(__file__))
_MODELS_DIR = _os.path.join(_BASE, "trained_models")

if 'MODEL_PATHS' not in dir():
    MODEL_PATHS = {
        "image_jpg":       _os.path.join(_MODELS_DIR, "image_jpg_model.pkl"),
        "image_png_alpha": _os.path.join(_MODELS_DIR, "image_png_alpha_model.pkl"),
        "video":           _os.path.join(_MODELS_DIR, "video_model.pkl"),
        "svg":             _os.path.join(_MODELS_DIR, "svg_model.pkl"),
    }