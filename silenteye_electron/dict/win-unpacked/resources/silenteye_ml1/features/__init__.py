"""
SilentEye ML — Features Dispatcher  (FIXED v13)
=================================================
HEIC support added via pillow-heif plugin.
Install: pip install pillow-heif

Routes each file extension to correct feature extractor.
"""

from typing import Optional, Dict
import numpy as np

from .image_features import extract as _extract_image, N_FEATURES as N_IMAGE
from .video_features import extract as _extract_video, N_FEATURES as N_VIDEO
from .svg_features   import extract as _extract_svg,   N_FEATURES as N_SVG

import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config

# Register HEIC support if pillow-heif is installed
try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
    _HEIC_SUPPORTED = True
except ImportError:
    _HEIC_SUPPORTED = False

# Map extension → (category, extractor_fn, n_features)
_DISPATCH = {}

for ext in config.IMAGE_EXTS:
    _DISPATCH[ext] = ("image", _extract_image, N_IMAGE)

for ext in config.VIDEO_EXTS:
    _DISPATCH[ext] = ("video", _extract_video, N_VIDEO)

for ext in config.SVG_EXTS:
    _DISPATCH[ext] = ("svg", _extract_svg, N_SVG)


def extract_features(file_bytes: bytes, ext: str) -> Optional[Dict]:
    """
    Main dispatcher. Routes by extension to correct extractor.
    Returns dict or None if unsupported/failed.

    BUG 20 FIX: on extraction failure returns None explicitly
    so caller can handle as uncertain instead of silently clean.
    """
    ext   = ext.lower()
    entry = _DISPATCH.get(ext)

    if entry is None:
        return None

    # Warn if HEIC requested but plugin not installed
    if ext in (".heic", ".heif") and not _HEIC_SUPPORTED:
        print(f"[WARN] HEIC support requires: pip install pillow-heif")
        return None

    category, extractor, n_features = entry

    try:
        features = extractor(file_bytes, ext)
        if features is None:
            return None
        return {
            "category":   category,
            "ext":        ext,
            "features":   features,
            "n_features": n_features,
        }
    except Exception:
        # BUG 20: return None explicitly — caller returns uncertain
        return None


def supported_extensions() -> set:
    return set(_DISPATCH.keys())
