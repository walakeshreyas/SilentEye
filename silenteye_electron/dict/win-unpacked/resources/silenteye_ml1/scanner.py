"""
SilentEye ML — Scanner  (FIXED v13)
======================================
BUG FIXES v13:
  Bug 19b — Camera guard was too aggressive:
    steghide files with high entropy + high corr were let through
    Fix: qt_sum < 0.09 overrides camera guard — always flags very low QT
  Bug 4   — Both ml_layers and layers keys returned
  Bug 5   — Entropy false positive guard kept
  Bug 6   — RS rules removed from scanner
  Bug 20  — Uncertain result handled
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config
from features import extract_features
from model.predictor import predict


def _scan_image(features, pred, ext: str) -> List[Dict]:
    results  = []
    is_jpeg  = ext in config.JPEG_EXTS

    # ── LSB stego (PNG only) ──────────────────────────────────────────────────
    if not is_jpeg:
        chi   = features[0]
        ratio = features[1]
        prob  = pred["probability"]
        lsb_s = (chi < config.LSB_CHI_THRESHOLD and
                 abs(ratio - 0.5) < config.LSB_RATIO_TOLERANCE)
        det   = lsb_s or (pred["detected"] and prob > 0.60)
        sev   = "high" if (lsb_s and prob > 0.55) else "medium" if det else "none"
        results.append({
            "layer":    "ml_lsb_stego",
            "detected": det,
            "severity": sev,
            "score":    70 if sev == "high" else 40 if det else 0,
            "reason":   f"LSB chi={chi:.1f}, ratio={ratio:.4f}" if det
                        else f"LSB normal (chi={chi:.1f})"
        })

    # ── DCT stego (JPEG only) ──────────────────────────────────────────────────
    if is_jpeg:
        qt_std  = features[15]
        qt_mean = features[16]
        qt_sum  = features[19]
        entropy = features[9]
        corr_rg = features[22]
        prob    = pred["probability"]

        # Camera-like check: high entropy + high correlation = likely camera photo
        is_camera_like = (entropy > 0.93 and corr_rg > 0.85)

        # BUG 19b FIX: qt_sum < 0.09 is a HARD steghide indicator
        # Overrides camera guard — steghide always produces very low qt_sum
        # Clean camera photos: qt_sum typically 0.15-0.50
        # Steghide: qt_sum typically 0.03-0.09
        is_definite_stego = qt_sum < 0.09

        dct_s = is_definite_stego or (
            qt_std < 0.08 and
            qt_mean < 0.15 and
            not is_camera_like
        )

        det = dct_s or (pred["detected"] and prob > 0.55)
        sev = "high" if (dct_s and (prob > 0.45 or is_definite_stego)) else \
              "medium" if det else "none"
        results.append({
            "layer":    "ml_dct_stego",
            "detected": det,
            "severity": sev,
            "score":    75 if sev == "high" else 40 if det else 0,
            "reason":   f"DCT QT std={qt_std:.3f} mean={qt_mean:.3f} sum={qt_sum:.3f}" if det
                        else "DCT normal"
        })

    # ── Alpha channel (PNG only) ──────────────────────────────────────────────
    if ext in (".png", ".webp", ".tiff", ".tif"):
        has_a = features[10] > 0
        mid_r = features[14]
        bin_r = features[13]
        prob  = pred["probability"]
        if not has_a:
            results.append({
                "layer": "ml_alpha_stego", "detected": False,
                "severity": "none", "score": 0,
                "reason": "No alpha channel"
            })
        else:
            alpha_s = (mid_r > config.ALPHA_MID_THRESHOLD and
                       bin_r < config.ALPHA_BIN_THRESHOLD)
            det     = alpha_s or (pred["detected"] and prob > 0.45)
            sev     = "high" if (alpha_s and prob > 0.60) else "medium" if det else "none"
            results.append({
                "layer":    "ml_alpha_stego",
                "detected": det,
                "severity": sev,
                "score":    75 if sev == "high" else 45 if det else 0,
                "reason":   f"Alpha mid={mid_r:.1%} bin={bin_r:.1%}" if det
                            else "Alpha normal"
            })

    # ── Pixel stats ───────────────────────────────────────────────────────────
    # BUG 5 FIX: entropy alone no longer triggers — requires BOTH low corr AND high entropy
    corr_rg   = features[22]
    corr_gb   = features[23]
    entropy_n = features[9]
    prob      = pred["probability"]
    is_color  = not (corr_rg == 0.0 and corr_gb == 0.0)

    pix_s = (is_color and
             corr_rg   < config.CORR_RG_THRESHOLD and
             corr_gb   < config.CORR_GB_THRESHOLD and
             entropy_n > 0.990)

    det = pix_s or (pred["detected"] and prob > 0.70)
    results.append({
        "layer":    "ml_pixel_stats",
        "detected": det,
        "severity": "medium" if det else "none",
        "score":    30 if det else 0,
        "reason":   f"Pixel: corr_RG={corr_rg:.3f} entropy={entropy_n:.4f}" if det
                    else "Pixel statistics normal"
    })

    return results


def _scan_video(features, pred) -> List[Dict]:
    exe_h = features[11]
    c2    = features[12]
    pe_t  = features[17]
    elf_t = features[18]
    ov    = features[15]
    spike = features[9]
    prob  = pred["probability"]

    hard = exe_h > 0 or pe_t > 0 or elf_t > 0 or c2 > 0
    soft = ov > 0.05 or spike > 0.2
    ml_d = pred["detected"] and prob >= config.THRESHOLDS["video"]["malicious"]

    det   = hard or ml_d or (soft and prob > 0.50)
    sev   = "high" if hard else "medium" if det else "none"
    score = 80 if hard else 50 if det else 0

    parts = []
    if exe_h:        parts.append("Executable in video header")
    if pe_t:         parts.append("PE in video tail")
    if elf_t:        parts.append("ELF in video tail")
    if c2:           parts.append("C2 domain in metadata")
    if ov > 0.05:    parts.append(f"Overlay ({ov:.1%})")
    if spike > 0.2:  parts.append(f"Entropy spike ({spike:.2f})")
    if ml_d and not parts: parts.append("ML anomaly detected")

    return [{
        "layer":    "ml_video_anomaly",
        "detected": det,
        "severity": sev,
        "score":    score,
        "reason":   " | ".join(parts) + f" (p={prob:.3f})" if parts
                    else f"Video clean (p={prob:.3f})"
    }]


def _scan_svg(features, pred) -> List[Dict]:
    danger  = features[0]
    js_exec = features[1]
    xxe     = features[2]
    pe_b64  = features[7]
    short_s = features[14]
    c2      = features[17]
    prob    = pred["probability"]

    hard  = pe_b64 > 0 or xxe > 0 or (danger > 0.3 and js_exec > 0.3) or short_s > 0
    soft  = danger > 0.15 or c2 > 0
    det   = hard or (soft and prob > 0.45) or (pred["detected"] and prob > 0.40)
    sev   = "high" if hard else "medium" if det else "none"
    score = 85 if hard else 45 if det else 0

    parts = []
    if pe_b64 > 0:   parts.append("PE/ELF in base64")
    if xxe > 0:      parts.append("XXE injection")
    if danger > 0.3: parts.append(f"Danger patterns={danger:.1%}")
    if js_exec > 0:  parts.append("JS execution")
    if c2 > 0:       parts.append("C2 URL")

    return [{
        "layer":    "ml_svg_payload",
        "detected": det,
        "severity": sev,
        "score":    score,
        "reason":   " | ".join(parts) + f" (p={prob:.3f})" if parts
                    else f"SVG clean (p={prob:.3f})"
    }]


def _aggregate_score(detected_layers: List[Dict]) -> int:
    if not detected_layers:
        return 0
    scores = sorted([l.get("score", 0) for l in detected_layers], reverse=True)
    total  = scores[0] + sum(int(s * 0.10) for s in scores[1:])
    return min(total, 100)


def scan_bytes(file_bytes: bytes, ext: str) -> Dict:
    """
    Scan file bytes. Returns full result dict.
    BUG 4 FIX: returns both ml_layers and layers keys.
    BUG 20 FIX: handles uncertain prediction.
    """
    ext = ext.lower()

    feat_result = extract_features(file_bytes, ext)
    if feat_result is None:
        return {
            "category":    "unknown", "ext": ext,
            "ml_layers":   [], "layers": [],
            "detected":    False,
            "verdict":     "skip",
            "score":       0,
            "probability": 0.0,
            "severity":    "none",
            "reason":      f"Unsupported or unreadable file ({ext})",
            "fallback":    False,
        }

    category = feat_result["category"]
    features = feat_result["features"]
    pred     = predict(features, category, ext=ext)

    if pred.get("uncertain"):
        return {
            "category":    category, "ext": ext,
            "ml_layers":   [], "layers": [],
            "detected":    False,
            "verdict":     "uncertain",
            "score":       0,
            "probability": 0.0,
            "severity":    "none",
            "reason":      pred.get("reason", "Prediction failed"),
            "fallback":    True,
        }

    if category == "image":
        ml_layers = _scan_image(features, pred, ext)
    elif category == "video":
        ml_layers = _scan_video(features, pred)
    elif category == "svg":
        ml_layers = _scan_svg(features, pred)
    else:
        ml_layers = []

    detected_layers = [l for l in ml_layers if l.get("detected")]
    total_score     = _aggregate_score(detected_layers)

    max_sev = "none"
    for l in detected_layers:
        s = l.get("severity", "none")
        if s == "high":     max_sev = "high";   break
        elif s == "medium": max_sev = "medium"

    verdict = ("malicious"  if max_sev == "high"  else
               "suspicious" if detected_layers    else
               "clean")

    return {
        "category":    category,
        "ext":         ext,
        "ml_layers":   ml_layers,
        "layers":      ml_layers,   # BUG 4 FIX: alias
        "detected":    bool(detected_layers),
        "verdict":     verdict,
        "score":       total_score,
        "probability": pred["probability"],
        "severity":    max_sev,
        "reason":      pred["reason"],
        "fallback":    pred.get("fallback", False),
    }


def scan_file(file_path: str) -> Dict:
    path = Path(file_path)
    if not path.exists():
        return {
            "verdict":   "error",
            "reason":    f"File not found: {file_path}",
            "ml_layers": [], "layers": [],
        }
    try:
        data = path.read_bytes()
        return scan_bytes(data, path.suffix)
    except Exception as e:
        return {
            "verdict":   "error",
            "reason":    str(e),
            "ml_layers": [], "layers": [],
        }
