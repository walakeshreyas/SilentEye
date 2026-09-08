import os
import sys
from typing import Dict, Optional

# Make sure silenteye_ml1 config loads, not silenteye1.1 config
_ML_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "silenteye_ml1")
if _ML_ROOT not in sys.path:
    sys.path.insert(0, _ML_ROOT)
    
# ── Path resolution ───────────────────────────────────────────────────────────
# Layout: Desktop/SilentEye/silenteye1.1/ml_integration.py
_THIS_DIR       = os.path.dirname(os.path.abspath(__file__))  # silenteye1.1/
_SILENTEYE_DIR  = os.path.dirname(_THIS_DIR)                  # SilentEye/
ML_PROJECT_ROOT = os.path.join(_SILENTEYE_DIR, "silenteye_ml1")
ML_PROJECT_ROOT = os.environ.get("SILENTEYE_ML_ROOT", ML_PROJECT_ROOT)

# ── Categories that have ML models ───────────────────────────────────────────
ML_CATEGORIES = {"image", "video", "svg"}

# ── Extension -> ML category ─────────────────────────────────────────────────
_EXT_TO_ML_CAT = {}
for _e in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".heic"):
    _EXT_TO_ML_CAT[_e] = "image"
for _e in (".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mpeg", ".3gp", ".webm"):
    _EXT_TO_ML_CAT[_e] = "video"
for _e in (".svg", ".svgz"):
    _EXT_TO_ML_CAT[_e] = "svg"

# ── ML confidence thresholds ─────────────────────────────────────────────────
ML_HIGH_CONF_PROB   = 0.75   # >= this -> ML is authoritative
ML_MEDIUM_CONF_PROB = 0.45   # >= this -> ML fires at medium confidence

# Hard layer names — deterministic structural signals, always reliable
# These override probability threshold when fired
ML_HARD_LAYERS = {
    "ml_dct_stego",     # JPEG: QT std < 0.09 — steghide fingerprint
    "ml_alpha_stego",   # PNG:  mid-range alpha — structural alpha stego
    "ml_video_anomaly", # Video: exe_in_header / pe_in_tail / c2_domain
    "ml_svg_payload",   # SVG:  PE in base64 / XXE / danger patterns
}

# Stage 1 flags that count as real threat signals
THREAT_FLAGS = {
    "double_extension", "magic_byte_mismatch",
    "integrity_fail", "svg_script_injection",
}

# ── Lazy ML import ────────────────────────────────────────────────────────────
_ml_scan_bytes = None
_ml_import_err = None

def _get_ml_scanner():
    global _ml_scan_bytes, _ml_import_err
    if _ml_scan_bytes is not None:
        return _ml_scan_bytes
    if _ml_import_err is not None:
        return None
    if not os.path.exists(ML_PROJECT_ROOT):
        _ml_import_err = f"ML project not found: {ML_PROJECT_ROOT}"
        print(f"[ML] WARN: {_ml_import_err}")
        print(f"[ML] Override: set SILENTEYE_ML_ROOT=<path>")
        return None
    if ML_PROJECT_ROOT not in sys.path:
        sys.path.insert(0, ML_PROJECT_ROOT)
    try:
        from scanner import scan_bytes
        _ml_scan_bytes = scan_bytes
        print(f"[ML] Scanner loaded from {ML_PROJECT_ROOT}")
        return _ml_scan_bytes
    except ImportError as e:
        _ml_import_err = str(e)
        print(f"[ML] WARN: Import failed: {e}")
        return None


# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC — run_ml_scan()
# ═════════════════════════════════════════════════════════════════════════════

def run_ml_scan(file_path: str, file_bytes: Optional[bytes] = None) -> Dict:
    """
    Run Stage 2B ML scan. Returns normalised result dict. Never raises.
    """
    ext    = os.path.splitext(file_path)[1].lower()
    ml_cat = _EXT_TO_ML_CAT.get(ext)

    if ml_cat is None:
        return _skip_result(f"No ML model for {ext}")

    scan_fn = _get_ml_scanner()
    if scan_fn is None:
        return _error_result(_ml_import_err or "ML scanner unavailable")

    if file_bytes is None:
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            return _error_result(f"File read failed: {e}")

    try:
        raw = scan_fn(file_bytes, ext)
    except Exception as e:
        return _error_result(f"ML scan exception: {e}")

    ml_layers  = raw.get("ml_layers") or raw.get("layers") or []
    hard_fired = any(
        l.get("detected") and l.get("layer") in ML_HARD_LAYERS
        for l in ml_layers
    )

    return {
        "detected":    raw.get("detected", False),
        "verdict":     raw.get("verdict", "clean"),
        "score":       raw.get("score", 0),
        "probability": raw.get("probability", 0.0),
        "severity":    raw.get("severity", "none"),
        "category":    raw.get("category", ml_cat),
        "ml_layers":   ml_layers,
        "reason":      raw.get("reason", ""),
        "fallback":    raw.get("fallback", False),
        "hard_fired":  hard_fired,
        "skipped":     False,
        "error":       False,
    }


# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC — combine_verdicts()
# ═════════════════════════════════════════════════════════════════════════════

def combine_verdicts(
    s1:       Dict,
    s2:       Dict,
    ml:       Optional[Dict],
    category: str,
) -> Dict:
    """
    Decision engine.

    pdf / audio / doc  -> heuristic only, identical to old main.py behaviour.

    image / video / svg:
      CASE A — heuristic zero detections:
        ML result taken as-is. Score and verdict directly from ML.
        This covers DCT stego, J-UNIWARD, alpha stego — things heuristic
        layers cannot see. No combination, no modification.

      CASE B — heuristic has detections:
        Decision table applied. ML weighting:
          prob >= 0.75 or hard layer -> ML authoritative, score = ml_score
          prob 0.45-0.74             -> combined_score = max(h, ml)
          prob < 0.45                -> h_score only
    """

    s1_threat = [f for f in s1.get("flags", []) if f in THREAT_FLAGS]
    h_verdict = s2.get("verdict", "clean")
    h_score   = s2.get("final_score", 0)

    # ── pdf / audio / doc — heuristic only ───────────────────────────────────
    if category not in ML_CATEGORIES:
        v, s, note = _heuristic_only(h_verdict, h_score, s1_threat, s2)
        return _result(v, s, note, s1, s2, None, False)

    # ── ML unavailable / error — degrade to heuristic only ───────────────────
    if ml is None or ml.get("skipped") or ml.get("error"):
        reason = f" [{ml.get('reason','')[:50]}]" if ml and ml.get("error") else ""
        v, s, note = _heuristic_only(h_verdict, h_score, s1_threat, s2)
        return _result(v, s, f"{note} [ML unavailable{reason}]", s1, s2, ml, False)

    ml_verdict  = ml.get("verdict", "clean")
    ml_score    = ml.get("score", 0)
    ml_prob     = ml.get("probability", 0.0)
    ml_hard     = ml.get("hard_fired", False)
    ml_detected = ml.get("detected", False)

    # ── CASE A: heuristic zero detections — ML result is final as-is ─────────
    h_detections = s2.get("detections") or []
    if len(h_detections) == 0:
        # Heuristic found nothing. ML is the only signal.
        # Map ML verdict directly to final verdict.
        if ml_verdict == "malicious":
            final_v = "malicious"
        elif ml_verdict == "suspicious":
            final_v = "suspicious"
        else:
            final_v = "clean"

        # Stage 1 threat flags still apply on top
        if s1_threat and final_v == "suspicious":
            final_v = "malicious"
            note = (f"Heuristic=0 detections | ML={ml_verdict}(p={ml_prob:.2f}) "
                    f"+ Stage1 flags {s1_threat} -> malicious")
        elif s1_threat and final_v == "clean":
            final_v = "suspicious"
            note = (f"Heuristic=0 detections | ML=clean "
                    f"+ Stage1 flags {s1_threat} -> suspicious")
        else:
            note = (f"Heuristic=0 detections — ML result final as-is: "
                    f"{ml_verdict}(p={ml_prob:.2f}, hard={ml_hard})")

        return _result(final_v, ml_score, note, s1, s2, ml, True)

    # ── CASE B: heuristic has detections — apply decision table ──────────────

    # Compute effective score
    high_conf   = ml_prob >= ML_HIGH_CONF_PROB or ml_hard
    medium_conf = (not high_conf and
                   ml_prob >= ML_MEDIUM_CONF_PROB and
                   ml_detected)

    if high_conf and ml_detected:
        eff_score = ml_score                    # ML authoritative
    elif medium_conf:
        eff_score = max(h_score, ml_score)      # take higher, no inflation
    else:
        eff_score = h_score                     # ML didn't fire, heuristic only

    # Decision table
    if h_verdict == "malicious":
        final_v = "malicious"
        final_s = h_score
        note    = (f"Heuristic=malicious | "
                   f"ML={ml_verdict}(p={ml_prob:.2f})")

    elif ml_verdict == "malicious" or (high_conf and ml_detected):
        final_v = "malicious"
        final_s = eff_score
        note    = (f"ML=malicious high-confidence "
                   f"(p={ml_prob:.2f}, hard={ml_hard}) | "
                   f"Heuristic={h_verdict}")

    elif h_verdict == "suspicious" and ml_verdict == "suspicious":
        final_v = "malicious"
        final_s = eff_score
        note    = (f"Both suspicious -> escalated malicious | "
                   f"H={h_score} ML={ml_score}(p={ml_prob:.2f})")

    elif h_verdict == "suspicious":
        final_v = "suspicious"
        final_s = h_score
        note    = (f"Heuristic=suspicious | ML=clean(p={ml_prob:.2f})")

    elif ml_verdict == "suspicious":
        final_v = "suspicious"
        final_s = eff_score
        note    = (f"ML=suspicious(p={ml_prob:.2f}) | Heuristic=clean")

    else:
        final_v = "clean"
        final_s = max(eff_score, 0)
        note    = (f"Both clean | H={h_score} ML={ml_score}(p={ml_prob:.2f})")

    # Stage 1 threat flag escalation — always last
    if s1_threat and final_v == "suspicious":
        final_v = "malicious"
        note    = f"Stage1 {s1_threat} + suspicious -> malicious | {note}"

    return _result(final_v, final_s, note, s1, s2, ml, True)


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _heuristic_only(h_verdict, h_score, s1_threat, s2):
    """Exact replica of old main.py verdict logic. Zero regression."""
    if h_verdict == "malicious":
        return "malicious", h_score, s2.get("summary", "")
    if s1_threat and h_verdict == "suspicious":
        return "malicious", h_score, f"Stage1 {s1_threat} + heuristic suspicious"
    if h_verdict == "suspicious":
        return "suspicious", h_score, s2.get("summary", "")
    if s1_threat:
        return "suspicious", 25, f"Stage1 threat flags: {s1_threat}"
    return "clean", max(h_score, 0), "File passed all checks"


def _result(verdict, score, summary, s1, s2, ml, ml_applied):
    return {
        "final_verdict": verdict,
        "final_score":   score,
        "summary":       summary,
        "stage1":        s1,
        "stage2":        s2,
        "stage2b_ml":    ml,
        "ml_applied":    ml_applied,
    }


def _skip_result(reason):
    return {
        "detected": False, "verdict": "skip", "score": 0,
        "probability": 0.0, "severity": "none", "category": "unknown",
        "ml_layers": [], "reason": reason, "fallback": False,
        "hard_fired": False, "skipped": True, "error": False,
    }


def _error_result(reason):
    return {
        "detected": False, "verdict": "error", "score": 0,
        "probability": 0.0, "severity": "none", "category": "unknown",
        "ml_layers": [], "reason": reason, "fallback": False,
        "hard_fired": False, "skipped": False, "error": True,
    }


# ═════════════════════════════════════════════════════════════════════════════
# STATUS CHECK
# ═════════════════════════════════════════════════════════════════════════════

def ml_status() -> Dict:
    if not os.path.exists(ML_PROJECT_ROOT):
        return {
            "available": False,
            "reason":    f"ML project not found: {ML_PROJECT_ROOT}",
            "models":    {},
        }
    try:
        if ML_PROJECT_ROOT not in sys.path:
            sys.path.insert(0, ML_PROJECT_ROOT)
        from model.predictor import models_ready
        ready = models_ready()
        return {
            "available": any(ready.values()),
            "reason":    "OK" if any(ready.values()) else "No trained models found",
            "models":    ready,
        }
    except Exception as e:
        return {"available": False, "reason": str(e), "models": {}}
