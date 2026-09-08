"""
SilentEye ML — Predictor  
=======================================
"""

import os
import sys
import numpy as np
from typing import Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config

_cache: Dict[str, object] = {}


def _model_key(category: str, ext: str, features: np.ndarray) -> str:
    
    if category != "image":
        return category

    ext = ext.lower()

    if ext in config.JPEG_EXTS:
        return "image_jpg"

    if ext in config.PNG_EXTS:
        # Route by actual alpha channel presence in the file
        has_alpha = (features is not None and
                     len(features) > 10 and
                     features[10] > 0)
        return "image_png_alpha" if has_alpha else "image_png_alpha"

    return "image_png_alpha"


def load(model_key: str):
    """Load model + mask from disk into cache."""
    if model_key in _cache:
        return _cache[model_key]

    path = config.MODEL_PATHS.get(model_key)
    if not path or not os.path.exists(path):
        return None

    try:
        import joblib
        saved = joblib.load(path)
        # Handle both old format (bare model) and new format (dict with mask)
        if isinstance(saved, dict) and "model" in saved:
            _cache[model_key] = saved
        else:
            _cache[model_key] = {"model": saved, "feature_mask": None}
        return _cache[model_key]
    except Exception:
        return None


def models_ready() -> Dict[str, bool]:
    return {cat: os.path.exists(path)
            for cat, path in config.MODEL_PATHS.items()}


def predict(features: np.ndarray, category: str, ext: str = "") -> Dict:
    """
    Run prediction. Returns full result dict.
    BUG 20 FIX: returns "uncertain" result on extraction failure
    instead of silently returning clean.
    """
    model_key = _model_key(category, ext, features)
    saved     = load(model_key)

    if saved is None:
        return _rule_fallback(features, category, ext)

    try:
        clf  = saved["model"]
        mask = saved.get("feature_mask", None)

        # BUG 14 FIX: validate mask against actual feature count
        if mask is not None:
            max_idx = max(mask)
            if max_idx >= len(features):
                # Mask references features that don't exist
                # Fall back to using all available features
                mask = None

        x    = features[mask] if mask is not None else features
        prob = float(clf.predict_proba(x.reshape(1, -1))[0][1])

        # BUG 19 FIX: JPEG threshold raised — internet JPEGs (camera quality)
        # often have low QT std similar to steghide output.
        # Using model_key-specific threshold from config.
        thresh_key = model_key if model_key in config.THRESHOLDS else category
        thresh     = config.THRESHOLDS.get(thresh_key, {"malicious": 0.50})

        # BUG 19 FIX: extra guard for JPEG false positives
        # If QT std is low but image looks like high-quality camera photo
        # (high pixel entropy + normal correlation), reduce probability
        if model_key == "image_jpg" and prob > thresh["malicious"]:
            qt_std   = features[15] if len(features) > 15 else 1.0
            entropy  = features[9]  if len(features) > 9  else 0.0
            corr_rg  = features[22] if len(features) > 22 else 0.0
            # High quality camera photos: low QT BUT also high entropy
            # and high inter-channel correlation
            # Steghide: low QT AND slightly lower entropy/correlation
            if (qt_std < 0.08 and entropy > 0.93 and corr_rg > 0.85):
                # Looks like high-quality camera photo not steghide
                prob = prob * 0.60  # reduce probability

        detected   = prob >= thresh["malicious"]
        confidence = "high"   if prob > 0.75 else "medium" if detected else "low"
        severity   = "high"   if prob > 0.75 else "medium" if detected else "none"
        score      = int(prob * 80) if detected else 0
        top        = _top_features(clf, mask, features, category)

        return {
            "detected":     detected,
            "probability":  round(prob, 4),
            "confidence":   confidence,
            "severity":     severity,
            "score":        score,
            "reason":       _build_reason(prob, top, thresh_key),
            "top_features": top,
            "fallback":     False,
            "model_used":   model_key,
        }

    except Exception as e:
        # BUG 20 FIX: don't silently return clean — return uncertain
        return _uncertain_result(category, str(e))


def _top_features(clf, mask, features, category) -> List[Tuple]:
    try:
        if not hasattr(clf, "feature_importances_"):
            return []
        from features.image_features import FEATURE_NAMES as I
        from features.video_features import FEATURE_NAMES as V
        from features.svg_features   import FEATURE_NAMES as S
        all_names = {"image": I, "video": V, "svg": S}.get(category, I)

        imp = clf.feature_importances_
        top = np.argsort(imp)[::-1][:3]
        result = []
        for i in top:
            orig_i = mask[i] if mask is not None else i
            name   = (all_names[orig_i]
                      if orig_i < len(all_names) else f"feat_{orig_i}")
            result.append((name, float(features[orig_i]), float(imp[i])))
        return result
    except Exception:
        return []


def _build_reason(prob: float, top: List[Tuple], model_key: str) -> str:
    thresh = config.THRESHOLDS.get(model_key, {"malicious": 0.50})["malicious"]
    if prob < thresh:
        return f"ML ({model_key}): Clean (p={prob:.3f})"

    readable = {
        "lsb_chi_combined":       f"LSB chi={top[0][1]:.1f}" if top else "",
        "rs_ratio":               f"RS ratio={top[0][1]:.3f}" if top else "",
        "alpha_midrange_ratio":   f"Alpha mid={top[0][1]:.1%}" if top else "",
        "dct_qt_std":             f"QT std={top[0][1]:.3f}" if top else "",
        "danger_pattern_density": f"Danger patterns={top[0][1]:.1%}" if top else "",
        "pe_in_b64":              "PE payload in base64",
        "xxe_present":            "XXE injection",
        "exe_in_header":          "Executable in header",
        "overlay_size_norm":      "Video overlay detected",
    }
    parts = [f"ML/{model_key} (p={prob:.3f})"]
    for name, val, _ in top[:2]:
        parts.append(readable.get(name, f"{name}={val:.3f}"))
    return " | ".join(parts)


def _uncertain_result(category: str, reason: str = "") -> Dict:
    """
    BUG 20 FIX: returned when model prediction fails.
    Returns uncertain/unknown instead of silently clean.
    """
    return {
        "detected":     False,
        "probability":  0.0,
        "confidence":   "low",
        "severity":     "none",
        "score":        0,
        "reason":       f"Prediction error ({reason[:60]})" if reason else "Prediction failed",
        "top_features": [],
        "fallback":     True,
        "model_used":   "error",
        "uncertain":    True,
    }


def _rule_fallback(features: np.ndarray, category: str,
                   ext: str = "") -> Dict:
    """Rule-based fallback when model not trained yet."""
    score = 0.0
    try:
        ext = ext.lower()
        if category == "image":
            if ext in config.JPEG_EXTS:
                qt_std  = features[15]
                qt_mean = features[16]
                qt_sum  = features[19]
                entropy = features[9]
                corr_rg = features[22]
                # BUG 19: only flag if QT low AND entropy/corr not camera-like
                if qt_std < 0.06 and qt_mean < 0.025:
                    if not (entropy > 0.93 and corr_rg > 0.85):
                        score += 0.50
                if qt_sum < 0.09:
                    score += 0.20
            else:
                if features[10] > 0:
                    mid_r = features[14]
                    bin_r = features[13]
                    if mid_r > 0.25 and bin_r < 0.70:
                        score += 0.60
        elif category == "video":
            if features[11] > 0: score += 0.50
            if features[17] > 0: score += 0.50
            if features[18] > 0: score += 0.50
            if features[12] > 0: score += 0.30
        elif category == "svg":
            if features[7]  > 0: score += 0.60
            if features[2]  > 0: score += 0.50
            if features[14] > 0: score += 0.40

    except Exception:
        pass

    score    = min(score, 1.0)
    thresh   = config.THRESHOLDS.get(category, {"malicious": 0.50})["malicious"]
    detected = score >= thresh
    severity = "high" if score > 0.75 else "medium" if detected else "none"

    return {
        "detected":     detected,
        "probability":  round(score, 4),
        "confidence":   "medium" if detected else "low",
        "severity":     severity,
        "score":        int(score * 75) if detected else 0,
        "reason":       f"Rule-based (model not trained): p={score:.3f}",
        "top_features": [],
        "fallback":     True,
        "model_used":   "rule_fallback",
    }
