"""
SilentEye ML — Image Feature Extractor  (FINAL v9)
====================================================
Extracts 30 statistical features from image files.
No external stego library required — pure PIL/numpy/scipy.

CHANGES v9:
  - N_FEATURES expanded from 25 to 30
  - feat[25-29]: DCT coefficient histogram features for JUNIWARD detection
  - _compute_dct_coeff_features() added

Feature layout:
  [0-4]   LSB chi-square + channel diff
  [5-9]   Pixel statistics (mean, std, skew, kurt, entropy)
  [10-14] Alpha channel features
  [15-19] DCT QT table features (steghide/F5 detection)
  [20-21] RS analysis
  [22-23] Inter-channel correlation
  [24]    Block uniformity
  [25-29] DCT coefficient histogram (JUNIWARD detection) ← NEW
"""

import math
from collections import Counter
from typing import Optional, Tuple

import numpy as np

import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import IMAGE_MAX_DIM, IMAGE_MIN_PIXELS


# ── CONSTANTS ─────────────────────────────────────────────────────────────────
N_FEATURES     = 30
_LSB_VAR_GATE  = 25.0
_RS_PATCH_SIZE = 128
_RS_N_PATCHES  = 4


# ── FEATURE NAMES ─────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "lsb_chi_combined",        # [0]
    "lsb_ratio_combined",      # [1]
    "lsb_chi_min_channel",     # [2]
    "lsb_channel_diff_rg",     # [3]
    "lsb_channel_diff_gb",     # [4]
    "pixel_mean_norm",         # [5]
    "pixel_std_norm",          # [6]
    "pixel_skewness",          # [7]
    "pixel_kurtosis",          # [8]
    "pixel_entropy_norm",      # [9]
    "alpha_present",           # [10]
    "alpha_mean",              # [11]
    "alpha_std",               # [12]
    "alpha_binary_ratio",      # [13]
    "alpha_midrange_ratio",    # [14]
    "dct_qt_std",              # [15]
    "dct_qt_mean",             # [16]
    "dct_qt_maxmin",           # [17]
    "dct_chroma_diff",         # [18]
    "dct_qt_sum",              # [19]
    "rs_ratio",                # [20]
    "rs_embed_rate",           # [21]
    "interchannel_corr_rg",    # [22]
    "interchannel_corr_gb",    # [23]
    "block_uniformity",        # [24]
    "dct_coeff_pm1_ratio",     # [25] NEW: ±1 DCT coeff ratio (JUNIWARD)
    "dct_coeff_zero_ratio",    # [26] NEW: zero DCT coeff ratio (JUNIWARD)
    "dct_coeff_entropy",       # [27] NEW: coeff histogram entropy (JUNIWARD)
    "dct_coeff_skewness",      # [28] NEW: coeff distribution skewness (JUNIWARD)
    "dct_coeff_large_ratio",   # [29] NEW: |coeff|>5 ratio (JUNIWARD avoids)
]


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _entropy_arr(arr: np.ndarray) -> float:
    flat  = arr.flatten().astype(np.uint8)
    freq  = np.bincount(flat, minlength=256).astype(np.float64)
    freq  = freq[freq > 0]
    freq /= freq.sum()
    return float(-np.sum(freq * np.log2(freq)))


# ── LSB ANALYSIS ──────────────────────────────────────────────────────────────

def _lsb_chi_square(channel: np.ndarray) -> Tuple[float, float]:
    flat = channel.flatten().astype(np.uint8)
    n    = flat.size
    if n < IMAGE_MIN_PIXELS:
        return 0.0, 0.5
    if np.var(flat.astype(np.float32)) < _LSB_VAR_GATE:
        return 999.0, 0.5
    lsbs   = flat & 1
    n0, n1 = int(np.sum(lsbs == 0)), int(np.sum(lsbs == 1))
    exp    = n / 2.0
    chi_sq = ((n0 - exp)**2 + (n1 - exp)**2) / exp
    return float(chi_sq), float(n1 / n)


def _compute_lsb_features(arr: np.ndarray, feat: np.ndarray):
    """Fills feat[0:5]."""
    is_color = arr.ndim == 3 and arr.shape[2] >= 3
    if is_color:
        chi_r, ratio_r = _lsb_chi_square(arr[:, :, 0])
        chi_g, ratio_g = _lsb_chi_square(arr[:, :, 1])
        chi_b, ratio_b = _lsb_chi_square(arr[:, :, 2])
        lsbs_all = arr[:, :, :3].flatten() & 1
        n        = lsbs_all.size
        n1_all   = int(np.sum(lsbs_all))
        n0_all   = n - n1_all
        exp_all  = n / 2.0
        if np.var(arr[:, :, :3].astype(np.float32)) < _LSB_VAR_GATE:
            feat[0] = 999.0; feat[1] = 0.5
        else:
            feat[0] = float(((n0_all-exp_all)**2 + (n1_all-exp_all)**2) / exp_all)
            feat[1] = float(n1_all / n)
        feat[2] = float(min(chi_r, chi_g, chi_b))
        feat[3] = float(abs(ratio_r - ratio_g))
        feat[4] = float(abs(ratio_g - ratio_b))
    else:
        gray = arr.flatten() if arr.ndim == 2 else arr[:, :, 0].flatten()
        chi, ratio = _lsb_chi_square(gray.astype(np.uint8))
        feat[0] = float(chi); feat[1] = float(ratio)
        feat[2] = feat[3] = feat[4] = 0.0


# ── PIXEL STATISTICS ──────────────────────────────────────────────────────────

def _compute_pixel_stats(gray_arr: np.ndarray, feat: np.ndarray):
    """Fills feat[5:10]."""
    flat   = gray_arr.flatten().astype(np.float64)
    mean_v = float(np.mean(flat))
    std_v  = float(np.std(flat))
    skew = kurt = 0.0
    if std_v > 1e-8:
        norm = (flat - mean_v) / std_v
        skew = float(np.mean(norm**3))
        kurt = float(np.mean(norm**4) - 3)
    feat[5] = mean_v / 255.0
    feat[6] = std_v / 128.0
    feat[7] = float(np.clip(skew, -5, 5))
    feat[8] = float(np.clip(kurt, -5, 5))
    feat[9] = _entropy_arr(gray_arr.astype(np.uint8)) / 8.0


# ── ALPHA CHANNEL ─────────────────────────────────────────────────────────────

def _compute_alpha_features(arr: np.ndarray, feat: np.ndarray):
    """Fills feat[10:15]."""
    if arr.ndim == 3 and arr.shape[2] == 4:
        alpha  = arr[:, :, 3].flatten().astype(np.float64)
        feat[10] = 1.0
        feat[11] = float(np.mean(alpha)) / 255.0
        feat[12] = float(np.std(alpha)) / 128.0
        feat[13] = float(np.sum((alpha == 255) | (alpha == 0))) / alpha.size
        feat[14] = float(np.sum((alpha > 0) & (alpha < 255))) / alpha.size
    else:
        feat[10] = feat[11] = feat[12] = feat[13] = feat[14] = 0.0


# ── DCT QT FEATURES (steghide/F5 detection) ───────────────────────────────────

def _compute_dct_features(file_bytes: bytes, feat: np.ndarray):
    """Fills feat[15:20]. Detects steghide high-quality re-encoding."""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(file_bytes))
        qt  = getattr(img, "quantization", None)
        if not qt or 0 not in qt:
            return
        q0       = np.array(list(qt[0]), dtype=np.float64)
        feat[15] = float(np.std(q0) / 64.0)
        feat[16] = float(np.mean(q0) / 255.0)
        feat[17] = float(np.clip(np.max(q0)/(np.min(q0)+1e-8), 1, 50) / 50.0)
        if 1 in qt:
            q1       = np.array(list(qt[1]), dtype=np.float64)
            feat[18] = float(np.mean(np.abs(q0 - q1[:len(q0)])) / 128.0)
        else:
            feat[18] = feat[15]
        feat[19] = float(np.clip(feat[15] + feat[16], 0, 1.0))
    except Exception:
        pass


# ── DCT COEFFICIENT FEATURES (JUNIWARD detection) ────────────────────────────

def _compute_dct_coeff_features(file_bytes: bytes, feat: np.ndarray):
    """
    Fills feat[25:30] with DCT coefficient histogram features.

    JUNIWARD (J-UNIWARD) embedding properties:
    - Embeds in DCT coefficients that minimize wavelet distortion
    - Prefers ±1 coefficient changes in AC coefficients
    - Converts 0-coefficients to ±1 (increases ±1 density)
    - Avoids large coefficient modifications (>5 stays untouched)
    - Changes the histogram shape and symmetry slightly

    Detection approach:
    - Compute 2D DCT on 8x8 pixel blocks (proxy for JPEG DCT coefficients)
    - Quantize using QT table to get realistic discrete coefficient values
    - Analyze resulting coefficient histogram for JUNIWARD fingerprints
    """
    try:
        from PIL import Image
        from scipy.fft import dctn
        import io

        img = Image.open(io.BytesIO(file_bytes))
        qt  = getattr(img, "quantization", None)

        # Get quantization step for luma channel
        q_mean = 8.0  # default fallback
        if qt and 0 in qt:
            q0     = np.array(list(qt[0])[1:], dtype=np.float64)
            q_mean = float(np.mean(q0))

        gray = np.array(img.convert("L"), dtype=np.float64)
        h, w = gray.shape
        if h < 16 or w < 16:
            return

        # Sample 8x8 blocks evenly across image — max 600 blocks
        all_coeffs = []
        step       = max(8, (h * w) // (600 * 64))

        for i in range(0, h - 8, step):
            for j in range(0, w - 8, step):
                block  = gray[i:i+8, j:j+8] - 128.0
                coeffs = dctn(block, norm="ortho").flatten()
                # Skip DC (index 0), use AC only
                ac     = coeffs[1:]
                # Quantize to discrete values
                ac_q   = np.round(ac / q_mean)
                all_coeffs.extend(ac_q.tolist())
                if len(all_coeffs) > 25000:
                    break
            if len(all_coeffs) > 25000:
                break

        if len(all_coeffs) < 200:
            return

        ca = np.array(all_coeffs, dtype=np.float64)
        n  = len(ca)

        # feat[25]: ±1 ratio — JUNIWARD increases this
        # Clean JPEG: ratio depends on quality, typically 0.10-0.25
        # JUNIWARD:   ratio increases by 0.02-0.08 depending on payload size
        feat[25] = float(np.sum((ca == 1.0) | (ca == -1.0)) / n)

        # feat[26]: zero ratio — JUNIWARD decreases this
        # Clean JPEG: typically 0.40-0.70 (high quality = more zeros)
        # JUNIWARD:   decreases as 0→±1 conversions occur
        feat[26] = float(np.sum(ca == 0.0) / n)

        # feat[27]: histogram entropy (normalized)
        # JUNIWARD changes the shape of the coefficient histogram
        bins      = np.arange(-15, 17, 1)
        hist, _   = np.histogram(ca, bins=bins)
        h_norm    = hist.astype(np.float64) + 1e-8
        h_norm   /= h_norm.sum()
        entropy   = float(-np.sum(h_norm * np.log2(h_norm)))
        feat[27]  = entropy / math.log2(len(bins))  # normalize [0,1]

        # feat[28]: skewness of coefficient distribution
        # Clean JPEG: symmetric → skewness near 0
        # JUNIWARD:   slight positive or negative bias from adaptive embedding
        mean_c = float(np.mean(ca))
        std_c  = float(np.std(ca))
        if std_c > 1e-8:
            skew_c  = float(np.mean(((ca - mean_c) / std_c)**3))
            feat[28] = float(np.clip(skew_c, -3, 3)) / 3.0
        else:
            feat[28] = 0.0

        # feat[29]: large coefficient ratio |coeff| > 5
        # JUNIWARD avoids large coefficients (high distortion)
        # This ratio stays similar between clean and stego but helps RF
        feat[29] = float(np.sum(np.abs(ca) > 5.0) / n)

    except Exception:
        pass


# ── RS ANALYSIS ───────────────────────────────────────────────────────────────

def _rs_single_patch(patch: np.ndarray) -> Tuple[float, float]:
    n      = 4
    groups = len(patch) // n
    if groups < 50:
        return 0.0, 0.0

    def flip(a):   return a ^ 1
    def iflip(a):  return np.where(a % 2 == 0, a - 1, a + 1)
    def smooth(g): return int(np.sum(np.abs(np.diff(g))))

    r_m = s_m = r_im = s_im = 0
    for i in range(groups):
        g   = patch[i*n:(i+1)*n].copy()
        gf  = g.copy(); gf[1::2]  = flip(gf[1::2])
        gfi = g.copy(); gfi[1::2] = iflip(gfi[1::2])
        sm0 = smooth(g); smf = smooth(gf); smfi = smooth(gfi)
        if smf  > sm0: r_m  += 1
        elif smf  < sm0: s_m  += 1
        if smfi > sm0: r_im += 1
        elif smfi < sm0: s_im += 1

    R_m  = r_m/groups;  S_m  = s_m/groups
    R_im = r_im/groups; S_im = s_im/groups
    rs_ratio  = (R_m - S_m) - (R_im - S_im)
    denom     = 2*(R_m - R_im) - (S_m - S_im) + 1e-8
    embed_est = abs(R_m - R_im) / abs(denom)
    return float(np.clip(rs_ratio, -1, 1)), float(np.clip(embed_est, 0, 1))


def _compute_rs_analysis(gray: np.ndarray, feat: np.ndarray):
    """Fills feat[20:22]."""
    try:
        if gray.size < 4096:
            return
        h, w   = gray.shape
        ph     = min(h, _RS_PATCH_SIZE)
        pw     = min(w, _RS_PATCH_SIZE)
        if ph * pw < 1024:
            return
        rng    = np.random.default_rng(42)
        ratios = []; embeds = []
        max_r  = max(1, h - ph); max_c = max(1, w - pw)
        for _ in range(_RS_N_PATCHES):
            r0    = int(rng.integers(0, max_r)) if max_r > 0 else 0
            c0    = int(rng.integers(0, max_c)) if max_c > 0 else 0
            patch = gray[r0:r0+ph, c0:c0+pw].flatten().astype(np.int32)
            if np.var(patch) < _LSB_VAR_GATE:
                continue
            rs, em = _rs_single_patch(patch)
            ratios.append(rs); embeds.append(em)
        if not ratios:
            feat[20] = 0.05; feat[21] = 0.0; return
        feat[20] = float(np.clip(np.mean(ratios), -1, 1))
        feat[21] = float(np.clip(np.mean(embeds), 0, 1))
    except Exception:
        pass


# ── INTER-CHANNEL CORRELATION ─────────────────────────────────────────────────

def _safe_corr(a: np.ndarray, b: np.ndarray) -> float:
    if np.std(a) < 1e-8 or np.std(b) < 1e-8:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def _compute_correlation(arr: np.ndarray, feat: np.ndarray):
    """Fills feat[22:24]."""
    if arr.ndim == 3 and arr.shape[2] >= 3:
        r = arr[:, :, 0].flatten().astype(np.float64)
        g = arr[:, :, 1].flatten().astype(np.float64)
        b = arr[:, :, 2].flatten().astype(np.float64)
        n = min(len(r), 5000)
        feat[22] = _safe_corr(r[:n], g[:n])
        feat[23] = _safe_corr(g[:n], b[:n])
    else:
        feat[22] = feat[23] = 0.0


# ── BLOCK UNIFORMITY ──────────────────────────────────────────────────────────

def _compute_block_uniformity(gray: np.ndarray, feat: np.ndarray):
    """Fills feat[24]."""
    try:
        h, w = gray.shape
        if h < 16 or w < 16:
            feat[24] = 0.0; return
        variances = []
        for i in range(0, min(h-8, 256), 8):
            for j in range(0, min(w-8, 256), 8):
                variances.append(float(np.var(gray[i:i+8, j:j+8])))
        if variances:
            feat[24] = float(np.std(variances) / (np.mean(variances) + 1e-8))
    except Exception:
        feat[24] = 0.0


# ── MAIN EXTRACTOR ────────────────────────────────────────────────────────────

def extract(file_bytes: bytes, ext: str) -> Optional[np.ndarray]:
    """
    Returns numpy array of shape (30,) or None if extraction fails.
    """
    try:
        from PIL import Image
        import io

        feat     = np.zeros(N_FEATURES, dtype=np.float64)
        img_orig = Image.open(io.BytesIO(file_bytes))
        img      = img_orig.copy()

        if max(img.size) > IMAGE_MAX_DIM:
            img.thumbnail((IMAGE_MAX_DIM, IMAGE_MAX_DIM), Image.LANCZOS)

        has_alpha = img.mode in ("RGBA", "LA", "PA")
        img  = img.convert("RGBA") if has_alpha else img.convert("RGB")
        arr  = np.array(img, dtype=np.uint8)
        gray = np.array(img.convert("L"), dtype=np.uint8)

        _compute_lsb_features(arr, feat)
        _compute_pixel_stats(gray.astype(np.float64), feat)
        _compute_alpha_features(arr, feat)

        if ext in (".jpg", ".jpeg"):
            _compute_dct_features(file_bytes, feat)        # steghide/F5
            _compute_dct_coeff_features(file_bytes, feat)  # JUNIWARD

        _compute_rs_analysis(gray, feat)
        _compute_correlation(arr, feat)
        _compute_block_uniformity(gray, feat)

        return feat

    except Exception:
        return None
