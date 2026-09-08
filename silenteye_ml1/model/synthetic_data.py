"""
SilentEye ML — Synthetic Data Generator  
======================================================
"""

import numpy as np
from typing import Tuple


def _image_clean(n: int, rng: np.random.Generator) -> np.ndarray:
    X = np.zeros((n, 30))   # FIX: was 25

    # [0-4] LSB
    X[:, 0]  = rng.normal(800, 300, n).clip(50, 5000)
    X[:, 1]  = rng.normal(0.48, 0.04, n).clip(0.35, 0.65)
    X[:, 2]  = rng.normal(750, 280, n).clip(50, 5000)
    X[:, 3]  = rng.exponential(0.005, n).clip(0, 0.05)
    X[:, 4]  = rng.exponential(0.005, n).clip(0, 0.05)
    # [5-9] pixel stats
    X[:, 5]  = rng.normal(0.45, 0.15, n).clip(0.1, 0.9)
    X[:, 6]  = rng.normal(0.60, 0.15, n).clip(0.1, 1.0)
    X[:, 7]  = rng.normal(0.0,  0.5,  n).clip(-2, 2)
    X[:, 8]  = rng.normal(0.0,  1.0,  n).clip(-3, 3)
    X[:, 9]  = rng.normal(0.87, 0.05, n).clip(0.6, 0.99)
    # [10-14] alpha — most clean images no alpha
    has_alpha = rng.random(n) < 0.15
    X[:, 10] = has_alpha.astype(float)
    X[:, 11] = np.where(has_alpha, rng.uniform(0.8, 1.0, n), 0)
    X[:, 12] = np.where(has_alpha, rng.uniform(0.0, 0.1, n), 0)
    X[:, 13] = np.where(has_alpha, rng.uniform(0.85, 1.0, n), 0)
    X[:, 14] = np.where(has_alpha, rng.uniform(0.0, 0.10, n), 0)
    # [15-19] DCT QT (JPEG only)
    is_jpeg = rng.random(n) < 0.4
    X[:, 15] = np.where(is_jpeg, rng.normal(0.25, 0.08, n).clip(0.08, 0.6), 0)
    X[:, 16] = np.where(is_jpeg, rng.normal(0.30, 0.10, n).clip(0.08, 0.8), 0)
    X[:, 17] = np.where(is_jpeg, rng.normal(1.5,  0.5,  n).clip(0.5, 4.0), 0)
    X[:, 18] = np.where(is_jpeg, rng.normal(0.22, 0.07, n).clip(0.03, 0.5), 0)
    X[:, 19] = np.where(is_jpeg, rng.normal(0.55, 0.10, n).clip(0.15, 0.9), 0)
    # [20-21] RS
    X[:, 20] = rng.normal(0.08, 0.04, n).clip(-0.02, 0.3)
    X[:, 21] = rng.normal(0.03, 0.02, n).clip(0, 0.1)
    # [22-23] inter-channel corr
    X[:, 22] = rng.normal(0.92, 0.05, n).clip(0.6, 1.0)
    X[:, 23] = rng.normal(0.90, 0.05, n).clip(0.6, 1.0)
    # [24] block uniformity
    X[:, 24] = rng.normal(1.2, 0.4, n).clip(0.1, 4.0)
    # [25-29] DCT coefficient features (JUNIWARD) — clean baseline
    X[:, 25] = np.where(is_jpeg, rng.normal(0.18, 0.05, n).clip(0.05, 0.35), 0)  # pm1 ratio
    X[:, 26] = np.where(is_jpeg, rng.normal(0.55, 0.08, n).clip(0.30, 0.80), 0)  # zero ratio
    X[:, 27] = np.where(is_jpeg, rng.normal(0.72, 0.05, n).clip(0.50, 0.90), 0)  # entropy
    X[:, 28] = np.where(is_jpeg, rng.normal(0.0,  0.05, n).clip(-0.2, 0.2),  0)  # skewness
    X[:, 29] = np.where(is_jpeg, rng.normal(0.12, 0.04, n).clip(0.03, 0.30), 0)  # large ratio

    return X


def _image_malicious(n: int, rng: np.random.Generator) -> np.ndarray:
    X = _image_clean(n, rng)

    lsb_stego   = rng.random(n) < 0.50
    alpha_stego = rng.random(n) < 0.25
    dct_stego   = rng.random(n) < 0.25

    # LSB stego
    X[lsb_stego, 0]  = rng.normal(3.0, 2.0, lsb_stego.sum()).clip(0, 15)
    X[lsb_stego, 1]  = rng.normal(0.500, 0.003, lsb_stego.sum()).clip(0.49, 0.51)
    X[lsb_stego, 2]  = rng.normal(3.0, 2.0, lsb_stego.sum()).clip(0, 15)
    X[lsb_stego, 20] = rng.normal(-0.12, 0.05, lsb_stego.sum()).clip(-0.5, -0.02)
    X[lsb_stego, 21] = rng.normal(0.25, 0.10, lsb_stego.sum()).clip(0.05, 0.6)
    X[lsb_stego, 9]  = rng.normal(0.998, 0.001, lsb_stego.sum()).clip(0.993, 1.0)
    X[lsb_stego, 22] = rng.normal(0.60, 0.08, lsb_stego.sum()).clip(0.3, 0.75)
    X[lsb_stego, 23] = rng.normal(0.58, 0.08, lsb_stego.sum()).clip(0.3, 0.75)

    # Alpha stego
    X[alpha_stego, 10] = 1.0
    X[alpha_stego, 13] = rng.normal(0.40, 0.10, alpha_stego.sum()).clip(0.1, 0.7)
    X[alpha_stego, 14] = rng.normal(0.50, 0.10, alpha_stego.sum()).clip(0.2, 0.8)

    # DCT steghide stego — very low QT
    X[dct_stego, 15] = rng.normal(0.04, 0.01, dct_stego.sum()).clip(0.01, 0.07)
    X[dct_stego, 16] = rng.normal(0.02, 0.01, dct_stego.sum()).clip(0.005, 0.04)
    X[dct_stego, 19] = rng.normal(0.06, 0.02, dct_stego.sum()).clip(0.01, 0.10)
    # JUNIWARD DCT coefficient changes
    X[dct_stego, 25] = rng.normal(0.24, 0.05, dct_stego.sum()).clip(0.12, 0.40)  # pm1 UP
    X[dct_stego, 26] = rng.normal(0.45, 0.07, dct_stego.sum()).clip(0.25, 0.65)  # zero DOWN
    X[dct_stego, 27] = rng.normal(0.76, 0.04, dct_stego.sum()).clip(0.60, 0.90)  # entropy UP
    X[dct_stego, 28] = rng.normal(0.08, 0.06, dct_stego.sum()).clip(-0.1, 0.3)   # slight skew
    X[dct_stego, 29] = rng.normal(0.09, 0.03, dct_stego.sum()).clip(0.02, 0.20)  # large DOWN

    return X


def _video_clean(n: int, rng: np.random.Generator) -> np.ndarray:
    X = np.zeros((n, 20))
    X[:, 0]  = rng.normal(0.7, 0.15, n).clip(0.1, 1.0)
    X[:, 1]  = rng.normal(0.0, 0.02, n).clip(0, 0.1)
    X[:, 2]  = np.zeros(n)
    X[:, 3]  = rng.normal(0.8, 0.3,  n).clip(0.1, 3.0)
    X[:, 4]  = rng.choice([0.0, 1.0], n, p=[0.05, 0.95])
    X[:, 5]  = rng.normal(0.85, 0.05, n).clip(0.6, 0.99)
    X[:, 6]  = rng.normal(0.05, 0.02, n).clip(0, 0.15)
    X[:, 7]  = rng.normal(0.90, 0.04, n).clip(0.7, 1.0)
    X[:, 8]  = rng.normal(0.75, 0.06, n).clip(0.5, 0.95)
    X[:, 9]  = rng.normal(0.05, 0.03, n).clip(0, 0.15)
    X[:, 10] = np.zeros(n)
    X[:, 11] = np.zeros(n)
    X[:, 12] = np.zeros(n)
    X[:, 13] = np.zeros(n)
    X[:, 14] = rng.normal(0.05, 0.03, n).clip(0, 0.2)
    X[:, 15] = np.zeros(n)
    X[:, 16] = rng.normal(0.82, 0.05, n).clip(0.6, 0.98)
    X[:, 17] = np.zeros(n)
    X[:, 18] = np.zeros(n)
    X[:, 19] = np.zeros(n)
    return X


def _video_malicious(n: int, rng: np.random.Generator) -> np.ndarray:
    X = _video_clean(n, rng)
    exe_inject = rng.random(n) < 0.50
    overlay    = rng.random(n) < 0.35
    c2_embed   = rng.random(n) < 0.25
    polyglot   = rng.random(n) < 0.20

    X[exe_inject, 11] = 1.0
    X[exe_inject, 17] = (rng.random(exe_inject.sum()) < 0.6).astype(float)
    X[exe_inject, 18] = (rng.random(exe_inject.sum()) < 0.4).astype(float)
    X[exe_inject, 1]  = rng.normal(0.3, 0.2, exe_inject.sum()).clip(0, 1)

    X[overlay, 15] = rng.normal(0.3, 0.2, overlay.sum()).clip(0.05, 1.0)
    X[overlay, 16] = rng.normal(0.95, 0.02, overlay.sum()).clip(0.88, 1.0)
    X[overlay, 9]  = rng.normal(0.4, 0.1, overlay.sum()).clip(0.2, 1.0)

    X[c2_embed, 12] = 1.0
    X[c2_embed, 10] = rng.normal(0.4, 0.2, c2_embed.sum()).clip(0, 1.0)

    X[polyglot, 19] = 1.0
    return X


def _svg_clean(n: int, rng: np.random.Generator) -> np.ndarray:
    X = np.zeros((n, 20))
    X[:, 0]  = rng.normal(0.05, 0.03, n).clip(0, 0.2)
    X[:, 1]  = np.zeros(n)
    X[:, 2]  = np.zeros(n)
    X[:, 3]  = rng.normal(0.05, 0.03, n).clip(0, 0.15)
    X[:, 4]  = np.zeros(n)
    X[:, 5]  = np.zeros(n)
    X[:, 6]  = rng.normal(0.02, 0.01, n).clip(0, 0.1)
    X[:, 7]  = np.zeros(n)
    X[:, 8]  = rng.normal(0.02, 0.01, n).clip(0, 0.1)
    X[:, 9]  = rng.normal(0.55, 0.08, n).clip(0.3, 0.8)
    X[:, 10] = rng.normal(0.15, 0.08, n).clip(0.01, 0.5)
    X[:, 11] = rng.normal(0.02, 0.01, n).clip(0, 0.1)
    X[:, 12] = rng.normal(0.10, 0.05, n).clip(0, 0.4)
    X[:, 13] = np.zeros(n)
    X[:, 14] = np.zeros(n)
    X[:, 15] = rng.normal(0.03, 0.02, n).clip(0, 0.15)
    X[:, 16] = np.zeros(n)
    X[:, 17] = np.zeros(n)
    X[:, 18] = np.zeros(n)
    X[:, 19] = np.zeros(n)
    return X


def _svg_malicious(n: int, rng: np.random.Generator) -> np.ndarray:
    X = _svg_clean(n, rng)
    js_attack  = rng.random(n) < 0.55
    xxe_attack = rng.random(n) < 0.25
    pe_payload = rng.random(n) < 0.20
    c2_beacon  = rng.random(n) < 0.30

    X[js_attack, 0]  = rng.normal(0.60, 0.20, js_attack.sum()).clip(0.2, 1.0)
    X[js_attack, 1]  = rng.normal(0.50, 0.20, js_attack.sum()).clip(0.1, 1.0)
    X[js_attack, 3]  = rng.normal(0.40, 0.15, js_attack.sum()).clip(0.1, 1.0)
    X[js_attack, 8]  = rng.normal(0.35, 0.15, js_attack.sum()).clip(0.1, 1.0)
    X[js_attack, 9]  = rng.normal(0.75, 0.08, js_attack.sum()).clip(0.5, 1.0)
    X[js_attack, 13] = rng.normal(0.30, 0.15, js_attack.sum()).clip(0.05, 0.8)
    small_s = rng.random(js_attack.sum()) < 0.4
    X[np.where(js_attack)[0][small_s], 14] = 1.0

    X[xxe_attack, 2] = 1.0
    X[xxe_attack, 0] = rng.normal(0.3, 0.1, xxe_attack.sum()).clip(0.1, 0.7)

    X[pe_payload, 7] = 1.0
    X[pe_payload, 5] = rng.normal(0.4, 0.2, pe_payload.sum()).clip(0.1, 1.0)
    X[pe_payload, 6] = rng.normal(0.6, 0.2, pe_payload.sum()).clip(0.2, 1.0)

    X[c2_beacon, 15] = rng.normal(0.4, 0.2, c2_beacon.sum()).clip(0.1, 1.0)
    X[c2_beacon, 17] = rng.normal(0.5, 0.2, c2_beacon.sum()).clip(0.1, 1.0)
    X[c2_beacon, 18] = (rng.random(c2_beacon.sum()) < 0.4).astype(float)

    return X


def generate(category: str, n_clean: int = 400, n_mal: int = 400,
             seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    generators = {
        "image": (_image_clean, _image_malicious),
        "video": (_video_clean, _video_malicious),
        "svg":   (_svg_clean,   _svg_malicious),
    }
    if category not in generators:
        raise ValueError(f"Unknown category: {category}")
    clean_fn, mal_fn = generators[category]
    X_clean = clean_fn(n_clean, rng)
    X_mal   = mal_fn(n_mal,   rng)
    X = np.vstack([X_clean, X_mal])
    y = np.hstack([np.zeros(n_clean, dtype=int), np.ones(n_mal, dtype=int)])
    idx = rng.permutation(len(X))
    return X[idx], y[idx]
