"""
SilentEye ML — SVG Feature Extractor
======================================
Extracts 20 features from SVG/SVGZ content.

Features:
  [0-4]   Script/JS danger pattern density
  [5-9]   Encoding anomalies (base64, obfuscation)
  [10-14] Structural complexity
  [15-19] External resource indicators
"""

import re
import gzip
import base64
import math
from collections import Counter
from typing import Optional

import numpy as np


# ── FEATURE NAMES ─────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "danger_pattern_density",   # [0]
    "js_exec_density",          # [1]
    "xxe_present",              # [2]
    "event_handler_density",    # [3]
    "data_html_uri",            # [4]
    "b64_blob_count",           # [5]
    "b64_size_ratio",           # [6]
    "pe_in_b64",                # [7]
    "obfuscation_escapes",      # [8]
    "content_entropy",          # [9]
    "element_count_norm",       # [10]
    "nesting_imbalance",        # [11]
    "attr_density",             # [12]
    "script_content_ratio",     # [13]
    "short_with_script",        # [14]
    "external_url_count",       # [15]
    "susp_tld_count",           # [16]
    "c2_url_count",             # [17]
    "raw_ip_url_count",         # [18]
    "non_font_data_uri",        # [19]
]

N_FEATURES = 20

DANGER_PATTERNS = [
    b"<script", b"javascript:", b"onload=", b"onerror=",
    b"onclick=", b"onmouseover=", b"onfocus=", b"<foreignobject",
    b"<iframe", b"ev:event", b"xlink:actuate",
]
JS_EXEC_PATTERNS = [b"eval(", b"document.write", b"unescape(", b"fromcharcode"]
SUSP_TLDS        = [".onion", ".xyz", ".ru", ".top"]
C2_DOMAINS       = ["ngrok.io", "pastebin.com", "duckdns.org", "bit.ly"]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq  = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


# ── MAIN EXTRACTOR ────────────────────────────────────────────────────────────

def extract(file_bytes: bytes, ext: str) -> Optional[np.ndarray]:
    """
    Main entry point.
    Returns numpy array of shape (20,) or None if extraction fails.
    """
    try:
        feat = np.zeros(N_FEATURES, dtype=np.float64)

        # Decompress SVGZ
        if ext == ".svgz":
            try:
                content = gzip.decompress(file_bytes)
            except Exception:
                content = file_bytes
        else:
            content = file_bytes

        size = len(content)
        if size < 5:
            return None

        low  = content.lower()
        text = content.decode("latin-1", errors="ignore")
        tlow = text.lower()

        # ── [0-4] SCRIPT / JS PATTERNS ───────────────────────────────────
        hit_count = sum(1 for p in DANGER_PATTERNS if p in low)
        feat[0]   = min(hit_count / len(DANGER_PATTERNS), 1.0)

        js_exec   = sum(1 for p in JS_EXEC_PATTERNS if p in low)
        feat[1]   = min(js_exec / 4.0, 1.0)

        feat[2] = 1.0 if (b"<!entity" in low and (b"system" in low or b"public" in low)) else 0.0

        event_count = len(re.findall(r'\bon\w+\s*=', text, re.IGNORECASE))
        feat[3]     = min(event_count / 10.0, 1.0)

        feat[4] = 1.0 if b"data:text/html" in low else 0.0

        # ── [5-9] ENCODING ANOMALIES ──────────────────────────────────────
        b64_matches = re.findall(r'base64,([A-Za-z0-9+/]{100,}={0,2})', text)
        total_b64   = sum(len(m) for m in b64_matches)

        feat[5] = min(len(b64_matches) / 5.0, 1.0)
        feat[6] = min(total_b64 / (size + 1), 1.0)

        pe_found = 0
        for m in b64_matches[:5]:
            try:
                decoded = base64.b64decode(m + "==")
                if decoded[:2] == b"\x4D\x5A" or decoded[:4] == b"\x7fELF":
                    pe_found = 1
                    break
            except Exception:
                pass
        feat[7] = float(pe_found)

        unicode_esc = len(re.findall(r'\\u[0-9a-fA-F]{4}', text))
        hex_esc     = len(re.findall(r'&#x[0-9a-fA-F]+;', text))
        feat[8]     = min((unicode_esc + hex_esc) / 20.0, 1.0)

        feat[9] = _entropy(content) / 8.0

        # ── [10-14] STRUCTURAL COMPLEXITY ─────────────────────────────────
        element_count = max(len(re.findall(r'<[a-zA-Z]', text)), 1)
        feat[10] = min(element_count / 100.0, 1.0)

        open_t  = len(re.findall(r'<[a-zA-Z][^/]', text))
        close_t = len(re.findall(r'</[a-zA-Z]', text))
        feat[11] = float(np.clip(abs(open_t - close_t) / (open_t + 1), 0, 1))

        attr_count = len(re.findall(r'\s+\w[\w:-]*\s*=', text))
        feat[12]   = min(attr_count / (element_count * 10.0), 1.0)

        script_bytes = sum(len(m) for m in re.findall(
            r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE))
        feat[13] = min(script_bytes / (size + 1), 1.0)

        feat[14] = 1.0 if (size < 2048 and hit_count > 0) else 0.0

        # ── [15-19] EXTERNAL RESOURCES ────────────────────────────────────
        ext_urls  = re.findall(
            r'(?:href|src|xlink:href)\s*=\s*["\']?(https?://[^\s"\'<>]{8,})',
            text, re.IGNORECASE)
        susp_tlds = [u for u in ext_urls if any(u.lower().endswith(t) for t in SUSP_TLDS)]
        c2_urls   = [u for u in ext_urls if any(d in u.lower() for d in C2_DOMAINS)]

        feat[15] = min(len(ext_urls) / 10.0, 1.0)
        feat[16] = min(len(susp_tlds) / 3.0, 1.0)
        feat[17] = min(len(c2_urls) / 3.0, 1.0)

        ip_urls  = re.findall(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
        feat[18] = min(len(ip_urls) / 3.0, 1.0)

        app_data  = re.findall(r'data:application/([^;,"\' ]{1,50})', text, re.IGNORECASE)
        non_font  = [a for a in app_data if not any(f in a.lower() for f in ["font","woff","otf","ttf"])]
        feat[19]  = min(len(non_font) / 3.0, 1.0)

        return feat

    except Exception:
        return None
