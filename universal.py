import math
import re
import base64
from collections import Counter
from typing import Dict
from urllib.parse import urlparse

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    ENTROPY_THRESHOLDS, ENTROPY_SKIP_EXTS, ENTROPY_CHUNK_SIZE,
    OVERLAY_ENTROPY_THRESHOLDS, OVERLAY_MIN_SIZE,
    BASE64_MIN_LENGTH, XOR_SAMPLE_BYTES, XOR_CHECK_BYTES,
    SUSPICIOUS_TLDS, INDIAN_BANKS, URL_SHORTENERS,
    LEGITIMATE_UPI_HANDLES, PRIVATE_IP_PREFIXES,
    C2_DOMAINS, C2_URL_PATHS, KNOWN_LEGIT_DOMAINS,
)

# ================================
# ENTROPY CALCULATION
# ================================

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequency = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in frequency.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)

# ================================
# ENTROPY ANALYSIS
# ================================
#
# KEY FIXES:
# 1. Require BOTH body AND tail to exceed threshold — not just one window
# 2. Raised thresholds based on real test data:
#    pdf: 7.85 → 7.97 (FlateDecode hits 7.9928 on clean PDFs)
#    doc: 7.75 → 7.90 (DOCX with images hits 7.9959)
# 3. PNG and TIFF skipped entirely — entropy is meaningless for these
# 4. Minimum file size check added

ENTROPY_THRESHOLDS = {
    "image": 7.98,
    "video": 7.98,
    "audio": 7.98,
    "pdf":   7.998,  # raised 7.97 → 7.998 — test data shows FlateDecode hits 7.9943-7.9949 body, 7.9934-7.9945 tail
    "doc":   7.998,  # raised 7.95 → 7.998 — test data shows DOCX hits 7.9935-7.9961 body, 7.9752-7.9875 tail
    "svg":   6.80,
}

# Formats where entropy analysis is MEANINGLESS — skip entirely.
#
# PNG/TIFF: compressed pixels = always near 8.0
# FLAC/OGG: DEFLATE compressed audio = always near 8.0
# WAV: raw PCM audio samples for music hit 7.95-7.99
# Video: H.264/HEVC/VP9/AV1 codec frames are by design near-random
# DOCX/XLSX/PPTX: ZIP containers — any file with embedded images pushes
#   both windows to 7.99+. Pure XML DOCX stays 5.0-6.5, but with images
#   entropy is unreliable. Threshold 7.998 handles the edge cases.
ENTROPY_SKIP_EXTS = {
    # Image
    ".png", ".tif", ".tiff",
    # Audio — compressed codecs
    ".flac", ".ogg", ".wav", ".aac", ".wma",
    # Video — compressed codec frames
    ".mp4", ".mkv", ".avi", ".mov", ".wmv",
    ".webm", ".flv", ".mpeg", ".3gp", ".m4v",
    # Office — ZIP containers with embedded images always push entropy to 7.99+
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
}

# CHUNK_SIZE moved to config.py as ENTROPY_CHUNK_SIZE

def run_entropy_analysis(file_bytes: bytes, category: str, ext: str = "") -> Dict:

    if ext in ENTROPY_SKIP_EXTS:
        return {
            "layer": "entropy_analysis", "detected": False,
            "severity": "none", "score": 0,
            "reason": f"Entropy skipped for {ext}"
        }

    size = len(file_bytes)
    threshold = ENTROPY_THRESHOLDS.get(category, 7.85)

    if size < ENTROPY_CHUNK_SIZE * 2:
        return {
            "layer": "entropy_analysis", "detected": False,
            "severity": "none", "score": 0,
            "reason": "File too small for entropy analysis"
        }

    mid   = max(0, size // 2 - ENTROPY_CHUNK_SIZE // 2)
    body  = file_bytes[mid: mid + ENTROPY_CHUNK_SIZE]
    tail  = file_bytes[max(0, size - ENTROPY_CHUNK_SIZE):]

    body_e = calculate_entropy(body)
    tail_e = calculate_entropy(tail)

    # BOTH must exceed threshold — single high window is normal in compressed formats
    both_high = body_e > threshold and tail_e > threshold

    if not both_high:
        return {
            "layer": "entropy_analysis", "detected": False,
            "severity": "none", "score": 0,
            "reason": f"Entropy normal (body:{body_e}, tail:{tail_e})"
        }

    severity = "medium"
    score    = 20 if category in ["image", "video", "audio"] else 30

    return {
        "layer": "entropy_analysis", "detected": True,
        "severity": severity, "score": score,
        "reason": f"Both windows anomalous: body={body_e}, tail={tail_e}"
    }

# ================================
# OVERLAY DETECTION
# ================================
#
# KEY FIXES:
# 1. rfind(-1) guard — was creating fake huge overlays
# 2. Requires entropy check on overlay — size alone is not enough
# 3. Per-format entropy thresholds (JPEG needs stricter threshold)
# 4. Added .jpeg to EOF_MARKERS

EOF_MARKERS = {
    ".jpg":  b"\xFF\xD9",
    ".jpeg": b"\xFF\xD9",
    ".png":  b"IEND\xaeB`\x82",
    ".pdf":  b"%%EOF",
}

OVERLAY_ENTROPY_THRESHOLDS = {
    ".jpg":  7.92,
    ".jpeg": 7.92,
    ".png":  7.5,
    ".pdf":  7.5,
}

def run_overlay_detection(file_bytes: bytes, ext: str) -> Dict:
    """
    FIXED: Two-tier detection — same approach as image_eof_check.

    Tier 1 — Executable header (HIGH, score 85):
      If overlay starts with MZ/ELF → always flag regardless of entropy.
      Real PE files: entropy 6.5-7.6 which is BELOW old threshold → FN.
      Strip null padding first — tools often pad before payload.

    Tier 2 — High entropy blob (MEDIUM, score 40):
      Threshold per-format from config. Catches encrypted/compressed payloads.
    """
    marker = EOF_MARKERS.get(ext)
    if not marker:
        return {"layer": "overlay_detection", "detected": False, "severity": "none", "score": 0}

    pos = file_bytes.rfind(marker)
    if pos == -1:
        return {"layer": "overlay_detection", "detected": False, "severity": "none", "score": 0}

    overlay      = file_bytes[pos + len(marker):]
    overlay_size = len(overlay)

    if overlay_size > 4096:
        # Tier 1: check for executable header (PE/ELF)
        stripped = overlay.lstrip(b"\x00\x0d\x0a\x20")
        if stripped[:2] == b"\x4D\x5A" or stripped[:4] == b"\x7f\x45\x4c\x46":
            return {
                "layer":    "overlay_detection",
                "detected": True,
                "severity": "high",
                "score":    85,
                "reason":   f"Executable (MZ/ELF) appended after {ext} EOF at offset {pos}. Overlay: {overlay_size} bytes"
            }

        # Tier 2: high entropy blob
        threshold  = OVERLAY_ENTROPY_THRESHOLDS.get(ext, 7.5)
        ov_entropy = calculate_entropy(overlay)
        if ov_entropy > threshold:
            return {
                "layer":    "overlay_detection",
                "detected": True,
                "severity": "medium",
                "score":    40,
                "reason":   f"High entropy overlay after {ext} EOF: {overlay_size} bytes, entropy={ov_entropy:.3f}"
            }

    return {"layer": "overlay_detection", "detected": False, "severity": "none", "score": 0,
            "reason": "No overlay detected"}

# ================================
# POLYGLOT DETECTION
# ================================
#
# KEY FIXES:
# 1. ext parameter added — skip ZIP for OpenXML, GZIP for compressed containers
# 2. GZIP_CONTAINER_EXTS: PDF added — FlateDecode uses zlib = 1F 8B appears naturally
# 3. DOCX/XLSX/PPTX already in GZIP list — deflate inside ZIP entries
# 4. IMAGE_SIG_SKIP_EXTS: DOCX family skips PNG/JPG — embedded images
# 5. PE-EXE: validates PE offset pointer — not just MZ bytes

POLYGLOT_SIGS = [
    (b"\x50\x4B\x03\x04", "ZIP"),
    (b"\x1f\x8b",         "GZIP"),
    (b"Rar!",             "RAR"),
    (b"\x4D\x5A",         "PE-EXE"),
    (b"\xFF\xD8\xFF",     "JPG"),
    (b"\x89\x50\x4E\x47","PNG"),
]

OPENXML_EXTS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk"}

GZIP_CONTAINER_EXTS = {
    ".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
    ".mp3", ".m4a", ".aac",
    # FIXED: FLAC uses DEFLATE compression internally — 1F 8B (GZIP sig) appears naturally
    # OGG uses similar internal compression — same issue
    # WAV can contain compressed chunks in some variants
    # WMA uses ASF container with internal compression
    ".flac", ".ogg", ".wav", ".wma",
    ".png",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".pdf",
    ".tiff", ".tif",
    # FIXED: AVI with MJPEG codec (UCF101) — each frame is JPEG
    # JPEG uses DEFLATE internally → 1F 8B (GZIP sig) in every frame
    # Without this, polyglot_detection fires on ALL clean UCF101 AVI files
    ".avi", ".wmv", ".flv", ".mpeg",
    ".jpg", ".jpeg",
}

# ZIP/RAR skip for video — MP4/MKV containers use ZIP-style compression internally
ZIP_CONTAINER_EXTS = {
    ".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
    ".avi", ".wmv", ".flv", ".mpeg",
}

# RAR skip for video — some container formats have RAR-like signatures in bitstream
RAR_CONTAINER_EXTS = {
    ".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
    ".avi", ".wmv", ".flv", ".mpeg",
}

IMAGE_SIG_SKIP_EXTS = {
    # Office formats embed images
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    # PDF regularly embeds JPEG/PNG images in content streams
    ".pdf",
    # VIDEO: MP4/MKV embed JPEG thumbnails (cover art) in moov/udta atoms — 100% legitimate
    ".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
    ".avi", ".wmv", ".flv", ".mpeg",
    # AUDIO: MP3 ID3v2 APIC frame contains album art in JPEG/PNG — every commercial MP3 has this
    ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".wav", ".wma",
    # JPEG file itself — finding JPG sig inside a JPG is always self-match
    ".jpg", ".jpeg",
}

def is_valid_pe(data: bytes, offset: int) -> bool:
    if data[offset:offset + 2] != b"MZ":
        return False
    try:
        pe_offset = int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
        return data[offset + pe_offset:offset + pe_offset + 4] == b"PE\x00\x00"
    except Exception:
        return False

def _jpg_contains_payload(file_bytes: bytes, jpg_offset: int) -> bool:
    """
    FIXED: Stricter PE/ELF detection inside embedded JPEG.
    Legitimate thumbnails in MP4/AVI never contain PE headers.
    Malicious polyglot = JPEG + appended PE executable.

    Changes from original:
      - MZ must appear AFTER FFD9 (JPEG end marker) — payload after image end
      - Require valid PE header pointer (is_valid_pe) — not random MZ bytes
      - Skip MZ found in first 4KB of JPEG segment (JFIF/EXIF markers)
      - ELF must appear after FFD9 too (same logic)
    """
    # Find JPEG end marker FFD9
    ffd9_pos = file_bytes.find(b"\xFF\xD9", jpg_offset + 4)
    if ffd9_pos == -1:
        return False  # no complete JPEG = no overlay possible

    # Only check data AFTER the JPEG end marker
    overlay_start = ffd9_pos + 2
    overlay = file_bytes[overlay_start: overlay_start + 1048576]

    if not overlay:
        return False

    # Strip null padding — tools pad before payload
    stripped = overlay.lstrip(b"\x00\x0d\x0a\x20")
    if stripped[:2] == b"\x4D\x5A" and is_valid_pe(stripped, 0):
        return True
    if stripped[:4] == b"\x7f\x45\x4c\x46":
        return True

    return False

def _png_contains_payload(file_bytes: bytes, png_offset: int) -> bool:
    """
    FIXED: Stricter PE/ELF detection inside embedded PNG.
    Only flag if PE/ELF appears AFTER PNG IEND chunk.
    Legitimate thumbnails never have executable after IEND.
    """
    # Find PNG end marker IEND
    iend_pos = file_bytes.find(b"IEND", png_offset + 8)
    if iend_pos == -1:
        return False

    # IEND chunk = 4 bytes length + 4 bytes "IEND" + 4 bytes CRC = 12 bytes
    overlay_start = iend_pos + 8
    overlay = file_bytes[overlay_start: overlay_start + 1048576]

    if not overlay:
        return False

    stripped = overlay.lstrip(b"\x00\x0d\x0a\x20")
    if stripped[:2] == b"\x4D\x5A" and is_valid_pe(stripped, 0):
        return True
    if stripped[:4] == b"\x7f\x45\x4c\x46":
        return True

    return False

def run_polyglot_detection(file_bytes: bytes, ext: str = "") -> Dict:

    findings    = []
    search_area = file_bytes[32:]

    for sig, name in POLYGLOT_SIGS:
        if name == "ZIP"  and (ext in OPENXML_EXTS or ext in ZIP_CONTAINER_EXTS): continue
        if name == "GZIP" and ext in GZIP_CONTAINER_EXTS:    continue
        if name == "RAR"  and ext in RAR_CONTAINER_EXTS:     continue

        # JPG/PNG in audio/video — smart check:
        # FIXED: For VIDEO formats, skip entirely.
        # Reason: smart_read gives only 64KB header for video.
        # The JPEG thumbnail is in the 64KB header, FFD9 is also there.
        # After FFD9 in the 64KB buffer = more H.264 header data (not EOF).
        # That data may accidentally contain MZ + valid-looking PE offset.
        # video_eof_check() handles appended executables via disk-seek — no need here.
        VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
                      ".avi", ".wmv", ".flv", ".mpeg"}
        if name in ("PNG", "JPG") and ext in IMAGE_SIG_SKIP_EXTS:
            if ext in VIDEO_EXTS:
                continue  # video_eof_check handles this — skip to avoid FPs
            pos = search_area.find(sig)
            if pos == -1:
                continue
            if pos < 512:
                continue
            abs_offset = pos + 32
            # Check if this embedded image contains a malicious payload
            has_payload = (
                _jpg_contains_payload(file_bytes, abs_offset) if name == "JPG"
                else _png_contains_payload(file_bytes, abs_offset)
            )
            if has_payload:
                findings.append({"format": f"{name}_with_executable_payload", "offset": abs_offset})
            continue  # whether payload or not, handled above — don't fall through

        pos = search_area.find(sig)
        if pos == -1:
            continue

        if name == "PE-EXE":
            # FIXED: Skip PE-EXE check for video formats.
            # AVI/MP4 codec data (H.264/MPEG-4) contains random byte sequences.
            # In 300 AVI files, accidental MZ + valid-looking PE offset creates
            # false positives (63 FPs observed). video_eof_check handles real
            # PE overlays via RIFF/box boundary analysis — more reliable.
            VIDEO_EXTS_PE = {".mp4",".mov",".m4v",".3gp",".mkv",".webm",
                             ".avi",".wmv",".flv",".mpeg"}
            if ext in VIDEO_EXTS_PE:
                continue
            if not is_valid_pe(file_bytes, pos + 32):
                continue

        if pos < 512:
            continue

        findings.append({"format": name, "offset": pos + 32})

    detected = len(findings) > 0
    return {
        "layer": "polyglot_detection",
        "detected": detected,
        "severity": "high" if any("executable_payload" in str(f) for f in findings) else "medium" if detected else "none",
        "score": 80 if any("executable_payload" in str(f) for f in findings) else 40 if detected else 0,
        "reason": f"Polyglot detected: {findings}" if detected else "No polyglot"
    }

# ================================
# PE DETECTION
# ================================

def run_pe_detection(file_bytes: bytes) -> Dict:
    """
    FIXED: mz_pos > 0 condition was wrong for polyglot files.

    Old logic: skipped MZ at offset 0 (correct — we're not a PE scanner)
               but also skipped when YARA disabled → nothing caught polyglot

    New logic: scan for MZ anywhere after offset 4 (skip format magic bytes).
    is_valid_pe() validates the PE header pointer — this prevents false positives
    from random MZ bytes in legitimate media files.

    Why offset 4 not 0:
      Offset 0 = the file's own magic bytes (JPEG FFD8, PNG 8950, etc.)
      We're looking for a HIDDEN PE, so it must start after the format header.
      Offset 4 is conservative — polyglot PE is always at offset >> 100.
    """
    search_start = 4  # skip format magic bytes at offset 0
    pos = search_start

    while pos < len(file_bytes) - 64:
        mz_pos = file_bytes.find(b"\x4D\x5A", pos)
        if mz_pos == -1:
            break
        if is_valid_pe(file_bytes, mz_pos):
            return {
                "layer":    "pe_detection",
                "detected": True,
                "severity": "high",
                "score":    80,
                "reason":   f"Valid PE header at offset {mz_pos} — executable hidden in media file"
            }
        pos = mz_pos + 2  # move forward, keep searching

    elf_pos = file_bytes.find(b"\x7fELF", search_start)
    if elf_pos != -1:
        return {
            "layer":    "pe_detection",
            "detected": True,
            "severity": "high",
            "score":    80,
            "reason":   f"ELF header at offset {elf_pos} — Linux executable hidden in media file"
        }

    return {"layer": "pe_detection", "detected": False, "severity": "none", "score": 0, "reason": "No PE/ELF header found"}

# ================================
# BASE64 DETECTION
# ================================
#
# KEY FIX: Only flag if decoded content is MZ/ELF executable
# Old logic flagged any high-entropy base64 — fires on every PDF image stream

def run_base64_detection(file_bytes: bytes) -> Dict:

    findings = []
    pattern  = re.compile(b"[A-Za-z0-9+/]{200,}={0,2}")

    for match in pattern.findall(file_bytes):
        try:
            decoded = base64.b64decode(match + b"==")
            # FIXED: removed "Large encrypted base64 blob" branch
            # That branch fired on every PDF image stream and DOCX embedded image
            # Only flag if decoded content is an actual executable (MZ/ELF header)
            if decoded[:2] == b"MZ" or decoded[:4] == b"\x7fELF":
                findings.append("Executable base64 payload")
                break
        except Exception:
            pass

    detected = len(findings) > 0
    return {
        "layer": "base64_obfuscation",
        "detected": detected,
        "severity": "high" if any("Executable" in f for f in findings) else "medium" if detected else "none",
        "score": 80 if any("Executable" in f for f in findings) else 40 if detected else 0,
        "reason": str(findings) if detected else "No suspicious base64"
    }

# ================================
# XOR DETECTION
# ================================

def run_xor_detection(file_bytes: bytes) -> Dict:

    sample = file_bytes[:65536]
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in sample[:16])
        if decoded[:2] == b"MZ" or decoded[:4] == b"\x7fELF":
            return {
                "layer": "xor_detection", "detected": True,
                "severity": "high", "score": 75,
                "reason": f"XOR-encoded executable (key=0x{key:02x})"
            }
    return {"layer": "xor_detection", "detected": False, "severity": "none", "score": 0}

# ================================
# HEX DETECTION
# ================================

def run_hex_detection(file_bytes: bytes) -> Dict:

    pattern  = re.compile(b"(?:[0-9a-fA-F]{2}){32,}")
    findings = []

    for match in pattern.findall(file_bytes):
        try:
            decoded = bytes.fromhex(match.decode("ascii"))
            if decoded[:2] == b"MZ" or decoded[:4] == b"\x7fELF":
                findings.append("Hex-encoded executable")
                break
        except Exception:
            pass

    detected = len(findings) > 0
    return {
        "layer": "hex_detection",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score": 70 if detected else 0,
        "reason": str(findings) if detected else "No hex-encoded executables"
    }

# ================================
# IOC EXTRACTION
# ================================
#
# KEY FIXES:
# 1. Requires 2+ suspicious TLD URLs or 1 .onion — not just 1 URL
# 2. UPI fraud detection added
# 3. URL shorteners only flagged in binary media — not in docs/PDF
# 4. Banking phishing domains — Indian bank names + bad TLD
# 5. Raw IP C2 URLs — private ranges excluded

SUSPICIOUS_TLDS = [".onion", ".xyz", ".top", ".ru"]

INDIAN_BANKS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "canara",
    "union", "bob", "bankofbaroda", "paytm", "phonepe", "gpay",
    "googlepay", "bhim", "upi", "npci", "yesbank", "idbi", "indusind"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "rb.gy", "ow.ly",
    "is.gd", "buff.ly", "tiny.cc", "s.id", "cutt.ly"
]

LEGITIMATE_UPI_HANDLES = [
    "@sbi", "@oksbi", "@okhdfcbank", "@okicici", "@okaxis",
    "@hdfc", "@icici", "@axisbank", "@kotak", "@ybl",
    "@paytm", "@ibl", "@upi", "@npci", "@apl"
]

PRIVATE_IP_PREFIXES = [
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "169.254.", "localhost"
]

def run_ioc_extraction(file_bytes: bytes, category: str = "") -> Dict:

    findings   = []
    all_scores = []

    try:
        text      = file_bytes.decode("latin-1", errors="ignore")
        http_urls = re.findall(r"https?://[^\s\"'<>]{8,}", text)

        # 1. Suspicious TLD URLs — require 2+ or 1 .onion
        suspicious_tld = []
        for url in http_urls:
            try:
                domain = urlparse(url).netloc.lower()
                if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    suspicious_tld.append(url)
            except Exception:
                continue

        onion_urls = [u for u in suspicious_tld if ".onion" in u]
        if onion_urls:
            findings.append({"type": "Tor .onion URL", "values": onion_urls[:3]})
            all_scores.append(("high", 70))
        elif len(suspicious_tld) >= 2:
            findings.append({"type": "Multiple suspicious TLD URLs", "values": suspicious_tld[:5]})
            all_scores.append(("medium", 40))

        # 2. UPI fraud links
        upi_urls = re.findall(r"upi://[^\s\"'<>]{8,}", text, re.IGNORECASE)
        for upi in upi_urls:
            try:
                pa_match = re.search(r"[?&]pa=([^&\s\"'<>]+)", upi, re.IGNORECASE)
                if pa_match:
                    vpa = pa_match.group(1).lower()
                    if not any(vpa.endswith(h) for h in LEGITIMATE_UPI_HANDLES):
                        findings.append({"type": "Suspicious UPI VPA", "value": vpa})
                        all_scores.append(("high", 75))
                    elif category in ("image", "audio", "video"):
                        findings.append({"type": "UPI in binary media", "value": vpa})
                        all_scores.append(("medium", 50))
            except Exception:
                continue

        # 3. URL shorteners — only in binary media files
        # FIXED: require URL to be in a readable text context — not just coincidental binary bytes
        # A real URL shortener in an image must be readable ASCII text embedded in metadata,
        # not random bytes that happen to spell bit.ly
        if category in ("image", "audio", "video"):
            for url in http_urls:
                try:
                    domain = urlparse(url).netloc.lower()
                    if any(short in domain for short in URL_SHORTENERS):
                        # Validate: surrounding context must be readable text (not binary noise)
                        url_pos = text.find(url)
                        if url_pos > 0:
                            context_before = text[max(0, url_pos - 20):url_pos]
                            # If surrounding bytes are mostly non-printable, it's binary noise
                            printable_ratio = sum(1 for c in context_before if 32 <= ord(c) <= 126) / max(len(context_before), 1)
                            if printable_ratio < 0.7:
                                continue  # Binary context — skip, likely coincidental bytes
                        findings.append({"type": "URL shortener in binary media", "value": url[:80]})
                        all_scores.append(("medium", 45))
                        break
                except Exception:
                    continue

        # 4. Banking phishing domains
        for url in http_urls:
            try:
                domain = urlparse(url).netloc.lower().replace("www.", "")
                has_bank    = any(b in domain for b in INDIAN_BANKS)
                has_bad_tld = any(domain.endswith(t) for t in SUSPICIOUS_TLDS)
                has_bad_kw  = any(k in domain for k in [
                    "alert", "secure", "kyc", "update", "verify", "login",
                    "support", "reward", "refund", "block", "suspend", "urgent"
                ])
                if has_bank and (has_bad_tld or has_bad_kw):
                    findings.append({"type": "Banking phishing domain", "value": domain})
                    all_scores.append(("high", 80))
                    break
            except Exception:
                continue

        # 5. Raw IP C2 URLs — exclude private ranges
        ip_pattern = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:/]", re.IGNORECASE)
        for match in ip_pattern.finditer(text):
            ip = match.group(1)
            if not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
                findings.append({"type": "Raw IP C2 URL", "value": ip})
                all_scores.append(("medium", 55))
                break

    except Exception:
        pass

    detected = len(findings) > 0

    if all_scores:
        severity = "high" if any(s == "high" for s, _ in all_scores) else "medium"
        score    = max(sc for _, sc in all_scores)
    else:
        severity = "none"
        score    = 0

    return {
        "layer":    "ioc_extraction",
        "detected": detected,
        "severity": severity,
        "score":    score,
        "reason":   f"IOC: {[f['type'] for f in findings]}" if detected else "No suspicious IOCs",
        "findings": findings
    }

# ================================
# DOMAIN DETECTION
# ================================
#
# KEY FIXES:
# 1. bit.ly removed — too common in legitimate documents
# 2. Severity downgraded to low — standalone domain match not enough
# 3. C2 framework path detection added

C2_DOMAINS = [
    "pastebin.com", "ngrok.io", "ngrok.app", "serveo.net",
    "pagekite.me", "duckdns.org", "no-ip.com", "ddns.net"
]

C2_URL_PATHS = [
    "/meterpreter", "/stager", "/payload", "/beacon",
    "/gate.php", "/panel", "/submit.php", "/bot.php",
    "/shell.php", "/cmd.php", "/rat/", "/c2/"
]

KNOWN_LEGIT_DOMAINS = [
    "github.com", "microsoft.com", "google.com",
    "stackoverflow.com", "apache.org", "python.org"
]

def run_domain_detection(file_bytes: bytes) -> Dict:

    findings = []

    try:
        text = file_bytes.decode("latin-1", errors="ignore")
        urls = re.findall(r"https?://[^\s\"'<>]{8,}", text)

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                path   = parsed.path.lower()

                if any(bad in domain for bad in C2_DOMAINS):
                    findings.append(f"C2 domain: {domain}")

                is_legit = any(legit in domain for legit in KNOWN_LEGIT_DOMAINS)
                if not is_legit:
                    for c2_path in C2_URL_PATHS:
                        if path.startswith(c2_path) or f"{c2_path}/" in path:
                            findings.append(f"C2 path: {url[:80]}")
                            break

            except Exception:
                continue

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "suspicious_domain_detection",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    35 if detected else 0,
        "reason":   f"Suspicious: {findings[:3]}" if detected else "No suspicious domains"
    }
