import os
import hashlib
from pathlib import Path

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import SVG_ALWAYS_DANGEROUS as _SVG_ALWAYS_DANGEROUS


# ================================
# ALLOWED FILE TYPES
# ================================

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp", ".heic"}
VIDEO_EXT = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mpeg", ".3gp", ".webm"}
PDF_EXT   = {".pdf"}
DOC_EXT   = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
             ".odt", ".ods", ".odp",
             # Macro-enabled Office formats — highest malware delivery risk
             # Same ZIP/OLE structure as their non-macro counterparts
             # Routed to doc_scan which already handles VBA/macro detection
             ".docm", ".xlsm", ".pptm",
             # Legacy binary formats
             ".xlsb", ".xltm", ".dotm"}
AUDIO_EXT = {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma"}
SVG_EXT   = {".svg", ".svgz"}

ALL_ALLOWED_EXT = IMAGE_EXT | VIDEO_EXT | PDF_EXT | DOC_EXT | AUDIO_EXT | SVG_EXT

# ================================
# SIZE LIMITS (Messaging apps)
# WhatsApp / Facebook / Instagram
# Size = indicator only, not hard block
# ================================

LIMITS_MB = {
    "image": 27,
    "video": 3000,
    "pdf":   110,
    "doc":   100,
    "audio": 16,
    "svg":   2,
}

# ================================
# MAGIC BYTE SIGNATURES
# FIXED: offset-aware, strict sigs
# FIXED: strict mode properly enforced
# FIXED: ODT/ODS/ODP added
# ================================

MAGIC_BYTES = {

    # --- Images ---
    "jpg":  {"offset": 0, "sigs": [b"\xFF\xD8\xFF"],          "strict": True},
    "jpeg": {"offset": 0, "sigs": [b"\xFF\xD8\xFF"],          "strict": True},
    "png":  {"offset": 0, "sigs": [b"\x89PNG\r\n\x1a\n"],     "strict": True},
    "gif":  {"offset": 0, "sigs": [b"GIF87a", b"GIF89a"],     "strict": True},
    "bmp":  {"offset": 0, "sigs": [b"BM"],                    "strict": True},
    "tif":  {"offset": 0, "sigs": [b"II*\x00", b"MM\x00*"],   "strict": True},
    "tiff": {"offset": 0, "sigs": [b"II*\x00", b"MM\x00*"],   "strict": True},

    # RIFF-based: primary = RIFF at 0, confirmed by subtype at offset 8
    "webp": {"offset": 0, "sigs": [b"RIFF"], "confirm": {"offset": 8, "sig": b"WEBP"}, "strict": True},

    # HEIC/M4A: ftyp at offset 4, confirmed by brand bytes at offset 8
    "heic": {"offset": 4, "sigs": [b"ftyp"], "confirm": {"offset": 8, "sig": b"heic"}, "strict": False},
    "m4a":  {"offset": 4, "sigs": [b"ftyp"], "confirm": {"offset": 8, "sig": b"M4A "}, "strict": False},

    # --- Video ---
    "mp4":  {"offset": 4, "sigs": [b"ftyp"],                  "strict": True},
    "mov":  {"offset": 4, "sigs": [b"ftyp", b"moov", b"wide"],"strict": True},
    "avi":  {"offset": 0, "sigs": [b"RIFF"], "confirm": {"offset": 8, "sig": b"AVI "}, "strict": True},
    "wmv":  {"offset": 0, "sigs": [b"\x30\x26\xB2\x75\x8E\x66\xCF\x11"], "strict": True},
    "mkv":  {"offset": 0, "sigs": [b"\x1A\x45\xDF\xA3"],      "strict": True},
    "webm": {"offset": 0, "sigs": [b"\x1A\x45\xDF\xA3"],      "strict": True},
    "flv":  {"offset": 0, "sigs": [b"FLV"],                   "strict": True},
    "3gp":  {"offset": 4, "sigs": [b"ftyp"],                  "strict": True},
    "mpeg": {"offset": 0, "sigs": [b"\x00\x00\x01\xBA", b"\x00\x00\x01\xB3"], "strict": True},

    # --- PDF ---
    "pdf":  {"offset": 0, "sigs": [b"%PDF"],                  "strict": True},

    # --- Audio ---
    "mp3":  {"offset": 0, "sigs": [b"ID3", b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2"], "strict": True},
    "wav":  {"offset": 0, "sigs": [b"RIFF"], "confirm": {"offset": 8, "sig": b"WAVE"}, "strict": True},
    "ogg":  {"offset": 0, "sigs": [b"OggS"],                  "strict": True},
    "flac": {"offset": 0, "sigs": [b"fLaC"],                  "strict": True},
    "aac":  {"offset": 0, "sigs": [b"\xFF\xF1", b"\xFF\xF9"], "strict": True},
    "wma":  {"offset": 0, "sigs": [b"\x30\x26\xB2\x75\x8E\x66\xCF\x11"], "strict": True},

    # --- SVG ---
    # strict=False because SVG has multiple valid preambles
    "svg":  {"offset": 0, "sigs": [b"<svg", b"<?xml", b"<SVG", b"<!DOCTYPE", b"\xef\xbb\xbf"], "strict": False},
    "svgz": {"offset": 0, "sigs": [b"\x1f\x8b"],              "strict": True},

    # --- Office Documents (OpenXML = ZIP-based) ---
    # FIXED: Added PK\x05\x06 and PK\x07\x08 ZIP variants
    #   PK\x03\x04 = local file header (most common — MS Office default)
    #   PK\x05\x06 = end of central directory (some minimal/empty ZIPs, Google Docs export)
    #   PK\x07\x08 = data descriptor (streaming ZIP writers, some LibreOffice versions)
    #   ALSO: Password-protected DOCX/XLSX/PPTX are stored as OLE2 containers
    #   (MS Office wraps the encrypted ZIP inside OLE2 when password-protected)
    #   So OLE2 magic is also valid for these extensions.
    "docx": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06", b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "xlsx": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06", b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "pptx": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06", b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},

    # --- Macro-enabled Office formats (.docm/.xlsm/.pptm/.dotm/.xlsb) ---
    # Magic bytes: ZIP (PK) or OLE — identical to their non-macro counterparts
    # The macro content is identified by doc_scan heuristics, not magic bytes
    "docm": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06",
                                    b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "xlsm": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06",
                                    b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "pptm": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06",
                                    b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "dotm": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06",
                                    b"\x50\x4B\x07\x08", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "xlsb": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "xltm": {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},

    # --- Office Documents (OLE2 legacy binary) ---
    # D0 CF 11 E0 = OLE2 magic — Word 97-2003, Excel 97-2003, PowerPoint 97-2003
    # {\\rtf = RTF format — Word 6.0/95 saved .doc as RTF, many tools still do this
    # \xDB\xA5\x2D\x00 = Word 6.0 / Word 95 native binary format (pre-OLE2)
    "doc":  {"offset": 0, "sigs": [b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", b"{\\rtf", b"\xDB\xA5\x2D\x00"], "strict": True},
    "xls":  {"offset": 0, "sigs": [b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},
    "ppt":  {"offset": 0, "sigs": [b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], "strict": True},

    # --- RTF ---
    "rtf":  {"offset": 0, "sigs": [b"{\\rtf"],                "strict": True},

    # --- OpenDocument Format (LibreOffice — ZIP-based like OpenXML) ---
    # FIXED: Added all ZIP variants — same reason as DOCX above
    "odt":  {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06", b"\x50\x4B\x07\x08"], "strict": True},
    "ods":  {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06", b"\x50\x4B\x07\x08"], "strict": True},
    "odp":  {"offset": 0, "sigs": [b"\x50\x4B\x03\x04", b"\x50\x4B\x05\x06", b"\x50\x4B\x07\x08"], "strict": True},
}

# ================================
# EXECUTABLE EXTENSIONS
# ================================

EXECUTABLE_EXT = {
    ".exe", ".bat", ".cmd", ".scr",
    ".js",  ".vbs", ".ps1", ".com",
    ".msi", ".dll", ".sh",  ".bin",
    ".jar", ".py",  ".rb",  ".php"
}

# ================================
# RISKY CONTAINER EXTENSIONS
# ================================

RISKY_EXT = EXECUTABLE_EXT | {
    ".zip", ".rar", ".7z", ".tar",
    ".gz",  ".iso", ".img", ".apk"
}

# ================================
# SVG DANGEROUS PATTERNS
# ================================

# SVG_ALWAYS_DANGEROUS imported from config.py — single source of truth
# FIXED: was duplicated here and in svg_scan.py causing silent divergence
SVG_ALWAYS_DANGEROUS = _SVG_ALWAYS_DANGEROUS

# ================================
# BASIC UTILITIES
# ================================

def get_extension(file_path):
    return Path(file_path).suffix.lower()

def get_file_size_mb(file_path):
    return os.path.getsize(file_path) / (1024 * 1024)

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def get_category(ext):
    if ext in IMAGE_EXT:  return "image"
    if ext in VIDEO_EXT:  return "video"
    if ext in PDF_EXT:    return "pdf"
    if ext in DOC_EXT:    return "doc"
    if ext in AUDIO_EXT:  return "audio"
    if ext in SVG_EXT:    return "svg"
    return "unsupported"

# ================================
# DOUBLE EXTENSION DETECTION
# ================================

def detect_double_extension(file_path):
    name  = os.path.basename(file_path)
    parts = name.lower().split(".")

    if len(parts) <= 2:
        return False, None

    final_ext = "." + parts[-1]
    prev_ext  = "." + parts[-2]

    if final_ext in RISKY_EXT and prev_ext in ALL_ALLOWED_EXT:
        return True, f"Safe media extension '{prev_ext}' hiding risky '{final_ext}'"

    if final_ext in EXECUTABLE_EXT:
        return True, f"Executable extension '{final_ext}' detected"

    return False, None

# ================================
# MAGIC BYTE VALIDATION
# FIXED: strict mode properly enforced
#   strict=True  → sig must match at declared offset only
#   strict=False → sig may appear anywhere in header (SVG, HEIC etc.)
# FIXED: unknown extension returns False
# ================================

def validate_magic_bytes(file_path, ext):
    ext_key = ext.lstrip(".")

    if ext_key not in MAGIC_BYTES:
        return False, "No magic byte signature defined for this extension"

    try:
        sig_info  = MAGIC_BYTES[ext_key]
        offset    = sig_info["offset"]
        sigs      = sig_info["sigs"]
        is_strict = sig_info.get("strict", True)
        read_size = 512 if ext_key == "svg" else 64

        with open(file_path, "rb") as f:
            full_header = f.read(read_size)

        # Primary signature check
        # FIXED: strict=True checks ONLY at declared offset
        #        strict=False allows sig anywhere in the header window
        primary_match = False
        for sig in sigs:
            if is_strict:
                # Must be at exact declared offset — no fallback scan
                chunk = full_header[offset:offset + len(sig)]
                if chunk == sig:
                    primary_match = True
                    break
            else:
                # Loose match — sig anywhere in header window is acceptable
                if sig in full_header:
                    primary_match = True
                    break

        if not primary_match:
            return False, f"Primary magic bytes not found for .{ext_key}"

        # Confirmation check for RIFF-based and brand-based formats
        if "confirm" in sig_info:
            confirm  = sig_info["confirm"]
            c_offset = confirm["offset"]
            c_sig    = confirm["sig"]
            c_chunk  = full_header[c_offset:c_offset + len(c_sig)]
            if c_chunk != c_sig:
                return False, f"Subtype mismatch — expected {c_sig} at offset {c_offset}"

        return True, "Magic bytes valid"

    except Exception as e:
        return False, f"Magic byte read error: {str(e)}"

# ================================
# FILE INTEGRITY CHECK
# FIXED: JPEG tail extended to 4096 bytes (DSLRs write large XMP after FF D9)
# FIXED: PNG tail extended to 1024 bytes (some writers append custom chunks after IEND)
# ================================

def check_file_integrity(file_path, ext, category):
    try:
        size = os.path.getsize(file_path)

        if size == 0:
            return False, "File is empty (0 bytes)"

        MIN_SIZE = {
            "image": 100,
            "video": 1024,
            "pdf":   100,
            "doc":   512,
            "audio": 512,
            "svg":   10,
        }

        min_bytes = MIN_SIZE.get(category, 50)
        if size < min_bytes:
            return False, f"File too small ({size} bytes) — likely truncated or fake header"

        # JPEG — check FF D9 EOF marker
        # FIXED: extended from 512 → 4096 bytes
        #   Canon/Nikon DSLRs and Android phones write large XMP/MakerNote blobs
        #   after FF D9, pushing it well beyond 512 bytes from actual EOF.
        if ext in (".jpg", ".jpeg"):
            with open(file_path, "rb") as f:
                f.seek(max(0, size - 4096), 0)
                tail = f.read(4096)
            if b"\xFF\xD9" not in tail:
                return False, "JPEG missing EOF marker (FF D9) — possibly truncated or payload injected"

        # PNG — check IEND chunk
        # FIXED: extended from 256 → 1024 bytes
        #   GIMP, ImageMagick and other tools append tIME/iTXt/private chunks
        #   after IEND, pushing it further back from EOF.
        if ext == ".png":
            with open(file_path, "rb") as f:
                f.seek(max(0, size - 1024), 0)
                tail = f.read(1024)
            if b"IEND" not in tail:
                return False, "PNG missing IEND chunk — possibly truncated or payload injected"

        # PDF — check %%EOF marker in last 32 bytes
        if ext == ".pdf":
            with open(file_path, "rb") as f:
                f.seek(max(0, size - 32), 0)
                tail = f.read(32)
            if b"%%EOF" not in tail:
                return False, "PDF missing %%EOF marker — possibly truncated or payload injected"

        return True, "File integrity check passed"

    except Exception as e:
        return False, f"Integrity check error: {str(e)}"

# ================================
# SVG DEEP INSPECTION
# FIXED: reads full file (was 16KB — missed payloads injected after large <defs>)
# Attacker evasion: embed payload after 20KB of legitimate SVG content
# Stage 1 now reads full file to match Stage 2 coverage
# ================================

def svg_is_malicious(file_path):
    try:
        import re as _re

        # FIXED: read full file — 16KB was an evasion vector
        #   Malicious payloads are commonly injected after large <defs> blocks
        #   or base64 images, pushing them past 16KB easily.
        with open(file_path, "rb") as f:
            content = f.read()

        # Cap at 2MB — SVG size limit is 2MB per LIMITS_MB, so this covers full file
        content = content[:2097152]

        low = content.lower()

        findings = []

        # ── PASS 1: Always-dangerous patterns ──────────────────────────
        for sig in SVG_ALWAYS_DANGEROUS:
            if sig in low:
                findings.append(
                    f"SVG dangerous pattern: {sig.decode('latin-1', errors='ignore')}"
                )

        if findings:
            return True, findings[0]

        # ── PASS 2: Context-aware checks ───────────────────────────────

        # xlink:href — only flag if value is javascript: or data:text
        for val in _re.findall(
            rb'xlink:href\s*=\s*["\']([^"\']{0,200})["\']', content, _re.IGNORECASE
        ):
            if b"javascript:" in val.lower() or b"data:text" in val.lower():
                return True, (
                    f"xlink:href with dangerous value: "
                    f"{val[:60].decode('latin-1', errors='ignore')}"
                )

        # <image href= — only flag if value is javascript: or data:text URI
        for val in _re.findall(
            rb'<image[^>]{0,200}href\s*=\s*["\']([^"\']{0,200})["\']',
            content, _re.IGNORECASE
        ):
            if b"javascript:" in val.lower() or b"data:text" in val.lower():
                return True, "image href= with JavaScript/data URI payload"

        # <?xml-stylesheet — only flag if href contains javascript:
        if b"<?xml-stylesheet" in low:
            for val in _re.findall(
                rb'href\s*=\s*["\']([^"\']{0,200})["\']', content, _re.IGNORECASE
            ):
                if b"javascript:" in val.lower():
                    return True, "xml-stylesheet href contains JavaScript URI"

        # <!ENTITY — XXE injection
        if b"<!entity" in low:
            if b"system" in low or b"public" in low:
                return True, "XXE entity injection (<!ENTITY SYSTEM/PUBLIC)"

        # data:application — legitimate only for fonts
        for val in _re.findall(
            rb"data:application/([^;,\"']{0,50})", content, _re.IGNORECASE
        ):
            font_types = [b"font", b"woff", b"otf", b"ttf"]
            if not any(ft in val.lower() for ft in font_types):
                return True, (
                    f"Suspicious data:application URI: "
                    f"{val.decode('latin-1', errors='ignore')}"
                )

        return False, "SVG content appears safe"

    except Exception as e:
        return False, f"SVG check error: {str(e)}"

# ================================
# MAIN PREPROCESSING FUNCTION
# ================================

def preprocess_file(file_path, db_path=None):

    result = {
        "file":         os.path.basename(file_path),
        "file_path":    file_path,
        "file_type":    "unknown",
        "file_size_mb": 0,
        "file_hash":    None,
        "status":       "unknown",
        "reason":       "",
        "flags":        [],
        "size_flag":    False,
    }

    try:
        ext      = get_extension(file_path)
        size_mb  = get_file_size_mb(file_path)
        category = get_category(ext)

        result["file_type"]    = category
        result["file_size_mb"] = round(size_mb, 2)
        result["file_hash"]    = get_file_hash(file_path)

        # 1. Unsupported file type
        if category == "unsupported":
            result["status"] = "skip"
            result["reason"] = f"Unsupported file type '{ext}' — not in allowed list"
            return result

        # 2. Double extension
        flagged, msg = detect_double_extension(file_path)
        if flagged:
            result["status"] = "suspicious"
            result["reason"] = msg
            result["flags"].append("double_extension")
            return result

        # 3. File integrity check
        valid, msg = check_file_integrity(file_path, ext, category)
        if not valid:
            result["status"] = "suspicious"
            result["reason"] = msg
            result["flags"].append("integrity_fail")
            return result

        # 4. Magic byte validation
        valid, msg = validate_magic_bytes(file_path, ext)
        if not valid:
            result["status"] = "suspicious"
            result["reason"] = msg
            result["flags"].append("magic_byte_mismatch")
            return result

        # 5. Size check — indicator only, not a block
        max_size = LIMITS_MB[category]
        if size_mb > max_size:
            result["flags"].append("size_exceeded")
            result["size_flag"] = True

        # 6. SVG deep inspection
        if category == "svg":
            malicious, msg = svg_is_malicious(file_path)
            if malicious:
                result["status"] = "malicious"
                result["reason"] = msg
                result["flags"].append("svg_script_injection")
                return result

        # Final verdict
        if result["flags"]:
            result["status"] = "suspicious"
            result["reason"] = f"Passed preprocessing with flags: {', '.join(result['flags'])}"
        else:
            result["status"] = "clean"
            result["reason"] = "File passed all preprocessing checks"

        return result

    except Exception as e:
        result["status"] = "error"
        result["reason"] = str(e)
        return result


# ================================
# TEST MODE
# ================================

if __name__ == "__main__":

    test_files = [
        r"C:\Users\Shreyas\OneDrive\Desktop\images.jpg.js",
        r"C:\Users\Shreyas\OneDrive\Desktop\photo.png.zip",
        r"C:\Users\Shreyas\OneDrive\Desktop\sample.jpg",
        r"C:\Users\Shreyas\OneDrive\Desktop\malware.svg",
        r"C:\Users\Shreyas\OneDrive\Desktop\document.pdf",
    ]

    print("SILENTEYE - PREPROCESSING RESULTS")
    print("=" * 60)

    for file_path in test_files:
        res = preprocess_file(file_path)
        print(f"File     : {res['file']}")
        print(f"Type     : {res['file_type']}")
        print(f"Size     : {res['file_size_mb']} MB")
        print(f"Hash     : {res['file_hash']}")
        print(f"Status   : {res['status']}")
        print(f"Reason   : {res['reason']}")
        print(f"Flags    : {res['flags']}")
        print("-" * 60)

# ================================
# EXPORTS
# ================================

__all__ = [
    "preprocess_file",
    "get_file_hash",
    "get_extension",
    "get_category",
]
