import struct
from typing import Dict
from .universal import calculate_entropy

# ================================
# IMAGE LAYER 1 — EOF CHECK (FIXED)
# ================================

def run_image_eof_check(file_bytes: bytes, ext: str) -> Dict:

    overlay_size = 0
    overlay_entropy = 0.0

    try:
        if ext in (".jpg", ".jpeg"):
            pos = file_bytes.rfind(b"\xFF\xD9")
            if pos != -1:
                overlay_data = file_bytes[pos + 2:]
                overlay_size = len(overlay_data)

        elif ext == ".png":
            pos = file_bytes.rfind(b"IEND")
            if pos != -1:
                overlay_data = file_bytes[pos + 8:]
                overlay_size = len(overlay_data)

        elif ext == ".gif":
            pos = file_bytes.rfind(b"\x3B")
            if pos != -1:
                overlay_data = file_bytes[pos + 1:]
                overlay_size = len(overlay_data)

        # 🔥 FIX: only large + high entropy
        if overlay_size > 4096:
            overlay_entropy = calculate_entropy(overlay_data)

    except:
        pass

    detected = overlay_size > 4096 and overlay_entropy > 7.8

    return {
        "layer": "image_eof_check",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score": 40 if detected else 0,
    }

# ================================
# IMAGE LAYER 2 — EXIF (FIXED)
# ================================

MAX_NORMAL_EXIF_SIZE = 65535

def run_exif_anomaly(file_bytes: bytes, ext: str) -> Dict:

    if ext not in (".jpg", ".jpeg"):
        return {"layer": "exif_anomaly", "detected": False, "severity": "none", "score": 0}

    findings = []

    try:
        # FIXED: Scan ALL APP markers (APP0-APP15 = 0xFFE0-0xFFEF)
        # not just first APP1. MZ injection may land in any APP segment.
        # Also scan up to 256KB of file (EXIF can be anywhere in header).
        scan_limit = min(len(file_bytes), 262144)
        pos = 0
        while pos < scan_limit - 4:
            # Find any APP marker (FFE0-FFEF)
            if file_bytes[pos] == 0xFF and 0xE0 <= file_bytes[pos+1] <= 0xEF:
                try:
                    marker_len = struct.unpack(">H", file_bytes[pos+2:pos+4])[0]
                    seg_data   = file_bytes[pos+4: pos+4+marker_len]
                    # Strong signal: executable header in any APP segment
                    if b"MZ" in seg_data or b"\x7fELF" in seg_data:
                        # Verify it's a valid PE structure (not random MZ bytes)
                        mz_off = seg_data.find(b"MZ")
                        if mz_off != -1:
                            # Check for PE signature at declared offset
                            if mz_off + 0x40 < len(seg_data):
                                pe_off = int.from_bytes(seg_data[mz_off+0x3C:mz_off+0x40], "little")
                                if (0 < pe_off < 512 and
                                        mz_off + pe_off + 4 <= len(seg_data) and
                                        seg_data[mz_off+pe_off:mz_off+pe_off+4] == b"PE\x00\x00"):
                                    findings.append({"type": "Valid PE in EXIF/APP segment"})
                                    break
                            # Even without valid PE offset — MZ in EXIF is suspicious
                            if not findings:
                                findings.append({"type": "Executable header in EXIF/APP segment"})
                                break
                        elif b"\x7fELF" in seg_data:
                            findings.append({"type": "ELF header in EXIF/APP segment"})
                            break
                    pos += marker_len + 2
                except Exception:
                    pos += 1
            else:
                pos += 1

    except:
        pass

    detected = len(findings) > 0

    severity = "high" if detected else "none"
    score = 80 if detected else 0

    return {
        "layer": "exif_anomaly",
        "detected": detected,
        "severity": severity,
        "score": score,
    }

# ================================
# IMAGE LAYER 3 — DIMENSION CHECK
# ================================

MAX_WIDTH = 8000
MAX_HEIGHT = 8000

def run_pixel_dimension_check(file_bytes: bytes, ext: str) -> Dict:

    findings = []

    try:
        if ext == ".png":
            if len(file_bytes) >= 24:
                width = struct.unpack(">I", file_bytes[16:20])[0]
                height = struct.unpack(">I", file_bytes[20:24])[0]

                if width > MAX_WIDTH or height > MAX_HEIGHT:
                    findings.append("Large dimensions")

        elif ext in (".jpg", ".jpeg"):
            pos = file_bytes.find(b"\xFF\xC0")
            if pos != -1 and pos + 9 < len(file_bytes):
                height = struct.unpack(">H", file_bytes[pos + 5:pos + 7])[0]
                width = struct.unpack(">H", file_bytes[pos + 7:pos + 9])[0]

                if width > MAX_WIDTH or height > MAX_HEIGHT:
                    findings.append("Large dimensions")

    except:
        pass

    detected = len(findings) > 0

    return {
        "layer": "pixel_dimension_check",
        "detected": detected,
        "severity": "low" if detected else "none",
        "score": 20 if detected else 0,
    }

# ================================
# IMAGE LAYER 4 — METADATA BLOB (FIXED)
# ================================

MAX_METADATA_BLOB = 20480  # 🔥 increased

def run_metadata_blob_check(file_bytes: bytes, ext: str) -> Dict:

    findings = []

    try:
        if ext in (".jpg", ".jpeg"):
            pos = 0
            while pos < len(file_bytes) - 4:
                if file_bytes[pos] == 0xFF and 0xE0 <= file_bytes[pos + 1] <= 0xEF:
                    marker_len = struct.unpack(">H", file_bytes[pos + 2:pos + 4])[0]

                    # 🔥 only VERY large metadata
                    if marker_len > MAX_METADATA_BLOB:
                        findings.append(marker_len)

                    pos += marker_len + 2
                else:
                    pos += 1

        elif ext == ".png":
            pos = 8
            while pos < len(file_bytes) - 12:
                chunk_len = struct.unpack(">I", file_bytes[pos:pos + 4])[0]
                chunk_type = file_bytes[pos + 4:pos + 8]

                if chunk_type in (b"tEXt", b"zTXt", b"iTXt") and chunk_len > MAX_METADATA_BLOB:
                    findings.append(chunk_len)

                pos += chunk_len + 12

    except:
        pass

    detected = len(findings) > 0

    return {
        "layer": "metadata_blob_check",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score": 35 if detected else 0,
    }