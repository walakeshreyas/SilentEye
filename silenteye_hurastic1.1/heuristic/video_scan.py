import os
import struct
import re
from typing import Dict
from urllib.parse import urlparse
from .universal import calculate_entropy

def _is_valid_pe_in_buffer(data: bytes, offset: int) -> bool:
    """Check if bytes at offset form a valid PE executable header."""
    try:
        if offset + 2 > len(data): return False
        if data[offset:offset+2] != b"MZ": return False
        if offset + 0x40 > len(data): return False
        pe_off = int.from_bytes(data[offset+0x3C:offset+0x40], "little")
        if pe_off == 0 or pe_off > 1024: return False
        if offset + pe_off + 4 > len(data): return False
        return data[offset+pe_off:offset+pe_off+4] == b"PE\x00\x00"
    except:
        return False

# ================================
# VIDEO LAYER 1 — CONTAINER CHECK
# ================================

def run_video_container_check(file_bytes: bytes, ext: str) -> Dict:

    findings = []

    try:
        if ext in (".mp4", ".mov", ".m4v", ".3gp"):
            if len(file_bytes) >= 8:
                if file_bytes[4:8] != b"ftyp":
                    findings.append("Invalid MP4 header")

        elif ext in (".mkv", ".webm"):
            if file_bytes[:4] != b"\x1A\x45\xDF\xA3":
                findings.append("Invalid MKV header")

        elif ext == ".avi":
            if file_bytes[:4] != b"RIFF" or file_bytes[8:12] != b"AVI ":
                findings.append("Invalid AVI header")

        elif ext == ".flv":
            if file_bytes[:3] != b"FLV":
                findings.append("Invalid FLV header")

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "video_container_check",
        "detected": detected,
        "severity": "low" if detected else "none",
        "score":    20 if detected else 0,
        "reason":   str(findings) if detected else "Container header valid"
    }

# ================================
# VIDEO LAYER 2 — MP4 BOX VALIDATION
# ================================

MAX_BOX_SIZE = 200 * 1024 * 1024

def run_mp4_box_validation(file_bytes: bytes, ext: str) -> Dict:
    """
    FIXED: smart_read gives us only 64KB header for video.
    Box walker must handle the case where box_size > available bytes —
    this is NORMAL for mdat (media data box) which is always huge.
    Old logic: box_size > len(file_bytes) → break → no validation at all.
    New logic: only flag boxes that claim to be larger than 200MB AND
    fit entirely within our read window (i.e. it's not just mdat extending
    beyond our truncated read).
    Also removed the oversized-box flag entirely — a large mdat is normal.
    Now only flags structurally corrupt headers: box_size < 8 means
    the box header itself is malformed, which IS suspicious.
    """
    if ext not in (".mp4", ".mov", ".3gp", ".m4v"):
        return {"layer": "mp4_box_validation", "detected": False, "severity": "none", "score": 0}

    findings = []
    pos      = 0
    boxes_walked = 0

    try:
        while pos < len(file_bytes) - 8:
            box_size = struct.unpack(">I", file_bytes[pos:pos + 4])[0]
            box_type = file_bytes[pos + 4:pos + 8]

            # box_size == 0 means "extends to EOF" — valid in MP4 spec
            if box_size == 0:
                break

            # box_size == 1 means 64-bit extended size — skip, valid
            if box_size == 1:
                pos += 16
                boxes_walked += 1
                continue

            # Malformed: box header claims less than minimum size
            if box_size < 8:
                findings.append(f"Malformed box header at offset {pos}: size={box_size}")
                break

            # Box extends beyond available bytes — normal for mdat in truncated read
            # Do NOT flag this — just stop walking
            if box_size > len(file_bytes) - pos:
                break

            boxes_walked += 1
            pos += box_size

            # Stop after walking first 50 boxes — header region is enough
            if boxes_walked > 50:
                break

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "mp4_box_validation",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    40 if detected else 0,
        "reason":   str(findings) if detected else "MP4 box structure valid"
    }

# ================================
# VIDEO LAYER 3 — METADATA CHECK
# ================================

SUSPICIOUS_TLDS    = [".onion", ".xyz", ".top", ".ru"]
SUSPICIOUS_DOMAINS = ["ngrok.io", "serveo.net", "duckdns.org", "pastebin.com"]

def run_video_metadata_check(file_bytes: bytes) -> Dict:

    findings = []

    try:
        # Scan header + tail only — not full file
        scan = (file_bytes[:65536] + file_bytes[-65536:]).decode("latin-1", errors="ignore")
        urls = re.findall(r"https?://[^\s\"'<>]{8,}", scan)

        for url in urls:
            try:
                domain = urlparse(url).netloc.lower()
                if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or \
                   any(bad in domain for bad in SUSPICIOUS_DOMAINS):
                    findings.append(domain)
            except Exception:
                continue

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "video_metadata_check",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    40 if detected else 0,
        "reason":   f"Suspicious domains: {findings}" if detected else "Video metadata clean"
    }

# ================================
# VIDEO LAYER 4 — EOF CHECK
# ================================

MIN_OVERLAY_SIZE = 524288  # 512KB

def run_video_eof_check(file_bytes: bytes, ext: str, file_path: str = None) -> Dict:
    
    if ext not in (".mp4", ".mov", ".m4v", ".3gp", ".avi"):
        return {
            "layer": "video_eof_check", "detected": False,
            "severity": "none", "score": 0,
            "reason": f"EOF check not applicable for {ext}"
        }

    findings = []

    try:
        # Get actual file size and tail bytes directly from disk
        if file_path and os.path.exists(file_path):
            actual_size = os.path.getsize(file_path)

            if actual_size < 500000:
                return {"layer": "video_eof_check", "detected": False, "severity": "none", "score": 0}

            # AVI: read RIFF header (first 8 bytes) for declared size
            # then check if file is larger than declared → overlay
            if ext == ".avi":
                with open(file_path, "rb") as f:
                    header = f.read(12)
                if header[:4] == b"RIFF" and len(header) >= 8:
                    declared_size = int.from_bytes(header[4:8], "little")
                    expected_end  = declared_size + 8
                    if actual_size > expected_end + 4096:
                        overlay_size = actual_size - expected_end
                        # Read overlay from disk
                        with open(file_path, "rb") as f:
                            f.seek(expected_end)
                            overlay = f.read(min(overlay_size, 1048576))
                        stripped = overlay.lstrip(b"\x00\x0d\x0a\x20")
                        if stripped[:2] == b"\x4D\x5A" or stripped[:4] == b"\x7f\x45\x4c\x46":
                            findings.append(f"Executable appended after AVI RIFF boundary: {overlay_size} bytes")
                        else:
                            ov_ent = calculate_entropy(overlay)
                            if ov_ent > 7.5:
                                findings.append(f"High entropy overlay after AVI: {overlay_size} bytes, entropy={ov_ent:.3f}")
                detected = len(findings) > 0
                return {
                    "layer":    "video_eof_check",
                    "detected": detected,
                    "severity": "high" if detected and any("Executable" in f for f in findings) else "medium" if detected else "none",
                    "score":    80 if detected and any("Executable" in f for f in findings) else 40 if detected else 0,
                    "reason":   str(findings) if detected else "No AVI overlay detected"
                }

            # Read last 2MB of actual file for MP4 check
            tail_read = min(2 * 1024 * 1024, actual_size)
            with open(file_path, "rb") as f:
                f.seek(actual_size - tail_read)
                tail_bytes = f.read(tail_read)

            found_pe = False
            pos_scan = 0
            while pos_scan < len(tail_bytes) - 64:
                mz_p = tail_bytes.find(b"\x4D\x5A", pos_scan)
                if mz_p == -1: break
                if _is_valid_pe_in_buffer(tail_bytes, mz_p):
                    findings.append(f"Valid PE appended to MP4 at tail offset {mz_p}")
                    found_pe = True
                    break
                pos_scan = mz_p + 2
            if not found_pe:
                elf_p = tail_bytes.find(b"\x7f\x45\x4c\x46")
                if elf_p != -1:
                    findings.append(f"ELF appended to MP4 at tail offset {elf_p}")

        else:
            # No file_path — fallback for small files or AVI with no disk path
            if ext == ".avi":
                # AVI RIFF boundary check
                # RIFF header: 4 bytes "RIFF" + 4 bytes declared_size + 4 bytes "AVI "
                # Declared size = file content size (not including 8-byte RIFF header)
                # Anything beyond 8 + declared_size = appended overlay
                if file_bytes[:4] == b"RIFF" and len(file_bytes) > 12:
                    declared_size = int.from_bytes(file_bytes[4:8], "little")
                    expected_end  = declared_size + 8
                    if len(file_bytes) > expected_end + 4096:
                        overlay     = file_bytes[expected_end:]
                        overlay_size = len(overlay)
                        stripped    = overlay.lstrip(b"\x00\x0d\x0a\x20")
                        if stripped[:2] == b"\x4D\x5A" or stripped[:4] == b"\x7f\x45\x4c\x46":
                            findings.append(f"Executable appended after AVI RIFF boundary: {overlay_size} bytes")
                        else:
                            ov_ent = calculate_entropy(overlay)
                            if ov_ent > 7.5:
                                findings.append(f"High entropy overlay after AVI: {overlay_size} bytes, entropy={ov_ent:.3f}")
            else:
                # MP4 fallback — small files only
                if len(file_bytes) < 500000:
                    return {"layer": "video_eof_check", "detected": False, "severity": "none", "score": 0}
                # Use is_valid_pe for fallback too — prevents random MZ FPs
                ps = 0
                found_fb = False
                while ps < len(file_bytes) - 64:
                    mp = file_bytes.find(b"\x4D\x5A", ps)
                    if mp == -1: break
                    if _is_valid_pe_in_buffer(file_bytes, mp):
                        findings.append(f"Valid PE in video container at offset {mp}")
                        found_fb = True
                        break
                    ps = mp + 2
                if not found_fb and b"\x7f\x45\x4c\x46" in file_bytes:
                    findings.append(f"ELF in video container")

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "video_eof_check",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    40 if detected else 0,
        "reason":   str(findings) if detected else "No suspicious video overlay"
    }
