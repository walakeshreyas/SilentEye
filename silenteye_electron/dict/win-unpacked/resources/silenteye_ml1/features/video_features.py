"""
SilentEye ML — Video Feature Extractor  (FINAL v3)
===================================================
Extracts 20 statistical features from video container data.
No FFmpeg required — byte-level container analysis only.

CHANGES v3:
  - AVI: added _avi_chunk_walk() — RIFF chunk walking (little-endian)
  - MOV: added _mov_atom_walk() — QuickTime atom walking with
         known atom type validation and 64-bit extended size support
  - _check_magic: added WMV magic, improved MOV detection
  - _eof_analysis: AVI overlay detection added
  - exe_in_header [11]: proper PE confirmation kept (v2 fix)
  - pe_in_tail [17]: full PE magic required (v2 fix)
  - polyglot_image_sig [19]: AVI-specific check added
"""

import re
import struct
import math
from collections import Counter
from typing import Optional

import numpy as np

from config import VIDEO_HEAD_BYTES, VIDEO_TAIL_BYTES


# ── FEATURE NAMES ─────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "container_valid_boxes",    # [0]
    "container_invalid_boxes",  # [1]
    "container_oversized",      # [2]
    "container_size_variance",  # [3]
    "container_magic_valid",    # [4]
    "entropy_mean",             # [5]
    "entropy_std",              # [6]
    "entropy_max",              # [7]
    "entropy_min",              # [8]
    "entropy_spike",            # [9]
    "susp_url_count",           # [10]
    "exe_in_header",            # [11]
    "c2_domain_present",        # [12]
    "raw_ip_url_count",         # [13]
    "header_entropy_anomaly",   # [14]
    "overlay_size_norm",        # [15]
    "tail_entropy",             # [16]
    "pe_in_tail",               # [17]
    "elf_in_tail",              # [18]
    "polyglot_image_sig",       # [19]
]

N_FEATURES = 20

SUSP_TLDS  = [b".onion", b".xyz", b".ru", b".top"]
C2_DOMAINS = [b"ngrok.io", b"pastebin.com", b"duckdns.org", b"serveo.net"]
MAX_BOX    = 200 * 1024 * 1024

_COVER_ART_ATOMS = {b"covr", b"APIC", b"PIC "}

# Valid QuickTime/MOV atom types
_VALID_MOV_ATOMS = {
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide",
    b"pnot", b"udta", b"uuid", b"moof", b"mfra", b"traf",
    b"mvex", b"mehd", b"trex", b"avcC", b"hvcC", b"esds",
    b"trak", b"mdia", b"minf", b"stbl", b"stsd", b"stts",
    b"ctts", b"stss", b"stsc", b"stsz", b"stco", b"co64",
    b"smhd", b"vmhd", b"hmhd", b"nmhd", b"dinf", b"dref",
    b"edts", b"elst", b"tkhd", b"mdhd", b"hdlr", b"mvhd",
    b"iods", b"meta", b"ilst", b"clip", b"crgn", b"matt",
    b"kmat", b"load", b"imap", b"tmcd", b"chap", b"sync",
    b"scpt", b"ssrc", b"pict",
}

# PE confirmation signatures
_PE_CONFIRM = [b"PE\x00\x00", b"This program cannot", b"!This program"]


# ── UTILITIES ─────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data or len(data) < 64:
        return 0.0
    freq  = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total)
                for c in freq.values() if c > 0)


def _is_real_pe(data: bytes, offset: int) -> bool:
    """Real PE check — requires MZ + PE confirmation string."""
    if offset + 2 > len(data) or data[offset:offset+2] != b"MZ":
        return False
    chunk = data[offset:min(offset+512, len(data))]
    return any(sig in chunk for sig in _PE_CONFIRM)


def _is_real_elf(data: bytes, offset: int) -> bool:
    return (offset + 4 <= len(data) and
            data[offset:offset+4] == b"\x7fELF")


# ── MP4 BOX WALK ──────────────────────────────────────────────────────────────

def _mp4_box_walk(data: bytes, feat: np.ndarray):
    """Walks MP4/M4V/3GP box structure — big-endian size."""
    valid = invalid = oversized = 0
    sizes = []
    pos   = 0
    size  = len(data)

    while pos < size - 8:
        try:
            bsize = struct.unpack(">I", data[pos:pos+4])[0]
            if bsize < 8 or bsize > size - pos:
                invalid += 1
                break
            if bsize > MAX_BOX:
                oversized += 1
            valid += 1
            sizes.append(bsize)
            pos += bsize
        except Exception:
            break

    feat[0] = min(valid / 20.0, 1.0)
    feat[1] = min(invalid / 5.0, 1.0)
    feat[2] = min(oversized / 3.0, 1.0)
    feat[3] = float(np.std(sizes) / (np.mean(sizes) + 1e-8)) if sizes else 0.0


# ── AVI RIFF CHUNK WALK ───────────────────────────────────────────────────────

def _avi_chunk_walk(data: bytes, feat: np.ndarray):
    """
    Walks AVI RIFF chunk structure — little-endian size.
    RIFF: [4B chunk_id][4B chunk_size LE][chunk_data]
    Chunks padded to even byte boundary.
    """
    valid = invalid = oversized = 0
    sizes = []

    if len(data) < 12 or data[:4] != b"RIFF":
        feat[0] = 0.0
        feat[1] = 1.0
        feat[2] = 0.0
        feat[3] = 0.0
        return

    pos  = 12   # skip RIFF header
    size = len(data)

    while pos < min(size - 8, 65536):
        try:
            chunk_size = struct.unpack("<I", data[pos+4:pos+8])[0]

            if chunk_size == 0:
                pos += 8
                continue

            if chunk_size > size - pos:
                invalid += 1
                break

            if chunk_size > MAX_BOX:
                oversized += 1

            valid += 1
            sizes.append(chunk_size)
            pos += 8 + chunk_size + (chunk_size % 2)

        except Exception:
            break

    feat[0] = min(valid / 10.0, 1.0)
    feat[1] = min(invalid / 3.0, 1.0)
    feat[2] = min(oversized / 3.0, 1.0)
    feat[3] = float(np.std(sizes) / (np.mean(sizes) + 1e-8)) if sizes else 0.0


# ── MOV ATOM WALK ─────────────────────────────────────────────────────────────

def _mov_atom_walk(data: bytes, feat: np.ndarray):
    """
    Walks QuickTime MOV atom structure.
    MOV uses big-endian box structure like MP4 but:
    - Different valid atom type set
    - Supports 64-bit extended size (size==1 means read next 8 bytes)
    - size==0 means atom extends to EOF

    Unknown atom types scored as partial invalids —
    legitimate MOV extensions exist but are rare.
    """
    valid = invalid = oversized = unknown = 0
    sizes = []
    pos   = 0
    size  = len(data)

    while pos < size - 8:
        try:
            bsize     = struct.unpack(">I", data[pos:pos+4])[0]
            atom_type = data[pos+4:pos+8]

            # Extended 64-bit size
            if bsize == 1:
                if pos + 16 > size:
                    break
                bsize    = struct.unpack(">Q", data[pos+8:pos+16])[0]
                pos_next = pos + bsize
            elif bsize == 0:
                bsize    = size - pos
                pos_next = size
            else:
                pos_next = pos + bsize

            if bsize < 8 or pos_next > size:
                invalid += 1
                break

            if bsize > MAX_BOX:
                oversized += 1

            if atom_type not in _VALID_MOV_ATOMS:
                unknown += 1

            valid += 1
            sizes.append(bsize)
            pos = pos_next

        except Exception:
            break

    # Unknown atoms count as 0.5 invalids each
    feat[0] = min(valid / 15.0, 1.0)
    feat[1] = min((invalid + unknown * 0.5) / 5.0, 1.0)
    feat[2] = min(oversized / 3.0, 1.0)
    feat[3] = float(np.std(sizes) / (np.mean(sizes) + 1e-8)) if sizes else 0.0


# ── MAGIC CHECK ───────────────────────────────────────────────────────────────

def _check_magic(data: bytes, ext: str) -> float:
    """Returns 1.0 if magic bytes match expected format."""
    if ext in (".mp4", ".m4v", ".3gp"):
        return 1.0 if len(data) > 8 and data[4:8] == b"ftyp" else 0.0
    elif ext == ".mov":
        if len(data) > 8:
            atom = data[4:8]
            # Modern MOV: ftyp. Legacy MOV: moov/wide/free/mdat
            return 1.0 if atom in (b"ftyp", b"moov", b"wide",
                                    b"free", b"skip", b"mdat") else 0.0
        return 0.0
    elif ext in (".mkv", ".webm"):
        return 1.0 if data[:4] == b"\x1A\x45\xDF\xA3" else 0.0
    elif ext == ".avi":
        return 1.0 if data[:4] == b"RIFF" and data[8:12] == b"AVI " else 0.0
    elif ext == ".flv":
        return 1.0 if data[:3] == b"FLV" else 0.0
    elif ext == ".wmv":
        return 1.0 if data[:4] == b"\x30\x26\xB2\x75" else 0.0
    return 1.0


# ── ENTROPY SEGMENTS ──────────────────────────────────────────────────────────

def _entropy_segments(data: bytes, feat: np.ndarray):
    """Fills feat[5:10] from 5 sampled entropy regions."""
    size    = len(data)
    chunk   = 65536
    offsets = [0, size//4, size//2, 3*size//4, max(0, size - chunk)]
    ents    = []

    for off in offsets:
        region = data[off:off+chunk]
        if len(region) >= 1024:
            ents.append(_entropy(region))

    if not ents:
        return

    feat[5] = float(np.mean(ents)) / 8.0
    feat[6] = float(np.std(ents)) / 4.0
    feat[7] = float(max(ents)) / 8.0
    feat[8] = float(min(ents)) / 8.0
    if len(ents) >= 2:
        diffs   = [abs(ents[i] - ents[i-1]) for i in range(1, len(ents))]
        feat[9] = float(max(diffs)) / 4.0


# ── METADATA ANOMALIES ────────────────────────────────────────────────────────

def _metadata_anomalies(head: bytes, tail: bytes, feat: np.ndarray):
    """Fills feat[10:15] from header+tail metadata."""
    meta = head + tail
    text = meta.decode("latin-1", errors="ignore")

    urls     = re.findall(r"https?://[^\s\"'<>]{8,}", text)
    susp_tld = [u for u in urls
                if any(u.lower().endswith(t.decode()) for t in SUSP_TLDS)]
    feat[10] = min(len(susp_tld) / 3.0, 1.0)

    # Proper PE/ELF detection — no bare MZ match
    exe_found = False
    for off in range(0, min(len(head) - 512, VIDEO_HEAD_BYTES), 512):
        if _is_real_pe(head, off):
            exe_found = True
            break
    if not exe_found and len(head) >= 4:
        if _is_real_elf(head, 0):
            exe_found = True
    if not exe_found and len(tail) >= 4:
        if _is_real_elf(tail, 0) or _is_real_pe(tail, 0):
            exe_found = True
    feat[11] = 1.0 if exe_found else 0.0

    feat[12] = 1.0 if any(d in meta for d in C2_DOMAINS) else 0.0

    ip_urls  = re.findall(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
    feat[13] = min(len(ip_urls) / 3.0, 1.0)

    h_ent    = _entropy(head[:65536]) if len(head) >= 65536 else _entropy(head)
    feat[14] = float(np.clip((h_ent - 6.0) / 2.0, 0, 1))


# ── EOF / OVERLAY ─────────────────────────────────────────────────────────────

def _find_mp4_cover_art_offsets(data: bytes) -> set:
    offsets = set()
    pos     = 0
    size    = len(data)
    while pos < size - 8:
        try:
            bsize    = struct.unpack(">I", data[pos:pos+4])[0]
            box_type = data[pos+4:pos+8]
            if bsize < 8 or bsize > size - pos:
                break
            if box_type in _COVER_ART_ATOMS:
                for off in range(pos, min(pos + bsize, size)):
                    offsets.add(off)
            pos += bsize
        except Exception:
            break
    return offsets


def _eof_analysis(data: bytes, tail: bytes, ext: str, feat: np.ndarray):
    """Fills feat[15:20] with overlay and payload indicators."""
    size = len(data)

    # Overlay calculation by format
    overlay = 0
    if ext in (".mp4", ".mov", ".m4v"):
        pos = last_valid = 0
        while pos < size - 8:
            try:
                bsize = struct.unpack(">I", data[pos:pos+4])[0]
                if bsize < 8 or bsize > size - pos:
                    break
                last_valid = pos + bsize
                pos += bsize
            except Exception:
                break
        overlay = size - last_valid

    elif ext == ".avi" and len(data) >= 8:
        try:
            riff_size    = struct.unpack("<I", data[4:8])[0]
            declared_end = riff_size + 8
            if declared_end < size:
                overlay = size - declared_end
        except Exception:
            pass

    feat[15] = min(overlay / (1024 * 1024), 1.0)
    feat[16] = _entropy(tail) / 8.0 if len(tail) >= 1024 else 0.0

    # PE in tail — full confirmation
    pe_in_tail = False
    for off in range(0, min(len(tail) - 512, len(tail)), 512):
        if _is_real_pe(tail, off):
            pe_in_tail = True
            break
    feat[17] = 1.0 if pe_in_tail else 0.0

    # ELF in tail
    feat[18] = 1.0 if (len(tail) >= 4 and _is_real_elf(tail, 0)) else 0.0

    # Polyglot image signature
    jpeg_sig = b"\xFF\xD8\xFF"
    png_sig  = b"\x89PNG"

    if ext in (".mp4", ".mov", ".m4v", ".3gp"):
        sig_positions = []
        search_start  = 131072
        chunk         = data[search_start:]
        for sig in (jpeg_sig, png_sig):
            idx = 0
            while True:
                pos = chunk.find(sig, idx)
                if pos == -1:
                    break
                sig_positions.append(search_start + pos)
                idx = pos + 1
        safe_offsets = _find_mp4_cover_art_offsets(data[:VIDEO_HEAD_BYTES])
        tail_start   = max(0, size - VIDEO_TAIL_BYTES)
        suspicious   = [p for p in sig_positions
                        if p not in safe_offsets and p < tail_start]
        feat[19] = 1.0 if suspicious else 0.0

    else:
        # AVI / MKV / others
        deep     = data[65536:131072] if len(data) > 131072 else b""
        feat[19] = 1.0 if (jpeg_sig in deep or png_sig in deep) else 0.0


# ── MAIN EXTRACTOR ────────────────────────────────────────────────────────────

def extract(file_bytes: bytes, ext: str) -> Optional[np.ndarray]:
    """
    Main entry point. Routes by extension to correct container parser.
    Returns numpy array of shape (20,) or None if extraction fails.
    """
    try:
        feat = np.zeros(N_FEATURES, dtype=np.float64)
        size = len(file_bytes)

        if size < 4096:
            return None

        head = file_bytes[:VIDEO_HEAD_BYTES]
        tail = file_bytes[-VIDEO_TAIL_BYTES:] if size > VIDEO_TAIL_BYTES else file_bytes

        # Route container parsing by format
        if ext in (".mp4", ".m4v", ".3gp"):
            _mp4_box_walk(head, feat)
        elif ext == ".mov":
            _mov_atom_walk(head, feat)
        elif ext == ".avi":
            _avi_chunk_walk(head, feat)
        else:
            # MKV / WMV / FLV / MPEG / WEBM — magic check only
            feat[0] = 0.5
            feat[1] = feat[2] = feat[3] = 0.0

        feat[4] = _check_magic(file_bytes, ext)

        _entropy_segments(file_bytes, feat)
        _metadata_anomalies(head, tail, feat)
        _eof_analysis(file_bytes, tail, ext, feat)

        return feat

    except Exception:
        return None
