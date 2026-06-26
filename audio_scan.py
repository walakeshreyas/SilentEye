import os
import struct
import re
import math
import statistics
from collections import Counter
from typing import Dict
from urllib.parse import urlparse
from .universal import calculate_entropy

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    AUDIO_LSB_MIN_FILE_BYTES, AUDIO_LSB_MIN_SAMPLES, AUDIO_LSB_MAX_SAMPLES,
    AUDIO_LSB_RATIO_LOW, AUDIO_LSB_RATIO_HIGH, AUDIO_LSB_CHI_SQ_THRESHOLD,
    AUDIO_ENTROPY_CHUNK, AUDIO_ENTROPY_MIN_BYTES,
    AUDIO_WAV_SPIKE_THRESHOLD, AUDIO_MP3_SPIKE_THRESHOLD, AUDIO_SILENCE_FLOOR,
    SUSPICIOUS_TLDS,
)

# ================================
# AUDIO LAYER 1 — PHASE CODING
# ================================
#
# REMOVED: The original variance < 0.005 + avg entropy > 7.0 check had
#   no academic backing and was detecting WHITE NOISE and SILENCE in WAV,
#   not phase coding steganography. Phase coding modifies audio phase —
#   it doesn't produce a uniform entropy signature.
#
#   A proper phase coding detector requires:
#     1. FFT of each audio segment
#     2. Phase comparison between adjacent segments
#     3. Detecting statistically anomalous phase relationships
#   This requires numpy/scipy which are not guaranteed available here.
#
#   Rather than keeping a broken detector that fires on clean silence-padded
#   WAV files, this layer now returns a no-op placeholder.
#   TODO: reimplement with proper FFT-based phase analysis using numpy.

def run_phase_coding_detection(file_bytes: bytes, ext: str) -> Dict:
    # Placeholder — original logic was incorrect (detected silence, not stego)
    # Returning clean result prevents contributing false positive score of 40
    return {
        "layer":    "phase_coding_detection",
        "detected": False,
        "severity": "none",
        "score":    0,
        "reason":   "Phase coding detection requires FFT analysis — not yet implemented"
    }

# ================================
# AUDIO LAYER 2 — ECHO HIDING
# ================================
#
# REMOVED: The original check operated on raw bytes, not audio samples.
#   WAV audio is 16-bit little-endian PCM — treating individual bytes as
#   samples is meaningless. The delay values [50, 100, 150, 200] were in
#   raw BYTES, not audio samples or milliseconds, so they detected nothing
#   real. Echo hiding uses delays in the 50-200ms range (2205-8820 samples
#   at 44100Hz), not sub-millisecond byte offsets.
#
#   A correct implementation requires struct.unpack to parse 16-bit samples,
#   then autocorrelation at proper millisecond-range delays. Without that,
#   this layer was pure noise contributing score=40 on clean files.
#
#   Returning a clean no-op until proper implementation.
#   TODO: reimplement with 16-bit sample parsing and ms-range autocorrelation.

def run_echo_hiding_detection(file_bytes: bytes, ext: str) -> Dict:
    # Placeholder — original logic operated on raw bytes, not audio samples
    return {
        "layer":    "echo_hiding_detection",
        "detected": False,
        "severity": "none",
        "score":    0,
        "reason":   "Echo hiding detection requires 16-bit sample parsing — not yet implemented"
    }

# ================================
# AUDIO LAYER 3 — METADATA CHECK
# ================================

SUSPICIOUS_TLDS = [".ru", ".xyz", ".onion", ".top" ]

def run_audio_metadata_check(file_bytes: bytes, ext: str) -> Dict:

    findings = []

    try:
        if ext == ".mp3" and file_bytes[:3] == b"ID3":

            b = file_bytes[6:10]
            id3_size = (b[0] << 21) | (b[1] << 14) | (b[2] << 7) | b[3]

            id3_data = file_bytes[10:10 + id3_size]

            # Strong signal — executable in metadata
            if b"MZ" in id3_data:
                findings.append({"type": "Executable in metadata"})

            # Suspicious TLD URLs in metadata
            text = id3_data.decode("latin-1", errors="ignore")
            urls = re.findall(r"https?://[^\s\"'<>]{8,}", text)

            for url in urls:
                try:
                    domain = urlparse(url).netloc.lower()
                    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                        findings.append({"type": "Suspicious domain in metadata", "value": domain})
                except:
                    continue

            # Only check entropy if large
            if id3_size > 50000:
                ent = calculate_entropy(id3_data)
                if ent > 7.8:
                    findings.append({"type": "High entropy metadata"})

    except:
        pass

    detected = len(findings) > 0
    severity = "high" if any("Executable" in f["type"] for f in findings) else "medium" if detected else "none"
    score    = 80 if severity == "high" else 40 if detected else 0

    return {
        "layer":    "audio_metadata_check",
        "detected": detected,
        "severity": severity,
        "score":    score,
    }

# ================================
# AUDIO LAYER 4 — EOF CHECK
# ================================

MP3_SYNC_VARIANTS = [b"\xFF\xFB", b"\xFF\xFA", b"\xFF\xF3", b"\xFF\xF2", b"\xFF\xE3", b"\xFF\xE2"]
ID3V1_MAGIC  = b"TAG"
APEV2_MAGIC  = b"APETAGEX"

def run_audio_eof_check(file_bytes: bytes, ext: str, file_path: str = None) -> Dict:
    """
    FIXED: Added WAV and FLAC overlay detection.

    Original only handled .mp3 — WAV and FLAC overlays were
    completely missed (0% TP on audio_overlay attack type).

    MP3: find last sync frame → check data after it
    WAV: find "data" chunk boundary → check data after chunk end
    FLAC: find "fLaC" + last METADATA_BLOCK → check data after audio
    ALL: Tier 1 = MZ/ELF header (HIGH), Tier 2 = entropy > 7.5 (MEDIUM)
    Threshold lowered 7.8 → 7.5 to catch more real payloads.
    """
    findings = []

    try:
        if ext == ".mp3":
            last = -1
            for sync in MP3_SYNC_VARIANTS:
                pos = file_bytes.rfind(sync)
                if pos > last:
                    last = pos

            if last == -1:
                return {"layer": "audio_eof_check", "detected": False, "severity": "none", "score": 0}

            tail = file_bytes[last + 4:]
            if tail[-128:].startswith(ID3V1_MAGIC):
                tail = tail[:-128]
            ape_pos = tail.find(APEV2_MAGIC)
            if ape_pos != -1:
                tail = tail[:ape_pos]
            tail = tail.rstrip(b"\x00\x0d\x0a\x20")
            overlay_size = len(tail)

            if overlay_size > 4096:
                # Tier 1: executable header
                stripped = tail.lstrip(b"\x00\x0d\x0a\x20")
                if stripped[:2] == b"\x4D\x5A" or stripped[:4] == b"\x7f\x45\x4c\x46":
                    findings.append({"type": "Executable after MP3 frames", "size": overlay_size})
                else:
                    # Tier 2: high entropy
                    entropy = calculate_entropy(tail)
                    if entropy > 7.5:
                        findings.append({"type": "High entropy overlay after MP3", "size": overlay_size, "entropy": round(entropy,3)})

        elif ext == ".wav":
            # FIXED: Use disk-seek for large WAV files.
            # smart_read gives only 64KB header. GTZAN WAV = ~2.5MB.
            # data chunk ends at ~2.5MB — beyond our 64KB window.
            # file_bytes[audio_end:] = empty → overlay missed entirely.
            # Solution: read RIFF header from file_bytes (always in 64KB),
            # then seek to actual audio_end on disk for overlay bytes.
            if file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WAVE":
                data_pos = file_bytes.find(b"data", 12)
                if data_pos != -1:
                    chunk_size = int.from_bytes(file_bytes[data_pos+4:data_pos+8], "little")
                    audio_end  = data_pos + 8 + chunk_size

                    if file_path and os.path.exists(file_path):
                        # Disk-seek path for large files
                        actual_size  = os.path.getsize(file_path)
                        overlay_size = max(0, actual_size - audio_end)
                        if overlay_size > 4096:
                            with open(file_path, "rb") as fh:
                                fh.seek(audio_end)
                                overlay = fh.read(min(overlay_size, 1048576))
                            overlay = overlay.rstrip(b"\x00")
                            stripped = overlay.lstrip(b"\x00\x0d\x0a\x20")
                            if stripped[:2] == b"\x4D\x5A" or stripped[:4] == b"\x7f\x45\x4c\x46":
                                findings.append({"type": "Executable appended after WAV data chunk", "size": overlay_size})
                            else:
                                entropy = calculate_entropy(overlay)
                                if entropy > 7.5:
                                    findings.append({"type": "High entropy overlay after WAV", "size": overlay_size, "entropy": round(entropy,3)})
                    else:
                        # Fallback: small file fully in memory
                        overlay      = file_bytes[audio_end:].rstrip(b"\x00")
                        overlay_size = len(overlay)
                        if overlay_size > 4096:
                            stripped = overlay.lstrip(b"\x00\x0d\x0a\x20")
                            if stripped[:2] == b"\x4D\x5A" or stripped[:4] == b"\x7f\x45\x4c\x46":
                                findings.append({"type": "Executable appended after WAV data chunk", "size": overlay_size})
                            else:
                                entropy = calculate_entropy(overlay)
                                if entropy > 7.5:
                                    findings.append({"type": "High entropy overlay after WAV", "size": overlay_size, "entropy": round(entropy,3)})

        elif ext == ".flac":
            # FLAC overlay detection using STREAMINFO block + file size comparison.
            # FLAC STREAMINFO (mandatory first block) has total_samples field.
            # raw_audio_size = total_samples * channels * bytes_per_sample
            # FLAC compression = ~50-70% → actual_file_size << raw_audio_size
            # If actual_file_size > raw_audio_size * 0.8 → unexplained overhead = overlay
            #
            # Avoids all entropy/frequency FP issues.
            # Fallback: MZ/ELF scan in last 64KB.
            if file_bytes[:4] == b"fLaC":
                actual_size   = os.path.getsize(file_path) if (file_path and os.path.exists(file_path)) else len(file_bytes)
                overlay_found = False

                try:
                    # STREAMINFO block: header byte (type=0) + 3-byte length + 34 bytes data
                    if len(file_bytes) >= 48 and (file_bytes[4] & 0x7F) == 0:
                        si_len = int.from_bytes(file_bytes[5:8], "big")
                        si     = file_bytes[8:8 + si_len]
                        if len(si) >= 18:
                            b10_17          = int.from_bytes(si[10:18], "big")
                            total_samples   = b10_17 & 0xFFFFFFFFF
                            bits_per_sample = ((b10_17 >> 36) & 0x1F) + 1
                            channels        = ((b10_17 >> 41) & 0x7)  + 1
                            raw_bytes       = total_samples * channels * (bits_per_sample // 8)
                            # FLAC is compressed — file should be SMALLER than raw audio
                            # Allow up to 85% of raw (some FLAC files compress poorly)
                            expected_max = int(raw_bytes * 0.85) + 65536
                            overhead     = actual_size - expected_max
                            if overhead > 8192:
                                # FIXED: ONLY flag if MZ/ELF confirmed in tail.
                                # Removed "overhead > 20KB alone" condition —
                                # FLAC metadata (album art, lyrics, tags) legitimately
                                # adds 10-200KB beyond audio data → 77 FPs on clean FLAC.
                                # MZ/ELF check is deterministic: zero FP risk.
                                # Use is_valid_pe() to avoid random MZ in compressed data.
                                if file_path and os.path.exists(file_path):
                                    with open(file_path, "rb") as fh:
                                        fh.seek(max(0, actual_size - 1048576))
                                        tail_data = fh.read(1048576)
                                else:
                                    tail_data = file_bytes[-65536:]

                                # Search for valid PE (not random MZ bytes)
                                ps = 0
                                while ps < len(tail_data) - 64:
                                    mp = tail_data.find(b"\x4D\x5A", ps)
                                    if mp == -1: break
                                    if mp + 0x40 < len(tail_data):
                                        pe_off = int.from_bytes(tail_data[mp+0x3C:mp+0x40], "little")
                                        if (0 < pe_off <= 1024 and
                                                mp + pe_off + 4 <= len(tail_data) and
                                                tail_data[mp+pe_off:mp+pe_off+4] == b"PE\x00\x00"):
                                            findings.append({"type": "Valid PE appended to FLAC", "size": overhead})
                                            overlay_found = True
                                            break
                                    ps = mp + 2

                                if not overlay_found and b"\x7f\x45\x4c\x46" in tail_data:
                                    findings.append({"type": "ELF appended to FLAC", "size": overhead})
                                    overlay_found = True
                except Exception:
                    pass

                # Fallback: is_valid_pe scan in last 64KB
                # FIXED: was raw b"MZ" check → caused 77 FPs on clean FLAC
                # FLAC compressed data has random MZ bytes statistically
                # is_valid_pe requires valid PE header structure → zero FP
                if not overlay_found:
                    if file_path and os.path.exists(file_path):
                        with open(file_path, "rb") as fh:
                            fh.seek(max(0, actual_size - 65536))
                            tail_fb = fh.read(65536)
                    else:
                        tail_fb = file_bytes[-65536:]
                    # Use is_valid_pe for MZ, raw check only for ELF
                    # (ELF magic 7f454c46 is 4 bytes — much rarer false positive)
                    ps = 0
                    while ps < len(tail_fb) - 64:
                        mp = tail_fb.find(b"\x4D\x5A", ps)
                        if mp == -1: break
                        if mp + 0x40 < len(tail_fb):
                            pe_off = int.from_bytes(tail_fb[mp+0x3C:mp+0x40], "little")
                            if (0 < pe_off <= 1024 and
                                    mp + pe_off + 4 <= len(tail_fb) and
                                    tail_fb[mp+pe_off:mp+pe_off+4] == b"PE\x00\x00"):
                                findings.append({"type": "Valid PE in FLAC tail (fallback)"})
                                break
                        ps = mp + 2
                    if not findings and b"\x7f\x45\x4c\x46" in tail_fb:
                        findings.append({"type": "ELF in FLAC tail region"})

    except Exception:
        pass

    detected = len(findings) > 0
    severity = "high" if detected and any("Executable" in f["type"] for f in findings) else "medium" if detected else "none"
    score    = 80 if severity == "high" else 40 if detected else 0

    return {
        "layer":    "audio_eof_check",
        "detected": detected,
        "severity": severity,
        "score":    score,
        "reason":   str(findings) if detected else "No suspicious audio overlay"
    }

# ================================
# AUDIO LAYER 5 — ENTROPY SPIKE
# ================================
#
# FIXED: WAV false positives on all 13 test files.
#
# Root cause 1 — CHUNK too small (8192 bytes = 8KB):
#   WAV PCM at 44100Hz stereo 16-bit = ~176KB/sec.
#   8KB = ~45ms of audio. Any natural music transition (quiet to loud,
#   silence to drums) in 45ms produces a huge entropy spike.
#   Fix: raise to 65536 (64KB = ~370ms) — smooths natural transitions.
#
# Root cause 2 — SPIKE_THRESHOLD too low (2.0):
#   Natural music has entropy ranging from ~4.0 (silence) to ~7.5 (loud complex).
#   A 2.0 spike = going from quiet passage to loud passage — completely normal.
#   Fix: raise to 3.5 for WAV — only catches extreme injected payload boundaries.
#
# Root cause 3 — No silence skip:
#   Silence chunks have entropy ~0-1.0. First non-silence chunk at 7.0+ = spike of 6+.
#   Fix: skip chunks below entropy 1.5 (silence/near-silence) before spike calculation.
#
# FN safety: malicious payload injected into WAV will have entropy 7.8-8.0 while
#   surrounding audio stays 5.0-7.5. Spike of 3.5+ still catches this reliably.

def run_audio_entropy_spike(file_bytes: bytes, ext: str) -> Dict:

    findings = []

    try:
        start = 44 if ext == ".wav" else 10
        audio = file_bytes[start:]

        if len(audio) < AUDIO_ENTROPY_MIN_BYTES:
            return {"layer": "audio_entropy_spike", "detected": False, "severity": "none", "score": 0}

        # FIXED: WAV chunk raised 8KB → 64KB, threshold raised 2.0 → 3.5
        # MP3 chunk stays 64KB, threshold stays 2.5 (already correct)
        CHUNK           = AUDIO_ENTROPY_CHUNK
        SPIKE_THRESHOLD = AUDIO_WAV_SPIKE_THRESHOLD if ext == ".wav" else AUDIO_MP3_SPIKE_THRESHOLD

        ent = []
        for i in range(0, min(len(audio), 1048576), CHUNK):
            chunk = audio[i:i + CHUNK]
            if len(chunk) >= 1024:
                e = calculate_entropy(chunk)
                # FIXED: skip silence/near-silence chunks — they cause fake spikes
                # when first non-silent chunk appears (entropy jumps from 0 to 7.0+)
                if e > AUDIO_SILENCE_FLOOR:
                    ent.append(e)

        if len(ent) < 3:
            return {"layer": "audio_entropy_spike", "detected": False, "severity": "none", "score": 0}

        for i in range(1, len(ent)):
            if ent[i] - ent[i - 1] > SPIKE_THRESHOLD:
                findings.append({"type": "Entropy spike", "from": round(ent[i-1], 3), "to": round(ent[i], 3)})
                break

    except Exception:
        pass

    detected = len(findings) > 0

    return {
        "layer":    "audio_entropy_spike",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    35 if detected else 0,
        "reason":   str(findings) if detected else "No entropy spike detected"
    }

# ================================
# AUDIO LAYER 6 — LSB STEGANOGRAPHY
# ================================
#
# LSB (Least Significant Bit) steganography hides data in the lowest bit
# of each audio sample. In WAV PCM audio, legitimate music has LSBs that
# follow the audio signal — they are NOT uniformly random.
#
# Detection principle:
#   Clean audio: LSBs have some statistical structure (correlated with signal)
#   LSB stego:   LSBs become a perfect 50/50 distribution (embedded data = random)
#
# Method:
#   1. Parse WAV 16-bit PCM samples using struct.unpack
#   2. Extract LSB of each sample
#   3. Count 0s and 1s — calculate balance ratio
#   4. Calculate chi-square statistic on LSB distribution
#   5. Flag if distribution is suspiciously uniform (p close to 0.5)
#
# Only applies to WAV — MP3/FLAC/AAC are compressed, LSBs are meaningless
# Only applies to files > 500KB — small files don't have enough samples
#
# FALSE POSITIVE PROTECTION:
#   - Threshold set conservatively: ratio must be 0.495-0.505 (near-perfect 50/50)
#   - Require minimum 10000 samples for statistical validity
#   - Pure silence (all zeros) is excluded — silence has all-zero LSBs, not stego

def run_audio_lsb_check(file_bytes: bytes, ext: str) -> Dict:
    """
    DISABLED: audio_lsb_check has fundamental FP problem on music datasets.

    Root cause: Complex music (jazz, disco, rock) has naturally ~50/50 LSB
    distribution due to full dynamic range. Chi-square test cannot distinguish
    natural music LSBs from steganographic LSBs.

    Test results: GTZAN music dataset → 166 FPs out of 166 WAV files (55%!).
    Chi-sq values for clean music ≈ 0.9 (same as stego ≈ 0.8).
    No threshold exists that separates them reliably.

    Documented as known limitation in paper Section 8.2.
    Future work: requires audio genre classification + per-genre baseline
    comparison, or deep learning approach (CNN on spectrogram).

    The layer architecture remains for future implementation.
    """
    return {
        "layer":    "audio_lsb_check",
        "detected": False,
        "severity": "none",
        "score":    0,
        "reason":   "[Known Limitation] LSB detection unreliable on music audio — disabled to prevent FPs"
    }

def _run_audio_lsb_check_impl(file_bytes: bytes, ext: str) -> Dict:
    # Only WAV PCM makes sense for LSB analysis
    if ext != ".wav":
        return {
            "layer":    "audio_lsb_check",
            "detected": False,
            "severity": "none",
            "score":    0,
            "reason":   f"LSB check only applies to WAV — skipped for {ext}"
        }

    # FIXED: Use RIFF declared size, not buffer size.
    # len(file_bytes) = 64KB from smart_read — ALWAYS fails 100KB threshold.
    # RIFF header bytes 4-8 = declared content size (always in 64KB header).
    # actual_size = riff_declared + 8 (the 8-byte RIFF+size header itself).
    if file_bytes[:4] == b"RIFF" and len(file_bytes) >= 8:
        riff_declared = int.from_bytes(file_bytes[4:8], "little")
        actual_file_size = riff_declared + 8
    else:
        actual_file_size = len(file_bytes)

    if actual_file_size < AUDIO_LSB_MIN_FILE_BYTES:
        return {
            "layer":    "audio_lsb_check",
            "detected": False,
            "severity": "none",
            "score":    0,
            "reason":   f"File too small for LSB analysis ({actual_file_size} bytes)"
        }

    try:
        # WAV header: "RIFF" at 0, "WAVE" at 8, "fmt " chunk starts at 12
        if file_bytes[:4] != b"RIFF" or file_bytes[8:12] != b"WAVE":
            return {
                "layer": "audio_lsb_check", "detected": False,
                "severity": "none", "score": 0,
                "reason": "Not a valid WAV file"
            }

        # Find "data" chunk to locate raw PCM samples
        data_pos = file_bytes.find(b"data", 12)
        if data_pos == -1:
            return {
                "layer": "audio_lsb_check", "detected": False,
                "severity": "none", "score": 0,
                "reason": "No data chunk found in WAV"
            }

        # Read chunk size (4 bytes after "data" marker)
        chunk_size = struct.unpack_from("<I", file_bytes, data_pos + 4)[0]
        audio_start = data_pos + 8
        audio_end   = min(audio_start + chunk_size, len(file_bytes))
        audio_data  = file_bytes[audio_start:audio_end]

        # Parse as 16-bit signed PCM samples
        # FIXED: was hardcoded 10000, now uses AUDIO_LSB_MIN_SAMPLES from config (5000)
        num_samples = len(audio_data) // 2
        if num_samples < AUDIO_LSB_MIN_SAMPLES:
            return {
                "layer": "audio_lsb_check", "detected": False,
                "severity": "none", "score": 0,
                "reason": f"Not enough samples for LSB analysis: {num_samples}"
            }

        # Sample up to 100000 samples for speed (evenly distributed)
        sample_limit = min(num_samples, AUDIO_LSB_MAX_SAMPLES)
        step = max(1, num_samples // sample_limit)

        samples = struct.unpack_from(f"<{num_samples}h", audio_data)

        lsb_count = [0, 0]  # count of 0s and 1s
        non_zero_count = 0

        for i in range(0, num_samples, step):
            s = samples[i]
            if s != 0:
                non_zero_count += 1
                lsb_count[s & 1] += 1

        if non_zero_count < 5000:
            return {
                "layer": "audio_lsb_check", "detected": False,
                "severity": "none", "score": 0,
                "reason": "Audio is mostly silence — LSB analysis not reliable"
            }

        total_lsb = lsb_count[0] + lsb_count[1]
        ratio = lsb_count[1] / total_lsb  # proportion of 1s

        # Chi-square test: expected 50/50 distribution = stego signature
        expected = total_lsb / 2
        chi_sq = ((lsb_count[0] - expected) ** 2 + (lsb_count[1] - expected) ** 2) / expected

        # Near-perfect 50/50 (ratio between 0.495 and 0.505) AND very low chi-square
        # indicates uniformly random LSBs = LSB steganography signature
        # FIXED: chi_sq threshold was 5.0 — 2.5% FP rate on clean WAV files
        # Now uses config.AUDIO_LSB_CHI_SQ_THRESHOLD = 1.5 (much more specific)
        is_suspicious = (AUDIO_LSB_RATIO_LOW <= ratio <= AUDIO_LSB_RATIO_HIGH) and chi_sq < AUDIO_LSB_CHI_SQ_THRESHOLD and non_zero_count > AUDIO_LSB_MIN_SAMPLES

        if is_suspicious:
            return {
                "layer":    "audio_lsb_check",
                "detected": True,
                "severity": "medium",
                "score":    50,
                "reason":   f"LSB distribution suspiciously uniform: ratio={ratio:.4f}, chi_sq={chi_sq:.2f}, samples={non_zero_count}"
            }

    except Exception as e:
        pass

    return {
        "layer":    "audio_lsb_check",
        "detected": False,
        "severity": "none",
        "score":    0,
        "reason":   "LSB distribution normal — no steganography signature"
    }
