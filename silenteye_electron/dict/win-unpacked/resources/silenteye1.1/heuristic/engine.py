import os
import sqlite3
import concurrent.futures
from typing import Dict

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    MAX_FULL_READ_BYTES, HEADER_READ_BYTES,
    TAIL_MIN_BYTES, TAIL_MAX_BYTES,
    YARA_HEADER_ONLY_EXTS, YARA_HEADER_SIZE,
    SCAN_TIMEOUT_SECONDS, UNAMBIGUOUS_HIGH_LAYERS,
)

from .universal import (
    run_entropy_analysis, run_overlay_detection,
    run_polyglot_detection, run_pe_detection,
    run_base64_detection, run_xor_detection,
    run_hex_detection, run_ioc_extraction,
    run_domain_detection
)
from .image_scan import (
    run_image_eof_check, run_exif_anomaly,
    run_pixel_dimension_check, run_metadata_blob_check
)
from .pdf_scan import (
    run_pdf_structure_analysis, run_pdf_embedded_check,
    run_pdf_stream_entropy, run_pdf_object_count,
    run_pdf_exploit_signatures
)
from .doc_scan import (
    run_macro_detection, run_ole_inspection,
    run_external_relationship_check, run_xml_anomaly_check,
    run_doc_exploit_signatures, run_odf_inspection
)
from .svg_scan import (
    run_svg_script_check, run_svg_xxe_check,
    run_svg_external_resource_check, run_svg_embedded_payload_check
)
from .video_scan import (
    run_video_container_check, run_mp4_box_validation,
    run_video_metadata_check, run_video_eof_check
)
from .audio_scan import (
    run_phase_coding_detection, run_echo_hiding_detection,
    run_audio_metadata_check, run_audio_eof_check,
    run_audio_entropy_spike, run_audio_lsb_check
)
from .risk_scoring import calculate_risk_score

# ================================
# YARA
# ================================

YARA_RULES = None

# FIXED: Office/ZIP-based formats excluded from polyglot YARA rules
# DOCX/XLSX/PPTX ARE ZIP files by spec — polyglot_jpg_zip fires on every
# DOCX with an embedded image = guaranteed FP on clean Office files
YARA_POLYGLOT_SKIP_EXTS = {
    ".docx", ".xlsx", ".pptx",
    ".odt",  ".ods",  ".odp",
    ".jar",  ".apk",
    # FIXED: Video formats contain embedded JPEG/PNG thumbnails (MJPEG codec)
    # polyglot_jpg_zip / polyglot_png_zip fire on all MJPEG AVI files
    # video_eof_check handles real payload detection for video via RIFF/box boundary
    ".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
    ".avi", ".wmv", ".flv", ".mpeg",
}
POLYGLOT_RULES_TO_SKIP = {"polyglot_jpg_zip", "polyglot_png_zip", "polyglot_pdf_zip"}

def load_yara_rules(rules_path: str = None):
    global YARA_RULES
    try:
        import yara
        if rules_path and os.path.exists(rules_path):
            YARA_RULES = yara.compile(filepath=rules_path)
    except Exception:
        YARA_RULES = None

def run_yara_scan(file_bytes: bytes, ext: str = "") -> Dict:
    if YARA_RULES is None:
        return {"layer": "yara_detection", "detected": False, "severity": "none", "score": 0}

    try:
        if ext in YARA_HEADER_ONLY_EXTS:
            header    = file_bytes[:YARA_HEADER_SIZE]
            file_size = len(file_bytes)
            tail_size = max(TAIL_MIN_BYTES, min(TAIL_MAX_BYTES, file_size // 100))
            tail      = file_bytes[-tail_size:] if file_size > YARA_HEADER_SIZE else b""
            scan_data = header + tail
        else:
            scan_data = file_bytes

        matches = YARA_RULES.match(data=scan_data)

        if matches:
            # FIXED: filter polyglot rules for ZIP-based Office formats
            if ext in YARA_POLYGLOT_SKIP_EXTS:
                matches = [m for m in matches if m.rule not in POLYGLOT_RULES_TO_SKIP]
            if matches:
                return {
                    "layer": "yara_detection", "detected": True,
                    "severity": "high", "score": 80,
                    "reason": f"{len(matches)} YARA rule(s): {[m.rule for m in matches]}"
                }
    except Exception:
        pass

    return {"layer": "yara_detection", "detected": False, "severity": "none", "score": 0}

# ================================
# HASH DB
# ================================

DB_PATH = None

def set_db_path(path: str):
    global DB_PATH
    DB_PATH = path

def check_hash_db(file_hash: str) -> Dict:
    try:
        if not file_hash:
            return {"layer": "hash_reputation", "detected": False, "severity": "none", "score": 0}
        db = DB_PATH
        if not db or not os.path.exists(db):
            return {"layer": "hash_reputation", "detected": False, "severity": "none", "score": 0}
        conn = sqlite3.connect(db)
        cur  = conn.cursor()
        cur.execute("SELECT malware_name FROM malicious_hashes WHERE sha256 = ?", (file_hash,))
        res  = cur.fetchone()
        conn.close()
        if res:
            return {
                "layer": "hash_reputation", "detected": True,
                "severity": "high", "score": 100,
                "reason": f"Known malware: {res[0]}"
            }
    except Exception:
        pass
    return {"layer": "hash_reputation", "detected": False, "severity": "none", "score": 0}

# ================================
# SMART FILE READER
# FIXED: Bug 1 — full file read replaced with format-aware chunked reading
#
# image/audio/video: header (64KB) + tail (1% of file, 4KB-512KB)
#   Payloads injected into media are ALWAYS in header/metadata or
#   appended after EOF. Never inside compressed pixel/codec data.
#   A 500MB video now uses ~600KB RAM instead of 500MB.
#
# pdf/doc/svg: full read, capped at 50MB
#   Text-based formats need full content for pattern matching.
#   50MB cap means attacker cannot force >50MB allocation.
# ================================

HEADER_ONLY_CATEGORIES = {"image", "audio", "video"}

def smart_read(file_path: str, category: str) -> bytes:
    file_size = os.path.getsize(file_path)

    if category in HEADER_ONLY_CATEGORIES:
        tail_size  = max(TAIL_MIN_BYTES, min(TAIL_MAX_BYTES, file_size // 100))
        tail_start = max(HEADER_READ_BYTES, file_size - tail_size)

        with open(file_path, "rb") as f:
            header = f.read(HEADER_READ_BYTES)
            if tail_start > HEADER_READ_BYTES and file_size > HEADER_READ_BYTES:
                f.seek(tail_start)
                tail = f.read(tail_size)
            else:
                tail = b""
        return header + tail
    else:
        read_size = min(file_size, MAX_FULL_READ_BYTES)
        with open(file_path, "rb") as f:
            return f.read(read_size)


# ================================
# SCAN WORKER — runs inside executor for timeout
# ================================

def _run_scan_layers(file_bytes: bytes, category: str, ext: str, file_hash: str, file_path: str = "") -> Dict:
    layer_results = []

    hash_result = check_hash_db(file_hash)
    layer_results.append(hash_result)

    if hash_result["detected"]:
        return {
            "verdict":        "malicious",
            "final_score":    100,
            "summary":        hash_result["reason"],
            "detections":     [hash_result],
            "layer_results":  layer_results,
            "total_layers":   1,
            "flagged_layers": 1,
            "weighted_score": 100,
        }

    # Universal layers
    layer_results.extend([
        run_entropy_analysis(file_bytes, category, ext),
        run_overlay_detection(file_bytes, ext),
        run_polyglot_detection(file_bytes, ext),
        run_pe_detection(file_bytes),
        run_base64_detection(file_bytes),
        run_xor_detection(file_bytes),
        run_hex_detection(file_bytes),
        run_ioc_extraction(file_bytes, category),
        run_domain_detection(file_bytes),
        run_yara_scan(file_bytes, ext),
    ])

    # Format-specific layers
    if category == "image":
        layer_results.extend([
            run_image_eof_check(file_bytes, ext),
            run_exif_anomaly(file_bytes, ext),
            run_pixel_dimension_check(file_bytes, ext),
            run_metadata_blob_check(file_bytes, ext),
        ])
    elif category == "pdf":
        layer_results.extend([
            run_pdf_structure_analysis(file_bytes),
            run_pdf_embedded_check(file_bytes),
            run_pdf_stream_entropy(file_bytes),
            run_pdf_object_count(file_bytes),
            run_pdf_exploit_signatures(file_bytes),
        ])
    elif category == "doc":
        layer_results.extend([
            run_macro_detection(file_bytes, ext),   # ext needed for .docm/.xlsm/.pptm fast-path
            run_ole_inspection(file_bytes),
            run_external_relationship_check(file_bytes),
            run_xml_anomaly_check(file_bytes),
            run_doc_exploit_signatures(file_bytes),
            run_odf_inspection(file_bytes, ext),    # ODT/ODS/ODP LibreOffice macro inspection
        ])
    elif category == "svg":
        # FIXED: SVG was completely dead — no branch existed. All 4 layers now wired.
        layer_results.extend([
            run_svg_script_check(file_bytes, ext),
            run_svg_xxe_check(file_bytes, ext),
            run_svg_external_resource_check(file_bytes, ext),
            run_svg_embedded_payload_check(file_bytes, ext),
        ])
    elif category == "video":
        layer_results.extend([
            run_video_container_check(file_bytes, ext),
            run_mp4_box_validation(file_bytes, ext),
            run_video_metadata_check(file_bytes),
            # FIXED: pass file_path so eof_check reads actual tail from disk
            # without this, smart_read truncated bytes caused FP on large videos
            run_video_eof_check(file_bytes, ext, file_path=file_path),
        ])
    elif category == "audio":
        layer_results.extend([
            run_phase_coding_detection(file_bytes, ext),
            run_echo_hiding_detection(file_bytes, ext),
            run_audio_metadata_check(file_bytes, ext),
            # FIXED: pass file_path — audio_eof_check needs disk-seek for large WAV/FLAC
            # smart_read gives only 64KB header, data chunk ends at ~2.5MB = missed
            run_audio_eof_check(file_bytes, ext, file_path=file_path),
            run_audio_entropy_spike(file_bytes, ext),
            run_audio_lsb_check(file_bytes, ext),
        ])

    scoring = calculate_risk_score(layer_results)
    scoring["layer_results"] = layer_results
    return scoring


# ================================
# MAIN ENGINE
# ================================

def run_heuristic_scan(file_path: str, stage1_result: Dict) -> Dict:
    category  = stage1_result.get("file_type", "unknown")
    ext       = os.path.splitext(file_path)[1].lower()
    file_hash = stage1_result.get("file_hash")

    result = {
        "file":          os.path.basename(file_path),
        "file_type":     category,
        "layer_results": []
    }

    # FIXED: Bug 1 — smart_read: media = header+tail only, docs = capped full read
    try:
        file_bytes = smart_read(file_path, category)
    except Exception as e:
        return {"verdict": "error", "summary": str(e), "layer_results": []}

    # FIXED: Bug 8 — per-scan timeout, crafted files cannot hang forever
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_scan_layers, file_bytes, category, ext, file_hash, file_path)
            try:
                scan_result = future.result(timeout=SCAN_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                future.cancel()
                return {
                    "verdict":        "timeout",
                    "final_score":    0,
                    "summary":        f"Scan exceeded {SCAN_TIMEOUT_SECONDS}s — file may be crafted",
                    "detections":     [],
                    "layer_results":  [],
                    "total_layers":   0,
                    "flagged_layers": 0,
                    "weighted_score": 0,
                }
    except Exception as e:
        return {"verdict": "error", "summary": str(e), "layer_results": []}

    result.update(scan_result)
    return result
