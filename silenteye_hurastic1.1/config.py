# ============================================================
# SilentEye — config.py
# Single source of truth for ALL constants, thresholds, lists.
# Import from here everywhere — never hardcode in modules.
# ============================================================

# ============================================================
# SCAN PERFORMANCE LIMITS
# ============================================================

# Max bytes to read per file for full-content scan (PDF, DOC, SVG)
# Files beyond this are truncated — attacker can't force 2GB RAM allocation
MAX_FULL_READ_BYTES = 50 * 1024 * 1024        # 50 MB

# Header region read for media formats (image, audio, video)
# Covers all metadata, EXIF, ID3 tags, container atoms
HEADER_READ_BYTES   = 65536                    # 64 KB

# Tail region: 1% of file size, bounded
TAIL_MIN_BYTES      = 4096                     # 4 KB minimum tail
TAIL_MAX_BYTES      = 524288                   # 512 KB maximum tail

# Per-file scan timeout (seconds) — kills hung regex/entropy on crafted files
SCAN_TIMEOUT_SECONDS = 30

# ============================================================
# SVG LIMITS
# ============================================================

# Max SVG file size to scan (matches preprocessing LIMITS_MB["svg"])
MAX_SVG_BYTES = 2 * 1024 * 1024               # 2 MB

# Max decompressed size for SVGZ — prevents decompression bombs
# A legitimate SVG rarely exceeds 5MB uncompressed
MAX_SVGZ_DECOMPRESSED_BYTES = 10 * 1024 * 1024  # 10 MB

# Max decompression ratio allowed for SVGZ
MAX_SVGZ_RATIO = 100

# ============================================================
# ENTROPY THRESHOLDS
# ============================================================

ENTROPY_THRESHOLDS = {
    "image": 7.98,
    "video": 7.98,
    "audio": 7.98,
    "pdf":   7.998,
    "doc":   7.998,
    "svg":   6.80,
}

# Extensions where entropy analysis is meaningless — skip entirely
ENTROPY_SKIP_EXTS = {
    ".png", ".tif", ".tiff",
    ".flac", ".ogg", ".wav", ".aac", ".wma",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv",
    ".webm", ".flv", ".mpeg", ".3gp", ".m4v",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
}

ENTROPY_CHUNK_SIZE = 51200                     # 50 KB windows for entropy analysis

# ============================================================
# OVERLAY DETECTION
# ============================================================

OVERLAY_MIN_SIZE = 4096                        # Overlays < 4KB are ignored (padding, null bytes)

OVERLAY_ENTROPY_THRESHOLDS = {
    ".jpg":  7.92,
    ".jpeg": 7.92,
    ".png":  7.5,
    ".pdf":  7.5,
}

# ============================================================
# PDF STREAM ENTROPY
# ============================================================

PDF_STREAM_SCAN_LIMIT  = 5 * 1024 * 1024      # Scan first 5MB of PDF only
PDF_STREAM_MAX_MATCHES = 200                   # Max stream objects to process

# ============================================================
# AUDIO LSB ANALYSIS
# ============================================================

AUDIO_LSB_MIN_FILE_BYTES   = 100000           
                                               
AUDIO_LSB_MIN_SAMPLES      = 5000             
AUDIO_LSB_MAX_SAMPLES      = 100000          
AUDIO_LSB_RATIO_LOW        = 0.490            
AUDIO_LSB_RATIO_HIGH       = 0.510
AUDIO_LSB_CHI_SQ_THRESHOLD = 3.0             
                                               
                                               

# ============================================================
# AUDIO ENTROPY SPIKE
# ============================================================

AUDIO_ENTROPY_CHUNK     = 65536               # 64 KB chunks
AUDIO_ENTROPY_MIN_BYTES = 131072              # Minimum file size for spike analysis
AUDIO_WAV_SPIKE_THRESHOLD = 3.5
AUDIO_MP3_SPIKE_THRESHOLD = 2.5
AUDIO_SILENCE_FLOOR       = 1.5              # Skip chunks below this (silence)

# ============================================================
# VIDEO EOF
# ============================================================

VIDEO_MIN_OVERLAY_BYTES = 524288              # 512 KB minimum overlay to flag
VIDEO_MIN_OVERLAY_ENTROPY = 7.5

# ============================================================
# IMAGE CHECKS
# ============================================================

IMAGE_MAX_WIDTH  = 8000
IMAGE_MAX_HEIGHT = 8000
IMAGE_MAX_EXIF_ENTROPY_SIZE = 100000          # Only check EXIF entropy if > this
IMAGE_EXIF_ENTROPY_THRESHOLD = 7.8
IMAGE_MAX_METADATA_BLOB = 20480               # 20 KB metadata blob threshold

# ============================================================
# YARA
# ============================================================

YARA_HEADER_SIZE = 65536                      # Always scan first 64 KB

# Formats where YARA scans header+tail only (compressed body = FP risk)
YARA_HEADER_ONLY_EXTS = {
    ".jpg", ".jpeg", ".png", ".bmp", ".gif",
    ".tif", ".tiff", ".webp", ".heic",
    ".wav", ".mp3", ".flac", ".ogg", ".aac", ".m4a", ".wma",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mpeg", ".3gp", ".webm",
    ".pdf",
    # Macro-enabled Office — ZIP-based, same FP risk as docx/xlsx/pptx
    ".docm", ".xlsm", ".pptm", ".dotm", ".xlsb", ".xltm",
    # OpenDocument — ZIP-based
    ".odt", ".ods", ".odp",
}

# ============================================================
# BASE64 DETECTION
# ============================================================

BASE64_MIN_LENGTH = 200                       # Minimum base64 string length to inspect

# ============================================================
# XOR DETECTION
# ============================================================

XOR_SAMPLE_BYTES = 65536                      # Only check first 64 KB
XOR_CHECK_BYTES  = 16                         # Check first 16 decoded bytes for MZ/ELF

# ============================================================
# IOC EXTRACTION
# ============================================================

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


# SVG / VIDEO suspicious domains (used by svg_scan, video_scan)
SUSPICIOUS_DOMAINS = ["ngrok.io", "pastebin.com", "bit.ly", "duckdns.org"]

# ============================================================
# DOMAIN / C2 DETECTION
# ============================================================

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

# ============================================================
# SVG DANGEROUS PATTERNS
# Single definition — imported by preprocessing.py AND svg_scan.py
# ============================================================

SVG_ALWAYS_DANGEROUS = [
    b"<script",
    b"javascript:",
    b"onload=",
    b"onerror=",
    b"onclick=",
    b"onmouseover=",
    b"onfocus=",
    b"onactivate=",
    b"<foreignobject",
    b"<iframe",
    b"<embed",
    b"<object",
    b"data:text/html",
    b"ev:event",
    b"xlink:actuate",
]

# ============================================================
# RISK SCORING
# ============================================================

# Weighted score thresholds → verdicts
SCORE_MALICIOUS   = 120
SCORE_SUSPICIOUS_HIGH = 80
SCORE_SUSPICIOUS_MED  = 50
SCORE_SUSPICIOUS_LOW  = 30

# Cap on total weighted score before verdict mapping
SCORE_CAP = 200
UNAMBIGUOUS_HIGH_LAYERS = {
    "hash_reputation",           # SHA256 match against MalwareBazaar = confirmed
    "yara_detection",            # YARA rule match = confirmed
    "correlation_metadata_payload",  # PE header in metadata = unambiguous
}

# Layer artifact tags for score deduplication
# Layers sharing the same tag = same root artifact = only highest score counts
ARTIFACT_TAGS = {
    "pe_detection":                  "executable_payload",
    "yara_detection":                "executable_payload",
    "base64_obfuscation":            "executable_payload",
    "hex_detection":                 "executable_payload",
    "xor_detection":                 "executable_payload",
    "correlation_base64_pe":         "executable_payload",
    "overlay_detection":             "appended_payload",
    "image_eof_check":               "appended_payload",
    "audio_eof_check":               "appended_payload",
    "video_eof_check":               "appended_payload",
    "entropy_analysis":              "high_entropy",
    "audio_entropy_spike":           "high_entropy",
    "pdf_stream_entropy":            "high_entropy",
    "ioc_extraction":                "network_ioc",
    "suspicious_domain_detection":   "network_ioc",
    "correlation_network_ioc":       "network_ioc",
}

# ============================================================
# PAPER — DOCUMENTED LIMITATIONS
# Honest scope boundaries for academic publication.
# Reviewers will check these — never claim support you don't have.
# ============================================================

SUPPORTED_WITH_DEEP_HEURISTICS = {
    # Format          : Heuristic layers
    ".jpg/.jpeg"      : "EOF, EXIF, dimension, metadata blob, LSB via universal",
    ".png"            : "EOF, dimension, metadata blob",
    ".pdf"            : "Structure, embedded files, stream entropy, object count, exploit sigs",
    ".docx/.doc"      : "Macro, OLE, external relationship, XML anomaly, exploit sigs",
    ".docm/.xlsm/.pptm": "Macro fast-path (VBA always present), + full doc_scan suite",
    ".mp4/.mov/.m4v"  : "Container validation, box walk, metadata, EOF with disk seek",
    ".svg/.svgz"      : "Script/JS, XXE, external resource, embedded payload",
    ".mp3"            : "ID3 metadata, EOF overlay, entropy spike",
    ".wav"            : "LSB chi-square, entropy spike, EOF overlay",
    ".odt/.ods/.odp"  : "LibreOffice Basic macro detection, external references",
}

SUPPORTED_WITH_GENERIC_HEURISTICS_ONLY = {
    # These receive: universal entropy, YARA, PE detection, IOC extraction, hash DB
    # No format-specific deep parsing
    ".bmp"   : "Magic bytes only + universal layers. No chunk-level analysis.",
    ".gif"   : "EOF check + universal. No frame-level animation analysis.",
    ".tif/.tiff": "Magic bytes + universal. No IFD chain analysis.",
    ".webp"  : "RIFF/WEBP magic validation + universal. No VP8 chunk parsing.",
    ".heic"  : "ftyp magic + universal. No HEIF box parsing — complex proprietary format.",
    ".mkv/.webm": "EBML magic + universal. No deep EBML container parsing.",
    ".wmv/.flv/.mpeg": "Magic bytes + universal. No container-specific analysis.",
    ".ogg/.flac": "Magic bytes + universal. No codec-level analysis.",
    ".aac/.m4a/.wma": "Magic bytes + universal. Minimal audio-specific coverage.",
    ".xls/.ppt": "OLE magic + universal. Legacy binary format, partial coverage.",
    ".xlsx/.pptx": "ZIP magic + universal + macro detection. Full Office XML support.",
    ".rtf"   : "Magic bytes + universal. No RTF parser — complex escape sequences.",
}

NOT_SUPPORTED = {
    # Not in preprocessing — will be rejected at Stage 1
    ".exe/.dll/.sys" : "PE binaries — out of scope (media scanner, not PE scanner)",
    ".zip/.rar/.7z"  : "Archives — not directly supported, contents not inspected",
    ".html/.js"      : "Web formats — out of scope for this version",
}

# ── ML constants (silenteye_ml1 imports these from config) ────────────────────
IMAGE_MAX_DIM         = 1024
IMAGE_MIN_PIXELS      = 500
LSB_CHI_THRESHOLD     = 8.0
LSB_RATIO_TOLERANCE   = 0.006
RS_RATIO_THRESHOLD    = -0.04
RS_EMBED_THRESHOLD    = 0.10
ALPHA_MID_THRESHOLD   = 0.25
ALPHA_BIN_THRESHOLD   = 0.70
CORR_RG_THRESHOLD     = 0.70
CORR_GB_THRESHOLD     = 0.68
DCT_PM1_CHI_THRESHOLD = 0.15
DCT_AC_ZERO_THRESHOLD = 0.55
DCT_DC_VAR_THRESHOLD  = 0.60
VIDEO_HEAD_BYTES      = 5 * 1024 * 1024
VIDEO_TAIL_BYTES      = 256 * 1024
TRAIN_N_ESTIMATORS    = 100
TRAIN_MAX_DEPTH       = 6
TRAIN_SYNTHETIC_N     = 400
JPEG_EXTS             = {".jpg", ".jpeg"}
PNG_EXTS              = {".png", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".heic"}
IMAGE_EXTS            = JPEG_EXTS | PNG_EXTS
VIDEO_EXTS            = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mpeg", ".3gp", ".webm"}
SVG_EXTS              = {".svg", ".svgz"}
THRESHOLDS = {
    "image_jpg":       {"malicious": 0.40, "clean": 0.20},
    "image_png_alpha": {"malicious": 0.45, "clean": 0.20},
    "video":           {"malicious": 0.70, "clean": 0.40},
    "svg":             {"malicious": 0.40, "clean": 0.20},
}
import os as _os
_ML_MODELS_DIR = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "silenteye_ml1", "trained_models")
MODEL_PATHS = {
    "image_jpg":       _os.path.join(_ML_MODELS_DIR, "image_jpg_model.pkl"),
    "image_png_alpha": _os.path.join(_ML_MODELS_DIR, "image_png_alpha_model.pkl"),
    "video":           _os.path.join(_ML_MODELS_DIR, "video_model.pkl"),
    "svg":             _os.path.join(_ML_MODELS_DIR, "svg_model.pkl"),
}