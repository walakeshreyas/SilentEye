import re
import gzip
from typing import Dict
from .universal import calculate_entropy

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SVG_ALWAYS_DANGEROUS, MAX_SVGZ_DECOMPRESSED_BYTES, MAX_SVGZ_RATIO, SUSPICIOUS_DOMAINS, SUSPICIOUS_TLDS

# ================================
# SVG UTILITIES
# ================================

def _get_svg_content(file_bytes: bytes, ext: str) -> bytes:
    """
    Returns decoded SVG text content.
    For .svgz: decompresses GZIP first with bomb protection.
    For .svg:  returns raw bytes.
    FIXED: Bug 5 — added decompression bomb guard.
    A crafted SVGZ can have tiny compressed size but expand to gigabytes.
    Guard 1: reject if compressed_size * MAX_SVGZ_RATIO < expected decompressed size
    Guard 2: hard cap at MAX_SVGZ_DECOMPRESSED_BYTES (10MB)
    """
    if ext == ".svgz":
        try:
            compressed_size = len(file_bytes)
            # Check ratio guard before decompressing — read first 20 bytes of gzip
            # to estimate uncompressed size (stored in last 4 bytes of gzip)
            if len(file_bytes) >= 4:
                import struct
                # GZIP stores uncompressed size mod 2^32 in last 4 bytes
                estimated_size = struct.unpack("<I", file_bytes[-4:])[0]
                if estimated_size > MAX_SVGZ_DECOMPRESSED_BYTES:
                    return file_bytes  # refuse decompression — likely bomb
                if compressed_size > 0 and estimated_size / compressed_size > MAX_SVGZ_RATIO:
                    return file_bytes  # ratio too high — likely bomb

            decompressed = gzip.decompress(file_bytes)

            # Hard cap — even if ratio check passed
            if len(decompressed) > MAX_SVGZ_DECOMPRESSED_BYTES:
                return decompressed[:MAX_SVGZ_DECOMPRESSED_BYTES]

            return decompressed
        except Exception:
            return file_bytes  # if decompression fails return raw
    return file_bytes

# ================================
# SVG LAYER 1 — SCRIPT & JS CHECK
# ================================
#
# Catches JS execution patterns that Stage 1 may have missed
# (Stage 1 only reads 16KB — large SVGs may have payloads deeper in the file)
# Stage 2 reads the full file, so this catches payloads in later sections.

# SVG_ALWAYS_DANGEROUS imported from config.py — single definition, no duplication

def run_svg_script_check(file_bytes: bytes, ext: str) -> Dict:

    content = _get_svg_content(file_bytes, ext)
    low     = content.lower()
    findings = []

    for sig in SVG_ALWAYS_DANGEROUS:
        if sig in low:
            findings.append(sig.decode("latin-1", errors="ignore"))

    detected = len(findings) > 0

    return {
        "layer":    "svg_script_check",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score":    85 if detected else 0,
        "reason":   f"SVG dangerous patterns: {findings[:3]}" if detected else "No script/JS patterns"
    }

# ================================
# SVG LAYER 2 — XXE DETECTION
# ================================
#
# XXE (XML External Entity) injection via <!ENTITY SYSTEM "file:///etc/passwd">
# This is a data exfiltration attack specific to XML parsers.
# Stage 1 does not check for this.

def run_svg_xxe_check(file_bytes: bytes, ext: str) -> Dict:

    content = _get_svg_content(file_bytes, ext)
    low     = content.lower()
    findings = []

    if b"<!entity" in low:
        # Only flag if SYSTEM or PUBLIC keyword present — these load external resources
        if b"system" in low or b"public" in low:
            matches = re.findall(rb"<!entity\s+\w+\s+(?:system|public)[^>]{0,200}>", content, re.IGNORECASE)
            for m in matches:
                findings.append(m[:80].decode("latin-1", errors="ignore"))

    detected = len(findings) > 0

    return {
        "layer":    "svg_xxe_check",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score":    80 if detected else 0,
        "reason":   f"XXE entity injection: {findings[0]}" if detected else "No XXE patterns"
    }

# ================================
# SVG LAYER 3 — EXTERNAL RESOURCE
# ================================
#
# Checks for external URLs loaded by SVG elements.
# Malicious SVGs often pull payloads from C2 servers via:
#   - xlink:href="http://evil.com/payload"
#   - <image href="http://evil.com/track.png"> (SSRF / tracking)
#   - <?xml-stylesheet href="http://evil.com/css"> (CSS injection)
#
# FALSE POSITIVE PROTECTION:
#   - xlink:href pointing to #internal-id is always clean (starts with #)
#   - <image href= pointing to a local file path is clean
#   - Only flag if URL is to a suspicious domain or uses javascript:/data: scheme

# SUSPICIOUS_TLDS and SUSPICIOUS_DOMAINS imported from config.py

def run_svg_external_resource_check(file_bytes: bytes, ext: str) -> Dict:

    content  = _get_svg_content(file_bytes, ext)
    findings = []

    try:
        from urllib.parse import urlparse

        # xlink:href — skip internal refs (#id) and relative paths
        for val in re.findall(rb'xlink:href\s*=\s*["\']([^"\']{0,300})["\']', content, re.IGNORECASE):
            val_str = val.decode("latin-1", errors="ignore").strip()

            if val_str.startswith("#"):      # internal reference — always clean
                continue
            if val_str.startswith("data:"):  # data URI — handled by script check
                continue

            if val_str.startswith("http"):
                try:
                    domain = urlparse(val_str).netloc.lower()
                    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or \
                       any(bad in domain for bad in SUSPICIOUS_DOMAINS):
                        findings.append(f"xlink:href suspicious URL: {val_str[:80]}")
                except Exception:
                    pass

        # <image href= — only flag external suspicious URLs
        for val in re.findall(rb'<image[^>]{0,200}href\s*=\s*["\']([^"\']{0,300})["\']', content, re.IGNORECASE):
            val_str = val.decode("latin-1", errors="ignore").strip()
            if val_str.startswith("http"):
                try:
                    domain = urlparse(val_str).netloc.lower()
                    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or \
                       any(bad in domain for bad in SUSPICIOUS_DOMAINS):
                        findings.append(f"image href suspicious URL: {val_str[:80]}")
                except Exception:
                    pass

        # <?xml-stylesheet — flag any external URL (CSS from unknown source)
        if b"<?xml-stylesheet" in content.lower():
            for val in re.findall(rb'href\s*=\s*["\']([^"\']{0,300})["\']', content, re.IGNORECASE):
                val_str = val.decode("latin-1", errors="ignore").strip()
                if val_str.startswith("http"):
                    try:
                        domain = urlparse(val_str).netloc.lower()
                        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or \
                           any(bad in domain for bad in SUSPICIOUS_DOMAINS):
                            findings.append(f"xml-stylesheet suspicious URL: {val_str[:80]}")
                    except Exception:
                        pass

    except Exception:
        pass

    detected = len(findings) > 0

    return {
        "layer":    "svg_external_resource_check",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    45 if detected else 0,
        "reason":   f"External resource: {findings[0]}" if detected else "No suspicious external resources"
    }

# ================================
# SVG LAYER 4 — EMBEDDED PAYLOAD
# ================================
#
# Checks for binary payloads hidden inside SVG:
#   - PE/ELF header embedded in base64 data URI
#   - High-entropy base64 blob in any attribute (encrypted payload)
#   - MZ/ELF bytes directly in the file content
#
# SVG is XML — it should contain only text and small data URIs.
# Large high-entropy base64 blobs have no legitimate use in SVG.

import base64
import math
from collections import Counter

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq  = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

def run_svg_embedded_payload_check(file_bytes: bytes, ext: str) -> Dict:

    content  = _get_svg_content(file_bytes, ext)
    findings = []

    # Check for PE/ELF directly in file
    if b"\x4D\x5A" in content[32:] or b"\x7fELF" in content[32:]:
        findings.append("PE/ELF header embedded in SVG content")

    # Check base64 data URIs for executable payloads
    b64_pattern = re.compile(rb'base64,([A-Za-z0-9+/]{100,}={0,2})')
    for match in b64_pattern.finditer(content):
        try:
            decoded = base64.b64decode(match.group(1) + b"==")

            # Executable payload
            if decoded[:2] == b"\x4D\x5A" or decoded[:4] == b"\x7fELF":
                findings.append("Executable payload in base64 data URI")
                break

            # Large encrypted blob — no legitimate use in SVG
            if len(decoded) > 10240 and _entropy(decoded) > 7.8:
                findings.append(f"Large encrypted base64 blob in SVG: {len(decoded)} bytes")
                break

        except Exception:
            pass

    detected = len(findings) > 0

    return {
        "layer":    "svg_embedded_payload_check",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score":    85 if detected else 0,
        "reason":   str(findings[0]) if detected else "No embedded payloads found"
    }
