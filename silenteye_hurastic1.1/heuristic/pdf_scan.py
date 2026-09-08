import re
from typing import Dict
from .universal import calculate_entropy

# ================================
# PDF LAYER 1 — STRUCTURE ANALYSIS
# ================================

def run_pdf_structure_analysis(file_bytes: bytes) -> Dict:

    findings = []

    try:
        text = file_bytes.decode("latin-1", errors="ignore")

        has_js      = "/JavaScript" in text or "/JS " in text
        has_launch  = "/Launch"      in text
        has_submit  = "/SubmitForm"  in text
        has_uri     = "/URI"         in text
        has_aa      = "/AA"          in text   # Additional Actions — auto-execute on open/close/print
        has_openact = "/OpenAction"  in text   # Runs on document open
        has_richmedia = "/RichMedia" in text   # Flash/multimedia exploit vector
        has_acroform  = "/AcroForm"  in text

        # HIGH — confirmed execution chains
        if has_js and has_launch:
            findings.append({"type": "JavaScript + Launch action", "severity": "high", "score": 80})

        if has_js and has_submit:
            findings.append({"type": "JavaScript + SubmitForm", "severity": "high", "score": 75})

        # HIGH — /Launch without JS is also dangerous (shell execution)
        if has_launch and not has_js:
            findings.append({"type": "Launch action without JS (direct shell exec)", "severity": "high", "score": 70})

        # HIGH — /OpenAction + /Launch = auto-execute on open
        if has_openact and has_launch:
            findings.append({"type": "OpenAction + Launch (auto-exec on open)", "severity": "high", "score": 85})

        # MEDIUM — JS with URI (data exfil / phishing redirect)
        if has_js and has_uri and not has_launch:
            findings.append({"type": "JavaScript + URI action", "severity": "medium", "score": 35})

        # MEDIUM — /AA (Additional Actions) with JS = triggered on page events
        if has_aa and has_js:
            findings.append({"type": "Additional Actions + JavaScript", "severity": "medium", "score": 45})

        # MEDIUM — /RichMedia (Flash exploit vector — legacy but still in the wild)
        if has_richmedia:
            findings.append({"type": "RichMedia (Flash exploit vector)", "severity": "medium", "score": 40})

        # LOW — standalone /OpenAction without launch (could be legitimate zoom/goto)
        # Only flag if combined with JS
        if has_openact and has_js and not has_launch:
            findings.append({"type": "OpenAction + JavaScript", "severity": "medium", "score": 40})

    except Exception:
        pass

    if not findings:
        return {"layer": "pdf_structure_analysis", "detected": False,
                "severity": "none", "score": 0, "reason": "No malicious PDF actions"}

    top = max(findings, key=lambda f: f["score"])
    return {
        "layer":    "pdf_structure_analysis",
        "detected": True,
        "severity": top["severity"],
        "score":    top["score"],
        "reason":   f"PDF action: {[f['type'] for f in findings]}"
    }

# ================================
# PDF LAYER 2 — EMBEDDED FILES
# ================================

def run_pdf_embedded_check(file_bytes: bytes) -> Dict:

    findings = []

    try:
        text = file_bytes.decode("latin-1", errors="ignore").lower()

        embed_positions = [m.start() for m in re.finditer(r"/embeddedfile|/filespec", text)]
        if not embed_positions:
            return {"layer": "pdf_embedded_check", "detected": False,
                    "severity": "none", "score": 0, "reason": "No embedded files"}

        exe_pattern = re.compile(r"\.(exe|bat|cmd|ps1|vbs|js|scr|msi)\b")
        for pos in embed_positions:
            context = text[max(0, pos - 100): pos + 512]
            if exe_pattern.findall(context):
                findings.append("Executable near EmbeddedFile object")

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "pdf_embedded_check",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score":    80 if detected else 0,
        "reason":   str(findings) if detected else "No executable embedded files"
    }

# ================================
# PDF LAYER 3 — STREAM ENTROPY
# ================================

PDF_STREAM_SCAN_LIMIT  = 5 * 1024 * 1024   # scan first 5MB only
PDF_STREAM_MAX_MATCHES = 200                 # process at most 200 stream objects

def run_pdf_stream_entropy(file_bytes: bytes) -> Dict:

    findings = []

    try:
        
        scan_data = file_bytes[:PDF_STREAM_SCAN_LIMIT]
        pattern   = re.compile(b"stream\r?\n(.*?)endstream", re.DOTALL)

        for i, match in enumerate(pattern.finditer(scan_data)):
            
            if i >= PDF_STREAM_MAX_MATCHES:
                break

            stream = match.group(1)

            if len(stream) < 50000:
                continue

            entropy = calculate_entropy(stream)

            if entropy > 7.97 and len(stream) > 100000:
                start_pos = match.start()
                context   = scan_data[max(0, start_pos - 512):start_pos].decode("latin-1", errors="ignore")

                # Skip known legitimate high-entropy stream types
                legitimate = (
                    "/Image"      in context or
                    "/Font"       in context or
                    "/XObject"    in context or
                    "FlateDecode" in context or
                    "DCTDecode"   in context or
                    "JPXDecode"   in context or
                    "CCITTFax"    in context
                )
                if legitimate:
                    continue

                findings.append(f"Suspicious stream: {len(stream)} bytes, entropy={entropy}")
                break

    except Exception:
        pass

    detected = len(findings) > 0
    return {
        "layer":    "pdf_stream_entropy",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "score":    40 if detected else 0,
        "reason":   str(findings) if detected else "PDF streams within normal range"
    }

# ================================
# PDF LAYER 4 — OBJECT COUNT
# ================================

def run_pdf_object_count(file_bytes: bytes) -> Dict:

    try:
        text  = file_bytes.decode("latin-1", errors="ignore")
        count = len(re.findall(r"\d+\s+\d+\s+obj", text))

       
        if count >= 10000:
            return {
                "layer":    "pdf_object_count",
                "detected": True,
                "severity": "high",
                "score":    70,
                "reason":   f"Extreme object count: {count} — strong heap spray indicator"
            }
        elif count >= 5000:
            return {
                "layer":    "pdf_object_count",
                "detected": True,
                "severity": "high",
                "score":    60,
                "reason":   f"Very high object count: {count} — likely heap spray"
            }
        elif count >= 3500:
            
            return {
                "layer":    "pdf_object_count",
                "detected": True,
                "severity": "low",
                "score":    20,
                "reason":   f"Elevated object count: {count} (complex document)"
            }

    except Exception:
        pass

    return {
        "layer":    "pdf_object_count",
        "detected": False,
        "severity": "none",
        "score":    0,
        "reason":   "Object count within normal range"
    }

# ================================
# PDF LAYER 5 — KNOWN EXPLOIT SIGNATURES
# ================================

ALWAYS_MALICIOUS_PDF_PATTERNS = [
    # Obfuscated JavaScript via name tree — common evasion
    (rb"/Names\s*\[.*?/JavaScript", "Obfuscated JS via Names tree (evasion)"),
    # Shell command patterns in PDF content
    (rb"cmd\.exe", "cmd.exe reference in PDF"),
    (rb"powershell", "PowerShell in PDF"),
    (rb"mshta\.exe", "mshta.exe in PDF"),
    (rb"wscript\.exe", "wscript.exe in PDF"),
    (rb"cscript\.exe", "cscript.exe in PDF"),
    # CVE-2010-0188 / classic JBIG2 exploit signature
    (rb"JBIG2Decode.*?JavaScript", "JBIG2 + JavaScript (CVE exploit pattern)"),
    # /URI with javascript: scheme (XSS-style in PDF)
    (rb"/URI\s*\(javascript:", "JavaScript URI scheme in PDF"),
    (rb"/URI\s*<.*?javascript:", "JavaScript URI scheme (hex encoded) in PDF"),
]

def run_pdf_exploit_signatures(file_bytes: bytes) -> Dict:
    """
    Checks for known malicious PDF patterns that are ALWAYS suspicious
    regardless of entropy thresholds or other tuning.
    This is the FN safety net for PDF scanning.
    """
    findings = []

    try:
        # Check raw bytes for binary patterns
        for pattern, label in ALWAYS_MALICIOUS_PDF_PATTERNS:
            if re.search(pattern, file_bytes, re.IGNORECASE | re.DOTALL):
                findings.append(label)

        # Also decode and check text
        text = file_bytes.decode("latin-1", errors="ignore")

        # /F with executable extension near /Launch — file launch exploit
        launch_positions = [m.start() for m in re.finditer(r"/Launch", text)]
        exe_pattern = re.compile(r"\.(exe|bat|cmd|ps1|vbs|scr|msi|com)\b", re.IGNORECASE)
        for pos in launch_positions:
            context = text[max(0, pos - 200): pos + 200]
            if exe_pattern.search(context):
                findings.append(f"Launch action targeting executable file")
                break

        # Hex-encoded JavaScript (obfuscation evasion)
        # Pattern: /JS <hex digits> — hex string containing "javascript"
        hex_js = re.findall(r"/(?:JS|JavaScript)\s*<([0-9a-fA-F\s]{20,})>", text)
        for hx in hex_js:
            try:
                decoded = bytes.fromhex(hx.replace(" ", "").replace("\n", ""))
                if b"eval" in decoded.lower() or b"unescape" in decoded.lower():
                    findings.append("Hex-obfuscated JavaScript with eval/unescape")
                    break
            except Exception:
                pass

    except Exception:
        pass

    detected = len(findings) > 0

    return {
        "layer":    "pdf_exploit_signatures",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score":    90 if detected else 0,
        "reason":   f"Known exploit signatures: {findings[:3]}" if detected else "No known exploit signatures"
    }
