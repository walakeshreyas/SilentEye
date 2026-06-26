import re
from typing import Dict

# ================================
# DOC LAYER 1 — MACRO DETECTION
# ================================
#
# FIX: CreateObject and WScript.Shell appear in many Office templates,
#   COM automation add-ins, and legitimate business documents. We now
#   require BOTH a macro signature AND a shell execution signature to
#   reach "high". A macro alone is only "medium".

MACRO_SIGNATURES = [
    b"VBAProject",
    b"ThisDocument",
    b"AutoOpen",
    b"AutoExec",
    b"Auto_Open",
    b"AutoClose",
    b"Document_Open",
    b"Workbook_Open",
]

SHELL_SIGNATURES = [
    b"Shell(",
    b"WScript.Shell",
    b"cmd.exe",
    b"powershell",
    b"mshta",
    b"wscript",
    b"cscript",
    b"regsvr32",
    b"rundll32",
]

# Signatures that are extremely common in legitimate Office files
# and should not independently count as suspicious
COMMON_OFFICE_STRINGS = {
    b"CreateObject",  # used by mail merge, COM automation, etc.
}

# Macro-enabled format identifiers inside ZIP container
# These strings appear in [Content_Types].xml of .docm/.xlsm/.pptm
MACRO_ENABLED_CONTENT_TYPES = [
    b"application/vnd.ms-office.activex",
    b"application/vnd.ms-word.document.macroEnabled",
    b"application/vnd.ms-excel.sheet.macroEnabled",
    b"application/vnd.ms-powerpoint.presentation.macroEnabled",
    b"vbaProject.bin",   # VBA binary present in ZIP = macro-enabled
]

def run_macro_detection(file_bytes: bytes, ext: str = "") -> Dict:

    macro_hits = []
    shell_hits = []
    lfile = file_bytes.lower()

    # ADDED: macro-enabled format fast-path
    # .docm/.xlsm/.pptm always contain VBA — flag immediately
    # Don't wait for VBAProject string scan — Content_Types confirms it
    if ext in (".docm", ".xlsm", ".pptm", ".dotm", ".xltm"):
        macro_hits.append(f"Macro-enabled format ({ext})")
        # Still check for shell execution — determines severity
    
    # Check for macro-enabled content type markers in ZIP container
    for marker in MACRO_ENABLED_CONTENT_TYPES:
        if marker in file_bytes:
            if "Macro-enabled format" not in str(macro_hits):
                macro_hits.append(f"VBA content type: {marker.decode('latin-1')}")
            break

    for sig in MACRO_SIGNATURES:
        if sig.lower() in lfile:
            macro_hits.append(sig.decode("latin-1"))

    for sig in SHELL_SIGNATURES:
        if sig.lower() in lfile:
            shell_hits.append(sig.decode("latin-1"))

    findings = []
    if macro_hits:
        findings.append({"type": "VBA macro signatures", "values": macro_hits})
    if shell_hits:
        findings.append({"type": "Shell execution signatures", "values": shell_hits})

    detected = len(findings) > 0

    # FIX: require BOTH macro + shell to reach high severity
    if macro_hits and shell_hits:
        severity = "high"
        score = 85
    elif shell_hits:
        # shell without macro context is suspicious but not definitively high
        severity = "medium"
        score = 50
    elif macro_hits:
        severity = "medium"
        score = 40
    else:
        severity = "none"
        score = 0

    return {
        "layer":    "macro_detection",
        "detected": detected,
        "severity": severity,
        "score":    score,
        "reason":   f"Macro/shell signatures found: {[f['type'] for f in findings]}" if detected else "No macro signatures found",
        "findings": findings
    }

# ================================
# DOC LAYER 2 — OLE INSPECTION
# ================================

OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

def run_ole_inspection(file_bytes: bytes) -> Dict:

    findings = []
    is_ole = file_bytes[:8] == OLE_MAGIC

    if is_ole:
        findings.append({"type": "OLE format detected (legacy Office)"})

        suspicious_streams = [
            b"\x01CompObj",
            b"Macros",
            b"VBA",
            b"_VBA_PROJECT",
        ]
        for stream in suspicious_streams:
            if stream in file_bytes:
                findings.append({"type": f"Suspicious OLE stream: {stream.decode('latin-1')}"})

    detected = len(findings) > 1
    severity = "high" if len(findings) >= 3 else "medium" if detected else "none"
    score    = 70 if severity == "high" else 40 if detected else 0

    return {
        "layer":    "ole_inspection",
        "detected": detected,
        "severity": severity,
        "score":    score,
        "reason":   f"OLE anomalies: {[f['type'] for f in findings]}" if detected else "No suspicious OLE structures",
        "findings": findings
    }

# ================================
# DOC LAYER 3 — EXTERNAL RELATIONSHIP
# ================================
#
# FIX: This was the single biggest false positive source.
#   ANY external HTTP link in a DOCX was flagged as severity=HIGH and
#   score=65, immediately triggering verdict=malicious.
#
#   Root cause: every DOCX with a hyperlink (e.g. a link to a website)
#   has a Target="https://..." in its .rels file. This is completely
#   normal — it's how all hyperlinks work in OpenXML.
#
#   Fix:
#     - HTTP/HTTPS external links → low severity, score=15 (they're normal)
#     - FTP links → medium (unusual in documents)
#     - UNC paths (\\server\share) → high (rare, often lateral movement)
#     - TargetMode=External alone → not flagged (it just means "outside the ZIP")

def run_external_relationship_check(file_bytes: bytes) -> Dict:

    findings = []

    try:
        text = file_bytes.decode("latin-1", errors="ignore")

        # High severity: UNC paths (unusual in docs, often C2)
        unc_matches = re.findall(r'Target="(\\\\[^"]+)"', text, re.IGNORECASE)
        if unc_matches:
            findings.append({
                "type":     "UNC path reference",
                "severity": "high",
                "score":    70,
                "values":   unc_matches[:3]
            })

        # Medium severity: FTP links (not common in normal docs)
        ftp_matches = re.findall(r'Target="(ftp://[^"]+)"', text, re.IGNORECASE)
        if ftp_matches:
            findings.append({
                "type":     "External FTP link",
                "severity": "medium",
                "score":    35,
                "values":   ftp_matches[:3]
            })

        # Low severity: HTTP/HTTPS links — completely normal in DOCX
        # Only note them as low; they contribute almost nothing to scoring
        http_matches = re.findall(r'Target="(https?://[^"]+)"', text, re.IGNORECASE)
        if len(http_matches) > 20:
            # More than 20 external HTTP links is unusual (possible phishing doc)
            findings.append({
                "type":     "Excessive external HTTP links",
                "severity": "low",
                "score":    15,
                "values":   http_matches[:5]
            })

    except Exception:
        pass

    if not findings:
        return {
            "layer":    "external_relationship_check",
            "detected": False,
            "severity": "none",
            "score":    0,
            "reason":   "No suspicious external relationships found",
            "findings": []
        }

    # Use the highest severity finding
    top = max(findings, key=lambda f: f["score"])
    detected = True

    return {
        "layer":    "external_relationship_check",
        "detected": detected,
        "severity": top["severity"],
        "score":    top["score"],
        "reason":   f"External relationships: {[f['type'] for f in findings]}",
        "findings": findings
    }

# ================================
# DOC LAYER 4 — XML ANOMALY
# ================================
#
# FIX: "instrtext" and "field char" appear in virtually every Word document
#   that has page numbers, a Table of Contents, cross-references, or mail
#   merge fields. These are completely normal OpenXML constructs.
#
#   Fix: Remove instrtext and field char from the baseline checks.
#   Only flag patterns that are genuinely anomalous in a document:
#     - <script> tags (XML documents should never have these)
#     - javascript: URIs
#     - vbaproject.bin references (embedded macro binary)
#     - DDE fields (specifically the DDEAUTO variant, which auto-executes)

def run_xml_anomaly_check(file_bytes: bytes) -> Dict:

    findings = []

    try:
        text = file_bytes.decode("latin-1", errors="ignore").lower()

        # Genuinely suspicious in a document context
        xml_checks = [
            ("<script",        "Script tag in document XML"),
            ("javascript:",    "JavaScript URI in document"),
            ("vbaproject.bin", "VBA binary reference"),
            ("ddeauto",        "DDE Auto-execute field"),  # DDEAUTO, not plain DDE
        ]

        for pattern, label in xml_checks:
            if pattern in text:
                findings.append({"type": label, "pattern": pattern})

    except Exception:
        pass

    detected = len(findings) > 0
    severity = "high" if len(findings) >= 2 else "medium" if detected else "none"
    score    = 70 if severity == "high" else 40 if detected else 0

    return {
        "layer":    "xml_anomaly_check",
        "detected": detected,
        "severity": severity,
        "score":    score,
        "reason":   f"XML anomalies found: {[f['type'] for f in findings]}" if detected else "XML structure appears clean",
        "findings": findings
    }

# ================================
# DOC LAYER 5 — KNOWN EXPLOIT SIGNATURES
# ================================
#
# FN safety net for DOCX/DOC scanning.
# Yeh patterns hamesha malicious hote hain — entropy threshold se independent.
# Agar FP fix ke wajah se koi layer miss kare, yeh pakdega.

ALWAYS_MALICIOUS_DOC_PATTERNS = [
    # DDE command execution — no legitimate use
    (b"ddeauto",          "DDEAUTO field (auto-execute on open)"),
    (b"dde ",             "DDE field command"),
    # Equation Editor exploit (CVE-2017-11882) — extremely common malware vector
    (b"equation native",  "Equation Editor (CVE-2017-11882 vector)"),
    (b"Microsoft Equation 3.0", "Equation Editor 3.0 (known exploit target)"),
    # Direct shell patterns in DOCX XML
    (b"cmd.exe",          "cmd.exe in document"),
    (b"powershell",       "PowerShell in document"),
    (b"mshta",            "mshta in document"),
    # Template injection via external relationship
    (b"attachedtemplate", "External template injection"),
    (b"oleobject",        "OLE object embedding"),
]

def run_doc_exploit_signatures(file_bytes: bytes) -> Dict:
    """
    Checks for known malicious DOCX/DOC patterns that are ALWAYS suspicious.
    This is the FN safety net — independent of entropy or other thresholds.
    """
    findings = []

    try:
        lfile = file_bytes.lower()

        for pattern, label in ALWAYS_MALICIOUS_DOC_PATTERNS:
            if pattern in lfile:
                findings.append(label)

        # Template injection: external URL in relationships pointing to .dotm/.dotx
        text = file_bytes.decode("latin-1", errors="ignore")
        template_matches = re.findall(
            r'Target="(https?://[^"]+\.dot[mx]?)"', text, re.IGNORECASE
        )
        if template_matches:
            findings.append(f"External template URL: {template_matches[0][:80]}")

        # Hex-encoded shell commands (obfuscation)
        hex_patterns = re.findall(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}', text)
        if hex_patterns:
            findings.append("Hex-encoded content in document (obfuscation)")

    except Exception:
        pass

    detected = len(findings) > 0

    return {
        "layer":    "doc_exploit_signatures",
        "detected": detected,
        "severity": "high" if detected else "none",
        "score":    85 if detected else 0,
        "reason":   f"Known exploit signatures: {findings[:3]}" if detected else "No known exploit signatures"
    }


# ================================
# DOC LAYER 6 — ODT/ODS/ODP INSPECTION
# ================================
#
# OpenDocument Format (LibreOffice) files are ZIP-based XML.
# Structure identical to DOCX — content.xml holds document body,
# macros live in Basic/ directory as .xba files.
#
# Malware vectors in ODF:
#   1. Basic macros (LibreOffice equivalent of VBA)
#   2. External data sources (linked spreadsheet data)
#   3. Script elements in content.xml
#   4. Embedded OLE objects
#
# Paper justification: ODF formats used in targeted attacks against
# Linux/Mac users where Office formats are less common.
# LibreOffice macro execution = same risk as VBA macros.

ODF_MACRO_SIGNATURES = [
    b"Basic/",              # LibreOffice Basic macro directory in ZIP
    b"macros/",             # Macro subdirectory
    b"script:module",       # Basic module declaration
    b"StarBasic",           # Legacy StarOffice Basic
    b"com.sun.star.script", # UNO API script reference
    b"Shell(",              # Shell execution in Basic
    b"CreateUnoService",    # Service creation (used for shell exec)
    b"environ(",            # Environment variable access
]

ODF_EXTERNAL_SIGNATURES = [
    b'xlink:href="http',   # External HTTP link in content
    b'xlink:href="ftp',    # External FTP link
    b"database:query",     # External database connection
    b"text:section",       # Section with external link
]

def run_odf_inspection(file_bytes: bytes, ext: str) -> Dict:
    """
    Inspects ODT/ODS/ODP files for macro and external reference threats.
    Only called for .odt/.ods/.odp extensions.
    """
    if ext not in (".odt", ".ods", ".odp"):
        return {"layer": "odf_inspection", "detected": False, "severity": "none", "score": 0}

    findings = []

    try:
        # ODF is ZIP — scan the raw bytes for macro signatures
        lfile = file_bytes.lower()

        macro_hits = []
        for sig in ODF_MACRO_SIGNATURES:
            if sig.lower() in lfile:
                macro_hits.append(sig.decode("latin-1"))

        if macro_hits:
            findings.append({"type": "LibreOffice macro signatures", "values": macro_hits})

        # External resource links
        ext_hits = []
        for sig in ODF_EXTERNAL_SIGNATURES:
            if sig.lower() in lfile:
                ext_hits.append(sig.decode("latin-1"))

        if ext_hits:
            findings.append({"type": "External references in ODF", "values": ext_hits})

        # Shell execution — always high severity regardless of context
        shell_sigs = [b"Shell(", b"CreateUnoService", b"com.sun.star.bridge"]
        shell_hits = [s.decode("latin-1") for s in shell_sigs if s.lower() in lfile]
        if shell_hits:
            findings.append({"type": "Shell execution in ODF macro", "values": shell_hits})

    except Exception:
        pass

    detected = len(findings) > 0

    # High if macro + shell, medium if macro only, low if external links only
    has_shell  = any("Shell" in str(f) for f in findings)
    has_macro  = any("macro" in str(f).lower() for f in findings)

    if has_shell and has_macro:
        severity, score = "high",   80
    elif has_macro:
        severity, score = "medium", 45
    elif detected:
        severity, score = "low",    20
    else:
        severity, score = "none",   0

    return {
        "layer":    "odf_inspection",
        "detected": detected,
        "severity": severity,
        "score":    score,
        "reason":   f"ODF findings: {[f['type'] for f in findings]}" if detected else "ODF structure clean",
        "findings": findings
    }
