// ============================================================
// SilentEye YARA Rules v3 — FP-reduced
//
// CHANGES FROM v2:
//   - office_macro_shell_combined: raised condition from 2→3 strings
//       + added filesize guard. 2 shell strings fired on any sysadmin doc.
//   - suspicious_commands: raised from 2→3 strings required.
//       wget+curl appeared in every Linux tutorial PDF.
//   - darkweb_indicators: removed .onion (duplicate of suspicious_urls).
//       Both rules had .onion — caused double YARA hits on same pattern.
//   - known_malware_families: removed Metasploit and meterpreter.
//       These appear in every pentest report and security research paper.
//       Kept only confirmed malware family names not used in legitimate docs.
// ============================================================


// ============================================================
// CATEGORY 1 — Executable inside media
// Solid rules — image header AT offset 0 + valid PE = very low FP
// ============================================================

rule exe_inside_image
{
    meta:
        description = "Windows PE executable hidden inside image file"
        severity    = "high"
        score       = 90

    strings:
        $jpg  = { FF D8 FF }
        $png  = { 89 50 4E 47 }
        $mz   = { 4D 5A }
        $pe   = { 50 45 00 00 }

    condition:
        ($jpg at 0 or $png at 0) and $mz and $pe
}

rule elf_inside_image
{
    meta:
        description = "Linux ELF executable hidden inside image"
        severity    = "high"
        score       = 90

    strings:
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 }
        $elf = { 7F 45 4C 46 }

    condition:
        ($jpg at 0 or $png at 0) and $elf
}

rule exe_inside_pdf
{
    meta:
        description = "Windows PE executable hidden inside PDF"
        severity    = "high"
        score       = 90

    strings:
        $pdf = { 25 50 44 46 }
        $mz  = { 4D 5A }
        $pe  = { 50 45 00 00 }

    condition:
        $pdf at 0 and $mz and $pe
}

rule exe_inside_audio
{
    meta:
        description = "Windows PE executable hidden inside audio file"
        severity    = "high"
        score       = 90

    strings:
        $mp3 = { 49 44 33 }
        $wav = { 52 49 46 46 }
        $mz  = { 4D 5A }
        $pe  = { 50 45 00 00 }

    condition:
        ($mp3 at 0 or $wav at 0) and $mz and $pe
}


// ============================================================
// CATEGORY 2 — Malicious PDF patterns
// ============================================================

rule malicious_pdf_js_launch
{
    meta:
        description = "PDF JavaScript combined with Launch action — execution risk"
        severity    = "high"
        score       = 90

    strings:
        $pdf    = "%PDF"
        $js1    = "/JavaScript"
        $js2    = "/JS"
        $launch = "/Launch"

    condition:
        $pdf at 0 and any of ($js1, $js2) and $launch
}

rule malicious_pdf_js_submit
{
    meta:
        description = "PDF JavaScript with SubmitForm — data exfiltration"
        severity    = "high"
        score       = 80

    strings:
        $pdf    = "%PDF"
        $js1    = "/JavaScript"
        $js2    = "/JS"
        $submit = "/SubmitForm"

    condition:
        $pdf at 0 and any of ($js1, $js2) and $submit
}

rule malicious_pdf_embedded_exe
{
    meta:
        description = "PDF has embedded file with executable extension"
        severity    = "high"
        score       = 85

    strings:
        $pdf  = "%PDF"
        $emb  = "/EmbeddedFile"
        $exe1 = ".exe" nocase
        $exe2 = ".bat" nocase
        $exe3 = ".ps1" nocase
        $exe4 = ".vbs" nocase
        $exe5 = ".cmd" nocase
        $exe6 = ".scr" nocase

    condition:
        $pdf at 0 and $emb and any of ($exe1, $exe2, $exe3, $exe4, $exe5, $exe6)
}


// ============================================================
// CATEGORY 3 — Office macro detection
//
// FIXED: office_macro_shell_combined
//   Old condition: 2 of them
//   Problem: cmd.exe + powershell appear in every IT documentation PDF,
//            Windows sysadmin guide, or pentest methodology doc.
//            No format constraint = fired on everything.
//   Fix: require 3 strings + filesize < 15MB (binary Office files are
//        not multi-hundred-MB documents)
// ============================================================

rule office_vba_macro_with_execution
{
    meta:
        description = "Office VBA macro with execution capability"
        severity    = "high"
        score       = 80

    strings:
        $vba1 = "VBAProject"
        $vba2 = "AutoOpen"
        $vba3 = "AutoExec"
        $vba4 = "Auto_Open"
        $vba5 = "Document_Open"
        $vba6 = "Workbook_Open"

        $exec1 = "Shell("        nocase
        $exec2 = "WScript.Shell" nocase
        $exec3 = "cmd.exe"       nocase
        $exec4 = "powershell"    nocase
        $exec5 = "mshta"         nocase
        $exec6 = "rundll32"      nocase
        $exec7 = "regsvr32"      nocase

    condition:
        any of ($vba*) and any of ($exec*)
}

rule office_macro_shell_combined
{
    meta:
        description = "Office document with multiple shell execution indicators"
        severity    = "high"
        score       = 90

    strings:
        $s1 = "Shell("        nocase
        $s2 = "WScript.Shell"  nocase
        $s3 = "cmd.exe"        nocase
        $s4 = "powershell"     nocase
        $s5 = "mshta"          nocase
        $s6 = "wscript.exe"    nocase
        $s7 = "cscript.exe"    nocase
        $s8 = "regsvr32"       nocase
        $s9 = "rundll32"       nocase

    condition:
        // FIXED: raised from 2→3 strings required
        //   2 strings (e.g. cmd.exe + powershell) appear in countless
        //   legitimate IT guides and pentest reports.
        //   3 co-occurring shell strings in the same file is a much
        //   stronger signal of macro/script malware.
        // FIXED: added filesize guard — legitimate multi-hundred-MB
        //   video or archive files containing a few shell strings
        //   in metadata should not fire this rule.
        3 of them and filesize < 15MB
}


// ============================================================
// CATEGORY 4 — Steganography tool signatures
// ============================================================

rule stego_tool_signature
{
    meta:
        description = "Known steganography tool output signature detected"
        severity    = "medium"
        score       = 65

    strings:
        $s1 = "Steghide"   nocase
        $s2 = "OpenStego"  nocase
        $s3 = "outguess"   nocase
        $s4 = "jphide"     nocase
        $s5 = "jpseek"     nocase
        $s6 = "stegosuite" nocase

    condition:
        any of them
}


// ============================================================
// CATEGORY 5 — Base64 encoded payloads
// ============================================================

rule base64_encoded_executable
{
    meta:
        description = "Base64 encoded Windows/Linux executable"
        severity    = "high"
        score       = 80

    strings:
        $b64_mz1 = "TVoA"
        $b64_mz2 = "TVqQ"
        $b64_mz3 = "TVpA"
        $b64_mz4 = "TVqA"
        $b64_elf = "f0VM"

    condition:
        any of them
}

rule base64_powershell
{
    meta:
        description = "Base64 encoded PowerShell command"
        severity    = "high"
        score       = 85

    strings:
        $ps1 = "cG93ZXJzaGVsbA"
        $ps2 = "JABwAG8AdwBlAHIAcwBoAGUAbABsAA"
        $ps3 = "-EncodedCommand" nocase
        $ps4 = "-enc "           nocase

    condition:
        any of them
}


// ============================================================
// CATEGORY 6 — Suspicious strings
//
// FIXED: suspicious_commands — raised from 2→3 required
//   wget + curl appear in every Linux tutorial, Docker README,
//   developer cheatsheet. Requiring 3 concurrent hits cuts FP
//   dramatically while still catching actual dropper scripts
//   which always have multiple download/exec primitives together.
//
// FIXED: darkweb_indicators — .onion REMOVED (was duplicate of
//   suspicious_urls which also matched .onion).
//   Two YARA rules matching the same string = two hits counted
//   separately in run_yara_scan result reporting (even though
//   score is capped at 80 in engine). Removed redundancy.
// ============================================================

rule suspicious_commands
{
    meta:
        description = "Multiple suspicious system commands in file"
        severity    = "medium"
        score       = 55

    strings:
        $c1 = "cmd.exe"    nocase
        $c2 = "powershell" nocase
        $c3 = "/bin/bash"
        $c4 = "/bin/sh"
        $c5 = "nc -e"
        $c6 = "bash -i"
        $c7 = "wget "      nocase
        $c8 = "curl "      nocase
        $c9 = "chmod +x"

    condition:
        // FIXED: raised from 2→3
        //   wget + curl alone = every Linux developer doc
        //   3 co-occurring = actual dropper / reverse shell script behavior
        3 of them
}

rule suspicious_urls
{
    meta:
        description = "High-confidence C2 / dark web URLs in file"
        severity    = "medium"
        score       = 50

    strings:
        $u1 = ".onion"       nocase
        $u2 = "ngrok.io"     nocase
        $u3 = "duckdns.org"  nocase
        $u4 = "serveo.net"   nocase
        $u5 = "pagekite.me"  nocase

    condition:
        any of them
}

rule darkweb_indicators
{
    meta:
        description = "Dark web communication indicators"
        severity    = "medium"
        score       = 45
        // FIXED: Bug 3 — score reduced 75→45, severity high→medium
        //   tor2web is a single string that appears in security research docs,
        //   news articles about darkweb markets, and threat intelligence reports.
        //   score=75 + severity=high was pushing verdict to suspicious/malicious
        //   on clean security research PDFs.
        //   .onion REMOVED from here — duplicate of suspicious_urls $u1

    strings:
        $d1 = "tor2web" nocase

    condition:
        any of them
}


// ============================================================
// CATEGORY 7 — Known malware family signatures
//
// FIXED: Metasploit and meterpreter REMOVED.
//   These strings appear in every penetration testing report,
//   malware analysis writeup, threat intelligence document, and
//   security research paper. Keeping them with score=95 was
//   producing verdict=malicious on completely clean documents.
//
//   Remaining strings are confirmed malware family names that
//   have no legitimate reason to appear as plaintext strings
//   in a media file, document, or PDF sent via a messaging app.
// ============================================================

rule known_malware_families
{
    meta:
        description = "Known malware family string detected (unambiguous names)"
        severity    = "high"
        score       = 95
        // These strings have NO legitimate reason to appear as plaintext
        // in a media file, image, PDF, or document sent via WhatsApp/Telegram.
        // Cobalt Strike MOVED to separate rule with filesize guard — it appears
        // in every threat intel report, APT writeup, and pentest methodology doc.

    strings:
        $m1  = "WannaCry"      nocase
        $m2  = "Emotet"        nocase
        $m3  = "TrickBot"      nocase
        $m4  = "AgentTesla"    nocase
        $m5  = "FormBook"      nocase
        $m6  = "Mirai"         nocase
        // Metasploit REMOVED — in every pentest report
        // meterpreter REMOVED — in every pentest report
        $m7  = "NjRAT"         nocase
        $m8  = "DarkComet"     nocase
        $m9  = "AsyncRAT"      nocase

    condition:
        any of them
}

rule cobalt_strike_in_small_file
{
    meta:
        description = "Cobalt Strike beacon string in small file (FP-filtered)"
        severity    = "high"
        score       = 75
        // FIXED: Bug 2 — 'Cobalt Strike' alone at score=95 fired on every
        //   threat intel PDF, APT analysis doc, pentest methodology report.
        //   Fix: only flag in files < 500KB (actual beacon/stager artifacts)
        //   Large files (reports, docs) almost certainly legitimate context.
        //   Score reduced 95→75 since size guard adds uncertainty.

    strings:
        $cs = "Cobalt Strike" nocase

    condition:
        $cs and filesize < 500KB
}


// ============================================================
// CATEGORY 8 — IOC patterns
// ============================================================

rule ioc_registry_keys
{
    meta:
        description = "Windows registry persistence keys found"
        severity    = "medium"
        score       = 60

    strings:
        $r1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"  nocase
        $r2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $r3 = "CurrentVersion\\Run" nocase

    condition:
        any of them
}

rule ioc_suspicious_paths
{
    meta:
        description = "Suspicious filesystem paths combined with execution indicators"
        severity    = "medium"
        score       = 50

    strings:
        // Filesystem drop locations
        $p1 = "\\AppData\\Roaming\\"     nocase
        $p2 = "\\AppData\\Local\\Temp\\" nocase
        $p3 = "\\Windows\\Temp\\"        nocase
        $p4 = "/tmp/"
        $p5 = "/var/tmp/"
        $p6 = "\\System32\\"             nocase

        // Execution indicators — must co-occur with paths
        // Without these, every Windows IT doc triggers this rule
        $exec1 = "cmd.exe"      nocase
        $exec2 = "powershell"   nocase
        $exec3 = "regsvr32"     nocase
        $exec4 = "rundll32"     nocase
        $exec5 = "mshta"        nocase
        $exec6 = "wscript"      nocase
        $exec7 = "certutil"     nocase

    condition:
        // FIXED: require path + execution indicator
        // Pure path matches fire on every Windows sysadmin/IT document
        2 of ($p*) and 1 of ($exec*)
}

rule ioc_ethereum_wallet
{
    meta:
        description = "Ethereum wallet address found in file"
        severity    = "medium"
        score       = 45
        // Bitcoin regex removed — matched binary data in PDF/DOCX streams
        // Ethereum kept — 0x prefix + 40 hex chars is specific enough

    strings:
        $eth = /0x[a-fA-F0-9]{40}/

    condition:
        $eth
}


// ============================================================
// CATEGORY 9 — Polyglot file detection
// ============================================================

rule polyglot_jpg_zip
{
    meta:
        description = "File has JPEG header but contains ZIP structure (polyglot)"
        severity    = "high"
        score       = 85

    strings:
        $jpg_head = { FF D8 FF }
        $zip_sig  = { 50 4B 03 04 }

    condition:
        $jpg_head at 0 and $zip_sig
}

rule polyglot_png_zip
{
    meta:
        description = "File has PNG header but contains ZIP structure (polyglot)"
        severity    = "high"
        score       = 85

    strings:
        $png_head = { 89 50 4E 47 }
        $zip_sig  = { 50 4B 03 04 }

    condition:
        $png_head at 0 and $zip_sig
}

rule polyglot_pdf_zip
{
    meta:
        description = "File has PDF header but contains ZIP structure (polyglot)"
        severity    = "high"
        score       = 85

    strings:
        $pdf_head = "%PDF"
        $zip_sig  = { 50 4B 03 04 }

    condition:
        $pdf_head at 0 and $zip_sig
}


// ============================================================
// CATEGORY 10 — Macro-enabled Office formats
// Added for .docm / .xlsm / .pptm / .dotm / .xlsb / .xltm
//
// These formats ALWAYS contain a VBA project binary (vbaProject.bin)
// inside their ZIP container. The content type string confirms it.
// Unlike .docx which may legitimately have no macros, .docm by
// definition always has macro capability enabled.
//
// Paper justification: Emotet, QakBot, Dridex, Agent Tesla all use
// .docm/.xlsm as primary delivery vectors. These rules provide
// format-level confirmation of macro-enabled documents.
// ============================================================

rule macro_enabled_office_format
{
    meta:
        description = "Macro-enabled Office format detected (docm/xlsm/pptm)"
        severity    = "high"
        score       = 75

    strings:
        // Content type strings present in [Content_Types].xml inside ZIP
        $ct1 = "application/vnd.ms-word.document.macroEnabled"        nocase
        $ct2 = "application/vnd.ms-excel.sheet.macroEnabled"          nocase
        $ct3 = "application/vnd.ms-powerpoint.presentation.macroEnabled" nocase
        $ct4 = "application/vnd.ms-excel.sheet.binary"                nocase
        // VBA project binary always present in macro-enabled formats
        $vba = "vbaProject.bin"                                        nocase
        // ActiveX component — often used alongside macros
        $ax  = "application/vnd.ms-office.activex"                    nocase

    condition:
        // Must be ZIP-based Office format (PK signature)
        uint32(0) == 0x04034B50 and
        (any of ($ct*) or $vba or $ax)
}

rule macro_enabled_with_shell_execution
{
    meta:
        description = "Macro-enabled Office format with shell execution strings"
        severity    = "high"
        score       = 90

    strings:
        // Macro-enabled format markers
        $ct1 = "vbaProject.bin"   nocase
        $ct2 = "macroEnabled"     nocase

        // Shell execution inside VBA
        $s1 = "Shell("         nocase
        $s2 = "WScript.Shell"  nocase
        $s3 = "cmd.exe"        nocase
        $s4 = "powershell"     nocase
        $s5 = "mshta"          nocase
        $s6 = "regsvr32"       nocase
        $s7 = "rundll32"       nocase
        $s8 = "certutil"       nocase

    condition:
        uint32(0) == 0x04034B50 and
        any of ($ct*) and
        2 of ($s*)
}

rule xlsb_binary_with_macros
{
    meta:
        description = "Excel Binary Workbook (.xlsb) with macro indicators"
        severity    = "high"
        score       = 80

    strings:
        // XLSB is ZIP-based but uses binary record format
        $xlsb = "xl/workbook.bin"  nocase
        $vba  = "vbaProject.bin"   nocase
        $exec1 = "Shell("          nocase
        $exec2 = "powershell"      nocase
        $exec3 = "cmd.exe"         nocase

    condition:
        uint32(0) == 0x04034B50 and $xlsb and $vba and any of ($exec*)
}


// ============================================================
// CATEGORY 11 — OpenDocument Format (ODT/ODS/ODP) macro detection
// Added for LibreOffice Basic macro coverage
//
// ODF uses a different macro language than VBA:
//   - LibreOffice Basic stored in Basic/ directory
//   - Macros referenced via script:module elements
//   - Shell access via Shell() or CreateUnoService
//
// Paper justification: ODF macros used in targeted attacks against
// Linux and macOS users (APT campaigns) where MS Office is absent.
// LibreOffice macro execution provides equivalent code execution risk.
// ============================================================

rule odf_macro_detected
{
    meta:
        description = "OpenDocument file contains LibreOffice Basic macro"
        severity    = "medium"
        score       = 60

    strings:
        // ODF macro directory structure inside ZIP
        $m1 = "Basic/"          nocase
        $m2 = "script:module"   nocase
        $m3 = "StarBasic"       nocase
        $m4 = "macros/"         nocase
        // ODF mimetype markers
        $ot1 = "application/vnd.oasis.opendocument.text"
        $ot2 = "application/vnd.oasis.opendocument.spreadsheet"
        $ot3 = "application/vnd.oasis.opendocument.presentation"

    condition:
        uint32(0) == 0x04034B50 and
        any of ($ot*) and
        any of ($m*)
}

rule odf_macro_with_shell
{
    meta:
        description = "OpenDocument macro with shell execution capability"
        severity    = "high"
        score       = 85

    strings:
        // ODF format markers
        $ot1 = "application/vnd.oasis.opendocument.text"
        $ot2 = "application/vnd.oasis.opendocument.spreadsheet"
        $ot3 = "application/vnd.oasis.opendocument.presentation"

        // LibreOffice Basic shell execution APIs
        $s1 = "Shell("              nocase
        $s2 = "CreateUnoService"    nocase
        $s3 = "com.sun.star.bridge" nocase
        $s4 = "environ("            nocase
        $s5 = "/bin/bash"
        $s6 = "/bin/sh"
        $s7 = "cmd.exe"             nocase
        $s8 = "powershell"          nocase

    condition:
        uint32(0) == 0x04034B50 and
        any of ($ot*) and
        2 of ($s*)
}

rule odf_external_data_link
{
    meta:
        description = "OpenDocument file with suspicious external data connection"
        severity    = "medium"
        score       = 45

    strings:
        // ODF external link patterns
        // FIXED: Bug 1 — unmatched quotes caused YARA compile failure
        //   Engine silently set YARA_RULES=None → all YARA detection disabled
        //   Fix: escape inner quotes with backslash
        $l1 = "xlink:href=\"http"  nocase
        $l2 = "xlink:href=\"ftp"   nocase
        $l3 = "database:query"     nocase
        // ODF format marker
        $ot1 = "opendocument"      nocase

    condition:
        uint32(0) == 0x04034B50 and $ot1 and any of ($l*)
}
