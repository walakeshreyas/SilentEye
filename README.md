# SilentEye

**Offline static malware detection for multimedia files exchanged over messaging platforms.**

SilentEye inspects images, video, audio, PDF, office documents, and SVG files for steganographic payloads and structural malware artifacts *before* the file is opened — without sending anything off-device. It was built to address a specific gap in the Indian mobile threat landscape: WhatsApp and Instagram move a huge volume of media daily, and almost none of it is inspected below the file-extension level.

The system combines a rule-based heuristic engine (YARA + structural/entropy analysis) with a machine-learning steganalysis layer (four specialized Random Forest classifiers), fused into a single verdict. Both engines were evaluated independently on real benchmark datasets, and the results — including where the system fails — are published in two peer-reviewed papers (see [Publications](#publications)).

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Supported File Categories](#supported-file-categories)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Performance and Benchmarks](#performance-and-benchmarks)
- [Limitations](#limitations)
- [Project Structure](#project-structure)
- [Publications](#publications)
- [Security Considerations](#security-considerations)
- [Future Work](#future-work)
- [Disclaimer](#disclaimer)
- [Contributors](#contributors)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Overview

Media-borne malware doesn't look like malware. Attackers embed payloads in JPEG quantization tables, PNG alpha channels, AVI container overlays, and SVG script tags — formats that conventional antivirus tools scan superficially because they're optimized for executables, not container internals. A file named `photo.jpg` isn't safe just because it opens like a photo.

SilentEye treats every incoming file as untrusted until proven otherwise. It runs a four-stage offline pipeline — preprocessing, heuristic analysis, ML-based steganalysis, and hybrid fusion — and returns a **Clean / Suspicious / Malicious** verdict with the supporting evidence behind it. Everything runs locally: no cloud upload, no telemetry, no dependency on an internet connection during a scan.

---

## Key Features

- **Multi-stage detection** — preprocessing, heuristic engine, ML steganalysis, and hybrid fusion, rather than a single detector deciding the outcome
- **29 custom YARA rules** across 11 categories, plus format-specific structural checks for each of the six supported file categories
- **Four specialized Random Forest classifiers** (JPEG, PNG, video, SVG) using 30 hand-crafted statistical features — no raw pixel data, fully interpretable via feature importance
- **Hash reputation lookup** against a local MalwareBazaar database (~1M known-malicious SHA-256 hashes) for zero-latency verdicts on known threats
- **Smart-read memory architecture** — scans an 800 MB video using ~3.5 MB of RAM by reading only header and tail regions instead of the full file
- **Offline-first** — no cloud dependency, no GPU requirement, deployable on consumer hardware
- **Desktop GUI** built on Electron, packaged as a standalone Windows installer
- **Scan history and reporting** — results persisted locally in SQLite, exportable for review

---

## Architecture

```
                        File Input (GUI)
                              │
                              ▼
              ┌───────────────────────────────┐
              │   Stage 0 — Preprocessing      │
              │ Extension check · magic bytes  │
              │ double-extension detection ·   │
              │ SHA-256 hash vs MalwareBazaar  │
              └───────────────┬────────────────┘
                     hash match │ no match
              (immediate verdict)
                              ▼
              ┌───────────────────────────────┐
              │ Stage 1 — Heuristic Engine     │
              │ 29 YARA rules · entropy ·      │
              │ overlay/polyglot detection ·   │
              │ format-specific structural     │
              │ checks (image/video/audio/     │
              │ PDF/office/SVG)                │
              └───────────────┬────────────────┘
                              ▼
              ┌───────────────────────────────┐
              │ Stage 2 — ML Steganalysis      │
              │ 4× Random Forest classifiers   │
              │ (JPEG / PNG / video / SVG)     │
              │ 30 features · <200 ms/file     │
              └───────────────┬────────────────┘
                              ▼
              ┌───────────────────────────────┐
              │   Hybrid Fusion Engine         │
              │ weighted combination of        │
              │ heuristic + ML verdicts        │
              └───────────────┬────────────────┘
                              ▼
                 CLEAN · SUSPICIOUS · MALICIOUS
                    (malicious → auto-quarantine)
```

Three conditions bypass full scoring entirely and produce an immediate malicious verdict: a MalwareBazaar hash match, a YARA rule match, or confirmed PE/executable detection in file metadata.

---

## Supported File Categories

| Category | Formats |
|---|---|
| Image | JPEG, PNG, BMP, TIFF |
| Video | AVI, MP4, MOV |
| Audio | MP3, WAV, FLAC |
| PDF | PDF |
| Office / Document | DOCX and other macro-enabled Office formats, OpenDocument (ODF) |
| SVG | SVG, SVGZ |

Detection depth varies by format — see [Limitations](#limitations) for what each engine does and doesn't catch per category.

---

## Technology Stack

| Layer | Technology |
|---|---|
| GUI | Electron (packaged as a Windows installer) |
| Backend / analysis engine | Python (Flask) |
| Heuristic detection | YARA (`yara-python`) |
| Machine learning | scikit-learn (Random Forest), NumPy |
| File & media parsing | Pillow, ExifRead, PyMuPDF, oletools, FFmpeg, MediaInfo |
| Storage | SQLite (scan history + hash reputation database) |

---

## Installation

### For End Users

Download the latest Windows installer (`.exe`) from the [Releases](../../releases) page and run it. No Python or Node.js setup required — the installer bundles the full application.

### For Developers (build from source)

**Prerequisites:** Windows 10/11, Python 3.x, Node.js, Git. Some analyzers require **FFmpeg** and **MediaInfo** available on the system `PATH`.

```bash
git clone https://github.com/walakeshreyas/SilentEye
cd SilentEye
```

**Backend (analysis engine):**

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**Frontend (Electron GUI):**

```bash
cd frontend
npm install
npm start          # development mode
npm run build       # produces the Windows installer
```

> Script and folder names above follow standard Electron + Flask conventions — match them against your actual `package.json` if your project layout differs.

---

## Usage

1. Launch SilentEye (installed app, or `npm start` in development)
2. Select a file, or drag and drop it onto the scan window
3. SilentEye runs the file through preprocessing, the heuristic engine, and the ML layer
4. Review the per-layer findings and the final risk verdict
5. Export the report (PDF / JSON / CSV) if needed — malicious files are automatically quarantined

---

## Performance and Benchmarks

All numbers below are the measured, published results from the SilentEye systems paper (see [Publications](#publications)), not estimates.

### Heuristic Engine (Stage 1)

Evaluated on 3,585 files (1,805 clean, 1,780 malicious across 29 attack types) with an 80/20 disjoint split.

| Metric | Result |
|---|---:|
| Overall true positive rate | 93.8% |
| Overall false positive rate | 0.8% |
| Average scan latency | 166 ms |

| Category | Detection rate | Avg. scan time |
|---|---:|---:|
| SVG | 100.0% | 13.0 ms |
| Video | 100.0% | 41.2 ms |
| DOCX | 100.0% | 51.1 ms |
| PDF | 99.5% | 1,276 ms |
| Images | 90.4% | 17.3 ms |
| Audio | 79.3% | 18.0 ms |

The false-positive rate on the clean corpus is 0.6% excluding a 25-file synthetic edge-case subset (worst-case constructs like disabled-but-not-removed VBA macros) — that subset alone accounts for a 16.0% FP rate and is analyzed separately in the paper.

### ML Steganalysis Layer (Stage 2)

Evaluated on 36,800 files across 6 benchmark datasets (ALASKA2, BOSSBase, DIV2K, UCF101, a flat-field calibration set, and a custom SVG corpus), 80/20 stratified split, 5-fold cross-validation, `random_state=42`.

| Model | Test F1 | FPR | FNR | Test files |
|---|---:|---:|---:|---:|
| PNG alpha-channel | 1.0000 | 0.00% | 0.00% | 2,037 |
| Video (AVI overlay) | 1.0000 | 0.00% | 0.00% | 800 |
| SVG (script/XXE injection) | 1.0000 | 0.00% | 0.00% | 520 |
| JPEG — Steghide (dev. dataset) | 0.9965 | 0.00% | 0.69% | — |
| JPEG — J-UNIWARD adaptive (ALASKA2) | **0.5231** | 60.65% | 42.84% | 3,977 |

The perfect F1 scores on PNG, video, and SVG reflect structurally deterministic signals in those attack types (e.g. `alpha_midrange_ratio` for PNG stego), confirmed stable under 5-fold CV — not overfitting on a small or leaky dataset. Full justification is in the paper.

**The JPEG result is split deliberately.** Against Steghide (a tool that re-encodes at a distinctive quantization-table signature), the classifier is near-perfect. Against J-UNIWARD — an adaptive algorithm designed specifically to avoid producing a detectable statistical footprint — it performs at essentially random chance. This matches published literature: CNN-based detectors (SRNet, EfficientNet-B4) top out at 64.3–68.1% on the same benchmark, and a Random Forest baseline on ALASKA2 is reported at ~50% by the dataset's own authors. Hand-crafted features cannot close this gap; it requires a GPU-based CNN, which is out of scope for this system (see [Future Work](#future-work)).

### Resource Efficiency

| File | Actual size | RAM used | Scan time |
|---|---:|---:|---:|
| 4K UHD MP4 video | ~800 MB | ~3.5 MB | <200 ms |
| WAV audio | ~2.6 MB | 91 KB | <20 ms |
| JPEG image | ~3 MB | 68 KB | <20 ms |
| DOCX document | ~200 KB | 200 KB (full read) | ~50 ms |
| PDF | ~5 MB | 5 MB (full read) | ~1,300 ms |

The smart-read architecture reads only header and tail regions for media formats, which is why video/image/audio RAM usage stays flat regardless of file size. PDF and DOCX require full-file reads for stream/XML parsing, which is why their memory and latency scale with file size.

---

## Limitations

- **J-UNIWARD adaptive steganography is not reliably detected** (F1 = 0.5231, effectively random chance). This is a documented, literature-consistent boundary of hand-crafted-feature Random Forest classifiers, not an implementation bug.
- **Audio LSB detection is disabled by default** — it produced a 55.3% false-positive rate on natural music recordings (GTZAN dataset), where sensor/recording noise is statistically indistinguishable from embedded payload.
- **PDF scanning is slow relative to other formats** (1,276–1,610 ms average) due to the full-file read required for stream pattern matching.
- **No real-time mobile scanning.** Android 14 and iOS background-access restrictions prevent continuous scanning on the platforms where WhatsApp/Instagram media actually arrives; SilentEye currently runs as a desktop pre-screening tool.
- **Static analysis only.** Runtime behaviors — macro-triggered network calls, process injection, fileless execution — are out of scope.
- **Detection is tool-specific.** All four ML classifiers are trained on known steganography tool signatures; an unrepresented tool is not guaranteed to be caught without retraining.

---

## Project Structure

```
SilentEye/
├── frontend/                  # Electron application (GUI)
│   ├── src/
│   ├── assets/
│   └── package.json
│
├── backend/                   # Python analysis engine
│   ├── analyzers/
│   │   ├── preprocessing/
│   │   ├── heuristic/
│   │   └── ml/
│   ├── rules/
│   │   └── yara/
│   ├── models/                 # Trained Random Forest models
│   ├── database/                # SQLite: scan history + hash reputation
│   ├── config.py
│   ├── app.py
│   └── requirements.txt
│
├── docs/
│   └── research-papers/
│
├── tests/
└── README.md
```

> Adjust to match your actual repository layout.

---

## Publications

**SilentEye: A Multi-Stage Static Detection Framework for Malware-Embedded Multimedia Files Using Heuristic Analysis and Random Forest Steganalysis**
Shreyas Santosh Walake, Prasad Vilas Wakchaure, Vaishnavi Sidram Shinde, Shravani Chittaranjan Takale, Prof. Shikha Dwivedi
*International Journal of Engineering Research & Technology (IJERT)*, Vol. 15, Issue 06, June 2026
DOI: [10.5281/zenodo.20844063](https://doi.org/10.5281/zenodo.20844063) · ISSN 2278-0181 · [Full text](https://www.ijert.org/silenteye-a-multi-stage-static-detection-framework-for-malware-embedded-multimedia-files-using-heuristic-analysis-and-random-forest-steganalysis-ijertv15is061009)

The systems paper — full architecture, dataset construction, and the benchmark results reported above.

**A Comparative Survey of Static and Machine Learning-Based Approaches for Detecting Malware in Multimedia Files**
Shreyas Santosh Walake, Prasad Vilas Wakchaure, Vaishnavi Sidram Shinde, Shravani Chittaranjan Takale, Prof. Shikha Dwivedi
*International Journal of Engineering Research & Technology (IJERT)*, Vol. 15, Issue 06, June 2026
DOI: [10.5281/zenodo.20846578](https://doi.org/10.5281/zenodo.20846578) · ISSN 2278-0181 · [Full text](https://www.ijert.org/a-comparative-survey-of-static-and-machine-learning-based-approaches-for-detecting-malware-in-multimedia-files-ijertv15is061008)

A comparative survey positioning SilentEye's hybrid heuristic + ML design against signature-based AV, classical steganalysis, and deep-learning steganalysis approaches.

Both papers are open access under [CC BY 4.0](http://creativecommons.org/licenses/by/4.0/).

---

## Security Considerations

- A "Clean" verdict is not a guarantee — treat results as an indicator, not an absolute.
- Run highly suspicious files in an isolated environment regardless of SilentEye's output.
- Keep the MalwareBazaar hash database and YARA rules updated.
- Restrict access to exported scan reports if they may contain sensitive file metadata.

---

## Future Work

- Optional GPU-accelerated CNN module (SRNet / EfficientNet-B4) for J-UNIWARD detection on low-confidence cases
- Genre-aware or spectrogram-based audio steganalysis to replace the disabled LSB layer
- VBA project binary parsing to distinguish disabled from active Office macros
- Behavioral sandbox integration for fileless/runtime threats
- Android-native foreground service or messaging-API interception for mobile deployment
- Selective PDF stream sampling to reduce scan latency
- Periodic retraining pipeline sourced from MalwareBazaar for novel steganography tools

---

## Disclaimer

SilentEye is a cybersecurity research and defensive-analysis project. It is not a replacement for commercial antivirus, EDR, or sandboxed dynamic analysis. Only scan files you are authorized to inspect. The developers are not responsible for damage, data loss, or security incidents resulting from use or misuse of this software.

---

## Contributors

**Team:** Shreyas Santosh Walake, Prasad Vilas Wakchaure, Vaishnavi Sidram Shinde, Shravani Chittaranjan Takal
**Project Guide:** Prof. Shikha Dwivedi
Department of Computer Engineering, JSPM's JSCOE, Pune

---

## License

MIT License

Copyright (c) 2026 Shreyas Walake

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Acknowledgements

SilentEye builds on YARA, scikit-learn, NumPy, Pillow, ExifRead, PyMuPDF, oletools, FFmpeg, MediaInfo, Electron, Flask, and SQLite, and on the MalwareBazaar hash reputation database (abuse.ch). Benchmark datasets: ALASKA2, BOSSBase, DIV2K, UCF101. Thanks to the maintainers of each.


## For Actual tool go for this link and download  

https://drive.google.com/drive/folders/1Ct7GDVHzfivYxcyrJX3TLXqW-i1k1eub?usp=drive_link 
