# SilentEye ML — Dataset Setup

## Quick Start

### Option A — Environment Variable (Recommended)

Set the dataset path before running any command:

**Windows:**
```
set SILENTEYE_DATASET=C:\path\to\ml_dataset1
python test.py realtrain --cat image
```

**Linux / Mac:**
```
export SILENTEYE_DATASET=/path/to/ml_dataset1
python3 test.py realtrain --cat image
```

### Option B — Place dataset in ./data/ folder

```
silenteye_ml1/
  config.py
  test.py
  data/              ← create this folder
    alaska/
      train/clean/
      train/malicious/
      test/clean/
      test/malicious/
    bossbase/
    div2k/
    flatfield/
    video/
    svg/
```

### Option C — Place dataset one level up

```
Desktop/
  silenteye_ml1/    ← your code folder
  ml_dataset1/      ← dataset folder (auto-detected)
    alaska/
    bossbase/
    ...
```

---

## Dataset Structure

```
ml_dataset1/
├── alaska/          ALASKA2 JPEG (DCT steghide embedding)
├── bossbase/        BOSSBase PNG (alpha channel stego)
├── div2k/           DIV2K PNG (alpha channel stego)
├── flatfield/       Flat-field TIFF (alpha channel stego)
├── video/           UCF101 AVI (payload injection)
└── svg/             SVG dataset (JS/XXE injection)

Each folder contains:
  train/clean/
  train/malicious/
  test/clean/
  test/malicious/
```

---

## Commands

```bash
# Train all models
python test.py realtrain --cat image
python test.py realtrain --cat video
python test.py realtrain --cat svg

# Evaluate
python test.py eval --cat image
python test.py eval --cat video
python test.py eval --cat svg

# Check model status
python test.py status

# Debug a single file
python test.py debug path/to/file.jpg
```

---

## Requirements

```
pip install numpy pillow scikit-learn joblib scipy
```
