# Dataset Setup — MalwareBazaar Hash Database

SilentEye's preprocessing gate does hash-reputation lookups against a local
MalwareBazaar hash dump. This file is **not committed to the repo** — it's a
large binary blob and doesn't belong in git history. Download it separately
and place it manually.

## Why it's not on GitHub

- Large file size (hash dump is bulky, degrades clone times)
- Binary/DB files bloat git history permanently even if later deleted
- No reason to version-control third-party data you don't own

## 1. Download

Dataset is hosted on Google Drive (not in this repo):

**Link:** https://drive.google.com/file/d/1nGBOVdSvyVetTFXXrem49qnDKEg71Ftg/view?usp=sharing

File: `silenteye_hashes.zip`

Download it manually — Drive doesn't allow reliable direct-download via
`wget`/`curl` for files this size without cookie handling, so don't bother
scripting it. Just click and download.

## 2. Extract

```bash
unzip silenteye_hashes.zip -d silenteye_hashes/
```

You should get a `.db` (SQLite) file inside — the MalwareBazaar SHA256 hash
dump, ~1M+ entries.

## 3. Place it in the project

> ⚠️ **PATH PLACEHOLDER — confirm against your `config.py`**
> Replace `<PATH_FROM_CONFIG>` below with whatever path your hash-lookup
> module actually reads from. Check `config.py` for the DB path variable
> before assuming this is right.

```bash
mv silenteye_hashes/*.db <PATH_FROM_CONFIG>/malwarebazaar_hashes.db
```

Example (adjust to your actual structure):
```
SilentEye/
└── backend/
    └── <PATH_FROM_CONFIG>/
        └── malwarebazaar_hashes.db
```

If the filename doesn't match what `config.py` expects, either rename the
file or update the path in config — don't hardcode a second path somewhere
else in the code. One source of truth for the DB path.

## 4. Verify

Run the backend and check the preprocessing gate initializes without a
missing-file error. If hash lookups silently return "not found" for known
malicious hashes, the DB path is wrong or the file didn't extract correctly
— check that first, don't assume the lookup logic is broken.

## Dataset source & attribution

```
MalwareBazaar full malware samples dump (SHA256 hashes)
Last updated: 2026-03-18 17:20:14 UTC
Terms Of Use: https://bazaar.abuse.ch/faq/#tos
Contact: bazaar [at] abuse.ch
```

This is third-party threat intelligence data from abuse.ch's MalwareBazaar
project. You are bound by their ToS (link above) — read it before
redistributing this file yourself. Do not re-upload the raw dump to a public
repo; keep it on Drive/similar and link to it, same as this setup does.

## Note on hash-reputation limitations

This is a **known-malicious hash blocklist**, not a detection engine. It only
catches samples that already exist in MalwareBazaar's corpus with matching
SHA256. Any repacked, recompiled, or novel malware will not match and falls
through to the heuristic/ML stages. Don't oversell this component in your
docs or papers as doing more than exact-hash lookup — it isn't.
