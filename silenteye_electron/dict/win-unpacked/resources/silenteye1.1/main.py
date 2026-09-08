import os
import sys
from collections import OrderedDict

# ================================
# PATH SETUP
# ================================

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_PATH)

# ================================
# IMPORTS
# ================================

from preprocessing    import preprocess_file
from heuristic.engine import run_heuristic_scan, load_yara_rules
from ml_integration   import run_ml_scan, combine_verdicts, ml_status, ML_CATEGORIES

# ================================
# STARTUP
# ================================

load_yara_rules(os.path.join(BASE_PATH, "rules", "silenteye.yar"))

_ml_stat = ml_status()
if _ml_stat["available"]:
    _ready = [k for k, v in _ml_stat["models"].items() if v]
    print(f"[ML] Models ready: {_ready}")
else:
    print(f"[ML] WARN: {_ml_stat['reason']} — ML layer skipped for image/video/svg")

# ================================
# SCAN FUNCTION
# Stage 1 → Stage 2A → Stage 2B → Decision
# ================================

def scan_file(file_path: str, s1: dict = None) -> dict:

    final_result = {
        "file":          os.path.basename(file_path),
        "file_path":     file_path,
        "stage1":        {},
        "stage2":        {},
        "stage2b_ml":    None,
        "final_verdict": "unknown",
        "final_score":   0,
        "summary":       "",
        "ml_applied":    False,
    }

    # ── STAGE 1 ───────────────────────────────────────────────────────────────
    if s1 is None:
        print(f"\n[STAGE 1] Preprocessing → {os.path.basename(file_path)}")
        s1 = preprocess_file(file_path)
    else:
        print(f"\n[STAGE 1] Preprocessing → {os.path.basename(file_path)} (cached)")

    final_result["stage1"] = s1

    print(f"          Status  : {s1['status']}")
    print(f"          Type    : {s1['file_type']}")
    print(f"          Size    : {s1['file_size_mb']} MB")
    print(f"          Hash    : {s1['file_hash'][:16] if s1['file_hash'] else 'N/A'}...")
    print(f"          Flags   : {s1['flags'] if s1['flags'] else 'none'}")

    if s1["status"] == "skip":
        final_result["final_verdict"] = "skip"
        final_result["summary"]       = s1["reason"]
        print(f"          → SKIPPED: {s1['reason']}")
        return final_result

    if s1["status"] == "error":
        final_result["final_verdict"] = "error"
        final_result["summary"]       = s1["reason"]
        print(f"          → ERROR: {s1['reason']}")
        return final_result

    # ── STAGE 2A — Heuristic ──────────────────────────────────────────────────
    print(f"\n[STAGE 2A] Heuristic → {os.path.basename(file_path)}")
    s2 = run_heuristic_scan(file_path, s1)
    final_result["stage2"] = s2

    print(f"           Verdict : {s2['verdict']}")
    print(f"           Score   : {s2['final_score']}")
    print(f"           Layers  : {s2.get('total_layers',0)} total, "
          f"{s2.get('flagged_layers',0)} flagged")

    if s2.get("detections"):
        for d in s2["detections"]:
            print(f"             → [{d['severity'].upper()}] {d['layer']}"
                  f"{' — ' + d['reason'][:70] if d.get('reason') else ''}")

    # ── STAGE 2B — ML (image / video / svg only) ──────────────────────────────
    category  = s1.get("file_type", "unknown")
    ml_result = None

    if category in ML_CATEGORIES:
        print(f"\n[STAGE 2B] ML scan → {os.path.basename(file_path)}")
        ml_result = run_ml_scan(file_path)
        final_result["stage2b_ml"] = ml_result

        if ml_result.get("skipped"):
            print(f"           Skipped  : {ml_result['reason']}")
        elif ml_result.get("error"):
            print(f"           Error    : {ml_result['reason'][:70]}")
        else:
            print(f"           Verdict  : {ml_result['verdict']}")
            print(f"           Score    : {ml_result['score']}")
            print(f"           Prob     : {ml_result['probability']:.4f}")
            print(f"           Hard hit : {ml_result.get('hard_fired', False)}")
            print(f"           Fallback : {ml_result.get('fallback', False)}")
            for layer in ml_result.get("ml_layers", []):
                if layer.get("detected"):
                    print(f"             → [{layer.get('severity','?').upper()}] "
                          f"{layer.get('layer','?')}"
                          f"{' — ' + layer.get('reason','')[:60] if layer.get('reason') else ''}")
    else:
        print(f"\n[STAGE 2B] ML not applicable for {category} — heuristic only")

    # ── DECISION ──────────────────────────────────────────────────────────────
    combined = combine_verdicts(s1, s2, ml_result, category)

    final_result["final_verdict"] = combined["final_verdict"]
    final_result["final_score"]   = combined["final_score"]
    final_result["summary"]       = combined["summary"]
    final_result["ml_applied"]    = combined["ml_applied"]

    print(f"\n[DECISION] Verdict  : {combined['final_verdict'].upper()}")
    print(f"           Score    : {combined['final_score']}")
    print(f"           ML used  : {combined['ml_applied']}")
    print(f"           Summary  : {combined['summary'][:100]}")

    return final_result


# ================================
# FOLDER SCAN
# ================================

MAX_CACHE_SIZE = 500

class _BoundedCache:
    def __init__(self, maxsize=500):
        self._cache   = OrderedDict()
        self._maxsize = maxsize

    def get(self, key):
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def set(self, key, value):
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)

    def __contains__(self, key):  return key in self._cache
    def __getitem__(self, key):   return self.get(key)
    def __setitem__(self, key, v): self.set(key, v)

_scan_cache = _BoundedCache(maxsize=MAX_CACHE_SIZE)


def scan_folder(folder_path: str):
    if not os.path.isdir(folder_path):
        print(f"ERROR: Folder not found → {folder_path}")
        return

    all_files = [
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
    ]

    if not all_files:
        print("No files found in folder.")
        return

    total  = len(all_files)
    counts = {"clean": 0, "suspicious": 0, "malicious": 0,
              "skipped": 0, "cached": 0, "errors": 0}

    print("\n" + "=" * 60)
    print(f"  SILENTEYE — FOLDER SCAN")
    print(f"  Folder : {folder_path}")
    print(f"  Files  : {total}")
    print("=" * 60)

    for file_path in all_files:
        try:
            s1        = preprocess_file(file_path)
            file_hash = s1.get("file_hash")

            if file_hash and file_hash in _scan_cache:
                cv = _scan_cache.get(file_hash)
                counts["cached"] += 1
                if cv in counts:
                    counts[cv] += 1
                print(f"\n[CACHED → {cv.upper()}] {os.path.basename(file_path)}")
                continue

            result  = scan_file(file_path, s1=s1)
            verdict = result["final_verdict"]

            if file_hash:
                _scan_cache[file_hash] = verdict

            key = {"skip": "skipped", "error": "errors"}.get(verdict, verdict)
            if key in counts:
                counts[key] += 1

            label = {
                "clean":      "CLEAN     ",
                "suspicious": "SUSPICIOUS",
                "malicious":  "MALICIOUS ",
                "skip":       "SKIP      ",
                "error":      "ERROR     ",
            }.get(verdict, "UNKNOWN   ")

            print(f"\n  [{label}] {result['file']}")
            print(f"   Score   : {result['final_score']}")
            print(f"   ML      : {'yes' if result['ml_applied'] else 'no/NA'}")
            print(f"   Summary : {result['summary'][:80]}")
            print("-" * 60)

        except Exception as e:
            counts["errors"] += 1
            print(f"\n  [ERROR     ] {os.path.basename(file_path)}")
            print(f"   Error   : {str(e)}")
            print("-" * 60)

    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE")
    print(f"  Total      : {total}")
    print(f"  Clean      : {counts['clean']}  (includes {counts['cached']} cached)")
    print(f"  Suspicious : {counts['suspicious']}")
    print(f"  Malicious  : {counts['malicious']}")
    print(f"  Skipped    : {counts['skipped']}")
    print(f"  Errors     : {counts['errors']}")
    print("=" * 60)


# ================================
# ENTRY POINT
# ================================

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python main.py scan   <file_path>")
        print("  python main.py folder <folder_path>")
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "scan" and len(sys.argv) >= 3:
        result = scan_file(sys.argv[2])
        print("\n" + "=" * 60)
        print(f"  FINAL VERDICT : {result['final_verdict'].upper()}")
        print(f"  FINAL SCORE   : {result['final_score']}")
        print(f"  ML APPLIED    : {result['ml_applied']}")
        print(f"  SUMMARY       : {result['summary']}")
        print("=" * 60)

    elif command == "folder" and len(sys.argv) >= 3:
        scan_folder(sys.argv[2])

    else:
        print("Invalid command.")
        print("Usage:")
        print("  python main.py scan   <file_path>")
        print("  python main.py folder <folder_path>")
