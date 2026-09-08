"""
SilentEye — Complete Test Script
==================================
Tests Stage 1 + Stage 2A (heuristic) + Stage 2B (ML if trained).

Run from the project root:
    python test_silenteye.py --file path/to/file.jpg
    python test_silenteye.py --folder path/to/folder
    python test_silenteye.py --folder path/to/folder --verbose
    python test_silenteye.py --benchmark path/to/folder

Results are printed to console AND saved to test_results.json
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

# ── PATH SETUP ───────────────────────────────────────────────────────────────
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_PATH)

# ── IMPORTS ──────────────────────────────────────────────────────────────────
try:
    from main import scan_file, scan_folder
    PIPELINE_OK = True
except ImportError as e:
    print(f"[ERROR] Cannot import pipeline: {e}")
    print("Make sure you are running from the project root directory")
    sys.exit(1)

# ── COLOUR OUTPUT ─────────────────────────────────────────────────────────────
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

VERDICT_COLOR = {
    "clean":      green,
    "suspicious": yellow,
    "malicious":  red,
    "cached":     lambda s: f"\033[90m{s}\033[0m",
    "skip":       lambda s: f"\033[90m{s}\033[0m",
    "error":      red,
}

def colorize_verdict(verdict):
    fn = VERDICT_COLOR.get(verdict, lambda s: s)
    return fn(verdict.upper())


# ── SINGLE FILE TEST ──────────────────────────────────────────────────────────
def test_single_file(file_path: str, verbose: bool = True):

    if not os.path.exists(file_path):
        print(red(f"[ERROR] File not found: {file_path}"))
        return None

    print()
    print(bold("=" * 65))
    print(bold(f"  SILENTEYE — SINGLE FILE SCAN"))
    print(f"  File: {os.path.basename(file_path)}")
    print(bold("=" * 65))

    start = time.perf_counter()
    result = scan_file(file_path)
    elapsed = (time.perf_counter() - start) * 1000

    verdict = result.get("final_verdict", "unknown")
    score   = result.get("final_score",   0)
    summary = result.get("summary",       "")

    print()
    print(f"  VERDICT  : {colorize_verdict(verdict)}")
    print(f"  SCORE    : {score}")
    print(f"  TIME     : {elapsed:.1f}ms")
    print(f"  SUMMARY  : {summary}")

    # Stage 1 details
    s1 = result.get("stage1", {})
    print()
    print(cyan("  [STAGE 1 — PREPROCESSING]"))
    print(f"  Status : {s1.get('status','?')}")
    print(f"  Type   : {s1.get('file_type','?')} ({s1.get('file_size_mb','?')} MB)")
    print(f"  Hash   : {(s1.get('file_hash') or 'N/A')[:32]}...")
    print(f"  Flags  : {s1.get('flags') or 'none'}")

    # Stage 2 details
    s2 = result.get("stage2", {})
    detections = s2.get("detections", [])
    total_layers = s2.get("total_layers", 0)
    flagged      = s2.get("flagged_layers", 0)
    weighted     = s2.get("weighted_score", 0)

    print()
    print(cyan("  [STAGE 2A — HEURISTIC ENGINE]"))
    print(f"  Layers checked  : {total_layers}")
    print(f"  Layers flagged  : {flagged}")
    print(f"  Weighted score  : {weighted}")

    if detections and verbose:
        print()
        print(cyan("  [DETECTIONS]"))
        for d in sorted(detections, key=lambda x: x.get("score", 0), reverse=True):
            sev    = d.get("severity", "?")
            layer  = d.get("layer",    "?")
            reason = d.get("reason",   "")
            score_d = d.get("score", 0)
            if sev == "high":
                tag = red(f"[HIGH +{score_d}]")
            elif sev == "medium":
                tag = yellow(f"[MED  +{score_d}]")
            else:
                tag = f"[LOW  +{score_d}]"
            print(f"  {tag} {layer}")
            if reason:
                print(f"         {reason[:100]}")

    print()
    print(bold("=" * 65))
    return result


# ── FOLDER TEST ────────────────────────────────────────────────────────────────
def test_folder(folder_path: str, verbose: bool = False, save_json: bool = True):

    if not os.path.isdir(folder_path):
        print(red(f"[ERROR] Folder not found: {folder_path}"))
        return

    # Collect all files
    ALLOWED_EXTS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mpeg", ".3gp", ".webm",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
        ".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma",
        ".svg", ".svgz",
    }

    all_files = [
        str(p) for p in Path(folder_path).rglob("*")
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTS
    ]

    total = len(all_files)
    if total == 0:
        print(yellow(f"[WARN] No supported files found in {folder_path}"))
        return

    print()
    print(bold("=" * 65))
    print(bold(f"  SILENTEYE — FOLDER SCAN"))
    print(f"  Folder : {folder_path}")
    print(f"  Files  : {total}")
    print(bold("=" * 65))

    results = []
    stats = {"clean": 0, "suspicious": 0, "malicious": 0,
             "cached": 0, "skip": 0, "error": 0}
    times = []
    scan_cache = {}

    for i, file_path in enumerate(all_files, 1):
        fname = os.path.basename(file_path)
        pct   = int((i / total) * 100)

        # Progress line
        print(f"\r  [{pct:3d}%] {i}/{total} — {fname[:45]:<45}", end="", flush=True)

        start   = time.perf_counter()
        result  = scan_file(file_path)
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)

        verdict = result.get("final_verdict", "error")
        score   = result.get("final_score", 0)
        summary = result.get("summary", "")
        dets    = result.get("stage2", {}).get("detections", [])

        stats[verdict] = stats.get(verdict, 0) + 1
        results.append({
            "file":    fname,
            "path":    file_path,
            "verdict": verdict,
            "score":   score,
            "summary": summary,
            "time_ms": round(elapsed, 1),
            "detections": [d.get("layer") for d in dets],
        })

        # Verbose: print each file
        if verbose:
            print()
            cv = colorize_verdict(verdict)
            print(f"  [{cv}] {fname}")
            if dets:
                top = sorted(dets, key=lambda x: x.get("score", 0), reverse=True)[:3]
                for d in top:
                    print(f"         → {d.get('layer')} ({d.get('severity')}): {d.get('reason','')[:80]}")

    print()  # newline after progress

    # ── Detect if this is malicious or clean dataset ──
    is_malicious = "malicious" in folder_path.lower()

    # ── Per-category breakdown ──
    cat_stats = {}
    for r in results:
        path = r.get("path", "")
        cat  = "unknown"
        for c in ["images","audio","video","svg","docx","pdf","edge_cases"]:
            if f"\\{c}\\" in path or f"/{c}/" in path:
                cat = c
                break
        if cat not in cat_stats:
            cat_stats[cat] = {"total":0,"clean":0,"suspicious":0,"malicious":0,"times":[]}
        cat_stats[cat]["total"] += 1
        cat_stats[cat][r["verdict"]] = cat_stats[cat].get(r["verdict"], 0) + 1
        cat_stats[cat]["times"].append(r["time_ms"])

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    total_scanned = total - stats.get("cached", 0)
    detected      = stats["suspicious"] + stats["malicious"]
    rate          = (detected / total_scanned * 100) if total_scanned > 0 else 0
    avg_time      = sum(times) / len(times) if times else 0
    max_time      = max(times) if times else 0

    print()
    print(bold("=" * 65))
    print(bold("  SCAN RESULTS"))
    print(bold("=" * 65))
    print(f"  Total files   : {total}")
    print(f"  {green('Clean')}         : {stats['clean']}")
    print(f"  {yellow('Suspicious')}    : {stats['suspicious']}")
    print(f"  {red('Malicious')}     : {stats['malicious']}")
    print(f"  Cached        : {stats['cached']}")
    print(f"  Skipped       : {stats['skip']}")
    print(f"  Errors        : {stats['error']}")
    print()

    if is_malicious:
        # TP rate for malicious dataset
        tp_color = green if rate > 80 else yellow if rate > 50 else red
        print(f"  TP rate       : {tp_color(f'{rate:.1f}%')} ({detected} detected out of {total_scanned})")
        print(f"  Missed        : {total_scanned - detected} files ({100-rate:.1f}%)")
    else:
        # FP rate for clean dataset
        fp_color = red if rate > 10 else yellow if rate > 5 else green
        print(f"  FP rate       : {fp_color(f'{rate:.1f}%')} ({detected} flagged out of {total_scanned})")

    print(f"  Avg scan time : {avg_time:.1f}ms per file")
    print(f"  Max scan time : {max_time:.1f}ms")
    print(bold("=" * 65))

    # ── Per-category table ──
    print()
    print(bold("  PER-CATEGORY BREAKDOWN"))
    print(bold("  " + "-" * 63))
    if is_malicious:
        print(f"  {'Category':<12} {'Total':>6} {'Detected':>9} {'Missed':>7} {'TP%':>7} {'Avg(ms)':>9}")
        print(f"  {'-'*58}")
        for cat in ["images","audio","video","svg","docx","pdf"]:
            cs = cat_stats.get(cat)
            if not cs or cs["total"] == 0: continue
            det    = cs.get("suspicious",0) + cs.get("malicious",0)
            missed = cs["total"] - det
            tp     = det / cs["total"] * 100
            avgt   = sum(cs["times"]) / len(cs["times"])
            tp_c   = green(f"{tp:>6.1f}%") if tp > 80 else yellow(f"{tp:>6.1f}%") if tp > 50 else red(f"{tp:>6.1f}%")
            print(f"  {cat:<12} {cs['total']:>6} {det:>9} {missed:>7} {tp_c} {avgt:>9.1f}")
    else:
        print(f"  {'Category':<12} {'Total':>6} {'FP':>5} {'FP%':>7} {'Avg(ms)':>9}")
        print(f"  {'-'*45}")
        for cat in ["images","audio","video","svg","docx","pdf","edge_cases"]:
            cs = cat_stats.get(cat)
            if not cs or cs["total"] == 0: continue
            fp   = cs.get("suspicious",0) + cs.get("malicious",0)
            fpr  = fp / cs["total"] * 100
            avgt = sum(cs["times"]) / len(cs["times"])
            fp_c = green(f"{fpr:>6.1f}%") if fpr < 2 else yellow(f"{fpr:>6.1f}%") if fpr < 10 else red(f"{fpr:>6.1f}%")
            print(f"  {cat:<12} {cs['total']:>6} {fp:>5} {fp_c} {avgt:>9.1f}")
    print(bold("  " + "-" * 63))

    # ── Attack type breakdown (malicious only) ──
    if is_malicious:
        print()
        print(bold("  DETECTION BY ATTACK TYPE"))
        print(bold("  " + "-" * 63))
        attack_stats = {}
        for r in results:
            fname = r["file"]
            # Extract attack type from filename (mal_<attack>_<id>.ext)
            parts = fname.split("_")
            if len(parts) >= 3 and fname.startswith("mal_"):
                attack = "_".join(parts[1:-1])
                if attack not in attack_stats:
                    attack_stats[attack] = {"total":0, "detected":0}
                attack_stats[attack]["total"] += 1
                if r["verdict"] in ("suspicious","malicious"):
                    attack_stats[attack]["detected"] += 1

        if attack_stats:
            print(f"  {'Attack Type':<32} {'Total':>6} {'Det':>5} {'TP%':>7}")
            print(f"  {'-'*53}")
            for at, ast in sorted(attack_stats.items(), key=lambda x: -x[1]["detected"]/max(x[1]["total"],1)):
                tp   = ast["detected"] / ast["total"] * 100 if ast["total"] > 0 else 0
                tp_c = green(f"{tp:>6.1f}%") if tp > 80 else yellow(f"{tp:>6.1f}%") if tp > 50 else red(f"{tp:>6.1f}%")
                print(f"  {at:<32} {ast['total']:>6} {ast['detected']:>5} {tp_c}")
        print(bold("  " + "-" * 63))

    # Print missed/flagged files
    if is_malicious:
        missed_files = [r for r in results if r["verdict"] == "clean"]
        if missed_files:
            print()
            print(bold(f"  MISSED FILES ({len(missed_files)} not detected)"))
            print(bold("  " + "-" * 63))
            by_attack = {}
            for r in missed_files:
                parts  = r["file"].split("_")
                attack = "_".join(parts[1:-1]) if len(parts) >= 3 and r["file"].startswith("mal_") else "unknown"
                by_attack[attack] = by_attack.get(attack, 0) + 1
            for at, cnt in sorted(by_attack.items(), key=lambda x: -x[1]):
                print(f"  {at:<35}: {cnt} files missed")
    else:
        flagged_files = [r for r in results if r["verdict"] in ("suspicious", "malicious")]
        if flagged_files:
            print()
            print(bold(f"  FLAGGED FILES — FALSE POSITIVES ({len(flagged_files)})"))
            print(bold("  " + "-" * 63))
            for r in sorted(flagged_files, key=lambda x: x["score"], reverse=True)[:20]:
                cv = colorize_verdict(r["verdict"])
                print(f"  [{cv}] {r['file']}")
                print(f"   Score   : {r['score']}")
                print(f"   Summary : {r['summary'][:80]}")
                if r["detections"]:
                    print(f"   Layers  : {', '.join(r['detections'][:5])}")
                print()

    # Save JSON
    if save_json:
        out_path = os.path.join(BASE_PATH, "test_results.json")
        save_data = {
            "folder":      folder_path,
            "total":       total,
            "stats":       stats,
            "avg_time_ms": round(avg_time, 1),
            "max_time_ms": round(max_time, 1),
            "results":     results,
        }
        if is_malicious:
            save_data["tp_rate_pct"] = round(rate, 2)
            save_data["missed_pct"]  = round(100 - rate, 2)
        else:
            save_data["fp_rate_pct"] = round(rate, 2)
        # FIXED: atomic write — temp file first, rename after complete
        # Prevents empty JSON if crash/error occurs during write
        import shutil
        tmp_path = out_path + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(save_data, f, indent=2)
            shutil.move(tmp_path, out_path)
            size_kb = os.path.getsize(out_path) / 1024
            print(f"  Results saved → {out_path} ({size_kb:.0f} KB)")
        except Exception as e:
            print(f"  ERROR saving results: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


# ── BENCHMARK ─────────────────────────────────────────────────────────────────
def run_benchmark(folder_path: str):
    """
    Performance benchmark — measures scan time per file type.
    """
    ALLOWED_EXTS = {
        ".jpg", ".jpeg", ".png", ".pdf", ".docx",
        ".mp3", ".mp4", ".svg", ".wav", ".flac",
    }
    files = [
        str(p) for p in Path(folder_path).rglob("*")
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTS
    ][:50]  # cap at 50 for benchmark

    if not files:
        print(red("No supported files found for benchmark"))
        return

    print()
    print(bold("=" * 65))
    print(bold("  SILENTEYE — PERFORMANCE BENCHMARK"))
    print(bold("=" * 65))

    by_type = {}
    for file_path in files:
        ext = Path(file_path).suffix.lower()
        start   = time.perf_counter()
        scan_file(file_path)
        elapsed = (time.perf_counter() - start) * 1000
        by_type.setdefault(ext, []).append(elapsed)

    print(f"\n  {'EXT':<8} {'COUNT':<7} {'AVG(ms)':<10} {'MAX(ms)':<10} {'STATUS'}")
    print(f"  {'-'*55}")
    for ext, times in sorted(by_type.items()):
        avg = sum(times) / len(times)
        mx  = max(times)
        status = green("GOOD") if avg < 100 else yellow("SLOW") if avg < 500 else red("TOO SLOW")
        print(f"  {ext:<8} {len(times):<7} {avg:<10.1f} {mx:<10.1f} {status}")
    print(bold("=" * 65))


# ── ML STATUS CHECK ───────────────────────────────────────────────────────────
def check_ml_status():
    print()
    print(bold("=" * 65))
    print(bold("  ML MODEL STATUS"))
    print(bold("=" * 65))
    try:
        sys.path.insert(0, os.path.join(BASE_PATH, "ml"))
        from ml_model import models_available
        avail = models_available()
        for cat, is_avail in avail.items():
            if is_avail:
                from ml_model import MODEL_FILES
                size = os.path.getsize(MODEL_FILES[cat]) / 1024
                print(f"  {cat:<8} {green('TRAINED')}  ({size:.0f} KB)")
            else:
                print(f"  {cat:<8} {yellow('NOT TRAINED')}  — run: python ml/ml_trainer.py --synthetic")
    except ImportError:
        print(f"  {red('ML not available')} — install: pip install scikit-learn pillow numpy joblib")
    print(bold("=" * 65))


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SilentEye — Test Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_silenteye.py --file photo.jpg
  python test_silenteye.py --folder ./test_images
  python test_silenteye.py --folder ./test_images --verbose
  python test_silenteye.py --folder /WhatsApp/Media
  python test_silenteye.py --benchmark ./test_images
  python test_silenteye.py --ml-status
        """
    )
    parser.add_argument("--file",      type=str, help="Scan a single file")
    parser.add_argument("--folder",    type=str, help="Scan all files in a folder")
    parser.add_argument("--benchmark", type=str, help="Run performance benchmark on folder")
    parser.add_argument("--verbose",   action="store_true", help="Show per-file detection details")
    parser.add_argument("--ml-status", action="store_true", help="Check ML model status")
    args = parser.parse_args()

    if args.ml_status:
        check_ml_status()
    elif args.file:
        test_single_file(args.file, verbose=True)
    elif args.folder:
        test_folder(args.folder, verbose=args.verbose)
    elif args.benchmark:
        run_benchmark(args.benchmark)
    else:
        parser.print_help()
