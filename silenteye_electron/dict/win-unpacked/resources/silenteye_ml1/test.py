"""
SilentEye ML — Test Script  (FIXED v12)
=========================================
BUG FIXES:
  Bug 4  — Debug: reads "layers" but scanner returns "ml_layers"
            Fixed: reads both keys with fallback
  Bug 15 — Comments updated to match actual predictor behavior
  Bug 20 — Uncertain result displayed properly in debug output

Commands:
  python test.py realtrain --cat image
  python test.py realtrain --cat video
  python test.py realtrain --cat svg
  python test.py eval --cat image
  python test.py eval --cat video
  python test.py eval --cat svg
  python test.py status
  python test.py debug <file>
"""

import os
import sys
import argparse
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import config

G   = "\033[92m"
R   = "\033[91m"
Y   = "\033[93m"
C   = "\033[96m"
B   = "\033[1m"
RST = "\033[0m"


def _col(text, color):
    return f"{color}{text}{RST}"


def _check_dirs(category):
    td = config.TRAIN_DIRS.get(category, {})
    ed = config.TEST_DIRS.get(category, {})

    def check(paths, label):
        if isinstance(paths, list):
            found = 0
            for p in paths:
                if os.path.exists(p):
                    print(f"  {_col('[OK]', G)} {label}: {p}")
                    found += 1
                else:
                    print(f"  {_col('[MISSING]', R)} {label}: {p}")
            return found > 0
        else:
            if os.path.exists(paths):
                print(f"  {_col('[OK]', G)} {label}: {paths}")
                return True
            else:
                print(f"  {_col('[MISSING]', R)} {label}: {paths}")
                return False

    ok  = True
    ok &= check(td.get("clean",     ""), f"{category}/train/clean")
    ok &= check(td.get("malicious", ""), f"{category}/train/malicious")
    ok &= check(ed.get("clean",     ""), f"{category}/test/clean")
    ok &= check(ed.get("malicious", ""), f"{category}/test/malicious")
    return ok


def cmd_realtrain(args):
    from model.trainer import train_from_dirs

    cats = [args.cat] if args.cat else ["image", "video", "svg"]

    print(_col("\n[REALTRAIN] Using pre-split dataset from config.TRAIN_DIRS", B))
    print(_col("[REALTRAIN] Held-out eval will use config.TEST_DIRS\n", B))

    for cat in cats:
        print(f"\nChecking directories for [{cat.upper()}]...")
        if not _check_dirs(cat):
            print(_col(f"  [ERROR] Missing dirs for {cat}. Check config.py or set SILENTEYE_DATASET", R))
            continue

        td = config.TRAIN_DIRS[cat]
        ed = config.TEST_DIRS[cat]
        train_from_dirs(
            td["clean"], td["malicious"], cat,
            ed.get("clean"),  ed.get("malicious")
        )

    cmd_status(args)


def cmd_eval(args):
    cat = args.cat or "image"
    print(_col(f"\n[EVAL] Using held-out test dirs from config.TEST_DIRS", B))

    from model.trainer import evaluate_from_dirs
    evaluate_from_dirs(cat)


def cmd_status(args):
    print(_col("\n[STATUS] ML Model Status", B))
    from model.predictor import models_ready
    ready = models_ready()
    for cat, status in ready.items():
        if status:
            size = os.path.getsize(config.MODEL_PATHS[cat]) / 1024
            path = config.MODEL_PATHS[cat]
            print(f"  {_col('OK', G)}  {cat:<22} {size:.1f} KB  →  {path}")
        else:
            print(f"  {_col('MISSING', R)}  {cat:<22} →  run: python test.py realtrain")


def cmd_debug(args):
    """
    Debug a single file — show full scan result + all features.
    BUG 4 FIX: reads both "ml_layers" and "layers" keys from scanner result.
    BUG 15 FIX: shows actual model used, not assumed routing.
    BUG 20 FIX: shows uncertain result clearly.
    """
    if not args.file:
        print(_col("[ERROR] Provide a file: python test.py debug <file>", R))
        return

    fpath = Path(args.file)
    if not fpath.exists():
        print(_col(f"[ERROR] File not found: {fpath}", R))
        return

    from features import extract_features
    from model.predictor import predict
    from scanner import scan_bytes

    ext  = fpath.suffix.lower()
    data = fpath.read_bytes()

    # Full scanner result
    result = scan_bytes(data, ext)

    print(f"\n{'='*60}")
    print(f"  SCAN RESULT — {fpath.name}")
    print(f"{'='*60}")

    verdict     = result.get("verdict", "unknown")
    is_detected = result.get("detected", False)
    is_uncert   = result.get("verdict") == "uncertain"

    if is_uncert:
        v_col = Y
    elif is_detected:
        v_col = R
    else:
        v_col = G

    print(f"  Verdict     : {_col(verdict.upper(), v_col)}")
    print(f"  Score       : {result.get('score', 0)}/100")
    print(f"  ML Prob     : {result.get('probability', 0):.4f}")
    print(f"  Severity    : {result.get('severity', 'none')}")
    print(f"  Category    : {result.get('category', 'unknown')}")
    print(f"  Reason      : {result.get('reason', '')[:80]}")

    # BUG 4 FIX: try both "ml_layers" and "layers" keys
    layers = result.get("ml_layers") or result.get("layers") or []

    if layers:
        print(f"\n  Detection layers:")
        for l in layers:
            det = l.get("detected", False)
            col = R if det else G
            sym = "✓" if det else "○"
            sev = l.get("severity", "none")
            print(f"    {_col(sym, col)} {l.get('layer',''):<25} "
                  f"sev={sev:<8} score={l.get('score',0):<4} "
                  f"{l.get('reason','')[:45]}")
    else:
        print(f"\n  {_col('[WARN] No detection layers returned', Y)}")

    # Feature values
    r = extract_features(data, ext)
    if r:
        features = r["features"]
        category = r["category"]

        if category == "image":
            from features.image_features import FEATURE_NAMES as names
        elif category == "video":
            from features.video_features import FEATURE_NAMES as names
        else:
            from features.svg_features import FEATURE_NAMES as names

        # Get model prediction separately to show model_used
        pred = predict(features, category, ext=ext)
        print(f"\n  Model used  : {pred.get('model_used', 'unknown')}")
        print(f"  Fallback    : {pred.get('fallback', False)}")
        if pred.get("uncertain"):
            print(f"  {_col('[UNCERTAIN] Prediction failed — check model status', Y)}")

        print(f"\n  Feature values ({len(features)} features):")
        print(f"  {'#':<4} {'Feature':<35} {'Value':>10}  Note")
        print(f"  {'-'*60}")

        for i, val in enumerate(features):
            name = names[i] if i < len(names) else f"feat_{i}"
            note = ""
            if category == "image":
                if i == 15 and val < 0.08: note = "← LOW QT (steghide?)"
                if i == 16 and val < 0.03: note = "← LOW QT mean"
                if i == 10 and val > 0:    note = "← HAS ALPHA"
                if i == 14 and val > 0.25: note = "← MID-RANGE ALPHA"
                if i == 25 and val > 0.22: note = "← HIGH ±1 (JUNIWARD?)"
                if i == 26 and val < 0.40: note = "← LOW ZERO (JUNIWARD?)"
            elif category == "video":
                if i == 11 and val > 0: note = "← EXE IN HEADER"
                if i == 15 and val > 0: note = "← OVERLAY DETECTED"
                if i == 17 and val > 0: note = "← PE IN TAIL"
                if i == 12 and val > 0: note = "← C2 DOMAIN"
            elif category == "svg":
                if i == 0  and val > 0.3: note = "← HIGH DANGER PATTERN"
                if i == 2  and val > 0:   note = "← XXE PRESENT"
                if i == 7  and val > 0:   note = "← PE IN BASE64"
                if i == 14 and val > 0:   note = "← SHORT WITH SCRIPT"

            print(f"  [{i:>2}] {name:<35} {val:>10.5f}  {note}")

    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="SilentEye ML Test Suite v12")
    sub    = parser.add_subparsers(dest="cmd", required=True)

    p_rt = sub.add_parser("realtrain")
    p_rt.add_argument("--cat", choices=["image", "video", "svg"], default=None)

    p_ev = sub.add_parser("eval")
    p_ev.add_argument("--cat", choices=["image", "video", "svg"], default="image")

    sub.add_parser("status")

    p_db = sub.add_parser("debug")
    p_db.add_argument("file", nargs="?", default=None)

    args = parser.parse_args()

    if   args.cmd == "realtrain": cmd_realtrain(args)
    elif args.cmd == "eval":      cmd_eval(args)
    elif args.cmd == "status":    cmd_status(args)
    elif args.cmd == "debug":     cmd_debug(args)


if __name__ == "__main__":
    main()
