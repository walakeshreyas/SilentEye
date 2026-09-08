"""
SilentEye ML — Trainer  
=====================================
"""

import os, sys, numpy as np
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config
from .synthetic_data import generate


def train_one(X, y, category, n_estimators=None, max_depth=None,
              save=True, model_key=None, feature_mask=None):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.metrics import f1_score, roc_auc_score
    import joblib

    n_estimators = n_estimators or config.TRAIN_N_ESTIMATORS
    max_depth    = max_depth    or config.TRAIN_MAX_DEPTH
    save_key     = model_key or category

    X_train = X[:, feature_mask] if feature_mask is not None else X
    n_clean = int(np.sum(y == 0))
    n_mal   = int(np.sum(y == 1))

    if n_clean < 10 or n_mal < 10:
        return {"error": f"Need >=10 samples. Got clean={n_clean}, mal={n_mal}"}

    print(f"\n{'='*55}")
    print(f"  TRAINING — {save_key.upper()}")
    print(f"  Samples  : {len(X)}  ({n_clean} clean, {n_mal} mal)")
    print(f"  Features : {X_train.shape[1]}"
          f"{'  [masked]' if feature_mask is not None else ''}")
    print(f"  Trees    : {n_estimators}, max_depth={max_depth}")
    print(f"{'='*55}")

    clf = RandomForestClassifier(
        n_estimators     = n_estimators,
        max_depth        = max_depth,
        min_samples_leaf = 2,
        max_features     = "sqrt",
        class_weight     = "balanced",
        random_state     = 42,
        n_jobs           = -1,
    )

    cv_folds = min(5, min(n_clean, n_mal))
    if cv_folds >= 3:
        cv     = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        cv_f1  = cross_val_score(clf, X_train, y, cv=cv, scoring="f1")
        cv_auc = cross_val_score(clf, X_train, y, cv=cv, scoring="roc_auc")
    else:
        cv_f1  = np.array([0.0])
        cv_auc = np.array([0.0])

    clf.fit(X_train, y)

    y_pred  = clf.predict(X_train)
    y_proba = clf.predict_proba(X_train)[:, 1]
    f1      = f1_score(y, y_pred, zero_division=0)
    auc     = roc_auc_score(y, y_proba) if len(np.unique(y)) > 1 else 0.0

    # FIX v11: use actual category not hardcoded "image"
    all_names  = _get_feature_names(category)
    if feature_mask is not None:
        feat_names = [all_names[i] if i < len(all_names) else f"feat_{i}"
                      for i in feature_mask]
    else:
        feat_names = all_names

    importances  = clf.feature_importances_
    top_idx      = np.argsort(importances)[::-1][:5]
    top_features = [(feat_names[i] if i < len(feat_names) else f"feat_{i}",
                     round(float(importances[i]), 4)) for i in top_idx]

    print(f"\n  Train F1   : {f1:.4f}")
    print(f"  Train AUC  : {auc:.4f}")
    print(f"  CV F1      : {cv_f1.mean():.4f} +/- {cv_f1.std():.4f}")
    print(f"\n  Top features:")
    for name, imp in top_features:
        bar = "█" * int(imp * 50)
        print(f"    {name:<35} {imp:.4f}  {bar}")

    metrics = {
        "category":     save_key,
        "n_samples":    len(X),
        "n_clean":      n_clean,
        "n_malicious":  n_mal,
        "train_f1":     round(float(f1), 4),
        "cv_f1_mean":   round(float(cv_f1.mean()), 4),
        "cv_f1_std":    round(float(cv_f1.std()), 4),
        "top_features": top_features,
        "feature_mask": feature_mask,
    }

    if save:
        os.makedirs(config.MODELS_DIR, exist_ok=True)
        out = config.MODEL_PATHS[save_key]
        joblib.dump({"model": clf, "feature_mask": feature_mask}, out, compress=3)
        size_kb = os.path.getsize(out) / 1024
        print(f"\n  Saved → {out} ({size_kb:.1f} KB)")
        metrics["model_path"]    = out
        metrics["model_size_kb"] = round(size_kb, 1)

    return metrics


def _load_dirs(dir_paths, label, exts, category):
    """Load features from one or multiple directories."""
    from features import extract_features
    if isinstance(dir_paths, str):
        dir_paths = [dir_paths]

    X_all, y_all = [], []

    for dir_path in dir_paths:
        if not os.path.exists(dir_path):
            print(f"  [WARN] Directory not found: {dir_path}")
            continue
        files = [f for f in Path(dir_path).rglob("*")
                 if f.is_file() and f.suffix.lower() in exts]
        lbl    = "clean" if label == 0 else "malicious"
        print(f"  Loading {len(files)} {lbl} from {Path(dir_path).name}...")
        loaded = failed = 0
        for f in files:
            try:
                r = extract_features(f.read_bytes(), f.suffix.lower())
                if r and r["category"] == category:
                    X_all.append(r["features"])
                    y_all.append(label)
                    loaded += 1
                else:
                    failed += 1
            except:
                failed += 1
        print(f"    Loaded={loaded}" + (f"  Failed={failed}" if failed else ""))

    return X_all, y_all


def _eval_model(model_key, eval_clean_dirs, eval_mal_dirs,
                exts_filter=None, category="image"):
    from sklearn.metrics import (precision_score, recall_score,
                                  f1_score, confusion_matrix)
    import joblib

    exts = exts_filter or config.IMAGE_EXTS

    Xc, yc = _load_dirs(eval_clean_dirs, 0, exts, category)
    Xm, ym = _load_dirs(eval_mal_dirs,   1, exts, category)

    if not Xc or not Xm:
        print(f"  [WARN] Not enough test data for {model_key}")
        return {}

    saved  = joblib.load(config.MODEL_PATHS[model_key])
    clf    = saved["model"]
    mask   = saved.get("feature_mask", None)

    X_eval = np.vstack([Xc, Xm])
    y_eval = np.hstack([yc, ym])
    if mask is not None:
        X_eval = X_eval[:, mask]

    y_pred  = clf.predict(X_eval)
    y_proba = clf.predict_proba(X_eval)[:, 1]

    prec = precision_score(y_eval, y_pred, zero_division=0)
    rec  = recall_score(y_eval, y_pred, zero_division=0)
    f1   = f1_score(y_eval, y_pred, zero_division=0)
    cm   = confusion_matrix(y_eval, y_pred)
    tn_v, fp_v, fn_v, tp_v = cm.ravel() if cm.shape==(2,2) else (0,0,0,0)
    fpr  = fp_v/(fp_v+tn_v) if (fp_v+tn_v)>0 else 0.0
    fnr  = fn_v/(fn_v+tp_v) if (fn_v+tp_v)>0 else 0.0

    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; RST = "\033[0m"
    f1c  = G if f1  > 0.80 else Y if f1  > 0.60 else R
    fprc = G if fpr < 0.05 else Y if fpr < 0.15 else R
    fnrc = G if fnr < 0.10 else Y if fnr < 0.20 else R

    print(f"\n  {'='*50}")
    print(f"  HELD-OUT TEST EVAL — {model_key.upper()}")
    print(f"  files: {len(y_eval)}  (clean={len(Xc)}, mal={len(Xm)})")
    print(f"  {'='*50}")
    print(f"  TP={tp_v}  TN={tn_v}  FP={fp_v}  FN={fn_v}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1        : {f1c}{f1:.4f}{RST}  (target > 0.80)")
    print(f"  FP Rate   : {fprc}{fpr:.4f}{RST}  (target < 0.05)")
    print(f"  FN Rate   : {fnrc}{fnr:.4f}{RST}  (target < 0.10)")
    print(f"  {'='*50}")

    return {
        "test_f1":  round(float(f1),  4),
        "test_fpr": round(float(fpr), 4),
        "test_fnr": round(float(fnr), 4),
        "test_tp":  int(tp_v), "test_tn": int(tn_v),
        "test_fp":  int(fp_v), "test_fn": int(fn_v),
    }


def _train_image_split(clean_dirs, mal_dirs,
                        eval_clean_dirs=None, eval_mal_dirs=None):
    """Train image_jpg and image_png_alpha models."""
    from features import extract_features

    ALPHA_MASK = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22, 23, 24]

    jpg_clean, jpg_mal         = [], []
    png_alp_clean, png_alp_mal = [], []

    def load_split(dirs, label):
        if isinstance(dirs, str):
            dirs = [dirs]
        lbl   = "clean" if label == 0 else "malicious"
        jpg_n = alp_n = fail_n = 0
        for dir_path in dirs:
            if not os.path.exists(dir_path):
                print(f"  [WARN] Not found: {dir_path}")
                continue
            all_files = [f for f in Path(dir_path).rglob("*")
                         if f.is_file() and f.suffix.lower() in config.IMAGE_EXTS]
            print(f"\n  Loading {len(all_files)} {lbl} from {Path(dir_path).name}...")
            for i, f in enumerate(all_files):
                ext = f.suffix.lower()
                try:
                    r = extract_features(f.read_bytes(), ext)
                    if not r or r["category"] != "image":
                        fail_n += 1; continue
                    feat = r["features"]
                    if ext in config.JPEG_EXTS:
                        (jpg_clean if label==0 else jpg_mal).append(feat)
                        jpg_n += 1
                    elif ext in config.PNG_EXTS:
                        (png_alp_clean if label==0 else png_alp_mal).append(feat)
                        alp_n += 1
                except:
                    fail_n += 1
                if (i+1) % 500 == 0:
                    print(f"    {i+1}/{len(all_files)} processed...")
            print(f"    Done: jpg={jpg_n}, png/tiff={alp_n}, failed={fail_n}")

    print(f"\n{'='*55}")
    print(f"  IMAGE SPLIT TRAINING v11")
    print(f"  Sources: ALASKA2 + BOSSBase + DIV2K + Flatfield")
    print(f"  Models : image_jpg + image_png_alpha")
    print(f"{'='*55}")

    load_split(clean_dirs, 0)
    load_split(mal_dirs,   1)

    results = {}

    # Train JPEG model
    if len(jpg_clean) >= 10 and len(jpg_mal) >= 10:
        Xj  = np.vstack([jpg_clean, jpg_mal])
        yj  = np.hstack([np.zeros(len(jpg_clean)), np.ones(len(jpg_mal))])
        idx = np.random.default_rng(42).permutation(len(Xj))
        m   = train_one(Xj[idx], yj[idx], "image", model_key="image_jpg")
        if eval_clean_dirs and eval_mal_dirs:
            em = _eval_model("image_jpg", eval_clean_dirs, eval_mal_dirs,
                             exts_filter=config.JPEG_EXTS, category="image")
            m.update(em)
        results["image_jpg"] = m
    else:
        print(f"  [WARN] Not enough JPEG: clean={len(jpg_clean)}, mal={len(jpg_mal)}")
        results["image_jpg"] = {"error": "Not enough JPEG data"}

    # Train PNG Alpha model
    if len(png_alp_clean) >= 10 and len(png_alp_mal) >= 10:
        Xa  = np.vstack([png_alp_clean, png_alp_mal])
        ya  = np.hstack([np.zeros(len(png_alp_clean)), np.ones(len(png_alp_mal))])
        idx = np.random.default_rng(42).permutation(len(Xa))
        m   = train_one(Xa[idx], ya[idx], "image",
                        model_key="image_png_alpha",
                        feature_mask=ALPHA_MASK)
        if eval_clean_dirs and eval_mal_dirs:
            em = _eval_model("image_png_alpha", eval_clean_dirs, eval_mal_dirs,
                             exts_filter=config.PNG_EXTS, category="image")
            m.update(em)
        results["image_png_alpha"] = m
    else:
        print(f"  [WARN] Not enough PNG/TIFF: "
              f"clean={len(png_alp_clean)}, mal={len(png_alp_mal)}")
        results["image_png_alpha"] = {"error": "Not enough PNG/TIFF data"}

    return results


def train_from_dirs(clean_dir, mal_dir, category,
                    eval_clean_dir=None, eval_mal_dir=None):
    if category == "image":
        return _train_image_split(
            clean_dir, mal_dir,
            eval_clean_dir, eval_mal_dir
        )

    exts = {"video": config.VIDEO_EXTS,
            "svg":   config.SVG_EXTS}.get(category, set())

    print(f"\nLoading TRAIN data for {category}...")
    Xc, yc = _load_dirs(clean_dir, 0, exts, category)
    Xm, ym = _load_dirs(mal_dir,   1, exts, category)

    if not Xc or not Xm:
        return {"error": "Could not load data"}

    X   = np.vstack([Xc, Xm])
    y   = np.hstack([yc, ym])
    idx = np.random.default_rng(42).permutation(len(X))
    # FIX v11: pass correct category
    m   = train_one(X[idx], y[idx], category)

    if eval_clean_dir and eval_mal_dir:
        em = _eval_model(category, eval_clean_dir, eval_mal_dir,
                         exts_filter=exts, category=category)
        m.update(em)
    return m


def train_all(synthetic=True, n_clean=None, n_mal=None):
    n_clean = n_clean or config.TRAIN_SYNTHETIC_N
    n_mal   = n_mal   or config.TRAIN_SYNTHETIC_N
    all_metrics = {}
    for cat in ["image", "video", "svg"]:
        X, y = generate(cat, n_clean=n_clean, n_mal=n_mal)
        key  = "image_jpg" if cat == "image" else cat
        all_metrics[cat] = train_one(X, y, cat, model_key=key)
    _print_all_summary(all_metrics)
    return all_metrics


def train_all_real(cats=None):
    all_metrics = {}
    cats = cats or ["image", "video", "svg"]

    for cat in cats:
        td = config.TRAIN_DIRS.get(cat, {})
        ed = config.TEST_DIRS.get(cat, {})
        clean_tr = td.get("clean", "")
        mal_tr   = td.get("malicious", "")
        clean_te = ed.get("clean",     "")
        mal_te   = ed.get("malicious", "")

        def paths_exist(p):
            if isinstance(p, list):
                return any(os.path.exists(x) for x in p)
            return os.path.exists(str(p))

        if not paths_exist(clean_tr) or not paths_exist(mal_tr):
            print(f"  [SKIP] {cat} — train dirs not found")
            continue

        has_test = paths_exist(clean_te) and paths_exist(mal_te)
        m = train_from_dirs(
            clean_tr, mal_tr, cat,
            clean_te if has_test else None,
            mal_te   if has_test else None,
        )
        all_metrics[cat] = m

    _print_all_summary(all_metrics)
    return all_metrics


def evaluate_from_dirs(category):
    """Called by test.py eval command."""
    ed       = config.TEST_DIRS.get(category, {})
    clean_te = ed.get("clean",     "")
    mal_te   = ed.get("malicious", "")

    exts = {
        "image": config.IMAGE_EXTS,
        "video": config.VIDEO_EXTS,
        "svg":   config.SVG_EXTS,
    }.get(category, config.IMAGE_EXTS)

    if category == "image":
        print(f"\nEvaluating image_jpg...")
        _eval_model("image_jpg", clean_te, mal_te,
                    exts_filter=config.JPEG_EXTS, category="image")
        print(f"\nEvaluating image_png_alpha...")
        _eval_model("image_png_alpha", clean_te, mal_te,
                    exts_filter=config.PNG_EXTS, category="image")
    else:
        _eval_model(category, clean_te, mal_te,
                    exts_filter=exts, category=category)


def _print_all_summary(all_metrics):
    print(f"\n{'='*60}")
    print(f"  ALL MODELS TRAINED")
    for cat, m in all_metrics.items():
        if isinstance(m, dict) and any(
                k in m for k in ("image_jpg", "image_png_alpha")):
            for sub in ("image_jpg", "image_png_alpha"):
                sm = m.get(sub, {})
                if sm.get("error"): continue
                kb  = sm.get("model_size_kb", 0)
                cv  = sm.get("cv_f1_mean",    0)
                tf1 = sm.get("test_f1", sm.get("train_f1", 0))
                fpr = sm.get("test_fpr", "N/A")
                fpr_s = f"{fpr:.4f}" if isinstance(fpr, float) else fpr
                print(f"  {sub:<22} CV_F1={cv:.4f}  "
                      f"test_F1={tf1:.4f}  FPR={fpr_s}  {kb:.1f}KB")
        else:
            if not m or m.get("error"): continue
            kb  = m.get("model_size_kb", 0)
            cv  = m.get("cv_f1_mean",   0)
            tf1 = m.get("test_f1", m.get("train_f1", 0))
            fpr = m.get("test_fpr", "N/A")
            fpr_s = f"{fpr:.4f}" if isinstance(fpr, float) else fpr
            print(f"  {cat:<22} CV_F1={cv:.4f}  "
                  f"test_F1={tf1:.4f}  FPR={fpr_s}  {kb:.1f}KB")
    print(f"{'='*60}\n")


def _get_feature_names(category):
    """FIX v11: returns correct feature names per category."""
    from features.image_features import FEATURE_NAMES as I
    from features.video_features import FEATURE_NAMES as V
    from features.svg_features   import FEATURE_NAMES as S
    return {"image": I, "video": V, "svg": S}.get(category, I)
