from typing import List, Dict

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    SCORE_MALICIOUS, SCORE_SUSPICIOUS_HIGH, SCORE_SUSPICIOUS_MED,
    SCORE_SUSPICIOUS_LOW, SCORE_CAP, UNAMBIGUOUS_HIGH_LAYERS, ARTIFACT_TAGS
)

# ================================
# CORRELATION RULES
# ================================

def apply_correlation(detections: List[Dict]):
    layers  = {d["layer"]: d for d in detections}
    boosted = []

    if "entropy_analysis" in layers and "polyglot_detection" in layers:
        boosted.append({"layer": "correlation_entropy_polyglot",
                        "severity": "medium", "score": 20,
                        "reason": "Entropy + Polyglot combined"})

    if "base64_obfuscation" in layers and "pe_detection" in layers:
        boosted.append({"layer": "correlation_base64_pe",
                        "severity": "high", "score": 50,
                        "reason": "Encoded executable payload"})

    if "ioc_extraction" in layers and "suspicious_domain_detection" in layers:
        boosted.append({"layer": "correlation_network_ioc",
                        "severity": "medium", "score": 25,
                        "reason": "Suspicious network indicators combined"})

    if any("metadata" in d["layer"] or "exif" in d["layer"] for d in detections) and "pe_detection" in layers:
        boosted.append({"layer": "correlation_metadata_payload",
                        "severity": "high", "score": 60,
                        "reason": "Executable hidden in metadata"})

    if "macro_detection" in layers and "external_relationship_check" in layers:
        ext_d = layers["external_relationship_check"]
        if ext_d.get("severity") in ("high", "medium"):
            boosted.append({"layer": "correlation_macro_network",
                            "severity": "high", "score": 55,
                            "reason": "Macro + suspicious external reference"})

    if "pdf_object_count" in layers and "pdf_stream_entropy" in layers:
        obj_d    = layers["pdf_object_count"]
        stream_d = layers["pdf_stream_entropy"]
        if obj_d.get("severity") in ("high", "medium") and stream_d.get("detected"):
            boosted.append({"layer": "correlation_pdf_heapspray_stream",
                            "severity": "high", "score": 65,
                            "reason": f"PDF heap spray + suspicious stream = exploit pattern"})

    if "pdf_structure_analysis" in layers and "pdf_object_count" in layers:
        struct_d = layers["pdf_structure_analysis"]
        obj_d    = layers["pdf_object_count"]
        if struct_d.get("detected") and obj_d.get("severity") in ("high", "medium"):
            boosted.append({"layer": "correlation_pdf_structure_heapspray",
                            "severity": "high", "score": 70,
                            "reason": "PDF malicious action + heap spray = confirmed exploit"})

    return boosted


# ================================
# SCORE DEDUPLICATION
# FIXED: Bug 7 — score inflation from correlated evidence
#
# Problem: one embedded PE triggers pe_detection(80) + yara(80) +
# base64(80) + overlay(40) + correlation_base64_pe(50) = 330 points
# for ONE root behavior.
#
# Fix: group detections by artifact_tag from config.ARTIFACT_TAGS.
# Within each artifact group, only the HIGHEST scoring layer counts.
# Untagged layers are always included (they represent independent signals).
#
# Example result:
#   executable_payload group: pe(80), yara(80), base64(80), xor(75)
#   → only pe(80) counts from this group
#   appended_payload group: overlay(40), image_eof(40)
#   → only one 40 counts
#   net score: 80 + 40 = 120 instead of 330
# ================================

def deduplicate_scores(detections: List[Dict]) -> List[Dict]:
    """
    Returns deduplicated detection list.
    For each artifact_tag group, keeps only the highest-scoring detection.
    Untagged layers are always kept.
    """
    tag_best: Dict[str, Dict] = {}  # tag -> best detection in that group
    untagged: List[Dict]      = []

    for d in detections:
        layer = d.get("layer", "")
        tag   = ARTIFACT_TAGS.get(layer)

        if tag is None:
            untagged.append(d)
        else:
            existing = tag_best.get(tag)
            if existing is None or d.get("score", 0) > existing.get("score", 0):
                tag_best[tag] = d

    deduped = untagged + list(tag_best.values())

    # Add a note to deduplicated detections so UI can show what was suppressed
    suppressed = [d for d in detections if d not in deduped]
    for d in deduped:
        tag = ARTIFACT_TAGS.get(d.get("layer", ""))
        if tag:
            suppressed_layers = [
                s["layer"] for s in suppressed
                if ARTIFACT_TAGS.get(s.get("layer", "")) == tag
            ]
            if suppressed_layers:
                d["_dedup_suppressed"] = suppressed_layers

    return deduped


# ================================
# MAIN SCORING ENGINE
# ================================

def calculate_risk_score(layer_results: List[Dict]) -> Dict:

    detections    = []
    high = medium = low = 0
    raw_weighted  = 0   # before dedup
    weighted_score = 0  # after dedup

    # Collect all detections
    for result in layer_results:
        if not result.get("detected", False):
            continue
        severity = result.get("severity", "none")
        layer    = result.get("layer",    "unknown")
        score    = result.get("score",    0)
        reason   = result.get("reason",   "")

        detections.append({
            "layer": layer, "severity": severity,
            "score": score, "reason": reason,
        })

    # Add correlations
    correlation_hits = apply_correlation(detections)
    detections.extend(correlation_hits)

    # FIXED: Bug 7 — deduplicate before scoring
    deduped = deduplicate_scores(detections)

    # Count severity and compute weighted score from DEDUPLICATED set
    for d in deduped:
        severity = d.get("severity", "none")
        if severity == "high":     high   += 1
        elif severity == "medium": medium += 1
        elif severity == "low":    low    += 1
        weighted_score += d.get("score", 0)

    # Unambiguous fast-path — only truly confirmed signals
    for d in detections:  # check ALL (including suppressed) for unambiguous
        if d["layer"] in UNAMBIGUOUS_HIGH_LAYERS:
            return {
                "final_score":    95,
                "verdict":        "malicious",
                "summary":        f"Confirmed: {d['layer']} — {d['reason']}",
                "detections":     deduped,
                "total_layers":   len(layer_results),
                "flagged_layers": len(deduped),
                "weighted_score": weighted_score,
            }

    # Weighted score → verdict
    capped = min(weighted_score, SCORE_CAP)

    if capped >= SCORE_MALICIOUS:
        verdict, final_score = "malicious",  85
    elif capped >= SCORE_SUSPICIOUS_HIGH:
        verdict, final_score = "suspicious", 65
    elif capped >= SCORE_SUSPICIOUS_MED:
        verdict, final_score = "suspicious", 45
    elif capped >= SCORE_SUSPICIOUS_LOW:
        verdict, final_score = "suspicious", 30
    else:
        verdict, final_score = "clean",      max(5, capped)

    # 3+ distinct high layers = suspicious even without score threshold
    high_layers = [d["layer"] for d in deduped if d["severity"] == "high"]
    if len(set(high_layers)) >= 3 and verdict == "clean":
        verdict, final_score = "suspicious", 55

    if deduped:
        top     = sorted(deduped, key=lambda x: x.get("score", 0), reverse=True)
        summary = " | ".join([f"{d['layer']}({d['severity']})" for d in top[:3]])
    else:
        summary = "No detections"

    return {
        "final_score":    final_score,
        "verdict":        verdict,
        "summary":        summary,
        "detections":     deduped,
        "total_layers":   len(layer_results),
        "flagged_layers": len(deduped),
        "weighted_score": weighted_score,
    }
