#!/usr/bin/env python3
"""
Offline scoring evaluation for IOC Enricher.

Collect API results ONCE into a labelled dataset, then re-score it as often as
you like with no API calls. That matters on free tiers (VirusTotal is ~4
requests/minute) and makes weight tuning fast and repeatable.

Dataset format (JSON Lines, one IOC per line):

  {"ioc": "185.220.101.7", "ioc_type": "ipv4", "label": "malicious",
   "results": [ {"source": "AbuseIPDB", "malicious": true, "confidence": 0.62},
                {"source": "VirusTotal", "malicious": true, "confidence": 0.91} ]}

"results" is exactly the list of normalized per-source dicts that
scorer.score() receives. "label" is "malicious" or "benign" (ground truth).

Usage:
  python evaluate.py dataset.jsonl

Prints, for the current scoring.yaml:
  1. precision / recall / F1 / confusion matrix, plus misclassified IOCs
  2. a comparison of scorer variants (v1-style baseline vs each v2 feature)
  3. a sweep of the "suspicious" threshold
  4. a per-source ablation (what happens if a source is removed)

A prediction counts as positive when the verdict is SUSPICIOUS or MALICIOUS
(an analyst should look at both). UNKNOWN (no usable data) is counted as
negative and reported separately.
"""

import argparse
import copy
import json
import sys
from contextlib import contextmanager

import scorer

POSITIVE = ("MALICIOUS", "SUSPICIOUS")


def load(path):
    rows = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("label") not in ("malicious", "benign"):
                sys.exit(f"line {n}: label must be 'malicious' or 'benign'")
            rows.append(row)
    if not rows:
        sys.exit("dataset is empty")
    return rows


@contextmanager
def patched(**attrs):
    """Temporarily override scorer module globals, restoring them afterwards."""
    saved = {k: copy.deepcopy(getattr(scorer, k)) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(scorer, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(scorer, k, v)


def run(rows, drop_source=None):
    tp = fp = fn = tn = unknown = 0
    wrong = []
    for row in rows:
        results = [r for r in row["results"] if r.get("source") != drop_source]
        out = scorer.score(results, row.get("ioc_type"))
        predicted = out["verdict"] in POSITIVE
        actual = row["label"] == "malicious"
        unknown += out["verdict"] == "UNKNOWN"
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
            wrong.append((row["ioc"], "benign", out["verdict"], out["score"]))
        elif not predicted and actual:
            fn += 1
            wrong.append((row["ioc"], "malicious", out["verdict"], out["score"]))
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "unknown": unknown,
            "precision": precision, "recall": recall, "f1": f1, "wrong": wrong}


def line(label, m):
    return (f"{label:<28} P={m['precision']:.2f}  R={m['recall']:.2f}  F1={m['f1']:.2f}  "
            f"(TP {m['tp']}, FP {m['fp']}, FN {m['fn']}, TN {m['tn']})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset")
    args = ap.parse_args()
    rows = load(args.dataset)

    n_mal = sum(r["label"] == "malicious" for r in rows)
    print(f"{len(rows)} IOCs ({n_mal} malicious, {len(rows) - n_mal} benign)\n")

    base = run(rows)
    print("== Current scoring.yaml ==")
    print(line("current", base))
    if base["unknown"]:
        print(f"  {base['unknown']} IOC(s) had no usable source data (verdict UNKNOWN)")
    for ioc, truth, verdict, sc in base["wrong"]:
        print(f"  wrong: {ioc}  truth={truth}  verdict={verdict}  score={sc}")

    print("\n== Variants (does each v2 feature help?) ==")
    no_corr = {"per_extra_source": 0, "max_bonus": 0}
    no_floor = {"min_source_weight": 0, "min_confidence": 99}
    variants = {
        "current": {},
        "no type weights": {"TYPE_WEIGHTS": {}},
        "no corroboration": {"CORROBORATION": no_corr},
        "no strong-signal floor": {"STRONG_SIGNAL": no_floor},
        "v1 baseline (all off)": {"TYPE_WEIGHTS": {}, "CORROBORATION": no_corr, "STRONG_SIGNAL": no_floor},
    }
    for name, overrides in variants.items():
        with patched(**overrides):
            print(line(name, run(rows)))

    print("\n== Sweep: 'suspicious' threshold ==")
    best = None
    s = 0.10
    while s <= scorer.THRESHOLDS["malicious"] + 1e-9:
        with patched(THRESHOLDS={**scorer.THRESHOLDS, "suspicious": round(s, 2)}):
            m = run(rows)
        if best is None or m["f1"] > best[1] + 1e-9:
            best = (round(s, 2), m["f1"])
        print(line(f"suspicious={s:.2f}", m))
        s += 0.05
    print(f"best F1 at suspicious={best[0]} (current: {scorer.THRESHOLDS['suspicious']})")
    print("note: tune on one part of your data and confirm on another, or the numbers flatter you")

    print("\n== Ablation: remove one source ==")
    sources = sorted({r["source"] for row in rows for r in row["results"] if "source" in r})
    for src in sources:
        m = run(rows, drop_source=src)
        print(line(f"without {src}", m) + f"   dF1={m['f1'] - base['f1']:+.2f}")


if __name__ == "__main__":
    main()
