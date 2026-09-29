"""
Combines normalized results from all sources into a single verdict.

Approach: weighted average of each source's confidence, weighted higher
for sources with stronger signal (VT's vendor consensus > Shodan's heuristic).
Only sources that actually returned data (not skipped/errored) count.

Weights and thresholds are NOT hardcoded here — they're loaded from
scoring.yaml (see config.SCORING_CONFIG_PATH) so they can be retuned
without touching code. If the file is missing or malformed, we fall
back to safe built-in defaults and log a warning rather than crashing.
"""

from __future__ import annotations

import yaml

import config
from logger import get_logger

log = get_logger("scorer")

# Fallback defaults, used only if scoring.yaml is missing or invalid.
_DEFAULT_SOURCE_WEIGHTS = {
    "AbuseIPDB": 1.0,
    "VirusTotal": 1.2,
    "Shodan": 0.6,
    "OTX": 0.9,
}
_DEFAULT_THRESHOLDS = {"malicious": 0.7, "suspicious": 0.35}


def _validate(raw: dict) -> tuple[dict, dict]:
    """Returns (source_weights, thresholds), raising ValueError on bad shape."""
    weights = raw.get("source_weights")
    thresholds = raw.get("thresholds")

    if not isinstance(weights, dict) or not weights:
        raise ValueError("scoring.yaml: 'source_weights' must be a non-empty mapping")
    for name, w in weights.items():
        if not isinstance(w, (int, float)) or w < 0:
            raise ValueError(f"scoring.yaml: weight for '{name}' must be a non-negative number")

    if not isinstance(thresholds, dict) or "malicious" not in thresholds or "suspicious" not in thresholds:
        raise ValueError("scoring.yaml: 'thresholds' must include 'malicious' and 'suspicious'")
    if not (0 <= thresholds["suspicious"] <= thresholds["malicious"] <= 1):
        raise ValueError("scoring.yaml: thresholds must satisfy 0 <= suspicious <= malicious <= 1")

    return weights, thresholds


def _load_scoring_config() -> tuple[dict, dict]:
    path = config.SCORING_CONFIG_PATH
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
        weights, thresholds = _validate(raw)
        log.debug("loaded scoring config", extra={"path": path})
        return weights, thresholds
    except FileNotFoundError:
        log.warning("scoring config not found, using built-in defaults", extra={"path": path})
    except (yaml.YAMLError, ValueError) as e:
        log.warning("scoring config invalid, using built-in defaults",
                    extra={"path": path, "error": str(e)})
    return dict(_DEFAULT_SOURCE_WEIGHTS), dict(_DEFAULT_THRESHOLDS)


# Loaded once at import time. Call reload_scoring_config() to pick up
# edits to scoring.yaml without restarting (e.g. from a long-running
# service or the Splunk command).
SOURCE_WEIGHTS, THRESHOLDS = _load_scoring_config()


def reload_scoring_config():
    global SOURCE_WEIGHTS, THRESHOLDS
    SOURCE_WEIGHTS, THRESHOLDS = _load_scoring_config()


def score(results: list[dict]) -> dict:
    usable = [r for r in results if not r.get("skipped") and not r.get("error")]

    if not usable:
        return {
            "verdict": "UNKNOWN",
            "score": 0.0,
            "sources_used": 0,
            "sources_total": len(results),
            "detail": "No sources returned usable data (check API keys / IOC type).",
        }

    weighted_sum = 0.0
    weight_total = 0.0
    flagged_by = []

    for r in usable:
        w = SOURCE_WEIGHTS.get(r["source"], 1.0)
        weighted_sum += r["confidence"] * w
        weight_total += w
        if r["malicious"]:
            flagged_by.append(r["source"])

    final_score = weighted_sum / weight_total if weight_total else 0.0

    if final_score >= THRESHOLDS["malicious"]:
        verdict = "MALICIOUS"
    elif final_score >= THRESHOLDS["suspicious"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "verdict": verdict,
        "score": round(final_score, 2),
        "sources_used": len(usable),
        "sources_total": len(results),
        "flagged_by": flagged_by,
        "detail": (
            f"Flagged by {len(flagged_by)}/{len(usable)} sources: {', '.join(flagged_by)}"
            if flagged_by else f"Not flagged by any of {len(usable)} sources"
        ),
    }
