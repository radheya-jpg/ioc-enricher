"""
Combines normalized results from all sources into a single verdict.

Base approach (unchanged): weighted average of each source's confidence.
Only sources that actually returned data (not skipped/errored) count, so a
missing source never drags the verdict toward CLEAN.

v2 accuracy changes, all tunable from scoring.yaml:

1. Per-IOC-type weights. AbuseIPDB is purpose-built for IPs, VirusTotal's
   engine consensus is the strongest signal for files, Shodan is exposure
   context rather than a maliciousness signal. One global weight per source
   can't express that.
2. Corroboration bonus. Independent sources agreeing is stronger evidence
   than the average alone shows, so each additional flagging source adds a
   small, capped bonus.
3. Strong-signal floor. A very confident, highly trusted source must never be
   averaged all the way down to CLEAN just because the other sources have
   not seen the indicator yet (fresh C2 infrastructure, new malware hash).
   It guarantees at least SUSPICIOUS and says so in the report.
4. Explainability. The result carries per-source contributions, a confidence
   label and a list of adjustments, so an analyst can see why.

score() keeps its old return keys; new keys are additions only.
"""

from __future__ import annotations

import copy

import yaml

import config
from logger import get_logger

log = get_logger("scorer")

_HASH_TYPES = ("md5", "sha1", "sha256")

# Fallback defaults, used only if scoring.yaml is missing or invalid.
_DEFAULT_SOURCE_WEIGHTS = {
    "AbuseIPDB": 1.0,
    "VirusTotal": 1.2,
    "Shodan": 0.6,
    "OTX": 0.9,
}
_DEFAULT_THRESHOLDS = {"malicious": 0.7, "suspicious": 0.35}
_DEFAULT_TUNING = {
    "type_weights": {},
    "corroboration": {"per_extra_source": 0.08, "max_bonus": 0.16},
    "strong_signal": {"min_source_weight": 1.0, "min_confidence": 0.85},
}
# Sources whose confidences differ by at least this much are flagged as conflicting.
_CONFLICT_SPREAD = 0.6


def _validate(raw: dict) -> tuple[dict, dict]:
    """Returns (source_weights, thresholds), raising ValueError on bad shape."""
    if not isinstance(raw, dict):
        raise ValueError("scoring.yaml: top level must be a mapping")
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


def _number(section: str, key: str, value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"scoring.yaml: {section}.{key} must be a non-negative number")
    return value


def _load_tuning() -> dict:
    """Loads the v2 sections (type_weights, corroboration, strong_signal).
    Any problem falls back to built-in defaults for these sections only; the
    base loader above has already logged file-level problems."""
    tuning = copy.deepcopy(_DEFAULT_TUNING)
    path = config.SCORING_CONFIG_PATH
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            return tuning

        tw = raw.get("type_weights")
        if tw is not None:
            if not isinstance(tw, dict):
                raise ValueError("scoring.yaml: 'type_weights' must be a mapping")
            parsed = {}
            for ioc_type, per_source in tw.items():
                if not isinstance(per_source, dict):
                    raise ValueError(f"scoring.yaml: type_weights.{ioc_type} must be a mapping")
                parsed[str(ioc_type)] = {
                    str(s): _number(f"type_weights.{ioc_type}", s, w) for s, w in per_source.items()
                }
            tuning["type_weights"] = parsed

        for section in ("corroboration", "strong_signal"):
            block = raw.get(section)
            if block is None:
                continue
            if not isinstance(block, dict):
                raise ValueError(f"scoring.yaml: '{section}' must be a mapping")
            for key in block:
                if key not in tuning[section]:
                    raise ValueError(f"scoring.yaml: unknown key {section}.{key}")
                tuning[section][key] = _number(section, key, block[key])
    except FileNotFoundError:
        return copy.deepcopy(_DEFAULT_TUNING)
    except (yaml.YAMLError, ValueError) as e:
        log.warning("scoring tuning sections invalid, using built-in defaults",
                    extra={"path": path, "error": str(e)})
        return copy.deepcopy(_DEFAULT_TUNING)
    return tuning


def _apply_tuning(t: dict):
    global TYPE_WEIGHTS, CORROBORATION, STRONG_SIGNAL
    TYPE_WEIGHTS = t["type_weights"]
    CORROBORATION = t["corroboration"]
    STRONG_SIGNAL = t["strong_signal"]


# Loaded once at import time. Call reload_scoring_config() to pick up
# edits to scoring.yaml without restarting (e.g. from a long-running
# service or the Splunk command).
SOURCE_WEIGHTS, THRESHOLDS = _load_scoring_config()
_apply_tuning(_load_tuning())


def reload_scoring_config():
    global SOURCE_WEIGHTS, THRESHOLDS
    SOURCE_WEIGHTS, THRESHOLDS = _load_scoring_config()
    _apply_tuning(_load_tuning())


def _weights_for(ioc_type) -> dict:
    """Global weights, overridden by the 'hash' group (for md5/sha1/sha256),
    then by the exact IOC type. `ioc_type` may be an IOCType enum or a string."""
    t = getattr(ioc_type, "value", ioc_type)
    merged = dict(SOURCE_WEIGHTS)
    if t:
        if t in _HASH_TYPES:
            merged.update(TYPE_WEIGHTS.get("hash", {}))
        merged.update(TYPE_WEIGHTS.get(t, {}))
    return merged


def score(results: list[dict], ioc_type=None) -> dict:
    usable = [r for r in results if not r.get("skipped") and not r.get("error")]

    if not usable:
        return {
            "verdict": "UNKNOWN",
            "score": 0.0,
            "sources_used": 0,
            "sources_total": len(results),
            "confidence": "none",
            "detail": "No sources returned usable data (check API keys / IOC type).",
        }

    weights = _weights_for(ioc_type)
    weighted_sum = 0.0
    weight_total = 0.0
    flagged_by = []
    contributions = []
    strong_source = None

    for r in usable:
        w = weights.get(r["source"], 1.0)
        c = r["confidence"]
        weighted_sum += c * w
        weight_total += w
        if r["malicious"]:
            flagged_by.append(r["source"])
        if (strong_source is None
                and w >= STRONG_SIGNAL["min_source_weight"]
                and c >= STRONG_SIGNAL["min_confidence"]):
            strong_source = r["source"]
        contributions.append({"source": r["source"], "confidence": round(c, 2), "weight": w})

    base_score = weighted_sum / weight_total if weight_total else 0.0
    adjustments = []

    # 2. corroboration: independent sources agreeing is stronger than the average shows
    bonus = min(
        CORROBORATION["max_bonus"],
        CORROBORATION["per_extra_source"] * max(0, len(flagged_by) - 1),
    )
    final_score = min(1.0, base_score + bonus)
    if bonus > 0:
        adjustments.append(f"+{bonus:.2f} corroboration ({len(flagged_by)} sources agree)")

    if final_score >= THRESHOLDS["malicious"]:
        verdict = "MALICIOUS"
    elif final_score >= THRESHOLDS["suspicious"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # 3. strong-signal floor: never let a trusted, confident source be averaged to CLEAN
    if verdict == "CLEAN" and strong_source:
        verdict = "SUSPICIOUS"
        final_score = max(final_score, THRESHOLDS["suspicious"])
        adjustments.append(f"raised to SUSPICIOUS: {strong_source} is highly confident on its own")

    confs = [c["confidence"] for c in contributions]
    if len(confs) >= 2 and max(confs) - min(confs) >= _CONFLICT_SPREAD:
        adjustments.append("sources disagree strongly, review manually")

    used = len(usable)
    confidence = "high" if used >= 3 else "medium" if used == 2 else "low"

    return {
        "verdict": verdict,
        "score": round(final_score, 2),
        "base_score": round(base_score, 2),
        "sources_used": used,
        "sources_total": len(results),
        "confidence": confidence,
        "flagged_by": flagged_by,
        "contributions": contributions,
        "adjustments": adjustments,
        "detail": (
            f"Flagged by {len(flagged_by)}/{used} sources: {', '.join(flagged_by)}"
            if flagged_by else f"Not flagged by any of {used} sources"
        ),
    }