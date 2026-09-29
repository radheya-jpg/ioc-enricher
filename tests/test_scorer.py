from scorer import score


def _result(source, malicious, confidence, skipped=False, error=None):
    return {
        "source": source,
        "skipped": skipped,
        "error": error,
        "malicious": malicious,
        "confidence": confidence,
        "summary": "test",
    }


def test_all_clean_gives_clean_verdict():
    results = [
        _result("AbuseIPDB", False, 0.0),
        _result("VirusTotal", False, 0.0),
    ]
    v = score(results)
    assert v["verdict"] == "CLEAN"


def test_strong_consensus_gives_malicious():
    results = [
        _result("AbuseIPDB", True, 0.9),
        _result("VirusTotal", True, 0.95),
        _result("OTX", True, 0.8),
    ]
    v = score(results)
    assert v["verdict"] == "MALICIOUS"
    assert set(v["flagged_by"]) == {"AbuseIPDB", "VirusTotal", "OTX"}


def test_mixed_signal_gives_suspicious():
    results = [
        _result("AbuseIPDB", True, 0.4),
        _result("VirusTotal", False, 0.1),
    ]
    v = score(results)
    assert v["verdict"] in ("SUSPICIOUS", "CLEAN")  # depends on weighting, but not MALICIOUS
    assert v["verdict"] != "MALICIOUS"


def test_all_skipped_or_errored_gives_unknown():
    results = [
        _result("AbuseIPDB", False, 0.0, skipped=True),
        _result("VirusTotal", False, 0.0, error="HTTP 500"),
    ]
    v = score(results)
    assert v["verdict"] == "UNKNOWN"
    assert v["sources_used"] == 0


def test_skipped_sources_excluded_from_scoring():
    results = [
        _result("AbuseIPDB", True, 0.9),
        _result("Shodan", False, 0.0, skipped=True),  # should not dilute the score
    ]
    v = score(results)
    assert v["sources_used"] == 1
    assert v["verdict"] == "MALICIOUS"
