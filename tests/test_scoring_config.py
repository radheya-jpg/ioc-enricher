import textwrap

import config
import scorer


def _write_yaml(tmp_path, content):
    path = tmp_path / "scoring.yaml"
    path.write_text(textwrap.dedent(content))
    return str(path)


def test_loads_valid_custom_config(tmp_path, monkeypatch):
    path = _write_yaml(tmp_path, """
        source_weights:
          AbuseIPDB: 2.0
          VirusTotal: 0.5
        thresholds:
          malicious: 0.8
          suspicious: 0.4
    """)
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", path)

    weights, thresholds = scorer._load_scoring_config()
    assert weights == {"AbuseIPDB": 2.0, "VirusTotal": 0.5}
    assert thresholds == {"malicious": 0.8, "suspicious": 0.4}


def test_falls_back_to_defaults_when_file_missing(monkeypatch):
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", "/nonexistent/path/scoring.yaml")

    weights, thresholds = scorer._load_scoring_config()
    assert weights == scorer._DEFAULT_SOURCE_WEIGHTS
    assert thresholds == scorer._DEFAULT_THRESHOLDS


def test_falls_back_to_defaults_on_malformed_yaml(tmp_path, monkeypatch):
    path = tmp_path / "scoring.yaml"
    path.write_text("this: is: not: valid: yaml: [[[")
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", str(path))

    weights, thresholds = scorer._load_scoring_config()
    assert weights == scorer._DEFAULT_SOURCE_WEIGHTS


def test_falls_back_to_defaults_on_missing_thresholds_key(tmp_path, monkeypatch):
    path = _write_yaml(tmp_path, """
        source_weights:
          AbuseIPDB: 1.0
    """)  # no 'thresholds' key at all
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", path)

    weights, thresholds = scorer._load_scoring_config()
    assert thresholds == scorer._DEFAULT_THRESHOLDS


def test_falls_back_to_defaults_on_invalid_threshold_ordering(tmp_path, monkeypatch):
    path = _write_yaml(tmp_path, """
        source_weights:
          AbuseIPDB: 1.0
        thresholds:
          malicious: 0.3
          suspicious: 0.7
    """)  # suspicious > malicious, invalid ordering
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", path)

    weights, thresholds = scorer._load_scoring_config()
    assert thresholds == scorer._DEFAULT_THRESHOLDS


def test_falls_back_to_defaults_on_negative_weight(tmp_path, monkeypatch):
    path = _write_yaml(tmp_path, """
        source_weights:
          AbuseIPDB: -1.0
        thresholds:
          malicious: 0.7
          suspicious: 0.35
    """)
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", path)

    weights, thresholds = scorer._load_scoring_config()
    assert weights == scorer._DEFAULT_SOURCE_WEIGHTS


def test_custom_weights_actually_change_scoring_output(tmp_path, monkeypatch):
    path = _write_yaml(tmp_path, """
        source_weights:
          AbuseIPDB: 5.0
        thresholds:
          malicious: 0.9
          suspicious: 0.5
    """)
    monkeypatch.setattr(config, "SCORING_CONFIG_PATH", path)
    monkeypatch.setattr(scorer, "SOURCE_WEIGHTS", {"AbuseIPDB": 5.0})
    monkeypatch.setattr(scorer, "THRESHOLDS", {"malicious": 0.9, "suspicious": 0.5})

    results = [{"source": "AbuseIPDB", "skipped": False, "error": None,
                "malicious": True, "confidence": 0.95}]
    verdict = scorer.score(results)

    # with malicious threshold raised to 0.9, a 0.95 confidence single
    # source should still cross it
    assert verdict["verdict"] == "MALICIOUS"
