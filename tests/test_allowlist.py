import config
import allowlist


def _write_allowlist(tmp_path, lines):
    path = tmp_path / "allowlist.txt"
    path.write_text("\n".join(lines))
    return str(path)


def _reload(monkeypatch, path):
    monkeypatch.setattr(config, "ALLOWLIST_PATH", path)
    allowlist.reload()


def test_exact_ip_match(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["8.8.8.8"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("8.8.8.8", "ipv4") is True


def test_ip_not_in_list(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["8.8.8.8"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("1.2.3.4", "ipv4") is False


def test_exact_domain_match(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["google.com"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("google.com", "domain") is True


def test_subdomain_matches_parent_domain(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["google.com"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("mail.google.com", "domain") is True


def test_unrelated_domain_does_not_match(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["google.com"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("evil-google.com", "domain") is False  # not a subdomain
    assert allowlist.is_allowlisted("notgoogle.com", "domain") is False


def test_hashes_are_never_allowlisted(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["d41d8cd98f00b204e9800998ecf8427e"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("d41d8cd98f00b204e9800998ecf8427e", "sha256") is False


def test_comments_and_blank_lines_ignored(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["# a comment", "", "8.8.8.8", "  "])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("8.8.8.8", "ipv4") is True


def test_case_insensitive_domain_match(tmp_path, monkeypatch):
    path = _write_allowlist(tmp_path, ["Google.com"])
    _reload(monkeypatch, path)
    assert allowlist.is_allowlisted("GOOGLE.COM", "domain") is True


def test_missing_file_disables_allowlist_gracefully(monkeypatch):
    monkeypatch.setattr(config, "ALLOWLIST_PATH", "/nonexistent/allowlist.txt")
    allowlist.reload()
    assert allowlist.is_allowlisted("8.8.8.8", "ipv4") is False
