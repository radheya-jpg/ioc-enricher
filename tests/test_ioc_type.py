from ioc_type import classify, IOCType


def test_classifies_ipv4():
    assert classify("8.8.8.8") == IOCType.IPV4
    assert classify("192.168.1.1") == IOCType.IPV4


def test_rejects_invalid_ipv4():
    # octet > 255 should not be classified as a valid IP
    assert classify("999.999.999.999") != IOCType.IPV4


def test_classifies_domain():
    assert classify("example.com") == IOCType.DOMAIN
    assert classify("sub.evil-domain.co.uk") == IOCType.DOMAIN


def test_classifies_md5():
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == IOCType.MD5


def test_classifies_sha1():
    assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.SHA1


def test_classifies_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85e"[:64]
    assert classify(h) == IOCType.SHA256


def test_unknown_for_garbage():
    assert classify("not-a-real-ioc!!") == IOCType.UNKNOWN
    assert classify("") == IOCType.UNKNOWN
