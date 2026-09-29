"""
Figures out what kind of IOC the user gave us: IPv4, domain, or file hash.
This decides which threat-intel sources we even bother querying.
"""

import re
from enum import Enum


class IOCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def classify(ioc: str) -> IOCType:
    ioc = ioc.strip()

    if _IPV4_RE.match(ioc):
        octets = ioc.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return IOCType.IPV4

    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return IOCType.MD5
    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return IOCType.SHA1
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return IOCType.SHA256

    if _DOMAIN_RE.match(ioc):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def is_hash(ioc_type: IOCType) -> bool:
    return ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)
