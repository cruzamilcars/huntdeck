import ipaddress
import re
from urllib.parse import urlparse, urlunparse

from app.domain.ioc.types import IocType, ParsedIoc

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$", re.IGNORECASE)
PHONE_RE = re.compile(r"^\+?[1-9][0-9 .()\-]{7,24}$")
IPV4_SHAPE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def parse_ioc(value: str) -> ParsedIoc:
    raw = value.strip()
    normalized = raw

    if not raw:
        return ParsedIoc(raw=value, normalized="", type=IocType.UNKNOWN)

    hash_type = _parse_hash(raw)
    if hash_type != IocType.UNKNOWN:
        return ParsedIoc(raw=raw, normalized=raw.lower(), type=hash_type)

    ip_type = _parse_ip(raw)
    if ip_type != IocType.UNKNOWN:
        return ParsedIoc(raw=raw, normalized=str(ipaddress.ip_address(raw)), type=ip_type)

    if _looks_like_url(raw):
        normalized_url = _normalize_url(raw)
        parsed = urlparse(normalized_url)
        if parsed.hostname:
            return ParsedIoc(raw=raw, normalized=normalized_url, type=IocType.URL)

    if EMAIL_RE.fullmatch(raw):
        return ParsedIoc(raw=raw, normalized=raw.lower(), type=IocType.EMAIL)

    if DOMAIN_RE.fullmatch(raw):
        return ParsedIoc(raw=raw, normalized=raw.lower().rstrip("."), type=IocType.DOMAIN)

    if IPV4_SHAPE_RE.fullmatch(raw):
        return ParsedIoc(raw=raw, normalized=raw, type=IocType.UNKNOWN)

    compact_phone = re.sub(r"[\s().-]", "", raw)
    if PHONE_RE.fullmatch(raw) and 8 <= len(compact_phone.lstrip("+")) <= 15:
        return ParsedIoc(raw=raw, normalized=compact_phone, type=IocType.PHONE)

    return ParsedIoc(raw=raw, normalized=normalized, type=IocType.UNKNOWN)


def _parse_hash(value: str) -> IocType:
    if MD5_RE.fullmatch(value):
        return IocType.MD5
    if SHA1_RE.fullmatch(value):
        return IocType.SHA1
    if SHA256_RE.fullmatch(value):
        return IocType.SHA256
    return IocType.UNKNOWN


def _parse_ip(value: str) -> IocType:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return IocType.UNKNOWN
    return IocType.IPV4 if parsed.version == 4 else IocType.IPV6


def _looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("http://", "https://"))


def _normalize_url(value: str) -> str:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))
