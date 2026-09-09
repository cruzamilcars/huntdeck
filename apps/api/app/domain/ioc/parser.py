import hashlib
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
SOCIAL_AT_RE = re.compile(r"^@[A-Za-z0-9_.-]{1,30}$")

# Web3 indicators.
ETHEREUM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{43,44}$")
ENS_RE = re.compile(r"^[a-z0-9-]{1,190}\.eth$", re.IGNORECASE)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
SOCIAL_PROFILE_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?"
    r"(?:(?:x|twitter|instagram|facebook|tiktok|linkedin|github|youtube|telegram|t\.me)\.(?:com|me|org|net|dev)"
    r"|(?:x|t)\.me)"
    r"/(?:in/|@)?[A-Za-z0-9_.-]{1,60}$",
    re.IGNORECASE,
)


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

    crypto_type = _parse_crypto(raw)
    if crypto_type != IocType.UNKNOWN:
        normalized = raw if crypto_type == IocType.BITCOIN_ADDRESS else raw.lower()
        return ParsedIoc(raw=raw, normalized=normalized, type=crypto_type)

    social = _parse_social(raw)
    if social is not None:
        return social

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


def _parse_crypto(value: str) -> IocType:
    if ETHEREUM_ADDRESS_RE.fullmatch(value):
        return IocType.ETHEREUM_ADDRESS
    if TX_HASH_RE.fullmatch(value):
        return IocType.TX_HASH
    if ENS_RE.fullmatch(value):
        return IocType.ENS_NAME
    if _is_btc_address(value):
        return IocType.BITCOIN_ADDRESS
    if SOLANA_ADDRESS_RE.fullmatch(value):
        return IocType.SOLANA_ADDRESS
    return IocType.UNKNOWN


def _is_btc_address(value: str) -> bool:
    if value.lower().startswith("bc1"):
        return _bech32_is_valid("bc", value)
    if value.startswith(("1", "3")):
        return _base58check_is_valid(value)
    return False


def _base58check_is_valid(address: str) -> bool:
    try:
        payload = _base58_to_bytes(address)
    except ValueError:
        return False
    if len(payload) != 25:
        return False
    if payload[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(payload[:-4]).digest()).digest()[:4] == payload[-4:]


def _base58_to_bytes(address: str) -> bytes:
    value = 0
    for char in address:
        if char not in _BASE58_ALPHABET:
            raise ValueError(f"invalid base58 char: {char!r}")
        value = value * 58 + _BASE58_ALPHABET.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(address) - len(address.lstrip("1"))) + raw


def _bech32_is_valid(hrp: str, address: str) -> bool:
    if len(address) < 8 or len(address) > 90:
        return False
    if not re.fullmatch(rf"{hrp}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+", address, re.IGNORECASE):
        return False
    if not (address.islower() or address.isupper()):
        return False
    lowered = address.lower()
    data = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    data += [_BECH32_CHARSET.index(x) for x in lowered[len(hrp) + 1 :]]
    return _bech32_polymod(data) == 1


def _bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate(_BECH32_GENERATOR):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("http://", "https://"))


def _parse_social(value: str) -> ParsedIoc | None:
    raw = value.strip()
    if SOCIAL_AT_RE.fullmatch(raw):
        return ParsedIoc(raw=raw, normalized=raw[1:].lower(), type=IocType.SOCIAL_HANDLE)

    lowered = raw.lower()
    if not lowered.startswith(("http://", "https://")) and "/" not in lowered:
        return None

    if SOCIAL_PROFILE_RE.fullmatch(raw):
        path = re.sub(r"^https?://(?:www\.)?", "", lowered).rstrip("/")
        parts = path.split("/")
        platform = parts[0]
        if platform == "linkedin.com" and len(parts) > 1:
            username = "/".join(parts[1:]).lstrip("@")
        else:
            username = parts[-1].lstrip("@")
        return ParsedIoc(
            raw=raw,
            normalized=f"{platform}/{username}",
            type=IocType.SOCIAL_HANDLE,
        )
    return None


def _normalize_url(value: str) -> str:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))
