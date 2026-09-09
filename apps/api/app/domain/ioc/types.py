from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    PHONE = "phone"
    SOCIAL_HANDLE = "social_handle"
    ETHEREUM_ADDRESS = "ethereum_address"
    BITCOIN_ADDRESS = "bitcoin_address"
    SOLANA_ADDRESS = "solana_address"
    TX_HASH = "tx_hash"
    ENS_NAME = "ens_name"
    UNKNOWN = "unknown"


class ParsedIoc(BaseModel):
    raw: str
    normalized: str
    type: IocType

    model_config = ConfigDict(use_enum_values=True)
