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
    UNKNOWN = "unknown"


class ParsedIoc(BaseModel):
    raw: str
    normalized: str
    type: IocType

    model_config = ConfigDict(use_enum_values=True)
