from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "HuntDeck API"
    daily_free_quota: int = Field(default=10, description="Daily free quota (default 10)")
    rate_limit_per_minute: int = 60
    service_rate_limit_per_minute: int = Field(
        default=300, description="Rate limit for X-API-Key service credentials"
    )
    watchlist_recheck_ttl_hours: int = Field(
        default=24, description="Watchlist items older than this are lazily re-checked"
    )
    watchlist_recheck_max: int = Field(
        default=3, description="Max watchlist auto-rechecks per listing request"
    )
    supabase_jwt_secret: str | None = None
    supabase_anon_key: str | None = None
    supabase_secret_key: str | None = None
    supabase_jwks_url: str | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    shodan_api_key: str | None = None
    urlscan_api_key: str | None = None
    hibp_api_key: str | None = None
    opencnam_api_key: str | None = None
    otx_api_key: str | None = None
    greynoise_api_key: str | None = None
    misp_url: str | None = Field(
        default=None, description="Base URL of your MISP instance (e.g. https://misp.example.org)"
    )
    misp_api_key: str | None = None
    misp_verify_ssl: bool = True
    urlhaus_api_key: str | None = None
    supabase_url: str | None = None
    supabase_service_role_key: str | None = None
    database_path: str = Field(
        default="data/huntdeck.db", description="Local durable store (SQLite) path"
    )
    api_cors_origins: list[AnyHttpUrl] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"]
    )

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
