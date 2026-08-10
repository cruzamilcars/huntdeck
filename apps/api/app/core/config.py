from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "OSINT MCP Hub API"
    daily_free_quota: int = Field(default=10, description="Daily free quota (default 10)")
    rate_limit_per_minute: int = 60
    supabase_jwt_secret: str | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    shodan_api_key: str | None = None
    urlscan_api_key: str | None = None
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
