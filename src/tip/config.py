from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from TIP_* environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="TIP_",
        case_sensitive=False,
        extra="ignore",
    )

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "threat_intelligence"
    elastic_url: str = "http://localhost:9200"
    elastic_index_prefix: str = "tip"
    request_timeout_seconds: int = Field(default=20, ge=3, le=120)
    risk_threshold: int = Field(default=85, ge=0, le=100)
    allowlist_cidrs: str = (
        "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    )
    otx_api_key: str | None = None
    firewall_enabled: bool = False
    firewall_chain: str = "TIP_BLOCKLIST"
    alert_webhook_url: str | None = None
    log_level: str = "INFO"

    @property
    def allowlist(self) -> list[str]:
        return [item.strip() for item in self.allowlist_cidrs.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
