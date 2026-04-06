"""Application settings (environment variables)."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # SecuritySnares
    securitysnares_base_url: str = Field(
        default="https://api.securitysnares.com",
        description="Base URL without trailing slash",
    )
    securitysnares_api_key: str = Field(default="", description="Bearer token")
    securitysnares_use_mssp: bool = Field(
        default=False,
        description="Use /mssp/alerts with minutes= window",
    )
    securitysnares_mssp_minutes: int = Field(default=15, ge=1, le=10080)
    securitysnares_poll_seconds: int = Field(default=60, ge=10, le=3600)

    # Ransomware filter: treat alert as ransomware if severity >= this OR keyword match
    ransomware_min_severity: int = Field(default=70, ge=0, le=100)
    ransomware_keyword: str = Field(
        default="ransomware",
        description="Case-insensitive substring in ai_analysis summary",
    )

    # BeyondTrust Password Safe
    beyondtrust_base_url: str = Field(
        default="https://the-server/BeyondTrust/api/public/v3",
        description="Full base including /BeyondTrust/api/public/v3",
    )
    beyondtrust_api_key: str = Field(default="")
    beyondtrust_runas: str = Field(default="", description="e.g. DOMAIN\\\\user")
    beyondtrust_password: str = Field(
        default="",
        description="Optional; use pwd=[...] if required by API registration",
    )
    beyondtrust_verify_tls: bool = Field(default=True)
    credential_change_queue: bool = Field(
        default=True,
        description="Queue rotation if target unreachable",
    )
    credential_change_update_system: bool = Field(default=True)

    # Email (SMTP)
    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=587)
    smtp_use_tls: bool = Field(default=True)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_from: str = Field(default="")
    admin_email_to: str = Field(
        default="",
        description="Comma-separated list for incident notifications",
    )

    # Persistence
    state_db_path: str = Field(default="./data/automation_state.sqlite3")

    # HTTP
    http_timeout_seconds: float = Field(default=30.0)
    max_retries: int = Field(default=5)

    # Circuit breaker (BeyondTrust)
    circuit_failure_threshold: int = Field(default=5)
    circuit_cooldown_seconds: float = Field(default=120.0)

    log_level: str = Field(default="INFO")


def get_settings() -> Settings:
    return Settings()
