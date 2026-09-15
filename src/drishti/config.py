from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from DRISHTI_* environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="DRISHTI_",
        env_file=".env",
        extra="ignore",
    )

    environment: Literal["local", "test", "staging", "production"] = "local"
    adapter_mode: Literal["memory", "durable"] = "memory"
    log_level: str = "INFO"
    max_event_bytes: int = Field(default=1_048_576, gt=0, le=16_777_216)
    kafka_bootstrap_servers: str = "redpanda:9092"
    kafka_raw_topic: str = "drishti.raw.accepted.v1"
    kafka_archived_topic: str = "drishti.raw.archived.v1"
    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "drishti"
    minio_secret_key: SecretStr = SecretStr("change-me-in-production")
    minio_bucket: str = "drishti-raw-evidence"
    minio_secure: bool = False
    registry_private_key_b64: SecretStr | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
