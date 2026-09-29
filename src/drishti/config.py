from functools import lru_cache
from pathlib import Path
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
    state_dir: Path = Path(".drishti-state")
    minio_results_bucket: str = "drishti-results"
    kafka_consumer_group: str = "drishti-normalizer-v1"
    outbox_interval_seconds: float = Field(default=2, gt=0)
    worker_stale_seconds: int = Field(default=30, ge=5)
    drift_baseline_size: int = Field(default=32, ge=4)
    drift_window_size: int = Field(default=16, ge=2)
    demo_admin_enabled: bool = False
    registry_private_key_b64: SecretStr | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
