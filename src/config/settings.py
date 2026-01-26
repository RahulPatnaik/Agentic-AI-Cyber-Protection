"""
Centralized Configuration with Pydantic Settings
All configuration loaded from environment variables
"""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
from pathlib import Path
import os
from dotenv import load_dotenv

# Get project root directory (2 levels up from this file)
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
ENV_FILE = PROJECT_ROOT / '.env'

# Load .env file into environment variables
load_dotenv(ENV_FILE)


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Uses .env file for local development.
    """

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding='utf-8',
        case_sensitive=False,
        extra='ignore'  # Ignore extra fields in .env
    )

    # ==================== API Keys ====================
    mistral_api_key: SecretStr = Field(..., description="Mistral AI API key")

    # ==================== Network Configuration ====================
    network_interface: str = Field("wlan0", description="WiFi interface for monitoring")
    promiscuous_mode: bool = Field(True, description="Enable promiscuous mode")
    enable_live_capture: bool = Field(True, description="Use live capture vs PCAP files")

    # ==================== ML Configuration ====================
    ml_models_path: str = Field("data/models", description="Path to trained models")
    ml_confidence_threshold: float = Field(0.85, description="Min confidence for escalation")

    # ==================== Database Configuration ====================
    database_url: str = Field(
        "sqlite+aiosqlite:///wifi_guardian.db",
        description="Database URL (SQLite or PostgreSQL)"
    )

    # ==================== Message Queue Configuration ====================
    use_in_memory_queue: bool = Field(True, description="Use in-memory queue for MVP")
    rabbitmq_url: str = Field("amqp://localhost:5672", description="RabbitMQ URL")
    queue_prefetch_count: int = Field(10, description="Max messages to prefetch")

    # ==================== Agent Configuration ====================
    guardian_batch_size: int = Field(100, description="Packets per batch")
    sentinel_timeout_seconds: int = Field(30, description="LLM timeout")
    max_retries: int = Field(3, description="Max retry attempts")

    # ==================== Response Configuration ====================
    whitelisted_devices: List[str] = Field(
        default_factory=list,
        description="Never block these MACs (comma-separated in .env)"
    )
    max_actions_per_minute: int = Field(10, description="Rate limit for responses")
    require_approval_for_critical: bool = Field(
        True,
        description="Human approval for critical actions"
    )

    # ==================== Caching Configuration ====================
    enable_response_cache: bool = Field(True, description="Enable Mistral response caching")
    mistral_cache_ttl: int = Field(3600, description="Cache TTL in seconds")

    # ==================== API/Dashboard Configuration ====================
    api_host: str = Field("0.0.0.0", description="API server host")
    api_port: int = Field(8000, description="API server port")
    enable_websocket: bool = Field(True, description="Enable WebSocket for real-time updates")

    # ==================== Logging Configuration ====================
    log_level: str = Field("INFO", description="Logging level")
    enable_logfire: bool = Field(False, description="Enable Logfire observability")
    audit_log_path: str = Field("logs/audit.log", description="Audit log file")

    # ==================== MITRE ATT&CK ====================
    mitre_data_path: str = Field(
        "data/threat_intel/mitre_attack.json",
        description="MITRE ATT&CK data"
    )

    # ==================== Directories ====================
    pcap_directory: str = Field("data/pcaps", description="Directory for PCAP files")
    threat_intel_directory: str = Field("data/threat_intel", description="Threat intel data")

    def get_mistral_api_key(self) -> str:
        """Get the Mistral API key as a string"""
        return self.mistral_api_key.get_secret_value()

    def ensure_directories(self) -> None:
        """Ensure all required directories exist"""
        directories = [
            self.ml_models_path,
            self.pcap_directory,
            self.threat_intel_directory,
            Path(self.audit_log_path).parent,
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @property
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return self.log_level == "WARNING" or self.log_level == "ERROR"

    @property
    def database_is_sqlite(self) -> bool:
        """Check if using SQLite database"""
        return "sqlite" in self.database_url.lower()

    model_config = SettingsConfigDict(
        json_schema_extra={
            "example": {
                "mistral_api_key": "your-api-key-here",
                "network_interface": "wlan0",
                "enable_live_capture": True,
                "ml_confidence_threshold": 0.85,
                "database_url": "sqlite+aiosqlite:///wifi_guardian.db",
                "api_port": 8000
            }
        }
    )


# Global settings instance (lazy loaded)
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get or create global settings instance.
    Useful for dependency injection in FastAPI.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_directories()
    return _settings


# For convenient imports
settings = get_settings()
