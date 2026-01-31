"""
Configuration Management
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    """Application settings from environment variables"""

    # LLM Configuration
    mistral_api_key: str = ""
    primary_llm: str = "mistral"

    # Database
    database_url: str = "sqlite:///./threat_modeling.db"
    chroma_db_path: str = "./data/chroma_db"

    # NVD API
    nvd_api_key: str = ""

    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Agent Configuration
    max_agents_concurrent: int = 5
    agent_timeout_seconds: int = 300

    # CVE Monitoring
    cve_check_interval_hours: int = 1
    cve_severity_threshold: float = 7.0

    # Logging
    log_level: str = "INFO"
    log_file: str = "logs/threat_modeling.log"

    # Reports
    reports_dir: str = "./reports"
    pdf_template_dir: str = "./templates"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
