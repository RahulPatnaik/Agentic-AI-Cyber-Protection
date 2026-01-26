"""
Structured Logging Configuration
Uses structlog for consistent logging across the application
"""

import logging
import sys
import structlog
from pathlib import Path

from src.config.settings import Settings


def configure_logging(config: Settings) -> None:
    """
    Configure structured logging for the application.

    Args:
        config: Application settings
    """
    # Ensure log directory exists
    if config.audit_log_path:
        Path(config.audit_log_path).parent.mkdir(parents=True, exist_ok=True)

    # Configure stdlib logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, config.log_level.upper())
    )

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer() if config.is_production else structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = None) -> structlog.BoundLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (optional)

    Returns:
        Structured logger
    """
    return structlog.get_logger(name)
