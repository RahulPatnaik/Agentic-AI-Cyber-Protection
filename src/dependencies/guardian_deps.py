"""
Dependency Injection for WiFi Guardian Agent
All dependencies needed for detection and analysis
"""

from dataclasses import dataclass
from typing import Optional
import structlog

from src.ml.inference import MLEnsemble
from src.ml.feature_extractor import FeatureExtractor
from src.capture.sniffer import PacketSniffer
from src.messaging.queue import MessageQueue
from src.config.settings import Settings

logger = structlog.get_logger()


@dataclass
class GuardianDependencies:
    """
    All dependencies injected into WiFi Guardian Agent.
    Used with RunContext[GuardianDependencies] in Pydantic AI tools.
    """
    # ML Components
    ml_ensemble: MLEnsemble
    feature_extractor: FeatureExtractor

    # Network Components
    packet_sniffer: PacketSniffer

    # Communication
    message_queue: MessageQueue

    # Configuration
    config: Settings

    # Simple threat database (in-memory for MVP)
    threat_database: dict = None

    def __post_init__(self):
        """Initialize threat database if not provided"""
        if self.threat_database is None:
            self.threat_database = {}

    @classmethod
    async def create(cls, config: Settings) -> "GuardianDependencies":
        """
        Factory method to instantiate all dependencies.
        Called at startup.

        Args:
            config: Application settings

        Returns:
            GuardianDependencies instance
        """
        logger.info("Initializing Guardian dependencies...")

        # Initialize ML models
        ml_ensemble = await MLEnsemble.load_from_disk(config)
        feature_extractor = FeatureExtractor(config)

        # Initialize network components
        packet_sniffer = PacketSniffer(config)

        # Initialize messaging
        message_queue = await MessageQueue.connect(config)

        # Simple threat database (would be real DB in production)
        threat_database = {
            # MAC address blacklist
            'blacklisted_macs': set(),
            # Known malicious SSIDs
            'malicious_ssids': {'Evil-WiFi', 'Free-WiFi-Hack'},
            # Known attack signatures
            'signatures': {}
        }

        logger.info("Guardian dependencies initialized successfully")

        return cls(
            ml_ensemble=ml_ensemble,
            feature_extractor=feature_extractor,
            packet_sniffer=packet_sniffer,
            message_queue=message_queue,
            config=config,
            threat_database=threat_database
        )

    async def cleanup(self):
        """Cleanup all resources"""
        logger.info("Cleaning up Guardian dependencies...")

        if self.packet_sniffer:
            self.packet_sniffer.stop()

        if self.message_queue:
            await self.message_queue.disconnect()

        logger.info("Guardian dependencies cleaned up")
