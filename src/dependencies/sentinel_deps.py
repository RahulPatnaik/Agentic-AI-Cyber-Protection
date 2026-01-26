"""
Dependency Injection for WiFi Sentinel Agent
All dependencies needed for reasoning and response
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional
import structlog

from src.messaging.queue import MessageQueue
from src.utils.caching import MistralResponseCache
from src.config.settings import Settings

logger = structlog.get_logger()


@dataclass
class SentinelDependencies:
    """
    All dependencies injected into WiFi Sentinel Agent.
    Used with RunContext[SentinelDependencies] in Pydantic AI tools.
    """
    # Communication
    message_queue: MessageQueue

    # Caching
    response_cache: MistralResponseCache

    # Configuration
    config: Settings

    # Simple storage (in-memory for MVP)
    threat_intel: dict = None
    incident_storage: list = None
    mitre_mappings: dict = None

    def __post_init__(self):
        """Initialize storage if not provided"""
        if self.threat_intel is None:
            self.threat_intel = self._load_threat_intel()

        if self.incident_storage is None:
            self.incident_storage = []

        if self.mitre_mappings is None:
            self.mitre_mappings = self._load_mitre_mappings()

    @classmethod
    async def create(cls, config: Settings) -> "SentinelDependencies":
        """
        Factory method to instantiate all dependencies.
        Called at startup.

        Args:
            config: Application settings

        Returns:
            SentinelDependencies instance
        """
        logger.info("Initializing Sentinel dependencies...")

        # Initialize messaging
        message_queue = await MessageQueue.connect(config)

        # Initialize caching
        response_cache = MistralResponseCache(config)

        logger.info("Sentinel dependencies initialized successfully")

        return cls(
            message_queue=message_queue,
            response_cache=response_cache,
            config=config
        )

    def _load_threat_intel(self) -> Dict[str, Any]:
        """Load threat intelligence data (mock for MVP)"""
        return {
            'MITM_Attack': {
                'severity': 'high',
                'indicators': ['arp_spoofing', 'duplicate_ip'],
                'response': 'isolate_device',
                'description': 'Man-in-the-Middle attack intercepting network traffic'
            },
            'Deauth_Attack': {
                'severity': 'medium',
                'indicators': ['excessive_deauth_frames'],
                'response': 'alert_only',
                'description': 'Deauthentication attack forcing clients to disconnect'
            },
            'Evil_Twin': {
                'severity': 'high',
                'indicators': ['ssid_mismatch', 'duplicate_ssid'],
                'response': 'block_mac',
                'description': 'Rogue access point mimicking legitimate network'
            },
            'DNS_Spoofing': {
                'severity': 'medium',
                'indicators': ['dns_anomaly'],
                'response': 'reset_connection',
                'description': 'DNS responses manipulated to redirect traffic'
            },
            'Rogue_AP': {
                'severity': 'high',
                'indicators': ['unknown_mac', 'signal_strength_anomaly'],
                'response': 'block_mac',
                'description': 'Unauthorized access point on the network'
            }
        }

    def _load_mitre_mappings(self) -> Dict[str, Dict[str, str]]:
        """Load MITRE ATT&CK mappings (mock for MVP)"""
        return {
            'MITM_Attack': {
                'technique_id': 'T1557.002',
                'technique_name': 'ARP Cache Poisoning',
                'tactic': 'Credential Access',
                'description': 'Adversaries may poison ARP caches to position themselves between two hosts.'
            },
            'Deauth_Attack': {
                'technique_id': 'T1498.001',
                'technique_name': 'Direct Network Flood',
                'tactic': 'Impact',
                'description': 'Adversaries may perform Network Denial of Service attacks.'
            },
            'Evil_Twin': {
                'technique_id': 'T1557',
                'technique_name': 'Adversary-in-the-Middle',
                'tactic': 'Collection',
                'description': 'Adversaries may attempt to position themselves between clients and access points.'
            },
            'DNS_Spoofing': {
                'technique_id': 'T1584.002',
                'technique_name': 'DNS Server',
                'tactic': 'Resource Development',
                'description': 'Adversaries may compromise DNS servers to redirect traffic.'
            },
            'Rogue_AP': {
                'technique_id': 'T1200',
                'technique_name': 'Hardware Additions',
                'tactic': 'Initial Access',
                'description': 'Adversaries may introduce computer accessories to gain initial access.'
            }
        }

    async def cleanup(self):
        """Cleanup all resources"""
        logger.info("Cleaning up Sentinel dependencies...")

        if self.message_queue:
            await self.message_queue.disconnect()

        logger.info("Sentinel dependencies cleaned up")
