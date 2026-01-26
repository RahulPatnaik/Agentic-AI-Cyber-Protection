"""
Multi-Agent Coordinator
Orchestrates WiFi Guardian and WiFi Sentinel agents
"""

import asyncio
from typing import Optional
import structlog

from src.agents.guardian import run_guardian_detection
from src.agents.sentinel import run_sentinel_analysis
from src.dependencies.guardian_deps import GuardianDependencies
from src.dependencies.sentinel_deps import SentinelDependencies
from src.models.alerts import SecurityAlert
from src.config.settings import Settings

logger = structlog.get_logger()


class AgentCoordinator:
    """
    Coordinates WiFi Guardian and WiFi Sentinel agents.
    Handles inter-agent communication via message queue.
    """

    def __init__(
        self,
        guardian_deps: GuardianDependencies,
        sentinel_deps: SentinelDependencies,
        config: Settings
    ):
        """
        Initialize coordinator.

        Args:
            guardian_deps: Guardian dependencies
            sentinel_deps: Sentinel dependencies
            config: Application settings
        """
        self.guardian_deps = guardian_deps
        self.sentinel_deps = sentinel_deps
        self.config = config

        self.guardian_task: Optional[asyncio.Task] = None
        self.sentinel_task: Optional[asyncio.Task] = None
        self.running = False

        # Statistics
        self.packets_processed = 0
        self.threats_detected = 0
        self.threats_escalated = 0

    async def start(self):
        """Start both agents and message queue consumers"""
        self.running = True

        logger.info("Starting Agent Coordinator...")

        # Start Guardian detection loop
        self.guardian_task = asyncio.create_task(self._guardian_loop())

        # Start Sentinel analysis loop (message queue consumer)
        self.sentinel_task = asyncio.create_task(self._sentinel_loop())

        logger.info(
            "Agent coordinator started",
            guardian_running=True,
            sentinel_running=True
        )

    async def stop(self):
        """Stop both agents gracefully"""
        logger.info("Stopping Agent Coordinator...")

        self.running = False

        # Cancel tasks
        if self.guardian_task:
            self.guardian_task.cancel()
            try:
                await self.guardian_task
            except asyncio.CancelledError:
                pass

        if self.sentinel_task:
            self.sentinel_task.cancel()
            try:
                await self.sentinel_task
            except asyncio.CancelledError:
                pass

        # Cleanup dependencies
        await self.guardian_deps.cleanup()
        await self.sentinel_deps.cleanup()

        logger.info(
            "Agent coordinator stopped",
            total_packets=self.packets_processed,
            threats_detected=self.threats_detected,
            threats_escalated=self.threats_escalated
        )

    async def _guardian_loop(self):
        """
        WiFi Guardian detection loop.
        Continuously captures packets and runs ML detection.
        """
        logger.info("Guardian detection loop started")

        sniffer = self.guardian_deps.packet_sniffer

        try:
            async for packet_batch in sniffer.capture_stream(batch_size=10):
                if not self.running:
                    break

                # Process each packet in batch
                for packet_data in packet_batch:
                    if not self.running:
                        break

                    try:
                        self.packets_processed += 1

                        # Run Guardian detection
                        alert = await run_guardian_detection(
                            packet_data,
                            self.guardian_deps
                        )

                        if alert:
                            self.threats_detected += 1

                            logger.info(
                                "Threat detected by Guardian",
                                threat_id=str(alert.threat_id),
                                threat_type=alert.threat_type.value,
                                severity=alert.severity.value,
                                confidence=alert.confidence
                            )

                            if alert.escalated_to_sentinel:
                                self.threats_escalated += 1

                    except Exception as e:
                        logger.error("Guardian detection error", error=str(e))
                        continue

                # Small delay between batches
                await asyncio.sleep(0.01)

        except Exception as e:
            logger.error("Guardian loop failed", error=str(e))
        finally:
            logger.info("Guardian detection loop stopped")

    async def _sentinel_loop(self):
        """
        WiFi Sentinel analysis loop.
        Consumes alerts from message queue and performs LLM reasoning.
        """
        logger.info("Sentinel analysis loop started")

        message_queue = self.sentinel_deps.message_queue

        try:
            async for message in message_queue.consume('sentinel_analysis'):
                if not self.running:
                    break

                try:
                    # Deserialize alert
                    alert = SecurityAlert.model_validate(message.body)

                    logger.info(
                        "Sentinel analyzing threat",
                        alert_id=str(alert.threat_id),
                        threat_type=alert.threat_type.value
                    )

                    # Run Sentinel analysis
                    response = await run_sentinel_analysis(
                        alert,
                        self.sentinel_deps
                    )

                    logger.info(
                        "Sentinel analysis complete",
                        incident_id=str(response.incident_id),
                        risk_score=response.risk_score,
                        recommended_action=response.recommended_action.action_type.value if response.recommended_action else None
                    )

                    # Acknowledge message
                    await message_queue.ack(message)

                except Exception as e:
                    logger.error("Sentinel analysis error", error=str(e))
                    # Negative acknowledge with requeue
                    await message_queue.nack(message, requeue=True)
                    continue

        except Exception as e:
            logger.error("Sentinel loop failed", error=str(e))
        finally:
            logger.info("Sentinel analysis loop stopped")

    def get_stats(self) -> dict:
        """Get coordinator statistics"""
        return {
            'running': self.running,
            'packets_processed': self.packets_processed,
            'threats_detected': self.threats_detected,
            'threats_escalated': self.threats_escalated,
            'guardian_status': 'running' if self.guardian_task and not self.guardian_task.done() else 'stopped',
            'sentinel_status': 'running' if self.sentinel_task and not self.sentinel_task.done() else 'stopped'
        }
