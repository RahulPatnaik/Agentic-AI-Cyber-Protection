"""
WiFi Guardian System - Main Entry Point
Multi-agent WiFi threat detection and response system
"""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
import structlog

from src.config.settings import Settings
from src.utils.logging import configure_logging
from src.dependencies.guardian_deps import GuardianDependencies
from src.dependencies.sentinel_deps import SentinelDependencies
from src.orchestration.coordinator import AgentCoordinator
from src.api.app import app, app_state
import uvicorn

logger = structlog.get_logger()


class WiFiGuardianSystem:
    """Main application orchestrator"""

    def __init__(self, config: Settings):
        """
        Initialize WiFi Guardian System.

        Args:
            config: Application settings
        """
        self.config = config
        self.coordinator: AgentCoordinator = None
        self.guardian_deps: GuardianDependencies = None
        self.sentinel_deps: SentinelDependencies = None
        self.shutdown_event = asyncio.Event()

    async def startup(self):
        """Initialize all components"""
        logger.info("=" * 60)
        logger.info("WiFi Guardian System starting up...")
        logger.info("=" * 60)

        # Ensure directories exist
        self.config.ensure_directories()

        # Initialize Guardian dependencies
        logger.info("Initializing Guardian dependencies...")
        self.guardian_deps = await GuardianDependencies.create(self.config)

        # Initialize Sentinel dependencies
        logger.info("Initializing Sentinel dependencies...")
        self.sentinel_deps = await SentinelDependencies.create(self.config)

        # Create agent coordinator
        logger.info("Creating agent coordinator...")
        self.coordinator = AgentCoordinator(
            self.guardian_deps,
            self.sentinel_deps,
            self.config
        )

        # Inject into app state for API access
        app_state['coordinator'] = self.coordinator
        app_state['guardian_deps'] = self.guardian_deps
        app_state['sentinel_deps'] = self.sentinel_deps

        # Start agents
        logger.info("Starting agents...")
        await self.coordinator.start()

        logger.info("=" * 60)
        logger.info("WiFi Guardian System startup complete!")
        logger.info(f"API: http://{self.config.api_host}:{self.config.api_port}")
        logger.info(f"Dashboard: http://{self.config.api_host}:{self.config.api_port}/dashboard")
        logger.info(f"Health: http://{self.config.api_host}:{self.config.api_port}/api/health")
        logger.info("=" * 60)

    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("=" * 60)
        logger.info("WiFi Guardian System shutting down...")
        logger.info("=" * 60)

        if self.coordinator:
            await self.coordinator.stop()

        logger.info("WiFi Guardian System shutdown complete")
        logger.info("=" * 60)

    async def run(self):
        """Main run loop"""
        # Setup signal handlers
        loop = asyncio.get_event_loop()

        def signal_handler():
            logger.info("Shutdown signal received")
            self.shutdown_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)

        # Wait for shutdown signal
        await self.shutdown_event.wait()


@asynccontextmanager
async def lifespan(app):
    """FastAPI lifespan manager"""
    # Startup
    system = app.state.system
    await system.startup()

    yield

    # Shutdown
    await system.shutdown()


async def main():
    """Main entry point"""
    # Load configuration
    config = Settings()

    # Configure logging
    configure_logging(config)

    # Welcome banner
    logger.info("=" * 60)
    logger.info("WiFi GUARDIAN SYSTEM")
    logger.info("Multi-Agent WiFi Threat Detection & Response")
    logger.info("Powered by Pydantic AI & Mistral AI")
    logger.info("=" * 60)

    # Create system
    system = WiFiGuardianSystem(config)

    # Attach to FastAPI app
    app.state.system = system

    # Configure API server
    api_config = uvicorn.Config(
        app,
        host=config.api_host,
        port=config.api_port,
        log_level=config.log_level.lower(),
        lifespan="on"
    )
    server = uvicorn.Server(api_config)

    # Run API server and system concurrently
    try:
        await asyncio.gather(
            server.serve(),
            system.run()
        )
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error("Fatal error", error=str(e))
        raise
    finally:
        await system.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete. Goodbye!")
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)
