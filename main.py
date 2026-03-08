"""
Agentic Threat Modeling System
Main entry point
"""

import asyncio
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Load .env into os.environ BEFORE any agents are imported
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env", override=True)

import uvicorn
import structlog
from src.config import Settings

# Configure structured logging - MINIMAL OUTPUT FOR CLEAN TERMINAL
import logging
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

# Set log level to WARNING to reduce noise (only show warnings and errors)
logging.basicConfig(level=logging.WARNING)

logger = structlog.get_logger()


def main():
    """Main entry point for the application"""

    # Load settings
    settings = Settings()

    # Validate configuration
    if not settings.mistral_api_key:
        logger.warning(
            "⚠️  No Mistral API key configured!",
            message="Set MISTRAL_API_KEY in .env file. Using fallback parser without LLM."
        )
        print("\n" + "="*80)
        print("⚠️  WARNING: No Mistral API key configured!")
        print("="*80)
        print("The system will use basic keyword-based parsing instead of AI-powered parsing.")
        print("To enable full functionality:")
        print("  1. Get a Mistral API key from: https://console.mistral.ai/")
        print("  2. Add it to .env file: MISTRAL_API_KEY=your_key_here")
        print("="*80 + "\n")

    # Print startup banner
    print("\n" + "="*80)
    print("🛡️  AGENTIC THREAT MODELING SYSTEM")
    print("="*80)
    print("AI-Powered Security Threat Analysis")
    print("Built with: Pydantic AI + Mistral AI + Z3 SMT + STRIDE + OWASP + CWE + NVD")
    print("-"*80)
    print(f"API Server: http://{settings.api_host}:{settings.api_port}")
    print(f"API Docs: http://{settings.api_host}:{settings.api_port}/docs")
    print(f"Dashboard: http://{settings.api_host}:{settings.api_port}/dashboard")
    print("-"*80)
    print("Agents:")
    print("  ✓ DFD Builder (Data Flow Diagram Generator)")
    print("  ✓ STRIDE Analyzer (Threat Categorization)")
    print("  ✓ OWASP Analyzer (OWASP Top 10 2021)")
    print("  ✓ Attack Tree Generator (Attack Paths)")
    print("  ✓ CWE Analyzer (Common Weakness Enumeration)")
    print("  ✓ MAESTRO Validator (Security Principles)")
    print("  ✓ Symbolic Verifier (Z3 SMT Formal Verification)")
    print("  ✓ CVE Scanner (NVD/MITRE CVE Enrichment)")
    print("  ✓ Automated Threat Generator (DFD-based)")
    print("-"*80)
    print("Features:")
    print("  • Natural language threat modeling with AI")
    print("  • Code snippet vulnerability analysis")
    print("  • STRIDE threat categorization across 6 dimensions")
    print("  • Data Flow Diagram (DFD) automatic generation")
    print("  • Z3 SMT symbolic verification of security properties")
    print("  • CVE enrichment with NVD/MITRE database integration")
    print("  • Interactive D3.js attack path visualizations")
    print("  • Top 5-10 critical vulnerabilities with remediation")
    print("  • CWE mappings and OWASP Top 10 classifications")
    print("  • MAESTRO security principles validation")
    print("  • PDF/HTML report export")
    print("="*80 + "\n")

    logger.info("Starting Agentic Threat Modeling System")

    # Start FastAPI server
    try:
        uvicorn.run(
            "src.api.app:app",
            host=settings.api_host,
            port=settings.api_port,
            reload=True,
            log_level=settings.log_level.lower(),
            access_log=True
        )
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
        print("\n" + "="*80)
        print("👋 Shutdown complete. Thank you for using Agentic Threat Modeling!")
        print("="*80 + "\n")
    except Exception as e:
        logger.error("Startup failed", error=str(e), exc_info=True)
        print(f"\n❌ Error: {str(e)}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
