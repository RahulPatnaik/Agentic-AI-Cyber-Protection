"""
Simplified configuration using ONLY Cerebras and SambaNova.
No more rate limits, all free!
"""

import os
from typing import Optional, Dict, Any
from pydantic import BaseSettings, Field
import structlog

logger = structlog.get_logger()


class CerebrasSambaConfig(BaseSettings):
    """Configuration for Cerebras and SambaNova only"""

    # Cerebras - Super fast, 1M tokens/day
    cerebras_api_key: str = Field(
        default_factory=lambda: os.getenv("CEREBRAS_API_KEY", ""),
        description="Cerebras API key"
    )

    # SambaNova - Free 405B model!
    sambanova_api_key: str = Field(
        default_factory=lambda: os.getenv("SAMBANOVA_API_KEY", ""),
        description="SambaNova API key"
    )

    # Keep Mistral as backup only
    mistral_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("MISTRAL_API_KEY"),
        description="Mistral (backup only)"
    )

    class Config:
        env_file = ".env"
        case_sensitive = False


def get_agent_llm_config(agent_name: str) -> Dict[str, Any]:
    """
    Simple routing: Fast agents → Cerebras, Heavy agents → SambaNova
    """
    config = CerebrasSambaConfig()

    # Verify we have keys
    if not config.cerebras_api_key or not config.sambanova_api_key:
        logger.warning("Missing API keys! Add CEREBRAS_API_KEY and SAMBANOVA_API_KEY to .env")

    # Fast, lightweight agents → Cerebras (8K context limit but FAST)
    fast_agents = [
        "nlp_parser",      # Ingestion
        "cwe_agent",       # CWE mapping
        "dfd_builder",     # DFD generation
        "attack_tree",     # Attack paths
        "threat_generator" # Threat generation
    ]

    # Heavy reasoning agents → SambaNova 405B (slower but SMART)
    heavy_agents = [
        "stride_agent",     # STRIDE analysis
        "owasp_agent",      # OWASP analysis
        "maestro_agent",    # MAESTRO validation
        "compliance_agent", # Compliance checks
        "agentic_security", # Agentic analysis
        "orchestrator"      # Main orchestration
    ]

    if agent_name in fast_agents:
        return {
            "provider": "cerebras",
            "api_key": config.cerebras_api_key,
            "model": "llama3.1-8b",  # Fast 8B model from Cerebras
            "max_tokens": 2000,
            "temperature": 0.3,
            "max_context": 8192  # Important limit!
        }
    elif agent_name in heavy_agents:
        return {
            "provider": "sambanova",
            "api_key": config.sambanova_api_key,
            "base_url": "https://api.sambanova.ai/v1",
            "model": "Meta-Llama-3.1-405B-Instruct",  # BIG brain
            "max_tokens": 4000,
            "temperature": 0.5,
            "max_context": 32768
        }
    else:
        # Default to Cerebras for unknown agents
        return {
            "provider": "cerebras",
            "api_key": config.cerebras_api_key,
            "model": "llama3.1-8b",  # Using 8B for all Cerebras tasks
            "max_tokens": 1500,
            "temperature": 0.3,
            "max_context": 8192
        }


def test_connections():
    """Test that both APIs are working"""
    config = CerebrasSambaConfig()
    results = {}

    # Test Cerebras
    if config.cerebras_api_key:
        try:
            from cerebras.cloud.sdk import Cerebras
            client = Cerebras(api_key=config.cerebras_api_key)
            completion = client.chat.completions.create(
                messages=[{"role": "user", "content": "Say 'OK' if working"}],
                model="llama3.1-8b",
                max_completion_tokens=10,
                temperature=0.1
            )
            results["cerebras"] = "✅ Connected"
            logger.info("Cerebras API connected successfully")
        except Exception as e:
            results["cerebras"] = f"❌ Error: {str(e)[:50]}"
            logger.error(f"Cerebras connection failed: {e}")
    else:
        results["cerebras"] = "❌ No API key"

    # Test SambaNova
    if config.sambanova_api_key:
        try:
            from openai import OpenAI
            client = OpenAI(
                api_key=config.sambanova_api_key,
                base_url="https://api.sambanova.ai/v1"
            )
            completion = client.chat.completions.create(
                model="Meta-Llama-3.1-8B-Instruct",  # Use smaller model for test
                messages=[{"role": "user", "content": "Say 'OK' if working"}],
                max_tokens=10,
                temperature=0.1
            )
            results["sambanova"] = "✅ Connected"
            logger.info("SambaNova API connected successfully")
        except Exception as e:
            results["sambanova"] = f"❌ Error: {str(e)[:50]}"
            logger.error(f"SambaNova connection failed: {e}")
    else:
        results["sambanova"] = "❌ No API key"

    return results


# Agent allocation summary
AGENT_ALLOCATION = """
=== CEREBRAS (Fast, 1M tokens/day, 30 RPM) ===
✓ NLP Parser - Ingestion pipeline
✓ CWE Agent - Vulnerability mapping
✓ DFD Builder - Diagram generation
✓ Attack Tree - Path analysis
✓ Threat Generator - Automated threats

=== SAMBANOVA 405B (Smart, 10 RPM) ===
✓ STRIDE Agent - Threat modeling
✓ OWASP Agent - Security analysis
✓ MAESTRO Agent - Validation
✓ Compliance Agent - Regulatory checks
✓ Agentic Security - Advanced analysis

This allocation maximizes:
- Speed for mechanical tasks (Cerebras)
- Intelligence for reasoning (SambaNova 405B)
- Zero API costs (all free tier)
"""

if __name__ == "__main__":
    print("Testing LLM connections...")
    results = test_connections()
    for provider, status in results.items():
        print(f"{provider}: {status}")
    print("\nAgent Allocation:")
    print(AGENT_ALLOCATION)