"""
Model Factory for Agent Configuration
Handles proper model allocation based on task complexity
"""

import os
from typing import Any
from pydantic_ai import Agent
from pydantic_ai.models import ModelSettings
from dotenv import load_dotenv

load_dotenv()

def create_agent_with_optimal_model(
    agent_name: str,
    output_type: Any,
    system_prompt: str
) -> Agent:
    """
    Create an agent with the optimal model based on task complexity.

    Big models for complex reasoning, small models for structured tasks.
    """

    # Model allocation based on task complexity
    model_config = {
        # BIG MODELS - Complex reasoning, domain knowledge
        "stride": {
            "model": "openai:gpt-4o",  # Using OpenAI provider with SambaNova endpoint
            "reason": "Real threat reasoning across 6 categories",
            "needs_sambanova": True
        },
        "owasp": {
            "model": "openai:gpt-4o",
            "reason": "Security domain expertise needed",
            "needs_sambanova": True
        },
        "compliance": {
            "model": "mistral:mistral-large-latest",
            "reason": "Framework knowledge: NIST, ISO, GDPR"
        },
        "agentic_security": {
            "model": "mistral:mistral-large-latest",
            "reason": "Niche attack vectors: MCP, prompt injection"
        },

        # SMALL MODELS - Structured/mechanical tasks
        "cwe": {
            "model": "mistral:mistral-small-latest",  # Fallback since Cerebras isn't in pydantic_ai
            "reason": "Pattern matching to finite CWE list"
        },
        "dfd": {
            "model": "mistral:mistral-small-latest",
            "reason": "Keyword to structure conversion"
        },
        "maestro": {
            "model": "mistral:mistral-small-latest",
            "reason": "Rule-based validation"
        },
        "attack_tree": {
            "model": "mistral:mistral-small-latest",
            "reason": "Structured path generation"
        }
    }

    # Get config for this agent
    config = model_config.get(agent_name, {
        "model": "mistral:mistral-small-latest",
        "reason": "Default for unknown agent"
    })

    # For SambaNova, we need to set up OpenAI client with custom endpoint
    if config.get("needs_sambanova"):
        # SambaNova uses OpenAI-compatible API
        # This requires custom setup - for now fall back to Mistral
        # TODO: Integrate SambaNova properly with pydantic_ai
        model_str = "mistral:mistral-large-latest"
    else:
        model_str = config["model"]

    # Create agent with appropriate model
    return Agent(
        model_str,
        output_type=output_type,
        system_prompt=system_prompt
    )


def get_model_settings(agent_name: str) -> ModelSettings:
    """Get optimized model settings for an agent"""

    # Optimize token limits based on agent needs
    settings_map = {
        # Complex agents need more tokens
        "stride": ModelSettings(max_tokens=2000, temperature=0.7),
        "owasp": ModelSettings(max_tokens=2000, temperature=0.7),
        "compliance": ModelSettings(max_tokens=3000, temperature=0.5),

        # Simple agents need fewer tokens
        "cwe": ModelSettings(max_tokens=500, temperature=0.3),
        "dfd": ModelSettings(max_tokens=1000, temperature=0.3),
        "maestro": ModelSettings(max_tokens=1000, temperature=0.5),
        "attack_tree": ModelSettings(max_tokens=1500, temperature=0.6),
    }

    return settings_map.get(agent_name, ModelSettings(max_tokens=1000, temperature=0.5))