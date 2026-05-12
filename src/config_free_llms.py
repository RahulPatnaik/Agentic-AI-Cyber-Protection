"""
Configuration for free LLM alternatives to reduce rate limiting.
Strategic distribution of agents across free tiers for maximum throughput.
"""

from typing import Optional, Dict, Any
from pydantic import BaseSettings, Field
import os

class FreeLLMConfig(BaseSettings):
    """Configuration for free LLM alternatives"""

    # Cerebras - 1M tokens/day, 30 RPM, super fast
    # Best for: Short prompts, fast agents (CWE, DFD, Attack Tree)
    cerebras_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("CEREBRAS_API_KEY"),
        description="Cerebras API key for fast inference"
    )
    cerebras_base_url: str = "https://api.cerebras.ai/v1"
    cerebras_model: str = "llama3.1-70b"  # Fast 70B model
    cerebras_max_tokens: int = 8192  # Context limit on free tier

    # SambaNova - Free 405B model(!), 10-30 RPM
    # Best for: Heavy reasoning (STRIDE, OWASP, Compliance)
    sambanova_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("SAMBANOVA_API_KEY"),
        description="SambaNova API key"
    )
    sambanova_base_url: str = "https://api.sambanova.ai/v1"
    sambanova_model_405b: str = "Meta-Llama-3.1-405B-Instruct"  # Big brain
    sambanova_model_70b: str = "Meta-Llama-3.1-70B-Instruct"   # Faster option

    # GitHub Models - Free GPT-4o with GitHub account
    # Best for: Emergency fallback, complex reasoning
    github_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN"),
        description="GitHub token for GitHub Models"
    )
    github_base_url: str = "https://models.inference.ai.azure.com"
    github_model_gpt4: str = "gpt-4o"
    github_model_llama: str = "Meta-Llama-3.1-70B-Instruct"

    # Groq - Still useful for parallel bursts
    groq_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GROQ_API_KEY"),
        description="Groq API key"
    )
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "llama-3.3-70b-versatile"

    # Keep Mistral for critical paths only
    mistral_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("MISTRAL_API_KEY"),
        description="Mistral API key - use sparingly"
    )

    class Config:
        env_file = ".env"
        case_sensitive = False


def get_llm_config_for_agent(agent_name: str) -> Dict[str, Any]:
    """
    Returns the optimal LLM configuration for each agent.
    Strategic distribution to maximize free tier usage.
    """
    config = FreeLLMConfig()

    # Fast, short-prompt agents -> Cerebras (30 RPM, ultra fast)
    if agent_name in ["cwe_agent", "dfd_builder", "attack_tree"]:
        return {
            "provider": "cerebras",
            "model": f"openai:{config.cerebras_model}",
            "base_url": config.cerebras_base_url,
            "api_key": config.cerebras_api_key,
            "max_tokens": 2000,  # Keep responses short
            "temperature": 0.3
        }

    # Heavy reasoning agents -> SambaNova 405B (10 RPM, massive model)
    elif agent_name in ["stride_agent", "owasp_agent", "compliance_agent"]:
        return {
            "provider": "sambanova",
            "model": f"openai:{config.sambanova_model_405b}",
            "base_url": config.sambanova_base_url,
            "api_key": config.sambanova_api_key,
            "max_tokens": 4000,
            "temperature": 0.5
        }

    # Parallel burst agents -> Groq or SambaNova 70B (30 RPM)
    elif agent_name in ["maestro_agent", "agentic_security"]:
        if config.groq_api_key:
            return {
                "provider": "groq",
                "model": f"openai:{config.groq_model}",
                "base_url": config.groq_base_url,
                "api_key": config.groq_api_key,
                "max_tokens": 3000,
                "temperature": 0.4
            }
        else:
            return {
                "provider": "sambanova",
                "model": f"openai:{config.sambanova_model_70b}",
                "base_url": config.sambanova_base_url,
                "api_key": config.sambanova_api_key,
                "max_tokens": 3000,
                "temperature": 0.4
            }

    # NLP Parser for ingestion -> Cerebras (fast, handles chunks well)
    elif agent_name == "nlp_parser":
        return {
            "provider": "cerebras",
            "model": f"openai:{config.cerebras_model}",
            "base_url": config.cerebras_base_url,
            "api_key": config.cerebras_api_key,
            "max_tokens": 1500,
            "temperature": 0.2
        }

    # Default fallback -> GitHub Models GPT-4o
    else:
        return {
            "provider": "github",
            "model": config.github_model_gpt4,
            "base_url": config.github_base_url,
            "api_key": config.github_token,
            "max_tokens": 2000,
            "temperature": 0.4
        }


class RateLimitFallbackChain:
    """
    Automatic fallback when rate limited.
    Tries providers in order until one works.
    """

    def __init__(self):
        self.config = FreeLLMConfig()
        self.fallback_order = [
            ("cerebras", self.config.cerebras_base_url, self.config.cerebras_api_key),
            ("sambanova", self.config.sambanova_base_url, self.config.sambanova_api_key),
            ("groq", self.config.groq_base_url, self.config.groq_api_key),
            ("github", self.config.github_base_url, self.config.github_token),
            ("mistral", None, self.config.mistral_api_key),  # Last resort
        ]

    async def execute_with_fallback(self, agent_func, *args, **kwargs):
        """
        Execute agent function with automatic fallback on rate limit.
        """
        errors = []

        for provider, base_url, api_key in self.fallback_order:
            if not api_key:
                continue

            try:
                # Update kwargs with provider config
                if base_url:
                    kwargs['base_url'] = base_url
                kwargs['api_key'] = api_key

                # Try execution
                result = await agent_func(*args, **kwargs)
                if provider != "cerebras":  # Log non-primary usage
                    logger.info(f"Succeeded with fallback provider: {provider}")
                return result

            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    errors.append(f"{provider}: rate limited")
                    continue
                else:
                    # Non-rate-limit error, re-raise
                    raise

        # All providers failed
        raise Exception(f"All LLM providers rate limited: {', '.join(errors)}")


# Example usage in agents:
"""
# In cwe_agent.py:
from src.config_free_llms import get_llm_config_for_agent

class CWEAgent:
    def __init__(self, settings):
        llm_config = get_llm_config_for_agent("cwe_agent")

        self.agent = Agent(
            llm_config["model"],
            base_url=llm_config["base_url"],
            api_key=llm_config["api_key"],
            output_type=CWEAnalysisResult,
            system_prompt="You are a CWE expert..."
        )

# In nlp_parser_improved.py:
from src.config_free_llms import get_llm_config_for_agent

class ImprovedNLPParser:
    def __init__(self, settings):
        llm_config = get_llm_config_for_agent("nlp_parser")

        if llm_config["api_key"]:
            # Use OpenAI client for all providers (they're OpenAI-compatible)
            from openai import OpenAI
            base_client = OpenAI(
                api_key=llm_config["api_key"],
                base_url=llm_config["base_url"]
            )
            self.client = instructor.from_openai(base_client)
            self.model = llm_config["model"].replace("openai:", "")
"""