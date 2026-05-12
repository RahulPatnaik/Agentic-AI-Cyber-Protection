"""
Intelligent Model Allocation Configuration
Based on actual task complexity and requirements

Big models for complex reasoning, small models for structured tasks.
"""

from typing import Dict, Any
import os
from dotenv import load_dotenv

load_dotenv()

def get_model_for_agent(agent_name: str) -> Dict[str, Any]:
    """
    Returns the optimal model configuration for each agent based on task complexity.

    Allocation strategy:
    - Big models (70B+): Complex reasoning, domain knowledge, security analysis
    - Small models (8B): Pattern matching, structured generation, JSON extraction
    """

    # Get API keys
    cerebras_key = os.getenv("CEREBRAS_API_KEY", "")
    sambanova_key = os.getenv("SAMBANOVA_API_KEY", "")
    mistral_key = os.getenv("MISTRAL_API_KEY", "")

    # AGENTS THAT NEED BIG MODELS (complex reasoning, domain knowledge)
    # Use Mistral as primary for heavy reasoning (always available)
    # Fallback to SambaNova if Mistral fails
    big_model_agents = {
        "stride_agent": {
            "provider": "mistral",  # Use Mistral for reliability
            "api_key": mistral_key,
            "model": "mistral-large-latest",
            "reason": "Real threat reasoning across 6 categories, needs security domain knowledge",
            "fallback": {
                "provider": "openai",
                "api_key": sambanova_key,
                "base_url": "https://api.sambanova.ai/v1",
                "model": "Meta-Llama-3.3-70B-Instruct"  # Correct model name
            }
        },
        "owasp_agent": {
            "provider": "mistral",  # Use Mistral for reliability
            "api_key": mistral_key,
            "model": "mistral-large-latest",
            "reason": "Security vulnerability detection requires deep domain knowledge",
            "fallback": {
                "provider": "openai",
                "api_key": sambanova_key,
                "base_url": "https://api.sambanova.ai/v1",
                "model": "Meta-Llama-3.3-70B-Instruct"  # Correct model name
            }
        },
        "compliance_agent": {
            "provider": "mistral",
            "api_key": mistral_key,
            "model": "mistral-large-latest",
            "reason": "NIST, ISO 27001, GDPR control mapping needs framework knowledge"
        },
        "agentic_security": {
            "provider": "mistral",
            "api_key": mistral_key,
            "model": "mistral-large-latest",
            "reason": "MCP exploitation, prompt injection - niche attack vectors"
        }
    }

    # AGENTS THAT CAN USE SMALL MODELS (structured/mechanical tasks)
    small_model_agents = {
        "nlp_parser": {
            "provider": "cerebras",
            "api_key": cerebras_key,
            "model": "llama3.1-8b",
            "reason": "Simple JSON extraction from descriptions"
        },
        "cwe_agent": {
            "provider": "cerebras",
            "api_key": cerebras_key,
            "model": "llama3.1-8b",
            "reason": "Pattern matching to finite CWE list, has fallback database"
        },
        "dfd_builder": {
            "provider": "cerebras",
            "api_key": cerebras_key,
            "model": "llama3.1-8b",
            "reason": "Keyword to structure conversion, mostly rule-based"
        },
        "maestro_agent": {
            "provider": "cerebras",
            "api_key": cerebras_key,
            "model": "llama3.1-8b",
            "reason": "Rule-based validation with narrative generation"
        },
        "attack_tree": {
            "provider": "cerebras",
            "api_key": cerebras_key,
            "model": "llama3.1-8b",  # Could use 70B if available
            "reason": "Structured generation of attack paths, doesn't need frontier reasoning"
        }
    }

    # Combine all agents
    all_agents = {**big_model_agents, **small_model_agents}

    # Return config for requested agent
    if agent_name in all_agents:
        return all_agents[agent_name]
    else:
        # Default to small model for unknown agents
        return {
            "provider": "cerebras",
            "api_key": cerebras_key,
            "model": "llama3.1-8b",
            "reason": "Default allocation for unknown agent"
        }


def get_allocation_summary() -> str:
    """Returns a human-readable summary of model allocations"""
    return """
=== OPTIMIZED MODEL ALLOCATION ===

BIG MODELS (Complex Reasoning, Domain Knowledge):
─────────────────────────────────────────────────
STRIDE Agent        → Mistral Large    (Threat reasoning across 6 categories)
OWASP Analyzer      → Mistral Large    (Security domain expertise needed)
Compliance Agent    → Mistral Large    (Framework knowledge: NIST, ISO, GDPR)
Agentic Security    → Mistral Large    (Niche: MCP, prompt injection)

SMALL MODELS (Structured/Mechanical Tasks):
─────────────────────────────────────────────────
NLP Parser          → Cerebras 8B      (JSON extraction - WASTEFUL on big model!)
CWE Analyzer        → Cerebras 8B      (Pattern matching to CWE database)
DFD Builder         → Cerebras 8B      (Keyword → structure conversion)
MAESTRO Validator   → Cerebras 8B      (Rule-based + narrative)
Attack Tree         → Cerebras 8B      (Structured path generation)

NO LLM NEEDED:
─────────────────────────────────────────────────
Symbolic Verifier   → Z3 SMT Solver    (Direct proof checking)
CVE Scanner         → NVD API          (Database lookup)

IMPACT:
• Shifts ~40% token load off Mistral to free Cerebras tier
• Keeps complex reasoning on appropriate models
• Instant savings on NLP parser (runs on EVERY request)
• Reduces Phase 3 parallel burst pressure
"""


# Helper to check if models are properly configured
def validate_configuration() -> Dict[str, bool]:
    """Check if all required API keys are present"""
    return {
        "cerebras_configured": bool(os.getenv("CEREBRAS_API_KEY")),
        "sambanova_configured": bool(os.getenv("SAMBANOVA_API_KEY")),
        "mistral_configured": bool(os.getenv("MISTRAL_API_KEY")),
    }


if __name__ == "__main__":
    print(get_allocation_summary())
    print("\nConfiguration Status:")
    for key, value in validate_configuration().items():
        status = "✓" if value else "✗"
        print(f"  {status} {key}")