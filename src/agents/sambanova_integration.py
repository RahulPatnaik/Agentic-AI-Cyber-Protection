"""
SambaNova Integration for Heavy Reasoning Agents
Uses OpenAI client with SambaNova's API endpoint
"""

import os
from typing import List, Dict, Any
from openai import OpenAI
from dotenv import load_dotenv
import json
import structlog

load_dotenv()
logger = structlog.get_logger()


class SambaNovaClient:
    """Client for SambaNova 405B model via OpenAI-compatible API"""

    def __init__(self):
        api_key = os.getenv("SAMBANOVA_API_KEY")
        if not api_key or api_key == "your-sambanova-api-key-here":
            raise ValueError("SAMBANOVA_API_KEY not configured")

        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.sambanova.ai/v1"
        )
        # Use Meta-Llama-3.3-70B-Instruct - latest production model with 128k context
        self.model = "Meta-Llama-3.3-70B-Instruct"
        logger.info(f"Initialized SambaNova client with {self.model}")

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Dict[str, Any] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Dict[str, Any]:
        """
        Get completion from SambaNova 405B model

        Args:
            system_prompt: System instructions
            user_prompt: User query
            response_format: Expected JSON schema for structured output
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Parsed JSON response or text
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        # Add JSON format instruction if schema provided
        if response_format:
            messages[0]["content"] += f"\n\nYou must respond with valid JSON matching this schema:\n{json.dumps(response_format, indent=2)}"

        try:
            # Build request params
            request_params = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }

            # Only add response_format if needed (SambaNova may not support it)
            # if response_format:
            #     request_params["response_format"] = {"type": "json_object"}

            response = self.client.chat.completions.create(**request_params)

            content = response.choices[0].message.content

            # Parse JSON if expected
            if response_format:
                try:
                    return json.loads(content)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse SambaNova JSON response: {e}")
                    logger.error(f"Raw response: {content[:500]}")
                    return {"error": "JSON parse failed", "raw": content}

            return {"content": content}

        except Exception as e:
            logger.error(f"SambaNova API error: {e}")
            raise


# Singleton instance
_sambanova_client = None


def get_sambanova_client() -> SambaNovaClient:
    """Get or create SambaNova client singleton"""
    global _sambanova_client
    if _sambanova_client is None:
        _sambanova_client = SambaNovaClient()
    return _sambanova_client


def test_sambanova_connection():
    """Test SambaNova API connection"""
    try:
        client = get_sambanova_client()
        result = client.complete(
            system_prompt="You are a helpful assistant.",
            user_prompt="Say 'OK' if you're working",
            temperature=0.1,
            max_tokens=10
        )
        logger.info(f"SambaNova test successful: {result}")
        return True
    except Exception as e:
        logger.error(f"SambaNova test failed: {e}")
        return False


if __name__ == "__main__":
    # Test the connection
    if test_sambanova_connection():
        print("✅ SambaNova 405B model connected successfully!")
    else:
        print("❌ SambaNova connection failed")