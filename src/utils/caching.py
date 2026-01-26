"""
Mistral API Response Caching
Minimize API costs by caching responses for similar threats
"""

import hashlib
import time
from typing import Optional, Dict, Any
import structlog

from src.config.settings import Settings

logger = structlog.get_logger()


class MistralResponseCache:
    """
    Cache Mistral API responses to minimize costs.
    Uses in-memory dictionary with TTL.
    """

    def __init__(self, config: Settings):
        """
        Initialize cache.

        Args:
            config: Application settings
        """
        self.config = config
        self.enabled = config.enable_response_cache
        self.ttl = config.mistral_cache_ttl

        # Cache: {prompt_hash: (response, timestamp)}
        self.cache: Dict[str, tuple[str, float]] = {}

        self.hits = 0
        self.misses = 0

    def _hash_prompt(self, prompt: str) -> str:
        """
        Create hash of prompt for cache key.

        Args:
            prompt: LLM prompt text

        Returns:
            SHA256 hash as hex string
        """
        return hashlib.sha256(prompt.encode()).hexdigest()

    def get(self, prompt: str) -> Optional[str]:
        """
        Get cached response for prompt.

        Args:
            prompt: LLM prompt text

        Returns:
            Cached response or None if not found/expired
        """
        if not self.enabled:
            return None

        cache_key = self._hash_prompt(prompt)

        if cache_key in self.cache:
            response, timestamp = self.cache[cache_key]

            # Check if expired
            age = time.time() - timestamp
            if age < self.ttl:
                self.hits += 1
                logger.debug(
                    "Cache hit",
                    age_seconds=age,
                    hit_rate=self.get_hit_rate()
                )
                return response
            else:
                # Expired, remove from cache
                del self.cache[cache_key]
                logger.debug("Cache entry expired", age_seconds=age)

        self.misses += 1
        return None

    def set(self, prompt: str, response: str) -> None:
        """
        Cache response for prompt.

        Args:
            prompt: LLM prompt text
            response: LLM response to cache
        """
        if not self.enabled:
            return

        cache_key = self._hash_prompt(prompt)
        self.cache[cache_key] = (response, time.time())

        logger.debug(
            "Response cached",
            cache_size=len(self.cache),
            ttl_seconds=self.ttl
        )

    def invalidate(self, prompt: Optional[str] = None) -> None:
        """
        Invalidate cache entry or all entries.

        Args:
            prompt: Specific prompt to invalidate, or None for all
        """
        if prompt:
            cache_key = self._hash_prompt(prompt)
            if cache_key in self.cache:
                del self.cache[cache_key]
                logger.debug("Cache entry invalidated")
        else:
            self.cache.clear()
            logger.info("All cache entries invalidated")

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        now = time.time()
        to_remove = []

        for key, (response, timestamp) in self.cache.items():
            age = now - timestamp
            if age >= self.ttl:
                to_remove.append(key)

        for key in to_remove:
            del self.cache[key]

        if to_remove:
            logger.debug(f"Removed {len(to_remove)} expired cache entries")

        return len(to_remove)

    def get_hit_rate(self) -> float:
        """
        Calculate cache hit rate.

        Returns:
            Hit rate as percentage (0.0 - 1.0)
        """
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'enabled': self.enabled,
            'cache_size': len(self.cache),
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': self.get_hit_rate(),
            'ttl_seconds': self.ttl
        }
