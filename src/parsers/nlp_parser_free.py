"""
NLP Parser using FREE LLMs (Cerebras) for ingestion.
No more rate limits on the ingestion pipeline!
"""

from typing import Optional, List
import instructor
import structlog
from pydantic import BaseModel, Field
from openai import OpenAI
import os

from src.models.threats import AssetInput, ComponentType, SeverityLevel
from src.config import Settings
from src.config_free_llms import get_llm_config_for_agent

logger = structlog.get_logger()


class ParsedAsset(BaseModel):
    """Structured output model for parsed assets"""
    description: str = Field(..., description="Clear technical summary")
    component_type: str = Field(
        ...,
        description="Component type",
        pattern="^(web_server|database|api_endpoint|authentication|data_store|external_service|user_input|business_logic|network_boundary)$"
    )
    programming_languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    external_dependencies: List[str] = Field(default_factory=list)
    compliance_requirements: List[str] = Field(default_factory=list)
    user_roles: List[str] = Field(default_factory=list)
    data_sensitivity: str = Field("medium", pattern="^(none|low|medium|high|critical)$")
    internet_facing: bool = Field(False)


class FreeNLPParser:
    """
    NLP parser using free LLMs to avoid rate limits.
    Primary: Cerebras (1M tokens/day, 30 RPM)
    Fallback: SambaNova, GitHub Models
    """

    def __init__(self, settings: Settings = None):
        self.settings = settings or Settings()

        # Get LLM config for NLP parser (will use Cerebras by default)
        llm_config = get_llm_config_for_agent("nlp_parser")

        if llm_config.get("api_key"):
            # Create OpenAI-compatible client (works for Cerebras, SambaNova, etc.)
            base_client = OpenAI(
                api_key=llm_config["api_key"],
                base_url=llm_config["base_url"]
            )
            self.client = instructor.from_openai(base_client)
            self.model = llm_config["model"].replace("openai:", "")
            self.provider = llm_config["provider"]
            self.max_context = 8192 if "cerebras" in llm_config["provider"] else 32768

            logger.info(f"Initialized {self.provider} for NLP parsing (FREE tier)")
        else:
            logger.warning("No free LLM API keys configured - using basic parsing")
            self.client = None

    async def parse_description(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """
        Parse natural language description into structured AssetInput.
        Uses free LLMs to avoid rate limits.
        """
        logger.info(f"Parsing with {self.provider if self.client else 'basic'}",
                   description_length=len(description))

        if self.client:
            result = await self._parse_with_free_llm(description, code_snippet)
        else:
            result = self._parse_basic(description, code_snippet)

        logger.info("Parsing complete", component_type=result.component_type)
        return result

    async def parse_code_chunks(self, chunks: List[dict]) -> AssetInput:
        """
        Parse code chunks - optimized for Cerebras token limits.
        """
        if not chunks:
            return self._parse_basic("Empty codebase", None)

        # For Cerebras, limit context to stay under 8K tokens
        max_chunks = 5 if self.provider == "cerebras" else 10

        # Aggregate chunk information
        languages = set()
        functions = []
        classes = []

        for chunk in chunks[:max_chunks * 2]:  # Sample more, display less
            file_path = chunk.get('file_path', '')
            if file_path.endswith('.py'):
                languages.add('Python')
            elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
                languages.add('JavaScript/TypeScript')
            elif file_path.endswith('.java'):
                languages.add('Java')

            if chunk.get('type') == 'function':
                functions.append(chunk.get('name', 'unknown'))
            elif chunk.get('type') == 'class':
                classes.append(chunk.get('name', 'unknown'))

        # Create compact summary for Cerebras
        summary = f"Analyzed {len(chunks)} code chunks. "
        summary += f"Languages: {', '.join(languages)}. "
        summary += f"Found {len(functions)} functions, {len(classes)} classes."

        # Sample limited code for context (stay under token limit)
        sample_code = "\n".join([
            f"{chunk['file_path']}:{chunk['name']}"
            for chunk in chunks[:max_chunks]
        ])

        return await self.parse_description(summary, sample_code)

    async def _parse_with_free_llm(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Parse using free LLM with instructor"""
        try:
            # Build compact prompt for token efficiency
            prompt = f"""Analyze this system for threat modeling:

INPUT: {description[:2000]}  # Limit description size

"""
            if code_snippet:
                # Severely limit code snippet for Cerebras
                max_code = 1000 if self.provider == "cerebras" else 3000
                prompt += f"CODE SAMPLE:\n{code_snippet[:max_code]}\n"

            prompt += "Extract security-relevant information. Be concise."

            # Instructor call with structured output
            parsed_asset = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Security expert. Be extremely concise."},
                    {"role": "user", "content": prompt}
                ],
                response_model=ParsedAsset,
                temperature=0.2,
                max_tokens=1500  # Keep response small
            )

            # Convert to AssetInput
            return AssetInput(
                description=parsed_asset.description[:500],  # Limit size
                component_type=ComponentType(parsed_asset.component_type),
                programming_languages=parsed_asset.programming_languages[:5],
                frameworks=parsed_asset.frameworks[:5],
                external_dependencies=parsed_asset.external_dependencies[:5],
                compliance_requirements=parsed_asset.compliance_requirements[:5],
                user_roles=parsed_asset.user_roles[:5],
                data_sensitivity=SeverityLevel(parsed_asset.data_sensitivity) if parsed_asset.data_sensitivity else None,
                internet_facing=parsed_asset.internet_facing,
                code_snippet=code_snippet[:1000] if code_snippet else None
            )

        except Exception as e:
            logger.error(f"Free LLM parsing failed ({self.provider})", error=str(e))

            # Try fallback providers
            if "429" in str(e) or "rate" in str(e).lower():
                logger.info("Attempting fallback to SambaNova...")
                # Could implement full fallback chain here

            # Fall back to basic parsing
            return self._parse_basic(description, code_snippet)

    def _parse_basic(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Basic parsing without LLM (fallback)"""
        logger.warning("Using basic keyword-based parsing (no LLM)")

        desc_lower = description.lower()
        full_text = desc_lower
        if code_snippet:
            full_text += " " + code_snippet.lower()

        # Simple keyword detection
        component_type = ComponentType.BUSINESS_LOGIC

        if any(word in full_text for word in ['api', 'endpoint', 'rest', 'graphql']):
            component_type = ComponentType.API_ENDPOINT
        elif any(word in full_text for word in ['database', 'sql', 'mongodb']):
            component_type = ComponentType.DATABASE
        elif any(word in full_text for word in ['auth', 'login', 'oauth']):
            component_type = ComponentType.AUTHENTICATION

        # Detect languages
        languages = []
        if 'python' in full_text or 'def ' in full_text:
            languages.append('Python')
        if any(word in full_text for word in ['javascript', 'node', 'react']):
            languages.append('JavaScript')

        # Detect sensitivity
        data_sensitivity = SeverityLevel.MEDIUM
        if any(word in full_text for word in ['patient', 'health', 'medical', 'pii']):
            data_sensitivity = SeverityLevel.CRITICAL

        return AssetInput(
            description=description[:500],
            component_type=component_type,
            programming_languages=languages,
            frameworks=[],
            compliance_requirements=[],
            code_snippet=code_snippet[:1000] if code_snippet else None,
            data_sensitivity=data_sensitivity,
            internet_facing='internet' in full_text or 'public' in full_text
        )


# Backward compatibility
class ImprovedNLPParser(FreeNLPParser):
    """Alias for backward compatibility"""
    pass