"""
NLP Parser using Cerebras for ultra-fast, free parsing.
No more rate limits on ingestion!
"""

from typing import Optional, List
import structlog
from pydantic import BaseModel, Field
from cerebras.cloud.sdk import Cerebras
import json
import os
from dotenv import load_dotenv

from src.models.threats import AssetInput, ComponentType, SeverityLevel
from src.config import Settings

# Load .env file to get CEREBRAS_API_KEY
# Try explicit path loading
from pathlib import Path
env_path = Path(__file__).parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)
    logger = structlog.get_logger()
    logger.info(f"Loaded .env from: {env_path}")
else:
    load_dotenv()  # Try standard loading
    logger = structlog.get_logger()
    logger.warning(f".env not found at {env_path}, trying standard load")


class CerebrasFastParser:
    """
    Ultra-fast NLP parser using Cerebras.
    1M tokens/day free, 30 RPM, <1s response times.
    """

    def __init__(self, settings: Settings = None):
        self.settings = settings or Settings()

        # Get Cerebras API key
        api_key = os.getenv("CEREBRAS_API_KEY")

        # Debug logging
        logger.info(f"Checking for CEREBRAS_API_KEY...")
        if api_key:
            logger.info(f"Found CEREBRAS_API_KEY: {api_key[:10]}... (length: {len(api_key)})")
            self.client = Cerebras(api_key=api_key)
            self.model = "llama3.1-8b"  # Fast 8B model from Cerebras
            logger.info("Initialized Cerebras for NLP parsing (FREE, FAST)")
        else:
            # Extra debug - check all env vars
            all_vars = os.environ.keys()
            cerebras_vars = [k for k in all_vars if 'CEREBRAS' in k.upper()]
            logger.warning(f"No CEREBRAS_API_KEY found. Cerebras-related vars: {cerebras_vars}")
            logger.warning("Using basic parsing")
            self.client = None

    async def parse_description(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """
        Parse with Cerebras - FAST and FREE.
        """
        logger.info("Parsing with Cerebras", description_length=len(description))

        # Check if code snippet is provided for tree-sitter analysis
        if code_snippet:
            logger.info(f"Code snippet provided for analysis, length: {len(code_snippet)} characters")

            # Use the REAL tree-sitter CodeChunker
            from src.utils.local_ingestion import CodeChunker
            import tempfile
            import os

            # Create temp file for tree-sitter parsing
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                tmp.write(code_snippet)
                tmp_path = tmp.name

            try:
                # Use the actual tree-sitter chunker
                chunker = CodeChunker()
                chunks = chunker.chunk_file(tmp_path)
                logger.info(f"Tree-sitter chunking complete: {len(chunks)} semantic chunks created")

                # Log chunk types
                chunk_types = {}
                for chunk in chunks:
                    chunk_type = chunk.get('type', 'unknown')
                    chunk_types[chunk_type] = chunk_types.get(chunk_type, 0) + 1
                logger.info(f"Chunk breakdown: {chunk_types}")

            finally:
                # Clean up
                os.unlink(tmp_path)

            # Parse chunks
            return await self.parse_code_chunks(chunks)

        if self.client:
            try:
                result = self._parse_with_cerebras(description, code_snippet)
            except Exception as e:
                logger.error(f"Cerebras parsing failed: {e}")
                result = self._parse_basic(description, code_snippet)
        else:
            result = self._parse_basic(description, code_snippet)

        logger.info("Parsing complete", component_type=result.component_type)
        return result

    def _basic_chunk_code(self, code_snippet: str) -> List[dict]:
        """
        Basic code chunking without tree-sitter.
        Splits code into logical chunks based on simple heuristics.
        """
        chunks = []
        lines = code_snippet.split('\n')

        # Create chunks of roughly 50 lines each
        chunk_size = 50
        for i in range(0, len(lines), chunk_size):
            chunk_lines = lines[i:i + chunk_size]
            chunk_content = '\n'.join(chunk_lines)

            # Try to detect what type of code this is
            chunk_type = 'code'
            if any(keyword in chunk_content.lower() for keyword in ['function', 'def ', 'const ', 'var ']):
                chunk_type = 'function'
            elif any(keyword in chunk_content.lower() for keyword in ['class ', 'interface ', 'struct ']):
                chunk_type = 'class'

            chunks.append({
                'type': chunk_type,
                'content': chunk_content,
                'start_line': i,
                'end_line': min(i + chunk_size, len(lines))
            })

        return chunks

    async def parse_code_chunks(self, chunks: List[dict]) -> AssetInput:
        """
        Parse code chunks - optimized for Cerebras 8K token limit.
        """
        if not chunks:
            return self._parse_basic("Empty codebase", None)

        logger.info(f"Analyzing {len(chunks)} code chunks")

        # For Cerebras, strictly limit to stay under 8K tokens
        # Roughly 1 token = 4 chars, so 8K tokens = ~32K chars
        # But we need room for response, so limit input to ~4K tokens = 16K chars

        # Aggregate basic info
        languages = set()
        functions = []
        classes = []
        files_seen = set()

        for chunk in chunks[:20]:  # Process up to 20 chunks for metadata
            file_path = chunk.get('file_path', '')
            files_seen.add(file_path)

            if file_path.endswith('.py'):
                languages.add('Python')
            elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
                languages.add('JavaScript')
            elif file_path.endswith('.json'):
                languages.add('JSON')

            if chunk.get('type') == 'function':
                functions.append(chunk.get('name', 'unknown'))
            elif chunk.get('type') == 'class':
                classes.append(chunk.get('name', 'unknown'))

        # Log detected files and languages
        logger.info(f"Files detected: {len(files_seen)}")
        logger.info(f"Languages detected: {', '.join(list(languages))}")
        logger.info(f"Functions found: {len(functions)}, Classes found: {len(classes)}")

        # Log sample of files being analyzed
        for file in list(files_seen)[:5]:
            logger.info(f"  - Analyzing file: {file}")

        # Create very concise summary
        summary = f"Codebase: {len(chunks)} chunks from {len(files_seen)} files. "
        summary += f"Languages: {', '.join(list(languages)[:3])}. "
        summary += f"Key components: {', '.join(functions[:5] + classes[:3])}"

        # Sample just file names, not full content (stay under token limit)
        code_context = "Files analyzed:\n"
        for file in list(files_seen)[:10]:
            code_context += f"- {file}\n"

        # Parse the summary and code context directly (don't call parse_description to avoid recursion)
        if self.client:
            try:
                result = self._parse_with_cerebras(summary, code_context)
            except Exception as e:
                logger.error(f"Cerebras parsing failed: {e}")
                result = self._parse_basic(summary, code_context)
        else:
            result = self._parse_basic(summary, code_context)

        logger.info("Code chunk parsing complete", component_type=result.component_type)
        return result

    def _parse_with_cerebras(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """
        Direct Cerebras parsing - no instructor needed.
        """
        # Build compact prompt (must fit in 8K context)
        prompt = f"""You are a security expert. Analyze this system and return ONLY a JSON object.

System: {description[:1500]}

"""
        if code_snippet:
            prompt += f"Code context:\n{code_snippet[:500]}\n\n"

        prompt += """Return JSON with these exact fields:
{
  "component_type": "one of: api_endpoint, database, web_server, authentication, business_logic, data_store",
  "languages": ["list", "of", "languages"],
  "frameworks": ["detected", "frameworks"],
  "compliance": ["GDPR", "PCI-DSS", "HIPAA"] (if applicable),
  "data_sensitivity": "low, medium, high, or critical",
  "internet_facing": true or false,
  "summary": "one sentence description"
}

Return ONLY the JSON, no explanation."""

        try:
            # Call Cerebras
            completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a JSON-only security analyzer. Never explain, only output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                max_completion_tokens=500,  # Keep response small
                temperature=0.2,
                top_p=0.9
            )

            response = completion.choices[0].message.content.strip()

            # Clean response (Cerebras might add markdown)
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]

            # Find JSON in response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                response = response[start:end]

            # Parse JSON
            data = json.loads(response)

            # Map to AssetInput
            component_map = {
                "api_endpoint": ComponentType.API_ENDPOINT,
                "database": ComponentType.DATABASE,
                "web_server": ComponentType.WEB_SERVER,
                "authentication": ComponentType.AUTHENTICATION,
                "business_logic": ComponentType.BUSINESS_LOGIC,
                "data_store": ComponentType.DATA_STORE,
                "external_service": ComponentType.EXTERNAL_SERVICE,
                "user_input": ComponentType.USER_INPUT
            }

            sensitivity_map = {
                "low": SeverityLevel.LOW,
                "medium": SeverityLevel.MEDIUM,
                "high": SeverityLevel.HIGH,
                "critical": SeverityLevel.CRITICAL
            }

            return AssetInput(
                description=data.get("summary", description[:200]),
                component_type=component_map.get(
                    data.get("component_type", "business_logic"),
                    ComponentType.BUSINESS_LOGIC
                ),
                programming_languages=data.get("languages", [])[:5],
                frameworks=data.get("frameworks", [])[:5],
                compliance_requirements=data.get("compliance", []),
                data_sensitivity=sensitivity_map.get(
                    data.get("data_sensitivity", "medium"),
                    SeverityLevel.MEDIUM
                ),
                internet_facing=data.get("internet_facing", False),
                code_snippet=code_snippet[:1000] if code_snippet else None
            )

        except json.JSONDecodeError as e:
            logger.error(f"Cerebras returned invalid JSON: {e}")
            return self._parse_basic(description, code_snippet)
        except Exception as e:
            logger.error(f"Cerebras call failed: {e}")

            # Try fallback to Mistral instead of basic parsing
            if "429" in str(e) or "rate" in str(e).lower():
                logger.info("Cerebras rate limited, trying Mistral fallback")
                return self._parse_with_mistral_fallback(description, code_snippet)

            return self._parse_basic(description, code_snippet)

    def _parse_with_mistral_fallback(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Fallback to Mistral when Cerebras rate limits"""
        try:
            from mistralai import Mistral
            import os

            mistral_key = os.getenv("MISTRAL_API_KEY")
            if not mistral_key:
                logger.warning("No Mistral API key for fallback")
                return self._parse_basic(description, code_snippet)

            client = Mistral(api_key=mistral_key)

            combined = f"System description: {description}\n"
            if code_snippet:
                combined += f"Code context: {code_snippet[:500]}\n"

            prompt = f"""Extract: component_type (api_endpoint|database|authentication|machine_learning|business_logic),
            languages, frameworks, compliance requirements, data_sensitivity (low|medium|high|critical), internet_facing (bool).

            {combined}

            Return ONLY valid JSON."""

            response = client.chat.complete(
                model="mistral-small-latest",  # Use small model for simple extraction
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )

            content = response.choices[0].message.content
            # Extract JSON from response
            import json
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                # Convert to AssetInput (same logic as Cerebras parsing)
                return self._convert_to_asset(data, description, code_snippet)
            else:
                raise ValueError("No JSON found in Mistral response")

        except Exception as e:
            logger.error(f"Mistral fallback also failed: {e}")
            return self._parse_basic(description, code_snippet)

    def _convert_to_asset(self, data: dict, description: str, code_snippet: Optional[str]) -> AssetInput:
        """Convert parsed data to AssetInput"""
        component_map = {
            "api_endpoint": ComponentType.API_ENDPOINT,
            "database": ComponentType.DATABASE,
            "authentication": ComponentType.AUTHENTICATION,
            "machine_learning": ComponentType.MACHINE_LEARNING,
            "business_logic": ComponentType.BUSINESS_LOGIC
        }

        sensitivity_map = {
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL
        }

        return AssetInput(
            description=description[:500],
            component_type=component_map.get(
                data.get("component_type", "business_logic"),
                ComponentType.BUSINESS_LOGIC
            ),
            programming_languages=data.get("languages", [])[:5],
            frameworks=data.get("frameworks", [])[:5],
            compliance_requirements=data.get("compliance", []),
            data_sensitivity=sensitivity_map.get(
                data.get("data_sensitivity", "medium"),
                SeverityLevel.MEDIUM
            ),
            internet_facing=data.get("internet_facing", False),
            code_snippet=code_snippet[:1000] if code_snippet else None
        )

    def _parse_basic(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Basic fallback parsing"""
        logger.warning("Using basic parsing (no LLM)")

        text = (description + " " + (code_snippet or "")).lower()

        # Detect component type - better detection for multimodal systems
        if any(w in text for w in ['multimodal', 'embedding', 'vector', 'audio', 'image', 'video',
                                    'matryoshka', 'chroma', 'chromadb', 'weaviate', 'pinecone',
                                    'qdrant', 'faiss', 'clip', 'llm', 'transformer', 'bert',
                                    'neural', 'rag', 'retrieval', 'semantic', 'similarity']):
            component_type = ComponentType.AI_AGENT
        elif any(w in text for w in ['api', 'endpoint', 'rest', 'fastapi']):
            component_type = ComponentType.API_ENDPOINT
        elif any(w in text for w in ['database', 'sql', 'mongo', 'index', 'storage']):
            component_type = ComponentType.DATABASE
        elif any(w in text for w in ['auth', 'login', 'password', 'jwt']):
            component_type = ComponentType.AUTHENTICATION
        else:
            component_type = ComponentType.BUSINESS_LOGIC

        # Detect languages
        languages = []
        if 'python' in text or '.py' in text:
            languages.append('Python')
        if 'javascript' in text or '.js' in text:
            languages.append('JavaScript')

        # Detect sensitivity and compliance requirements
        compliance_reqs = []
        if any(w in text for w in ['pii', 'health', 'medical', 'patient']):
            sensitivity = SeverityLevel.CRITICAL
            compliance_reqs.extend(['HIPAA', 'GDPR'])
        elif any(w in text for w in ['payment', 'credit', 'card', 'financial']):
            sensitivity = SeverityLevel.CRITICAL
            compliance_reqs.extend(['PCI-DSS', 'GDPR'])
        elif any(w in text for w in ['personal', 'private', 'password', 'user']):
            sensitivity = SeverityLevel.HIGH
            compliance_reqs.append('GDPR')
        else:
            sensitivity = SeverityLevel.MEDIUM
            # Default compliance for any system handling user data
            compliance_reqs.append('GDPR')

        return AssetInput(
            description=description[:200],
            component_type=component_type,
            programming_languages=languages,
            frameworks=[],
            compliance_requirements=compliance_reqs,  # Now includes compliance!
            data_sensitivity=sensitivity,
            internet_facing='public' in text or 'internet' in text,
            code_snippet=code_snippet[:1000] if code_snippet else None
        )


# Backward compatibility
class ImprovedNLPParser(CerebrasFastParser):
    """Alias for backward compatibility"""
    pass

class FreeNLPParser(CerebrasFastParser):
    """Alias for backward compatibility"""
    pass