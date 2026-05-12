"""
Improved Natural Language Parser using Instructor for guaranteed structured output.
Replaces brittle JSON parsing with Pydantic-enforced schema validation.
"""

from mistralai import Mistral
from typing import Optional, List
import instructor
import structlog
from pydantic import BaseModel, Field
from enum import Enum

from src.models.threats import AssetInput, ComponentType, SeverityLevel
from src.config import Settings

logger = structlog.get_logger()


class ParsedAsset(BaseModel):
    """Structured output model for parsed assets - guaranteed by instructor"""
    description: str = Field(..., description="Clear technical summary of what this system/feature does")
    component_type: str = Field(
        ...,
        description="Component type",
        pattern="^(web_server|database|api_endpoint|authentication|data_store|external_service|user_input|business_logic|network_boundary)$"
    )
    programming_languages: List[str] = Field(default_factory=list, description="Detected programming languages")
    frameworks: List[str] = Field(default_factory=list, description="Detected frameworks")
    external_dependencies: List[str] = Field(default_factory=list, description="Third-party services and APIs")
    compliance_requirements: List[str] = Field(default_factory=list, description="Compliance requirements (HIPAA, FDA, NIST, GDPR, etc.)")
    user_roles: List[str] = Field(default_factory=list, description="User roles (admin, user, guest, etc.)")
    data_sensitivity: str = Field("medium", pattern="^(none|low|medium|high|critical)$")
    internet_facing: bool = Field(False, description="Whether the component is internet-facing")


class ImprovedNLPParser:
    """
    Improved NLP parser using instructor for structured output.
    No more JSON parsing errors or markdown stripping needed.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

        if settings.mistral_api_key:
            # Initialize Mistral client with instructor
            base_client = Mistral(api_key=settings.mistral_api_key)
            self.client = instructor.from_mistral(base_client)
            self.model = "mistral-large-latest"
            logger.info("Initialized Mistral with instructor for structured output")
        else:
            logger.warning("No Mistral API key configured - using basic parsing")
            self.client = None

    async def parse_description(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """
        Parse natural language description into structured AssetInput.

        Args:
            description: User's natural language description
            code_snippet: Optional code snippet to analyze

        Returns:
            Structured AssetInput for threat modeling
        """
        logger.info("Parsing user input", description_length=len(description))

        if self.client:
            result = await self._parse_with_instructor(description, code_snippet)
        else:
            # Fallback to basic parsing
            result = self._parse_basic(description, code_snippet)

        logger.info("Parsing complete", component_type=result.component_type)
        return result

    async def parse_code_chunks(self, chunks: List[dict]) -> AssetInput:
        """
        Parse code chunks from tree-sitter into structured AssetInput.

        Args:
            chunks: List of code chunks from tree-sitter

        Returns:
            Structured AssetInput aggregating all chunks
        """
        if not chunks:
            return self._parse_basic("Empty codebase", None)

        # Aggregate chunk information
        languages = set()
        functions = []
        classes = []

        for chunk in chunks:
            # Extract language from file extension
            file_path = chunk.get('file_path', '')
            if file_path.endswith('.py'):
                languages.add('Python')
            elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
                languages.add('JavaScript/TypeScript')
            elif file_path.endswith('.java'):
                languages.add('Java')

            # Collect function and class names
            if chunk.get('type') == 'function':
                functions.append(chunk.get('name', 'unknown'))
            elif chunk.get('type') == 'class':
                classes.append(chunk.get('name', 'unknown'))

        # Create summary for analysis
        summary = f"""
        Codebase Analysis:
        - {len(chunks)} code chunks analyzed
        - Languages: {', '.join(languages) if languages else 'Unknown'}
        - {len(functions)} functions found
        - {len(classes)} classes found
        - Key functions: {', '.join(functions[:10])}
        - Key classes: {', '.join(classes[:10])}
        """

        # Sample content from first few chunks for context
        sample_code = "\n\n".join([
            f"# {chunk['file_path']}:{chunk['name']}\n{chunk['content'][:500]}"
            for chunk in chunks[:5]
        ])

        return await self.parse_description(summary, sample_code)

    async def _parse_with_instructor(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Parse using Mistral with instructor for guaranteed structured output"""
        try:
            # Build the analysis prompt
            prompt = f"""You are a cybersecurity expert analyzing a system/feature for threat modeling using OWASP Top 10, CWE, and security best practices.

USER INPUT:
{description}

"""
            if code_snippet:
                prompt += f"""CODE PROVIDED:
```
{code_snippet[:5000]}  # Limit code size
```

"""
            prompt += """Analyze this and extract security-relevant information. Focus on:
1. What type of component/system this is
2. Technologies and frameworks used
3. Data sensitivity and compliance requirements
4. Security-relevant architectural details
5. Whether it's internet-facing or internal
"""

            # Use instructor to get structured output - no JSON parsing needed!
            # Instructor with Mistral is synchronous, not async
            parsed_asset = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing systems for threat modeling."},
                    {"role": "user", "content": prompt}
                ],
                response_model=ParsedAsset,
                temperature=0.3,
                max_tokens=2000,
                max_retries=3  # Instructor will retry on validation errors
            )

            # Convert to AssetInput
            return AssetInput(
                description=parsed_asset.description,
                component_type=ComponentType(parsed_asset.component_type),
                programming_languages=parsed_asset.programming_languages,
                frameworks=parsed_asset.frameworks,
                external_dependencies=parsed_asset.external_dependencies,
                compliance_requirements=parsed_asset.compliance_requirements,
                user_roles=parsed_asset.user_roles,
                data_sensitivity=SeverityLevel(parsed_asset.data_sensitivity) if parsed_asset.data_sensitivity else None,
                internet_facing=parsed_asset.internet_facing,
                code_snippet=code_snippet
            )

        except Exception as e:
            logger.error("Instructor parsing failed", error=str(e))
            # Fall back to basic parsing
            return self._parse_basic(description, code_snippet)

    def _parse_basic(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Basic parsing without LLM (fallback)"""
        logger.warning("Using basic keyword-based parsing (no AI)")

        desc_lower = description.lower()

        # Combine description and code for analysis
        full_text = desc_lower
        if code_snippet:
            full_text += " " + code_snippet.lower()

        # Simple keyword detection for component type
        component_type = ComponentType.BUSINESS_LOGIC

        if any(word in full_text for word in ['api', 'endpoint', 'rest', 'graphql', 'webhook', 'fastapi', 'flask']):
            component_type = ComponentType.API_ENDPOINT
        elif any(word in full_text for word in ['database', 'sql', 'mongodb', 'postgres', 'mysql', 'redis', 'chromadb']):
            component_type = ComponentType.DATABASE
        elif any(word in full_text for word in ['auth', 'login', 'oauth', 'jwt', 'password', 'credential']):
            component_type = ComponentType.AUTHENTICATION
        elif any(word in full_text for word in ['server', 'nginx', 'apache', 'web server']):
            component_type = ComponentType.WEB_SERVER
        elif any(word in full_text for word in ['user input', 'form', 'upload', 'file upload']):
            component_type = ComponentType.USER_INPUT

        # Detect programming languages
        languages = []
        if 'python' in full_text or 'import' in full_text or 'def ' in full_text:
            languages.append('Python')
        if any(word in full_text for word in ['javascript', 'node', 'react', 'const ', 'let ', 'var ']):
            languages.append('JavaScript')
        if 'java' in full_text and 'javascript' not in full_text:
            languages.append('Java')
        if 'php' in full_text or '<?php' in full_text:
            languages.append('PHP')
        if 'ruby' in full_text:
            languages.append('Ruby')
        if 'go' in full_text or 'golang' in full_text or 'func ' in full_text:
            languages.append('Go')

        # Detect frameworks
        frameworks = []
        framework_map = {
            'django': 'Django',
            'flask': 'Flask',
            'fastapi': 'FastAPI',
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'spring': 'Spring',
            'express': 'Express.js',
            'nextjs': 'Next.js',
            'rails': 'Ruby on Rails'
        }

        for keyword, framework in framework_map.items():
            if keyword in full_text:
                frameworks.append(framework)

        # Detect compliance
        compliance = []
        compliance_keywords = {
            'hipaa': 'HIPAA',
            'fda': 'FDA',
            'nist': 'NIST',
            'gdpr': 'GDPR',
            'pci': 'PCI-DSS',
            'sox': 'SOX',
            'iso27001': 'ISO 27001'
        }

        for keyword, requirement in compliance_keywords.items():
            if keyword in full_text:
                compliance.append(requirement)

        # Detect data sensitivity
        data_sensitivity = SeverityLevel.MEDIUM
        if any(word in full_text for word in ['patient', 'health', 'medical', 'pii', 'ssn', 'credit card', 'payment']):
            data_sensitivity = SeverityLevel.CRITICAL
        elif any(word in full_text for word in ['personal', 'private', 'confidential', 'secret']):
            data_sensitivity = SeverityLevel.HIGH
        elif any(word in full_text for word in ['public', 'anonymous', 'open']):
            data_sensitivity = SeverityLevel.LOW

        # Detect internet facing
        internet_facing = any(word in full_text for word in ['internet', 'public', 'external', 'cloud', 'saas', 'web'])

        return AssetInput(
            description=description[:500],  # Limit description length
            component_type=component_type,
            programming_languages=languages,
            frameworks=frameworks,
            compliance_requirements=compliance,
            code_snippet=code_snippet,
            data_sensitivity=data_sensitivity,
            internet_facing=internet_facing
        )


# Backward compatibility wrapper
class NLPParser(ImprovedNLPParser):
    """Wrapper for backward compatibility with existing code"""
    pass