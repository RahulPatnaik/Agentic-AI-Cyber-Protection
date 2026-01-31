"""
Natural Language Parser for Threat Modeling
Converts user descriptions into structured AssetInput using Mistral AI
"""

from mistralai import Mistral
from typing import Optional
import json
import structlog

from src.models.threats import AssetInput, ComponentType, SeverityLevel
from src.config import Settings

logger = structlog.get_logger()


class NLPParser:
    """Parses natural language descriptions into structured threat model inputs using Mistral AI"""

    def __init__(self, settings: Settings):
        self.settings = settings

        if settings.mistral_api_key:
            self.mistral_client = Mistral(api_key=settings.mistral_api_key)
            self.model = "mistral-large-latest"
        else:
            logger.warning("No Mistral API key configured - using basic parsing")
            self.mistral_client = None

    async def parse_description(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """
        Parse natural language description into structured AssetInput.

        Args:
            description: User's natural language description of the system/feature/client requirement
            code_snippet: Optional code snippet to analyze

        Returns:
            Structured AssetInput for threat modeling
        """
        logger.info("Parsing user input with Mistral AI", description_length=len(description))

        prompt = self._build_parsing_prompt(description, code_snippet)

        if self.mistral_client:
            result = await self._parse_with_mistral(prompt)
        else:
            # Fallback: basic parsing
            result = self._parse_basic(description, code_snippet)

        logger.info("Parsing complete", component_type=result.component_type)
        return result

    def _build_parsing_prompt(self, description: str, code_snippet: Optional[str] = None) -> str:
        """Build prompt for Mistral AI to extract structured information"""

        prompt = f"""You are a cybersecurity expert analyzing a system/feature/client requirement for threat modeling using OWASP Top 10, CWE, and MAESTRO principles.

USER INPUT:
{description}

"""

        if code_snippet:
            prompt += f"""CODE PROVIDED:
```
{code_snippet}
```

"""

        prompt += """Analyze this and extract security-relevant information. Return ONLY valid JSON (no markdown formatting, no code blocks, just raw JSON):

{
  "description": "clear technical summary of what this system/feature does",
  "component_type": "one of: web_server, database, api_endpoint, authentication, data_store, external_service, user_input, business_logic, network_boundary",
  "programming_languages": ["list", "detected", "languages"],
  "frameworks": ["list", "of", "frameworks"],
  "external_dependencies": ["third-party", "services", "apis"],
  "compliance_requirements": ["HIPAA", "FDA", "NIST", "GDPR", etc.],
  "user_roles": ["admin", "user", "guest", etc.],
  "data_sensitivity": "none/low/medium/high/critical",
  "internet_facing": true/false
}

Return ONLY the JSON - nothing before or after it."""

        return prompt

    async def _parse_with_mistral(self, prompt: str) -> AssetInput:
        """Parse using Mistral AI"""
        try:
            messages = [
                {"role": "system", "content": "You are a security expert. Return only valid JSON with no markdown formatting."},
                {"role": "user", "content": prompt}
            ]

            response = self.mistral_client.chat.complete(
                model=self.model,
                messages=messages,
                temperature=0.3,
                max_tokens=2000
            )

            result_text = response.choices[0].message.content.strip()

            # Clean any markdown if Mistral adds it despite instructions
            if result_text.startswith("```json"):
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif result_text.startswith("```"):
                result_text = result_text.split("```")[1].split("```")[0].strip()

            # Remove any leading/trailing text
            start_idx = result_text.find('{')
            end_idx = result_text.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                result_text = result_text[start_idx:end_idx]

            data = json.loads(result_text)

            # Convert to AssetInput
            return AssetInput(
                description=data.get("description", ""),
                component_type=ComponentType(data.get("component_type", "business_logic")),
                programming_languages=data.get("programming_languages", []),
                frameworks=data.get("frameworks", []),
                external_dependencies=data.get("external_dependencies", []),
                compliance_requirements=data.get("compliance_requirements", []),
                user_roles=data.get("user_roles", []),
                data_sensitivity=SeverityLevel(data.get("data_sensitivity", "medium")) if data.get("data_sensitivity") else None,
                internet_facing=data.get("internet_facing", False)
            )

        except json.JSONDecodeError as e:
            logger.error("Mistral returned invalid JSON", error=str(e), response=result_text[:200])
            # Fall back to basic parsing
            return self._parse_basic(prompt.split("USER INPUT:")[1].split("\n")[0], None)

        except Exception as e:
            logger.error("Mistral parsing failed", error=str(e))
            raise

    def _parse_basic(self, description: str, code_snippet: Optional[str] = None) -> AssetInput:
        """Basic parsing without LLM (fallback)"""
        logger.warning("Using basic keyword-based parsing (no Mistral AI)")

        desc_lower = description.lower()

        # Simple keyword detection for component type
        component_type = ComponentType.BUSINESS_LOGIC

        if any(word in desc_lower for word in ['api', 'endpoint', 'rest', 'graphql', 'webhook']):
            component_type = ComponentType.API_ENDPOINT
        elif any(word in desc_lower for word in ['database', 'sql', 'mongodb', 'postgres', 'mysql', 'redis']):
            component_type = ComponentType.DATABASE
        elif any(word in desc_lower for word in ['auth', 'login', 'oauth', 'jwt', 'password', 'credential']):
            component_type = ComponentType.AUTHENTICATION
        elif any(word in desc_lower for word in ['server', 'nginx', 'apache', 'web server']):
            component_type = ComponentType.WEB_SERVER
        elif any(word in desc_lower for word in ['user input', 'form', 'upload', 'file upload']):
            component_type = ComponentType.USER_INPUT

        # Detect programming languages
        languages = []
        if 'python' in desc_lower:
            languages.append('Python')
        if 'javascript' in desc_lower or 'node' in desc_lower or 'react' in desc_lower:
            languages.append('JavaScript')
        if 'java' in desc_lower and 'javascript' not in desc_lower:
            languages.append('Java')
        if 'php' in desc_lower:
            languages.append('PHP')
        if 'ruby' in desc_lower:
            languages.append('Ruby')
        if 'go' in desc_lower or 'golang' in desc_lower:
            languages.append('Go')

        # Detect frameworks
        frameworks = []
        if 'django' in desc_lower:
            frameworks.append('Django')
        if 'flask' in desc_lower:
            frameworks.append('Flask')
        if 'react' in desc_lower:
            frameworks.append('React')
        if 'angular' in desc_lower:
            frameworks.append('Angular')
        if 'vue' in desc_lower:
            frameworks.append('Vue.js')
        if 'spring' in desc_lower:
            frameworks.append('Spring')

        # Detect compliance
        compliance = []
        if 'hipaa' in desc_lower:
            compliance.append('HIPAA')
        if 'fda' in desc_lower:
            compliance.append('FDA')
        if 'nist' in desc_lower:
            compliance.append('NIST')
        if 'gdpr' in desc_lower:
            compliance.append('GDPR')
        if 'pci' in desc_lower:
            compliance.append('PCI-DSS')

        # Detect sensitivity
        data_sensitivity = SeverityLevel.MEDIUM
        if any(word in desc_lower for word in ['patient', 'health', 'medical', 'pii', 'ssn', 'credit card']):
            data_sensitivity = SeverityLevel.CRITICAL
        elif any(word in desc_lower for word in ['personal', 'private', 'confidential']):
            data_sensitivity = SeverityLevel.HIGH
        elif any(word in desc_lower for word in ['public', 'anonymous']):
            data_sensitivity = SeverityLevel.LOW

        return AssetInput(
            description=description,
            component_type=component_type,
            programming_languages=languages,
            frameworks=frameworks,
            compliance_requirements=compliance,
            code_snippet=code_snippet,
            data_sensitivity=data_sensitivity,
            internet_facing='internet' in desc_lower or 'public' in desc_lower or 'external' in desc_lower
        )
