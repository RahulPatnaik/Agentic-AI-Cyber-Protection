"""
CWE (Common Weakness Enumeration) Analyzer Agent
Maps vulnerabilities to CWE database with detailed mitigation strategies
"""

from pydantic_ai import Agent, RunContext
from typing import List, Dict
import structlog

from src.models.threats import (
    AssetInput,
    AgentAnalysis,
    CWEReference,
    Vulnerability,
    OWASPCategory,
    SeverityLevel
)
from src.config import Settings

logger = structlog.get_logger()


# Define the CWE Analyzer Agent
cwe_agent = Agent(
    'mistral:mistral-large-latest',
    system_prompt="""You are an expert CWE (Common Weakness Enumeration) analyst with deep knowledge of software weaknesses.

Your role:
1. Map identified vulnerabilities to specific CWE entries
2. Provide detailed weakness descriptions and contexts
3. Suggest mitigation strategies based on CWE guidance
4. Identify MAESTRO security principle violations
5. Map CWEs to OWASP Top 10 categories

CWE Knowledge:
- 900+ software and hardware weakness types
- Root cause analysis of vulnerabilities
- Language and framework-specific weaknesses
- Architectural and design-level weaknesses

MAESTRO Security Principles:
- M: Minimize attack surface
- A: Authentication & authorization
- E: Establish secure defaults
- S: Separation of duties
- T: Trust but verify
- R: Resilience and recovery
- O: Observability and monitoring

Guidelines:
- Provide specific CWE IDs (e.g., CWE-89, CWE-79)
- Identify root causes, not just symptoms
- Map to appropriate OWASP categories
- Suggest concrete mitigation strategies
- Consider language/framework context

Return comprehensive CWE mappings with actionable guidance.
"""
)


class CWEAnalyzer:
    """CWE Database Analyzer and Mapper"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.cwe_database = self._load_cwe_database()
        logger.info("Initialized CWE Analyzer Agent")

    async def analyze(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> AgentAnalysis:
        """
        Analyze vulnerabilities and map to CWE database.

        Args:
            asset: Structured asset input
            vulnerabilities: List of identified vulnerabilities

        Returns:
            AgentAnalysis with CWE mappings
        """
        logger.info("Starting CWE analysis", vuln_count=len(vulnerabilities))

        # Build CWE analysis prompt
        prompt = self._build_cwe_prompt(asset, vulnerabilities)

        try:
            # Run the agent
            result = await cwe_agent.run(prompt)

            # Extract text response from agent
            if hasattr(result, 'data'):
                analysis_text = str(result.data)
            elif hasattr(result, 'output'):
                analysis_text = str(result.output)
            else:
                analysis_text = str(result)

            # Generate CWE references
            cwe_references = self._generate_cwe_references(asset, vulnerabilities)

            return AgentAnalysis(
                agent_name="CWE Analyzer",
                agent_type="cwe_analyzer",
                findings=[
                    f"Mapped {len(vulnerabilities)} vulnerabilities to CWE database",
                    "Identified root cause weaknesses",
                    "Generated mitigation strategies"
                ],
                vulnerabilities_found=[],  # CWE agent doesn't find new vulns
                confidence=0.90,
                reasoning=analysis_text[:500] if len(analysis_text) > 500 else analysis_text
            )

        except Exception as e:
            logger.error("CWE analysis failed", error=str(e))
            # Still generate CWE references using rule-based method
            cwe_references = self._generate_cwe_references(asset, vulnerabilities)
            return AgentAnalysis(
                agent_name="CWE Analyzer",
                agent_type="cwe_analyzer",
                findings=[f"LLM failed, using CWE database: {len(vulnerabilities)} mapped"],
                vulnerabilities_found=[],
                confidence=0.85,
                reasoning="Using direct CWE database mapping"
            )

    def _build_cwe_prompt(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Build CWE analysis prompt"""

        prompt = f"""Map the following vulnerabilities to CWE (Common Weakness Enumeration) entries:

SYSTEM CONTEXT:
Component: {asset.component_type.value if asset.component_type else 'unknown'}
Languages: {', '.join(asset.programming_languages)}
Frameworks: {', '.join(asset.frameworks)}

VULNERABILITIES TO MAP:
"""

        for i, vuln in enumerate(vulnerabilities, 1):
            prompt += f"""
{i}. {vuln.title}
   - Current CWE: {vuln.cwe_id}
   - Description: {vuln.description[:200]}...
   - Attack Vector: {vuln.attack_vector}
"""

        prompt += """
REQUIRED OUTPUT:

For each vulnerability, provide:

1. **Confirmed CWE ID** (verify or correct existing mapping)
2. **CWE Name** (official CWE name)
3. **Root Cause Analysis** (why this weakness exists)
4. **Affected Languages/Frameworks** (which tech stacks are vulnerable)
5. **MAESTRO Violations** (which MAESTRO principles are violated)
6. **Mitigation Strategies** (specific, actionable mitigations)
7. **References** (CWE links, OWASP guidelines, etc.)

Focus on:
- Accurate CWE mapping (use most specific CWE)
- Root cause identification
- Context-aware mitigation strategies
- MAESTRO principle violations
"""

        return prompt

    def _generate_cwe_references(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[CWEReference]:
        """Generate CWE references from vulnerabilities"""

        cwe_refs = []

        for vuln in vulnerabilities:
            # Get CWE details from database
            cwe_details = self.cwe_database.get(vuln.cwe_id, {})

            cwe_ref = CWEReference(
                cwe_id=vuln.cwe_id,
                cwe_name=vuln.cwe_name,
                description=cwe_details.get('description', vuln.description),
                likelihood=vuln.likelihood,
                severity=vuln.severity,
                owasp_mapping=vuln.owasp_category,
                affected_languages=asset.programming_languages,
                affected_frameworks=asset.frameworks,
                maestro_violations=self._identify_maestro_violations(vuln),
                mitigation_strategies=vuln.remediation_steps,
                references=[
                    f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.split('-')[1]}.html",
                    f"OWASP: {vuln.owasp_category.value}"
                ]
            )
            cwe_refs.append(cwe_ref)

        return cwe_refs

    def _identify_maestro_violations(self, vuln: Vulnerability) -> List[str]:
        """Identify which MAESTRO principles are violated"""

        violations = []

        # M: Minimize attack surface
        if any(word in vuln.title.lower() for word in ['exposed', 'unnecessary', 'debug', 'admin']):
            violations.append("Minimize attack surface - Unnecessary functionality exposed")

        # A: Authentication & Authorization
        if any(word in vuln.title.lower() for word in ['access control', 'authorization', 'authentication', 'auth']):
            violations.append("Authentication & Authorization - Improper access controls")

        # E: Establish secure defaults
        if any(word in vuln.title.lower() for word in ['default', 'misconfiguration', 'configuration']):
            violations.append("Establish secure defaults - Insecure default configuration")

        # S: Separation of duties
        if any(word in vuln.title.lower() for word in ['privilege', 'elevation', 'escalation']):
            violations.append("Separation of duties - Insufficient privilege separation")

        # T: Trust but verify
        if any(word in vuln.title.lower() for word in ['injection', 'validation', 'sanitization', 'input']):
            violations.append("Trust but verify - Untrusted input not validated")

        # R: Resilience and recovery
        if any(word in vuln.title.lower() for word in ['denial', 'dos', 'resource', 'availability']):
            violations.append("Resilience and recovery - Inadequate error handling")

        # O: Observability and monitoring
        if any(word in vuln.title.lower() for word in ['logging', 'monitoring', 'audit']):
            violations.append("Observability and monitoring - Insufficient logging/monitoring")

        return violations if violations else ["No specific MAESTRO violations identified"]

    def _load_cwe_database(self) -> Dict[str, dict]:
        """
        Load CWE database (simplified version for MVP).

        In production, this would load from the official CWE XML database.
        """
        return {
            "CWE-89": {
                "name": "SQL Injection",
                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                "abstraction": "Base",
                "likelihood": "high",
                "severity": "critical"
            },
            "CWE-79": {
                "name": "Cross-site Scripting (XSS)",
                "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                "abstraction": "Base",
                "likelihood": "high",
                "severity": "high"
            },
            "CWE-285": {
                "name": "Improper Authorization",
                "description": "The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.",
                "abstraction": "Class",
                "likelihood": "high",
                "severity": "high"
            },
            "CWE-327": {
                "name": "Use of Broken or Risky Cryptographic Algorithm",
                "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
                "abstraction": "Base",
                "likelihood": "medium",
                "severity": "high"
            },
            "CWE-521": {
                "name": "Weak Password Requirements",
                "description": "The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.",
                "abstraction": "Base",
                "likelihood": "high",
                "severity": "high"
            },
            "CWE-16": {
                "name": "Configuration",
                "description": "Weaknesses in this category are typically introduced during the configuration of the software.",
                "abstraction": "Class",
                "likelihood": "medium",
                "severity": "medium"
            },
            "CWE-78": {
                "name": "OS Command Injection",
                "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
                "abstraction": "Base",
                "likelihood": "high",
                "severity": "critical"
            },
            "CWE-22": {
                "name": "Path Traversal",
                "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
                "abstraction": "Base",
                "likelihood": "medium",
                "severity": "high"
            },
            "CWE-352": {
                "name": "Cross-Site Request Forgery (CSRF)",
                "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
                "abstraction": "Base",
                "likelihood": "medium",
                "severity": "high"
            },
            "CWE-502": {
                "name": "Deserialization of Untrusted Data",
                "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
                "abstraction": "Base",
                "likelihood": "medium",
                "severity": "critical"
            },
            "CWE-287": {
                "name": "Improper Authentication",
                "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
                "abstraction": "Class",
                "likelihood": "high",
                "severity": "high"
            },
            "CWE-798": {
                "name": "Use of Hard-coded Credentials",
                "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
                "abstraction": "Base",
                "likelihood": "medium",
                "severity": "critical"
            }
        }
