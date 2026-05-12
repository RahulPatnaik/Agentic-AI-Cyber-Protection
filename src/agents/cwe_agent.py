"""
CWE (Common Weakness Enumeration) Analyzer Agent
Maps vulnerabilities to CWE database with detailed mitigation strategies
"""

from pydantic_ai import Agent, RunContext
from pydantic import BaseModel, Field
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


# Structured output models for LLM
class CWEMapping(BaseModel):
    """Single CWE mapping from LLM"""
    vulnerability_title: str = Field(description="Original vulnerability title")
    cwe_id: str = Field(description="CWE ID (e.g., CWE-89)")
    cwe_name: str = Field(description="Official CWE name")
    root_cause: str = Field(description="Why this weakness exists")
    maestro_violations: List[str] = Field(description="MAESTRO principles violated")
    mitigation_strategies: List[str] = Field(description="Specific mitigation steps")


class CWEAnalysisResult(BaseModel):
    """Complete CWE analysis from LLM"""
    cwe_mappings: List[CWEMapping] = Field(description="List of CWE mappings")
    summary: str = Field(description="Overall CWE analysis summary")


# Define the CWE Analyzer Agent with structured output
cwe_agent = Agent(
    'mistral:mistral-small-latest',
    output_type=CWEAnalysisResult,  # 🔥 STRUCTURED OUTPUT
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
            # Run the agent with structured output 🔥
            result = await cwe_agent.run(prompt)

            # Extract structured data from LLM
            llm_result: CWEAnalysisResult = result.output

            # Update vulnerabilities with enhanced CWE info from LLM
            for mapping in llm_result.cwe_mappings:
                # Find matching vulnerability
                for vuln in vulnerabilities:
                    if vuln.title == mapping.vulnerability_title:
                        # Clean CWE ID - extract just "CWE-XXX" part
                        # LLM might return "CWE-89: SQL Injection", we only want "CWE-89"
                        cwe_id_clean = mapping.cwe_id.split(':')[0].strip() if ':' in mapping.cwe_id else mapping.cwe_id

                        # Update CWE info with LLM analysis
                        vuln.cwe_id = cwe_id_clean
                        vuln.cwe_name = mapping.cwe_name
                        # Enhance remediation steps with LLM suggestions
                        vuln.remediation_steps.extend(mapping.mitigation_strategies)
                        break

            logger.info(
                "CWE analysis complete using LLM",
                cwe_mappings=len(llm_result.cwe_mappings),
                using_llm=True
            )

            return AgentAnalysis(
                agent_name="CWE Analyzer",
                agent_type="cwe_analyzer",
                findings=[
                    f"Mapped {len(llm_result.cwe_mappings)} vulnerabilities to CWE database using LLM",
                    "Identified root cause weaknesses",
                    "Generated enhanced mitigation strategies",
                    f"Summary: {llm_result.summary}"
                ],
                vulnerabilities_found=[],  # CWE agent doesn't find new vulns
                confidence=0.95,  # Higher confidence with LLM
                reasoning=llm_result.summary
            )

        except Exception as e:
            logger.error("CWE analysis failed, using fallback", error=str(e))
            # Fallback to rule-based CWE mapping
            cwe_references = self._generate_cwe_references(asset, vulnerabilities)
            logger.info(
                "Using fallback CWE database mapping",
                cwe_mappings=len(vulnerabilities),
                using_llm=False
            )
            return AgentAnalysis(
                agent_name="CWE Analyzer",
                agent_type="cwe_analyzer",
                findings=[
                    f"LLM failed: {str(e)}",
                    f"Using CWE database: {len(vulnerabilities)} mapped",
                    "Fallback to rule-based CWE mapping"
                ],
                vulnerabilities_found=[],
                confidence=0.75,
                reasoning=f"Direct CWE database mapping (LLM error: {str(e)})"
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
            # Clean and normalize CWE ID - extract just "CWE-XXX" part
            # Handle cases like "CWE-89: SQL Injection", "CWEs-798", "CW-319", or "Cwe-89"
            cwe_id_raw = vuln.cwe_id.split(':')[0].strip() if ':' in vuln.cwe_id else vuln.cwe_id

            # Remove any quotes or special characters that shouldn't be there
            cwe_id_raw = cwe_id_raw.replace('"', '').replace("'", '').strip()

            # Skip empty or whitespace-only CWE IDs
            if not cwe_id_raw or cwe_id_raw.isspace():
                logger.warning(f"Skipping vulnerability with empty CWE ID: '{vuln.title}'")
                continue

            # Convert to uppercase for consistent handling
            cwe_id_raw = cwe_id_raw.upper()

            # Fix common typos
            if cwe_id_raw.startswith('CW-'):
                # CW-319 -> CWE-319
                cwe_id_raw = 'CWE-' + cwe_id_raw[3:]
            elif cwe_id_raw.startswith('CWES-'):
                # CWEs-798 -> CWE-798
                cwe_id_raw = 'CWE-' + cwe_id_raw[5:]
            elif not cwe_id_raw.startswith('CWE-'):
                # CWE89 -> CWE-89
                cwe_id_raw = cwe_id_raw.replace('CWE', 'CWE-')

            # Extract just the CWE-XXX part using regex
            import re
            match = re.match(r'(CWE-\d+)', cwe_id_raw)
            if match:
                cwe_id_clean = match.group(1)
            else:
                # If no valid CWE pattern found, skip this vulnerability
                logger.warning(f"Invalid CWE ID format: '{vuln.cwe_id}' (normalized to '{cwe_id_raw}')")
                continue

            # Get CWE details from database
            cwe_details = self.cwe_database.get(cwe_id_clean, {})

            try:
                # Validate CWE ID format
                if not cwe_id_clean or not cwe_id_clean.startswith('CWE-'):
                    logger.warning(f"Invalid CWE ID format: {vuln.cwe_id}, skipping")
                    continue

                cwe_ref = CWEReference(
                    cwe_id=cwe_id_clean,
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
                        f"https://cwe.mitre.org/data/definitions/{cwe_id_clean.split('-')[1]}.html",
                        f"OWASP: {vuln.owasp_category.value}"
                    ]
                )
                cwe_refs.append(cwe_ref)
            except Exception as e:
                logger.error(f"Failed to create CWE reference for {vuln.cwe_id}: {e}")
                continue

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
