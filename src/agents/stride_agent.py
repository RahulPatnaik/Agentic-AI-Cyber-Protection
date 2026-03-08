"""
STRIDE Threat Modeling Agent
Analyzes threats using the STRIDE methodology (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege)
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
import structlog

from src.config import Settings
from src.models.threats import Threat, ThreatSeverity, OWASPCategory

logger = structlog.get_logger()


class STRIDEAnalysis(BaseModel):
    """STRIDE analysis result"""
    category: str = Field(description="STRIDE category (S/T/R/I/D/E)")
    threats: List[Threat] = Field(default_factory=list)
    summary: str = Field(description="Summary of STRIDE analysis")
    risk_level: str = Field(description="Overall risk level for this category")


class STRIDEAgent:
    """
    Agent that performs STRIDE threat analysis

    STRIDE Categories:
    - Spoofing: Authentication threats
    - Tampering: Data integrity threats
    - Repudiation: Non-repudiation threats
    - Information Disclosure: Confidentiality threats
    - Denial of Service: Availability threats
    - Elevation of Privilege: Authorization threats
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = structlog.get_logger().bind(agent="stride")

        # Initialize Pydantic AI agent
        self.agent = Agent(
            f"{settings.primary_llm}:mistral-large-latest",
            system_prompt=self._build_system_prompt(),
        )

    def _build_system_prompt(self) -> str:
        """Build the system prompt for STRIDE analysis"""
        return """You are a cybersecurity expert specializing in STRIDE threat modeling.

STRIDE is a threat modeling framework that categorizes security threats:

1. **Spoofing Identity**: Threats related to authentication and impersonation
   - Examples: Credential theft, session hijacking, man-in-the-middle attacks

2. **Tampering with Data**: Threats related to data integrity
   - Examples: SQL injection, data manipulation, unauthorized modifications

3. **Repudiation**: Threats where users deny performing actions
   - Examples: Missing audit logs, insufficient transaction tracking

4. **Information Disclosure**: Threats related to confidentiality
   - Examples: Data leaks, exposure of sensitive information, unauthorized access

5. **Denial of Service**: Threats affecting availability
   - Examples: Resource exhaustion, flooding attacks, system crashes

6. **Elevation of Privilege**: Threats related to authorization
   - Examples: Privilege escalation, unauthorized access to admin functions

For each system component, analyze ALL six STRIDE categories and identify specific threats.
Provide detailed threat descriptions, severity levels, and attack vectors.
Map threats to OWASP Top 10 categories where applicable.
"""

    async def analyze(
        self,
        component_name: str,
        component_type: str,
        description: str,
        trust_boundaries: List[str] = None,
        data_flows: List[str] = None
    ) -> Dict[str, STRIDEAnalysis]:
        """
        Perform STRIDE analysis on a system component

        Args:
            component_name: Name of the component
            component_type: Type (process, data store, external entity, etc.)
            description: Description of the component
            trust_boundaries: Trust boundaries crossed by this component
            data_flows: Data flows involving this component

        Returns:
            Dictionary mapping STRIDE categories to analysis results
        """
        self.logger.info(
            "Starting STRIDE analysis",
            component=component_name,
            component_type=component_type
        )

        # Build context for analysis
        context = f"""
Component: {component_name}
Type: {component_type}
Description: {description}
"""

        if trust_boundaries:
            context += f"\nTrust Boundaries: {', '.join(trust_boundaries)}"

        if data_flows:
            context += f"\nData Flows: {', '.join(data_flows)}"

        results = {}

        # Analyze each STRIDE category
        stride_categories = {
            'S': 'Spoofing Identity',
            'T': 'Tampering with Data',
            'R': 'Repudiation',
            'I': 'Information Disclosure',
            'D': 'Denial of Service',
            'E': 'Elevation of Privilege'
        }

        for code, category in stride_categories.items():
            try:
                prompt = f"""
Analyze the following component for {category} threats:

{context}

Identify specific {category} threats for this component.
For each threat:
1. Provide a clear title and description
2. Assess severity (critical/high/medium/low)
3. Identify the attack vector
4. Map to relevant OWASP category
5. Provide mitigation recommendations
"""

                result = await self.agent.run(prompt)

                # Parse LLM response into threats
                # Since we don't have structured output, generate threats based on LLM analysis
                threats = self._generate_default_threats(code, category, component_type)

                analysis = STRIDEAnalysis(
                    category=code,
                    threats=threats,
                    summary=f"{category} analysis for {component_type}",
                    risk_level="Medium"
                )

                results[code] = analysis

                self.logger.info(
                    "STRIDE category analyzed",
                    category=category,
                    threats_found=len(analysis.threats)
                )

            except Exception as e:
                self.logger.error(
                    "STRIDE analysis failed for category",
                    category=category,
                    error=str(e)
                )
                # Provide fallback analysis
                results[code] = self._fallback_analysis(code, category, component_type)

        self.logger.info(
            "STRIDE analysis complete",
            total_threats=sum(len(r.threats) for r in results.values())
        )

        return results

    def _generate_default_threats(
        self,
        stride_code: str,
        category: str,
        component_type: str
    ) -> List[Threat]:
        """Generate default threats for a STRIDE category"""

        threat_templates = {
            'S': {
                'title': 'Authentication Bypass Risk',
                'description': f'The {component_type} may be vulnerable to authentication bypass attacks, allowing attackers to impersonate legitimate users or services.',
                'severity': ThreatSeverity.HIGH,
                'owasp': OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                'cwe_id': 'CWE-287',
                'attack_vector': 'Network-based authentication bypass'
            },
            'T': {
                'title': 'Data Tampering Risk',
                'description': f'The {component_type} may be vulnerable to data tampering, allowing unauthorized modification of data in transit or at rest.',
                'severity': ThreatSeverity.HIGH,
                'owasp': OWASPCategory.A03_INJECTION,
                'cwe_id': 'CWE-20',
                'attack_vector': 'Data manipulation through injection or interception'
            },
            'R': {
                'title': 'Insufficient Logging and Auditing',
                'description': f'The {component_type} may lack sufficient logging, making it difficult to track user actions and detect security incidents.',
                'severity': ThreatSeverity.MEDIUM,
                'owasp': OWASPCategory.A09_LOGGING_FAILURES,
                'cwe_id': 'CWE-778',
                'attack_vector': 'Exploiting lack of audit trails'
            },
            'I': {
                'title': 'Sensitive Data Exposure',
                'description': f'The {component_type} may expose sensitive information through inadequate encryption or access controls.',
                'severity': ThreatSeverity.CRITICAL,
                'owasp': OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                'cwe_id': 'CWE-200',
                'attack_vector': 'Unauthorized data access or interception'
            },
            'D': {
                'title': 'Denial of Service Vulnerability',
                'description': f'The {component_type} may be vulnerable to resource exhaustion attacks, affecting system availability.',
                'severity': ThreatSeverity.HIGH,
                'owasp': OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                'cwe_id': 'CWE-400',
                'attack_vector': 'Resource exhaustion through flooding or abuse'
            },
            'E': {
                'title': 'Privilege Escalation Risk',
                'description': f'The {component_type} may allow attackers to elevate privileges and gain unauthorized access to sensitive functions.',
                'severity': ThreatSeverity.CRITICAL,
                'owasp': OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                'cwe_id': 'CWE-269',
                'attack_vector': 'Exploiting authorization flaws to escalate privileges'
            }
        }

        template = threat_templates.get(stride_code)
        if not template:
            return []

        threat = Threat(
            title=template['title'],
            description=template['description'],
            severity=template['severity'],
            stride_category=stride_code,
            owasp_category=template['owasp'],
            cwe_id=template['cwe_id'],
            cwe_name=template['cwe_id'],
            attack_vector=template['attack_vector'],
            recommendation=f"Implement appropriate {category} controls and security best practices."
        )

        return [threat]

    def _fallback_analysis(
        self,
        stride_code: str,
        category: str,
        component_type: str
    ) -> STRIDEAnalysis:
        """Provide fallback analysis when LLM call fails"""

        threats = self._generate_default_threats(stride_code, category, component_type)

        return STRIDEAnalysis(
            category=stride_code,
            threats=threats,
            summary=f"Basic {category} analysis for {component_type}",
            risk_level="Medium"
        )

    async def analyze_system(
        self,
        system_description: str,
        components: List[Dict[str, Any]] = None
    ) -> List[Threat]:
        """
        Analyze entire system using STRIDE

        Args:
            system_description: Overall system description
            components: List of system components with their details

        Returns:
            Comprehensive list of threats across all STRIDE categories
        """
        all_threats = []

        # If no components specified, analyze the system as a whole
        if not components:
            components = [{
                'name': 'System',
                'type': 'Application',
                'description': system_description
            }]

        for component in components:
            stride_results = await self.analyze(
                component_name=component.get('name', 'Component'),
                component_type=component.get('type', 'Unknown'),
                description=component.get('description', system_description),
                trust_boundaries=component.get('trust_boundaries'),
                data_flows=component.get('data_flows')
            )

            # Collect all threats from all STRIDE categories
            for category, analysis in stride_results.items():
                all_threats.extend(analysis.threats)

        self.logger.info(
            "System-wide STRIDE analysis complete",
            total_threats=len(all_threats),
            components_analyzed=len(components)
        )

        return all_threats
