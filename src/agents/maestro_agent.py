"""
MAESTRO Security Principles Validator Agent
Validates system design against MAESTRO security principles
"""

from pydantic_ai import Agent, RunContext
from typing import List, Dict
import structlog

from src.models.threats import (
    AssetInput,
    AgentAnalysis,
    Vulnerability
)
from src.config import Settings

logger = structlog.get_logger()


# Define the MAESTRO Validator Agent
maestro_agent = Agent(
    'mistral:mistral-large-latest',
    system_prompt="""You are an expert security architect specializing in MAESTRO security principles validation.

MAESTRO Security Principles:

M - Minimize Attack Surface
    - Reduce exposed functionality
    - Disable unnecessary features
    - Remove unused code and dependencies
    - Principle of least functionality

A - Authentication & Authorization
    - Strong authentication mechanisms
    - Proper authorization checks
    - Role-based access control (RBAC)
    - Principle of least privilege

E - Establish Secure Defaults
    - Secure-by-default configuration
    - Fail securely
    - No default credentials
    - Security should not rely on obscurity

S - Separation of Duties
    - Segregate critical functions
    - Multi-person authorization for sensitive operations
    - Prevent single points of failure
    - Isolate security-critical components

T - Trust But Verify
    - Validate all inputs
    - Never trust external data
    - Verify assumptions and constraints
    - Defense in depth

R - Resilience and Recovery
    - Graceful error handling
    - System availability and redundancy
    - Backup and recovery mechanisms
    - Fail-safe defaults

O - Observability and Monitoring
    - Comprehensive logging
    - Real-time security monitoring
    - Audit trails
    - Anomaly detection

Your role:
1. Evaluate system design against each MAESTRO principle
2. Identify principle violations
3. Assess severity of violations
4. Provide concrete recommendations for compliance
5. Prioritize fixes by security impact

Return detailed MAESTRO validation report with actionable recommendations.
"""
)


class MAESTROValidator:
    """MAESTRO Security Principles Validator"""

    def __init__(self, settings: Settings):
        self.settings = settings
        logger.info("Initialized MAESTRO Validator Agent")

    async def analyze(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> AgentAnalysis:
        """
        Validate system against MAESTRO security principles.

        Args:
            asset: Structured asset input
            vulnerabilities: List of identified vulnerabilities

        Returns:
            AgentAnalysis with MAESTRO validation results
        """
        logger.info("Starting MAESTRO validation")

        # Build MAESTRO validation prompt
        prompt = self._build_maestro_prompt(asset, vulnerabilities)

        try:
            # Run the agent
            result = await maestro_agent.run(prompt)
            analysis = result.data

            # Generate MAESTRO analysis
            maestro_analysis = self._generate_maestro_analysis(asset, vulnerabilities)

            return AgentAnalysis(
                agent_name="MAESTRO Validator",
                agent_type="maestro",
                findings=analysis.findings if hasattr(analysis, 'findings') else list(maestro_analysis.keys()),
                vulnerabilities_found=[],  # MAESTRO doesn't find new vulns
                confidence=0.88,
                reasoning=analysis.reasoning if hasattr(analysis, 'reasoning') else "MAESTRO validation complete",
                maestro_analysis=maestro_analysis
            )

        except Exception as e:
            logger.error("MAESTRO validation failed", error=str(e))
            return AgentAnalysis(
                agent_name="MAESTRO Validator",
                agent_type="maestro",
                findings=[f"Analysis failed: {str(e)}"],
                vulnerabilities_found=[],
                confidence=0.0,
                reasoning="Analysis encountered an error"
            )

    def _build_maestro_prompt(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Build MAESTRO validation prompt"""

        prompt = f"""Validate the following system against MAESTRO security principles:

SYSTEM DESCRIPTION:
{asset.description}

SYSTEM CHARACTERISTICS:
- Component Type: {asset.component_type.value if asset.component_type else 'unknown'}
- Programming Languages: {', '.join(asset.programming_languages)}
- Frameworks: {', '.join(asset.frameworks)}
- External Dependencies: {', '.join(asset.external_dependencies)}
- Internet Facing: {'Yes' if asset.internet_facing else 'No'}
- Data Sensitivity: {asset.data_sensitivity.value if asset.data_sensitivity else 'unknown'}
- User Roles: {', '.join(asset.user_roles)}

IDENTIFIED VULNERABILITIES:
"""

        for i, vuln in enumerate(vulnerabilities[:5], 1):  # Top 5 vulnerabilities
            prompt += f"""
{i}. {vuln.title}
   - Severity: {vuln.severity.value}
   - CWE: {vuln.cwe_id}
   - Impact: {vuln.impact}
"""

        prompt += """
VALIDATION REQUIRED:

For each MAESTRO principle (M-A-E-S-T-R-O):

1. **Compliance Status** (compliant/partial/non-compliant)
2. **Violations Found** (list specific violations)
3. **Severity** (critical/high/medium/low)
4. **Evidence** (what indicates the violation)
5. **Recommendations** (how to achieve compliance)
6. **Priority** (1-5, where 1 is highest priority)

Provide a comprehensive MAESTRO validation report.
"""

        return prompt

    def _generate_maestro_analysis(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> Dict[str, str]:
        """Generate MAESTRO principle analysis"""

        analysis = {}

        # M: Minimize Attack Surface
        analysis["M - Minimize Attack Surface"] = self._validate_minimize_attack_surface(asset, vulnerabilities)

        # A: Authentication & Authorization
        analysis["A - Authentication & Authorization"] = self._validate_authentication(asset, vulnerabilities)

        # E: Establish Secure Defaults
        analysis["E - Establish Secure Defaults"] = self._validate_secure_defaults(asset, vulnerabilities)

        # S: Separation of Duties
        analysis["S - Separation of Duties"] = self._validate_separation_of_duties(asset, vulnerabilities)

        # T: Trust But Verify
        analysis["T - Trust But Verify"] = self._validate_trust_but_verify(asset, vulnerabilities)

        # R: Resilience and Recovery
        analysis["R - Resilience and Recovery"] = self._validate_resilience(asset, vulnerabilities)

        # O: Observability and Monitoring
        analysis["O - Observability and Monitoring"] = self._validate_observability(asset, vulnerabilities)

        return analysis

    def _validate_minimize_attack_surface(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Minimize Attack Surface principle"""

        issues = []

        # Check for unnecessary exposed functionality
        if asset.internet_facing:
            issues.append("System is internet-facing, increasing attack surface")

        # Check for admin/debug endpoints
        if any('admin' in str(asset.description).lower() or 'debug' in str(asset.description).lower()):
            issues.append("Potential admin/debug endpoints exposed")

        # Check for misconfiguration vulnerabilities
        misconfig_vulns = [v for v in vulnerabilities if 'misconfiguration' in v.title.lower() or 'configuration' in v.title.lower()]
        if misconfig_vulns:
            issues.append(f"Found {len(misconfig_vulns)} misconfiguration vulnerabilities")

        if issues:
            return f"⚠️ NON-COMPLIANT - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Disable unnecessary features\n- Remove debug/admin endpoints in production\n- Implement network segmentation\n- Use API gateways to control access"
        else:
            return "✓ COMPLIANT - Attack surface appears minimized"

    def _validate_authentication(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Authentication & Authorization principle"""

        issues = []

        # Check for authentication/authorization vulnerabilities
        auth_vulns = [v for v in vulnerabilities if 'auth' in v.title.lower() or 'access control' in v.title.lower()]
        if auth_vulns:
            issues.append(f"Found {len(auth_vulns)} authentication/authorization vulnerabilities")

        # Check if authentication component
        if asset.component_type == 'authentication':
            issues.append("Authentication component requires extra scrutiny")

        # Check for weak password vulnerabilities
        if any('password' in v.title.lower() for v in vulnerabilities):
            issues.append("Weak password policy detected")

        if issues:
            return f"⚠️ NON-COMPLIANT - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Implement strong authentication (MFA)\n- Use RBAC for authorization\n- Enforce principle of least privilege\n- Regular access reviews\n- Strong password policies"
        else:
            return "✓ COMPLIANT - Authentication and authorization appear properly implemented"

    def _validate_secure_defaults(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Establish Secure Defaults principle"""

        issues = []

        # Check for default credential issues
        if any('default' in v.title.lower() or 'credential' in v.title.lower() for v in vulnerabilities):
            issues.append("Default credentials or insecure defaults detected")

        # Check for misconfiguration
        if any('misconfiguration' in v.title.lower() for v in vulnerabilities):
            issues.append("Security misconfiguration suggests insecure defaults")

        if issues:
            return f"⚠️ NON-COMPLIANT - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Remove default credentials\n- Secure-by-default configuration\n- Fail securely on errors\n- Force configuration review on setup"
        else:
            return "✓ COMPLIANT - Secure defaults appear to be established"

    def _validate_separation_of_duties(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Separation of Duties principle"""

        issues = []

        # Check for privilege escalation
        if any('privilege' in v.title.lower() or 'escalation' in v.title.lower() for v in vulnerabilities):
            issues.append("Privilege escalation vulnerability indicates insufficient separation")

        # Check if multiple roles defined
        if len(asset.user_roles) <= 1:
            issues.append("Single or no user roles defined - may lack separation of duties")

        if issues:
            return f"⚠️ PARTIAL COMPLIANCE - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Implement multiple user roles\n- Segregate critical functions\n- Require dual authorization for sensitive operations\n- Isolate security-critical components"
        else:
            return "✓ COMPLIANT - Separation of duties appears implemented"

    def _validate_trust_but_verify(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Trust But Verify principle"""

        issues = []

        # Check for injection vulnerabilities (lack of input validation)
        injection_vulns = [v for v in vulnerabilities if 'injection' in v.title.lower()]
        if injection_vulns:
            issues.append(f"Found {len(injection_vulns)} injection vulnerabilities - untrusted input not validated")

        # Check for XSS (output encoding issues)
        if any('xss' in v.title.lower() or 'cross-site' in v.title.lower() for v in vulnerabilities):
            issues.append("XSS vulnerability indicates insufficient input/output validation")

        # Check for deserialization issues
        if any('deserialization' in v.title.lower() for v in vulnerabilities):
            issues.append("Deserialization vulnerability - untrusted data trusted")

        if issues:
            return f"⚠️ NON-COMPLIANT - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Validate ALL inputs (whitelisting)\n- Sanitize outputs\n- Use parameterized queries\n- Implement defense in depth\n- Never trust external data"
        else:
            return "✓ COMPLIANT - Input validation and verification appear implemented"

    def _validate_resilience(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Resilience and Recovery principle"""

        issues = []

        # Check for availability issues
        if any('denial' in v.title.lower() or 'dos' in v.title.lower() for v in vulnerabilities):
            issues.append("DoS vulnerability indicates insufficient resilience")

        # Check for error handling issues
        if any('error' in v.title.lower() or 'exception' in v.title.lower() for v in vulnerabilities):
            issues.append("Error handling issues may affect resilience")

        if issues:
            return f"⚠️ PARTIAL COMPLIANCE - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Implement graceful error handling\n- Add redundancy and failover\n- Implement rate limiting\n- Add circuit breakers\n- Regular backup and recovery testing"
        else:
            return "✓ COMPLIANT - Resilience mechanisms appear adequate"

    def _validate_observability(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Validate Observability and Monitoring principle"""

        issues = []

        # Check for logging/monitoring vulnerabilities
        logging_vulns = [v for v in vulnerabilities if 'logging' in v.title.lower() or 'monitoring' in v.title.lower()]
        if logging_vulns:
            issues.append(f"Found {len(logging_vulns)} logging/monitoring vulnerabilities")

        # High sensitivity data requires strong monitoring
        if asset.data_sensitivity in ['high', 'critical']:
            issues.append("High sensitivity data requires comprehensive monitoring")

        if issues:
            return f"⚠️ NON-COMPLIANT - {len(issues)} issues: " + "; ".join(issues) + "\n\nRecommendations:\n- Implement comprehensive logging\n- Add security event monitoring\n- Create audit trails\n- Implement anomaly detection\n- Real-time alerting for security events"
        else:
            return "✓ COMPLIANT - Observability and monitoring appear adequate"
