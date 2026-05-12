"""
OWASP Top 10 Analyzer Agent
Uses Pydantic AI with Mistral to identify OWASP vulnerabilities
"""

from pydantic_ai import Agent, RunContext
from pydantic import BaseModel, Field
from typing import List, Optional
import structlog

from src.models.threats import (
    AssetInput,
    AgentAnalysis,
    Vulnerability,
    OWASPCategory,
    SeverityLevel,
    MITRECategory
)
from src.config import Settings

logger = structlog.get_logger()


# Structured output model for LLM response
class VulnerabilityFinding(BaseModel):
    """Single vulnerability finding from LLM"""
    title: str = Field(description="Vulnerability title")
    description: str = Field(description="Detailed description")
    severity: str = Field(description="critical/high/medium/low")
    cvss_score: float = Field(description="CVSS score 0.0-10.0")
    cwe_id: str = Field(description="CWE ID (e.g., CWE-89)")
    cwe_name: str = Field(description="CWE name")
    owasp_category: str = Field(description="OWASP category (e.g., A03_INJECTION)")
    attack_vector: str = Field(description="How the attack works")
    prerequisites: List[str] = Field(description="What conditions enable this vulnerability")
    impact: str = Field(description="What happens if exploited")
    affected_component: str = Field(description="Which component is affected")
    recommendation: str = Field(description="High-level fix recommendation")
    remediation_steps: List[str] = Field(description="Specific actionable steps to fix")
    likelihood: str = Field(description="low/medium/high")
    exploitability: str = Field(description="easy/moderate/difficult")


class OWASPAnalysisResult(BaseModel):
    """Complete OWASP analysis from LLM"""
    vulnerabilities: List[VulnerabilityFinding] = Field(description="List of vulnerabilities found")
    summary: str = Field(description="Overall analysis summary")
    risk_assessment: str = Field(description="Overall risk level")


# Define the OWASP Analyzer Agent with structured output
owasp_agent = Agent(
    'mistral:mistral-large-latest',
    output_type=OWASPAnalysisResult,  # 🔥 STRUCTURED OUTPUT
    system_prompt="""You are an expert OWASP security analyst specializing in OWASP Top 10 2021 vulnerability detection AND OWASP LLM Top 10 for AI/agentic systems.

Your role:
1. Analyze system/feature descriptions for OWASP Top 10 vulnerabilities
2. Identify specific weaknesses with CWE mappings
3. Assess severity and likelihood
4. Provide detailed remediation recommendations
5. **For AI/agentic systems: detect prompt injection, tool misuse, MCP vulnerabilities, and agent-specific threats**

OWASP Top 10 2021 Categories (use these exact strings for owasp_category):
- A01_BROKEN_ACCESS_CONTROL
- A02_CRYPTOGRAPHIC_FAILURES
- A03_INJECTION (also applies to prompt injection!)
- A04_INSECURE_DESIGN
- A05_SECURITY_MISCONFIGURATION
- A06_VULNERABLE_COMPONENTS
- A07_AUTH_FAILURES
- A08_DATA_INTEGRITY_FAILURES
- A09_LOGGING_FAILURES
- A10_SSRF

**OWASP LLM Top 10 2023 (for AI/agentic systems):**
When analyzing AI agents, LLM endpoints, MCP servers, or agentic components, ALSO consider:
- **LLM01: Prompt Injection** - Direct/indirect manipulation of agent instructions
- **LLM02: Insecure Output Handling** - Unvalidated agent outputs used in dangerous contexts
- **LLM03: Supply Chain** - Malicious MCP servers, compromised packages
- **LLM06: Sensitive Information Disclosure** - Agents leaking credentials, PII, secrets
- **LLM07: Insecure Plugin Design** - MCP tools without proper security controls
- **LLM08: Excessive Agency** - Agents with too much autonomy/tool access
- **LLM09: Overreliance** - Agents trusted without validation

**AI/Agentic System Vulnerabilities to Check:**
- Prompt injection vulnerabilities (user input influencing agent behavior)
- Missing input validation on prompts
- Tool misuse (filesystem, database, code execution tools without restrictions)
- MCP security issues (authentication, parameter injection, response poisoning)
- Agent goal hijacking risks
- Context poisoning vulnerabilities
- Multi-agent coordination attack vectors
- Recursive delegation exploits

Guidelines:
- Focus on the most critical vulnerabilities (severity: high/critical)
- Map each vulnerability to specific CWE IDs (format: CWE-89, CWE-79, etc.)
- **For agentic systems, use CWE-94 (Code Injection) for prompt injection, CWE-732 for tool permission issues**
- Provide concrete, actionable remediation steps
- Consider the component type and context
- **If component is AI agent, LLM endpoint, MCP server, or tool integration - prioritize agentic threats**
- Return 5-10 most critical vulnerabilities

IMPORTANT: Return a structured OWASPAnalysisResult with vulnerabilities list.
"""
)


class OWASPAnalyzer:
    """OWASP Top 10 Vulnerability Analyzer"""

    def __init__(self, settings: Settings):
        self.settings = settings
        logger.info("Initialized OWASP Analyzer Agent")

    async def analyze(self, asset: AssetInput) -> AgentAnalysis:
        """
        Analyze an asset for OWASP Top 10 vulnerabilities.

        Args:
            asset: Structured asset input from NLP parser

        Returns:
            AgentAnalysis with OWASP vulnerability findings
        """
        logger.info("Starting OWASP analysis", component_type=asset.component_type)

        # Build detailed prompt for Mistral
        prompt = self._build_analysis_prompt(asset)

        try:
            # Run the agent - NOW WITH STRUCTURED OUTPUT! 🔥
            result = await owasp_agent.run(prompt)

            # Extract structured data (Pydantic AI returns OWASPAnalysisResult)
            llm_analysis: OWASPAnalysisResult = result.output

            # Convert LLM findings to Vulnerability objects
            vulnerabilities = []
            for finding in llm_analysis.vulnerabilities:
                # Map string severity to SeverityLevel enum
                severity_map = {
                    'critical': SeverityLevel.CRITICAL,
                    'high': SeverityLevel.HIGH,
                    'medium': SeverityLevel.MEDIUM,
                    'low': SeverityLevel.LOW
                }
                severity = severity_map.get(finding.severity.lower(), SeverityLevel.MEDIUM)

                # Map OWASP category string to enum
                owasp_map = {
                    'A01_BROKEN_ACCESS_CONTROL': OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                    'A02_CRYPTOGRAPHIC_FAILURES': OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    'A03_INJECTION': OWASPCategory.A03_INJECTION,
                    'A04_INSECURE_DESIGN': OWASPCategory.A04_INSECURE_DESIGN,
                    'A05_SECURITY_MISCONFIGURATION': OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    'A06_VULNERABLE_COMPONENTS': OWASPCategory.A06_VULNERABLE_COMPONENTS,
                    'A07_AUTH_FAILURES': OWASPCategory.A07_AUTH_FAILURES,
                    'A08_DATA_INTEGRITY_FAILURES': OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                    'A09_LOGGING_FAILURES': OWASPCategory.A09_LOGGING_FAILURES,
                    'A10_SSRF': OWASPCategory.A10_SSRF
                }
                owasp_category = owasp_map.get(finding.owasp_category, OWASPCategory.A04_INSECURE_DESIGN)

                # Calculate risk score
                likelihood_score = {'low': 0.3, 'medium': 0.6, 'high': 0.9}.get(finding.likelihood.lower(), 0.5)
                risk_score = finding.cvss_score * likelihood_score

                vuln = Vulnerability(
                    title=finding.title,
                    description=finding.description,
                    severity=severity,
                    cvss_score=finding.cvss_score,
                    cwe_id=finding.cwe_id,
                    cwe_name=finding.cwe_name,
                    owasp_category=owasp_category,
                    mitre_tactic=MITRECategory.INITIAL_ACCESS,  # Could be enhanced
                    attack_vector=finding.attack_vector,
                    prerequisites=finding.prerequisites,
                    impact=finding.impact,
                    affected_component=finding.affected_component,
                    recommendation=finding.recommendation,
                    remediation_steps=finding.remediation_steps,
                    code_fix_example=None,  # LLM can provide this if needed
                    likelihood=finding.likelihood,
                    risk_score=risk_score,
                    exploitability=finding.exploitability
                )
                vulnerabilities.append(vuln)

            findings = [
                f"Analyzed {asset.component_type.value if asset.component_type else 'system'} for OWASP Top 10 vulnerabilities",
                f"Found {len(vulnerabilities)} vulnerabilities using LLM analysis",
                f"Risk Assessment: {llm_analysis.risk_assessment}",
                f"Summary: {llm_analysis.summary}"
            ]

            logger.info(
                "OWASP analysis complete",
                vulnerabilities_found=len(vulnerabilities),
                using_llm=True
            )

            return AgentAnalysis(
                agent_name="OWASP Analyzer",
                agent_type="owasp",
                findings=findings,
                vulnerabilities_found=vulnerabilities,
                confidence=0.95,  # Higher confidence with actual LLM analysis
                reasoning=llm_analysis.summary
            )

        except Exception as e:
            logger.error("OWASP analysis failed, using fallback patterns", error=str(e))
            # Fallback to pattern-based detection if LLM fails
            fallback_patterns = self._get_vulnerability_patterns(asset)
            fallback_vulns = []
            for pattern in fallback_patterns:
                vuln = Vulnerability(
                    title=pattern['title'],
                    description=pattern['description'],
                    severity=pattern['severity'],
                    cvss_score=pattern['cvss_score'],
                    cwe_id=pattern['cwe_id'],
                    cwe_name=pattern['cwe_name'],
                    owasp_category=pattern['owasp_category'],
                    mitre_tactic=pattern.get('mitre_tactic'),
                    attack_vector=pattern['attack_vector'],
                    prerequisites=pattern['prerequisites'],
                    impact=pattern['impact'],
                    affected_component=str(asset.component_type.value if asset.component_type else 'system'),
                    recommendation=pattern['recommendation'],
                    remediation_steps=pattern['remediation_steps'],
                    code_fix_example=pattern.get('code_fix_example'),
                    likelihood=pattern['likelihood'],
                    risk_score=pattern['risk_score'],
                    exploitability=pattern['exploitability']
                )
                fallback_vulns.append(vuln)

            logger.info(
                "Using fallback pattern detection",
                vulnerabilities_found=len(fallback_vulns),
                using_llm=False
            )

            return AgentAnalysis(
                agent_name="OWASP Analyzer",
                agent_type="owasp",
                findings=[
                    f"LLM analysis failed: {str(e)}",
                    f"Using pattern-based detection as fallback",
                    f"Found {len(fallback_vulns)} potential vulnerabilities"
                ],
                vulnerabilities_found=fallback_vulns,
                confidence=0.6,  # Lower confidence for fallback
                reasoning=f"Pattern-based detection (LLM error: {str(e)})"
            )

    def _build_analysis_prompt(self, asset: AssetInput) -> str:
        """Build detailed analysis prompt for Mistral"""

        prompt = f"""Analyze the following system/feature for OWASP Top 10 2021 vulnerabilities:

DESCRIPTION:
{asset.description}

COMPONENT TYPE: {asset.component_type.value if asset.component_type else 'unknown'}
PROGRAMMING LANGUAGES: {', '.join(asset.programming_languages) if asset.programming_languages else 'not specified'}
FRAMEWORKS: {', '.join(asset.frameworks) if asset.frameworks else 'not specified'}
EXTERNAL DEPENDENCIES: {', '.join(asset.external_dependencies) if asset.external_dependencies else 'none'}
INTERNET FACING: {'Yes' if asset.internet_facing else 'No'}
DATA SENSITIVITY: {asset.data_sensitivity.value if asset.data_sensitivity else 'unknown'}
USER ROLES: {', '.join(asset.user_roles) if asset.user_roles else 'not specified'}
"""

        if asset.code_snippet:
            prompt += f"""
CODE SNIPPET:
```
{asset.code_snippet}
```
"""

        prompt += """
REQUIRED OUTPUT:

For each OWASP Top 10 vulnerability you identify:

1. **Vulnerability Title** (e.g., "SQL Injection in User Login")
2. **OWASP Category** (e.g., A03:2021-Injection)
3. **CWE ID** (e.g., CWE-89)
4. **CWE Name** (e.g., "SQL Injection")
5. **Severity** (critical/high/medium/low)
6. **CVSS Score** (0.0-10.0)
7. **Description** (detailed explanation of the vulnerability)
8. **Attack Vector** (how an attacker would exploit this)
9. **Prerequisites** (what conditions must exist)
10. **Impact** (what happens if exploited)
11. **Affected Component** (specific part of the system)
12. **Likelihood** (low/medium/high)
13. **Risk Score** (0.0-10.0, calculated as likelihood × impact)
14. **Exploitability** (easy/moderate/difficult)
15. **Recommendation** (high-level fix)
16. **Remediation Steps** (specific actionable steps)
17. **Code Fix Example** (if applicable)

Identify the TOP 5-10 most critical vulnerabilities. Focus on those with highest risk scores.
"""

        return prompt

    def _extract_vulnerabilities(self, analysis: AgentAnalysis, asset: AssetInput) -> List[Vulnerability]:
        """
        Extract structured vulnerabilities from agent analysis.

        This method parses the agent's findings and creates structured Vulnerability objects.
        """
        vulnerabilities = []

        # Common OWASP vulnerability patterns based on component type
        vuln_patterns = self._get_vulnerability_patterns(asset)

        for pattern in vuln_patterns:
            vuln = Vulnerability(
                title=pattern['title'],
                description=pattern['description'],
                severity=pattern['severity'],
                cvss_score=pattern['cvss_score'],
                cwe_id=pattern['cwe_id'],
                cwe_name=pattern['cwe_name'],
                owasp_category=pattern['owasp_category'],
                mitre_tactic=pattern.get('mitre_tactic'),
                attack_vector=pattern['attack_vector'],
                prerequisites=pattern['prerequisites'],
                impact=pattern['impact'],
                affected_component=str(asset.component_type.value if asset.component_type else 'system'),
                recommendation=pattern['recommendation'],
                remediation_steps=pattern['remediation_steps'],
                code_fix_example=pattern.get('code_fix_example'),
                likelihood=pattern['likelihood'],
                risk_score=pattern['risk_score'],
                exploitability=pattern['exploitability']
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_vulnerability_patterns(self, asset: AssetInput) -> List[dict]:
        """
        Get common vulnerability patterns based on component type.

        This provides baseline vulnerabilities that are refined by the LLM analysis.
        """
        patterns = []

        # A01: Broken Access Control
        if asset.component_type in ['api_endpoint', 'web_server', 'authentication']:
            patterns.append({
                'title': 'Broken Access Control - Missing Authorization Checks',
                'description': f'The {asset.component_type.value} may lack proper authorization checks, allowing users to access resources beyond their permissions.',
                'severity': SeverityLevel.HIGH,
                'cvss_score': 8.1,
                'cwe_id': 'CWE-285',
                'cwe_name': 'Improper Authorization',
                'owasp_category': OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                'mitre_tactic': MITRECategory.PRIVILEGE_ESCALATION,
                'attack_vector': 'Attacker modifies access control parameters (user IDs, roles) to bypass authorization',
                'prerequisites': ['User authentication exists', 'No proper authorization checks'],
                'impact': 'Unauthorized access to sensitive data or functionality',
                'recommendation': 'Implement proper authorization checks on all endpoints',
                'remediation_steps': [
                    'Implement role-based access control (RBAC)',
                    'Validate user permissions for every request',
                    'Use principle of least privilege',
                    'Implement access control lists (ACLs)',
                    'Log all access control failures'
                ],
                'code_fix_example': '''# Before (vulnerable)
@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    return db.query(User).filter(User.id == user_id).first()

# After (secure)
@app.get("/api/users/{user_id}")
def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    return db.query(User).filter(User.id == user_id).first()
''',
                'likelihood': 'high',
                'risk_score': 8.1,
                'exploitability': 'easy'
            })

        # A03: Injection
        if asset.component_type in ['api_endpoint', 'database', 'user_input']:
            if 'SQL' in str(asset.description).upper() or asset.component_type == 'database':
                patterns.append({
                    'title': 'SQL Injection Vulnerability',
                    'description': 'User input may be directly concatenated into SQL queries without proper sanitization or parameterization.',
                    'severity': SeverityLevel.CRITICAL,
                    'cvss_score': 9.8,
                    'cwe_id': 'CWE-89',
                    'cwe_name': 'SQL Injection',
                    'owasp_category': OWASPCategory.A03_INJECTION,
                    'mitre_tactic': MITRECategory.INITIAL_ACCESS,
                    'attack_vector': 'Attacker injects malicious SQL code through user input fields',
                    'prerequisites': ['Direct SQL query construction', 'Unsanitized user input'],
                    'impact': 'Complete database compromise, data exfiltration, data modification',
                    'recommendation': 'Use parameterized queries or ORM',
                    'remediation_steps': [
                        'Use parameterized queries (prepared statements)',
                        'Use ORM frameworks (SQLAlchemy, Django ORM)',
                        'Validate and sanitize all user inputs',
                        'Apply principle of least privilege to database accounts',
                        'Implement input validation with whitelisting'
                    ],
                    'code_fix_example': '''# Before (vulnerable)
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
result = db.execute(query)

# After (secure)
query = "SELECT * FROM users WHERE username=? AND password=?"
result = db.execute(query, (username, password))
''',
                    'likelihood': 'high',
                    'risk_score': 9.8,
                    'exploitability': 'easy'
                })

        # A02: Cryptographic Failures
        if asset.component_type in ['authentication', 'data_store'] or asset.data_sensitivity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            patterns.append({
                'title': 'Weak Cryptography - Insufficient Data Protection',
                'description': 'Sensitive data may not be properly encrypted at rest or in transit, or may use weak cryptographic algorithms.',
                'severity': SeverityLevel.HIGH,
                'cvss_score': 7.5,
                'cwe_id': 'CWE-327',
                'cwe_name': 'Use of Broken or Risky Cryptographic Algorithm',
                'owasp_category': OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                'mitre_tactic': MITRECategory.CREDENTIAL_ACCESS,
                'attack_vector': 'Attacker intercepts or accesses unencrypted sensitive data',
                'prerequisites': ['Weak or no encryption', 'Sensitive data exposure'],
                'impact': 'Exposure of sensitive data (credentials, PII, financial data)',
                'recommendation': 'Implement strong encryption for data at rest and in transit',
                'remediation_steps': [
                    'Use TLS 1.3 for data in transit',
                    'Use AES-256 for data at rest',
                    'Store passwords with bcrypt/Argon2',
                    'Implement proper key management',
                    'Avoid deprecated algorithms (MD5, SHA1, DES)'
                ],
                'code_fix_example': '''# Before (vulnerable)
password_hash = hashlib.md5(password.encode()).hexdigest()

# After (secure)
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
''',
                'likelihood': 'medium',
                'risk_score': 7.5,
                'exploitability': 'moderate'
            })

        # A07: Authentication Failures
        if asset.component_type == 'authentication':
            patterns.append({
                'title': 'Weak Authentication - Insufficient Password Policy',
                'description': 'Authentication mechanism may lack proper controls such as rate limiting, password complexity, or multi-factor authentication.',
                'severity': SeverityLevel.HIGH,
                'cvss_score': 8.0,
                'cwe_id': 'CWE-521',
                'cwe_name': 'Weak Password Requirements',
                'owasp_category': OWASPCategory.A07_AUTH_FAILURES,
                'mitre_tactic': MITRECategory.CREDENTIAL_ACCESS,
                'attack_vector': 'Attacker performs brute force or credential stuffing attacks',
                'prerequisites': ['Weak password policy', 'No rate limiting', 'No MFA'],
                'impact': 'Account takeover, unauthorized access',
                'recommendation': 'Implement strong authentication controls',
                'remediation_steps': [
                    'Enforce strong password policy (length, complexity)',
                    'Implement rate limiting and account lockout',
                    'Add multi-factor authentication (MFA)',
                    'Implement CAPTCHA for login forms',
                    'Monitor for credential stuffing attacks',
                    'Use secure session management'
                ],
                'likelihood': 'high',
                'risk_score': 8.0,
                'exploitability': 'easy'
            })

        # A05: Security Misconfiguration
        if asset.internet_facing:
            patterns.append({
                'title': 'Security Misconfiguration - Exposed Sensitive Endpoints',
                'description': 'System may expose administrative interfaces, debug endpoints, or sensitive configuration to the internet.',
                'severity': SeverityLevel.HIGH,
                'cvss_score': 7.5,
                'cwe_id': 'CWE-16',
                'cwe_name': 'Configuration',
                'owasp_category': OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                'mitre_tactic': MITRECategory.INITIAL_ACCESS,
                'attack_vector': 'Attacker discovers and exploits misconfigured endpoints',
                'prerequisites': ['Internet-facing system', 'Inadequate hardening'],
                'impact': 'Information disclosure, unauthorized access',
                'recommendation': 'Harden system configuration and minimize attack surface',
                'remediation_steps': [
                    'Disable debug/admin endpoints in production',
                    'Remove default credentials',
                    'Implement proper error handling (no stack traces)',
                    'Use security headers (CSP, HSTS, X-Frame-Options)',
                    'Regular security configuration reviews',
                    'Principle of least privilege for services'
                ],
                'likelihood': 'medium',
                'risk_score': 7.5,
                'exploitability': 'moderate'
            })

        return patterns[:10]  # Return top 10 most relevant patterns
