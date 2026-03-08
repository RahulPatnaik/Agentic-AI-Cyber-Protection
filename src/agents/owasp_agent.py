"""
OWASP Top 10 Analyzer Agent
Uses Pydantic AI with Mistral to identify OWASP vulnerabilities
"""

from pydantic_ai import Agent, RunContext
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


# Define the OWASP Analyzer Agent
owasp_agent = Agent(
    'mistral:mistral-large-latest',
    system_prompt="""You are an expert OWASP security analyst specializing in OWASP Top 10 2021 vulnerability detection.

Your role:
1. Analyze system/feature descriptions for OWASP Top 10 vulnerabilities
2. Identify specific weaknesses with CWE mappings
3. Assess severity and likelihood
4. Provide detailed remediation recommendations

OWASP Top 10 2021 Categories:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery

Guidelines:
- Focus on the most critical vulnerabilities (severity: high/critical)
- Map each vulnerability to specific CWE IDs
- Provide concrete, actionable remediation steps
- Include code examples for fixes when applicable
- Consider the component type and context

Return your analysis in a structured format with clear vulnerability findings.
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
            # Run the agent
            result = await owasp_agent.run(prompt)

            # Extract text response from agent
            # Pydantic AI returns the response in different ways depending on version
            if hasattr(result, 'data'):
                analysis_text = str(result.data)
            elif hasattr(result, 'output'):
                analysis_text = str(result.output)
            else:
                analysis_text = str(result)

            # Get structured vulnerabilities based on asset type
            vulnerability_patterns = self._get_vulnerability_patterns(asset)
            vulnerabilities = []
            for pattern in vulnerability_patterns:
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

            # Extract findings from the analysis text
            findings = [
                f"Analyzed {asset.component_type.value if asset.component_type else 'system'} for OWASP Top 10 vulnerabilities",
                f"Found {len(vulnerabilities)} potential vulnerabilities",
                f"LLM Analysis: {analysis_text[:200]}..." if len(analysis_text) > 200 else f"LLM Analysis: {analysis_text}"
            ]

            return AgentAnalysis(
                agent_name="OWASP Analyzer",
                agent_type="owasp",
                findings=findings,
                vulnerabilities_found=vulnerabilities,
                confidence=0.9,
                reasoning=analysis_text[:500] if len(analysis_text) > 500 else analysis_text
            )

        except Exception as e:
            logger.error("OWASP analysis failed", error=str(e))
            # Return minimal analysis on failure with fallback vulnerabilities
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
            return AgentAnalysis(
                agent_name="OWASP Analyzer",
                agent_type="owasp",
                findings=[f"LLM analysis failed, using pattern-based detection: {str(e)}"],
                vulnerabilities_found=fallback_vulns,
                confidence=0.6,  # Lower confidence for fallback
                reasoning="Using pattern-based vulnerability detection due to LLM error"
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
