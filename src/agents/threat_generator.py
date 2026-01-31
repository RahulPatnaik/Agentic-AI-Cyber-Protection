"""
Automated Threat Generator
Generates threats automatically based on DFD structure and component properties
Based on OWASP pytm methodology - STRIDE mapped to OWASP Top 10
"""

from typing import List
import structlog

from src.models.dfd_components import (
    DataFlowDiagram,
    Process,
    DataStore,
    DataFlow,
    ExternalEntity,
    AuthenticationMethod,
    DataClassification
)
from src.models.threats import (
    Vulnerability,
    OWASPCategory,
    SeverityLevel,
    MITRECategory
)
from src.config import Settings

logger = structlog.get_logger()


class AutomatedThreatGenerator:
    """
    Automatically generates threats based on DFD structure.
    This mimics OWASP pytm's threat generation approach.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        logger.info("Initialized Automated Threat Generator")

    def generate_threats(self, dfd: DataFlowDiagram) -> List[Vulnerability]:
        """
        Generate all applicable threats for the DFD.

        Args:
            dfd: Data Flow Diagram

        Returns:
            List of automatically generated vulnerabilities
        """
        threats = []

        # Analyze each component type
        threats.extend(self._analyze_processes(dfd))
        threats.extend(self._analyze_data_stores(dfd))
        threats.extend(self._analyze_data_flows(dfd))
        threats.extend(self._analyze_trust_boundaries(dfd))

        logger.info(f"Generated {len(threats)} threats from DFD analysis")
        return threats

    def _analyze_processes(self, dfd: DataFlowDiagram) -> List[Vulnerability]:
        """Analyze processes for vulnerabilities"""
        vulns = []

        for process in dfd.processes:
            # Check for missing input validation (Injection)
            if not process.sanitizesInput:
                vulns.append(Vulnerability(
                    title=f"Injection Vulnerability in {process.name}",
                    description=f"Process '{process.name}' does not sanitize input, making it vulnerable to injection attacks (SQL, XSS, Command Injection).",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                    cwe_name="SQL Injection",
                    owasp_category=OWASPCategory.A03_INJECTION,
                    mitre_tactic=MITRECategory.INITIAL_ACCESS,
                    attack_vector="Attacker injects malicious code through user input fields",
                    prerequisites=["Process accepts user input", "No input validation implemented"],
                    impact="Complete system compromise, data exfiltration, remote code execution",
                    affected_component=process.name,
                    recommendation="Implement input validation and sanitization using parameterized queries",
                    remediation_steps=[
                        "Use parameterized queries or ORM for database operations",
                        "Implement whitelist-based input validation",
                        "Sanitize all user inputs before processing",
                        "Use prepared statements for SQL queries",
                        "Encode outputs to prevent XSS"
                    ],
                    code_fix_example="""# Before (vulnerable)
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# After (secure)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))""",
                    likelihood="high",
                    risk_score=9.8,
                    exploitability="easy"
                ))

            # Check for missing authentication (Broken Access Control)
            if process.processes_pii and not process.implementsAuthentication:
                vulns.append(Vulnerability(
                    title=f"Missing Authentication in {process.name}",
                    description=f"Process '{process.name}' handles sensitive data (PII) without implementing authentication.",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.1,
                    cwe_id="CWE-287",
                    cwe_name="Improper Authentication",
                    owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                    mitre_tactic=MITRECategory.CREDENTIAL_ACCESS,
                    attack_vector="Unauthenticated access to sensitive data processing",
                    prerequisites=["No authentication mechanism", "Processes sensitive data"],
                    impact="Unauthorized access to sensitive personal information",
                    affected_component=process.name,
                    recommendation="Implement strong authentication mechanism (OAuth, JWT, MFA)",
                    remediation_steps=[
                        "Implement authentication layer (OAuth 2.0, JWT)",
                        "Add authorization checks for all sensitive operations",
                        "Implement multi-factor authentication for high-value operations",
                        "Use secure session management",
                        "Implement rate limiting"
                    ],
                    likelihood="high",
                    risk_score=9.1,
                    exploitability="easy"
                ))

            # Check for missing authorization (Broken Access Control)
            if process.implementsAuthentication and not process.implementsAuthorization:
                vulns.append(Vulnerability(
                    title=f"Missing Authorization in {process.name}",
                    description=f"Process '{process.name}' has authentication but lacks proper authorization checks.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=8.1,
                    cwe_id="CWE-285",
                    cwe_name="Improper Authorization",
                    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                    mitre_tactic=MITRECategory.PRIVILEGE_ESCALATION,
                    attack_vector="Authenticated user can access resources beyond their privileges",
                    prerequisites=["Authentication exists", "No authorization checks"],
                    impact="Privilege escalation, unauthorized data access",
                    affected_component=process.name,
                    recommendation="Implement role-based access control (RBAC)",
                    remediation_steps=[
                        "Implement RBAC or ABAC model",
                        "Check user permissions for every request",
                        "Apply principle of least privilege",
                        "Use access control lists (ACLs)",
                        "Log all access control failures"
                    ],
                    likelihood="high",
                    risk_score=8.1,
                    exploitability="moderate"
                ))

            # Check for missing output encoding (XSS)
            if not process.encodesOutput:
                vulns.append(Vulnerability(
                    title=f"Cross-Site Scripting (XSS) in {process.name}",
                    description=f"Process '{process.name}' does not encode output, potentially allowing XSS attacks.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.2,
                    cwe_id="CWE-79",
                    cwe_name="Cross-site Scripting (XSS)",
                    owasp_category=OWASPCategory.A03_INJECTION,
                    mitre_tactic=MITRECategory.INITIAL_ACCESS,
                    attack_vector="Attacker injects malicious JavaScript through unencoded output",
                    prerequisites=["User-controlled data in output", "No output encoding"],
                    impact="Session hijacking, credential theft, phishing",
                    affected_component=process.name,
                    recommendation="Implement context-aware output encoding",
                    remediation_steps=[
                        "Encode all user-controlled data in HTML context",
                        "Use Content Security Policy (CSP) headers",
                        "Implement HTTP-only cookies for sessions",
                        "Sanitize HTML using a whitelist approach",
                        "Use auto-escaping template engines"
                    ],
                    code_fix_example="""# Before (vulnerable)
return f"<div>Hello {username}</div>"

# After (secure)
from html import escape
return f"<div>Hello {escape(username)}</div>" """,
                    likelihood="medium",
                    risk_score=7.2,
                    exploitability="moderate"
                ))

        return vulns

    def _analyze_data_stores(self, dfd: DataFlowDiagram) -> List[Vulnerability]:
        """Analyze data stores for vulnerabilities"""
        vulns = []

        for store in dfd.data_stores:
            # Check for unencrypted sensitive data (Cryptographic Failures)
            if store.stores_pii and not store.isEncrypted:
                vulns.append(Vulnerability(
                    title=f"Unencrypted Sensitive Data in {store.name}",
                    description=f"DataStore '{store.name}' contains sensitive data (PII) but is not encrypted at rest.",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=8.5,
                    cwe_id="CWE-311",
                    cwe_name="Missing Encryption of Sensitive Data",
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    mitre_tactic=MITRECategory.COLLECTION,
                    attack_vector="Direct database access or backup theft exposes plaintext sensitive data",
                    prerequisites=["Unencrypted data at rest", "Contains PII/sensitive data"],
                    impact="Mass data breach, regulatory violations (GDPR, HIPAA), reputation damage",
                    affected_component=store.name,
                    recommendation="Implement encryption at rest using AES-256",
                    remediation_steps=[
                        "Enable transparent data encryption (TDE) for databases",
                        "Use AES-256 encryption for sensitive columns",
                        "Implement proper key management (KMS)",
                        "Encrypt database backups",
                        "Use encrypted file systems for file storage"
                    ],
                    likelihood="medium",
                    risk_score=8.5,
                    exploitability="moderate"
                ))

            # Check for missing access controls
            if not store.hasAccessControl:
                vulns.append(Vulnerability(
                    title=f"Missing Access Control on {store.name}",
                    description=f"DataStore '{store.name}' lacks access control mechanisms.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.5,
                    cwe_id="CWE-284",
                    cwe_name="Improper Access Control",
                    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                    mitre_tactic=MITRECategory.PRIVILEGE_ESCALATION,
                    attack_vector="Unauthorized access to database or storage",
                    prerequisites=["No access control", "Direct database access possible"],
                    impact="Unauthorized data access, modification, or deletion",
                    affected_component=store.name,
                    recommendation="Implement database-level access controls",
                    remediation_steps=[
                        "Use principle of least privilege for database accounts",
                        "Implement role-based database access",
                        "Use separate accounts for different services",
                        "Restrict network access to database",
                        "Enable audit logging for all access"
                    ],
                    likelihood="medium",
                    risk_score=7.5,
                    exploitability="moderate"
                ))

        return vulns

    def _analyze_data_flows(self, dfd: DataFlowDiagram) -> List[Vulnerability]:
        """Analyze data flows for vulnerabilities"""
        vulns = []

        for flow in dfd.data_flows:
            # Check for unencrypted sensitive data in transit
            if (flow.carries_pii or flow.carries_credentials) and not flow.isEncrypted:
                vulns.append(Vulnerability(
                    title=f"Unencrypted Sensitive Data in Transit: {flow.name}",
                    description=f"DataFlow '{flow.name}' carries sensitive data (credentials/PII) without encryption.",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.1,
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    mitre_tactic=MITRECategory.CREDENTIAL_ACCESS,
                    attack_vector="Man-in-the-Middle attack to intercept sensitive data",
                    prerequisites=["Unencrypted communication channel", "Sensitive data transmission"],
                    impact="Credential theft, session hijacking, data interception",
                    affected_component=flow.name,
                    recommendation="Implement TLS 1.3 for all sensitive data transmission",
                    remediation_steps=[
                        "Use TLS 1.3 for all communications",
                        "Disable weak cipher suites",
                        "Implement certificate pinning",
                        "Use HSTS headers",
                        "Enforce HTTPS redirects"
                    ],
                    code_fix_example="""# Before (vulnerable)
conn = http.client.HTTPConnection("api.example.com")

# After (secure)
conn = http.client.HTTPSConnection("api.example.com")""",
                    likelihood="high",
                    risk_score=9.1,
                    exploitability="easy"
                ))

            # Check for missing authentication on sensitive flows
            if flow.carries_pii and flow.authentication == AuthenticationMethod.NONE:
                vulns.append(Vulnerability(
                    title=f"Unauthenticated Access: {flow.name}",
                    description=f"DataFlow '{flow.name}' carries sensitive data without authentication.",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=8.6,
                    cwe_id="CWE-306",
                    cwe_name="Missing Authentication for Critical Function",
                    owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                    mitre_tactic=MITRECategory.INITIAL_ACCESS,
                    attack_vector="Unauthenticated access to sensitive data endpoints",
                    prerequisites=["No authentication mechanism", "Sensitive data exposed"],
                    impact="Unauthorized access to sensitive information",
                    affected_component=flow.name,
                    recommendation="Implement authentication for all sensitive endpoints",
                    remediation_steps=[
                        "Require authentication for all API endpoints handling PII",
                        "Implement JWT or OAuth 2.0 tokens",
                        "Add API key validation",
                        "Use mutual TLS for service-to-service communication",
                        "Implement rate limiting"
                    ],
                    likelihood="high",
                    risk_score=8.6,
                    exploitability="easy"
                ))

        return vulns

    def _analyze_trust_boundaries(self, dfd: DataFlowDiagram) -> List[Vulnerability]:
        """Analyze trust boundary crossings for vulnerabilities"""
        vulns = []

        crossing_flows = dfd.get_flows_crossing_boundaries()

        for flow, boundary in crossing_flows:
            # Check for unprotected boundary crossings
            if not boundary.has_firewall:
                vulns.append(Vulnerability(
                    title=f"Unprotected Trust Boundary: {boundary.name}",
                    description=f"Trust boundary '{boundary.name}' lacks firewall protection.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.8,
                    cwe_id="CWE-16",
                    cwe_name="Configuration",
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    mitre_tactic=MITRECategory.INITIAL_ACCESS,
                    attack_vector="Direct network access across trust boundaries",
                    prerequisites=["No firewall", "Trust boundary exists"],
                    impact="Unauthorized network access, lateral movement",
                    affected_component=boundary.name,
                    recommendation="Implement firewall and network segmentation",
                    remediation_steps=[
                        "Deploy firewall at trust boundary",
                        "Implement network segmentation",
                        "Use least privilege network access",
                        "Enable IDS/IPS monitoring",
                        "Implement WAF for web applications"
                    ],
                    likelihood="medium",
                    risk_score=7.8,
                    exploitability="moderate"
                ))

            # Check for sensitive data crossing boundaries without encryption
            if flow.carries_pii and not flow.isEncrypted:
                vulns.append(Vulnerability(
                    title=f"Sensitive Data Crosses Boundary Unencrypted: {boundary.name}",
                    description=f"Sensitive data crosses trust boundary '{boundary.name}' without encryption.",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.3,
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    mitre_tactic=MITRECategory.COLLECTION,
                    attack_vector="Network interception at trust boundary",
                    prerequisites=["Unencrypted transmission", "Trust boundary crossing"],
                    impact="Data interception, man-in-the-middle attacks",
                    affected_component=f"{flow.name} crossing {boundary.name}",
                    recommendation="Encrypt all data crossing trust boundaries",
                    remediation_steps=[
                        "Use TLS 1.3 for all boundary crossings",
                        "Implement VPN for sensitive internal communications",
                        "Use IPSec for network-level encryption",
                        "Implement mutual TLS authentication",
                        "Monitor encrypted traffic for anomalies"
                    ],
                    likelihood="high",
                    risk_score=9.3,
                    exploitability="easy"
                ))

        return vulns
