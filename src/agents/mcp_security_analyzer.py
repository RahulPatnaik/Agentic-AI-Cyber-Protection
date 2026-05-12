"""
MCP Security Analyzer
Audits MCP server configurations and tool permissions for security vulnerabilities
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from enum import Enum
import structlog

from src.models.threats import (
    Vulnerability,
    SeverityLevel,
    OWASPCategory,
    OWASPLLMCategory,
    MCPThreatCategory,
    MITRECategory
)
from src.knowledge.agentic_attack_vectors import get_mcp_specific_attacks
from src.utils.mitigation_strategies import MCP_MITIGATIONS

logger = structlog.get_logger()


class MCPToolRiskLevel(str, Enum):
    """Risk levels for MCP tools"""
    CRITICAL = "critical"  # filesystem_write, code_execution, database_modify
    HIGH = "high"          # filesystem_read, database_query, network_request
    MEDIUM = "medium"      # web_search, text_processing
    LOW = "low"            # calculator, date_time


class MCPSecurityIssue(BaseModel):
    """Security issue found in MCP configuration"""
    issue_type: str
    severity: SeverityLevel
    title: str
    description: str
    affected_component: str
    recommendation: str
    detection_method: str


class MCPToolConfig(BaseModel):
    """Configuration for an MCP tool"""
    tool_name: str
    tool_type: str
    risk_level: MCPToolRiskLevel
    permissions: List[str] = Field(default_factory=list)
    allowed_paths: Optional[List[str]] = None
    blocked_paths: Optional[List[str]] = None
    requires_approval: bool = False
    authentication_required: bool = False
    rate_limit: Optional[int] = None


class MCPServerConfig(BaseModel):
    """Configuration for an MCP server"""
    server_name: str
    server_url: str
    authentication_method: Optional[str] = None
    tls_enabled: bool = False
    certificate_validation: bool = False
    allowed_agents: Optional[List[str]] = None
    tools: List[MCPToolConfig] = Field(default_factory=list)


class MCPSecurityAuditReport(BaseModel):
    """Complete MCP security audit report"""
    server_name: str
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    issues: List[MCPSecurityIssue] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    compliance_status: str
    risk_score: float  # 0-10


class MCPSecurityAnalyzer:
    """Analyzes MCP configurations for security vulnerabilities"""

    # High-risk tools that require strict controls
    HIGH_RISK_TOOLS = {
        'filesystem_write', 'filesystem_delete', 'code_execution', 'shell_command',
        'database_modify', 'database_delete', 'network_request', 'api_call'
    }

    # Sensitive file patterns that should be blocked
    SENSITIVE_FILE_PATTERNS = [
        '.env', '.aws/credentials', '.ssh/id_rsa', '.ssh/id_ed25519',
        'secrets.json', 'credentials.json', 'config.yml', 'database.yml',
        '/etc/passwd', '/etc/shadow', 'web.config', 'settings.py'
    ]

    def __init__(self):
        logger.info("Initialized MCP Security Analyzer")

    def analyze_mcp_server(self, config: MCPServerConfig) -> MCPSecurityAuditReport:
        """
        Perform comprehensive security audit of MCP server configuration

        Args:
            config: MCP server configuration to audit

        Returns:
            Complete security audit report with vulnerabilities and recommendations
        """
        logger.info("Starting MCP security audit", server=config.server_name)

        issues: List[MCPSecurityIssue] = []
        vulnerabilities: List[Vulnerability] = []
        recommendations: List[str] = []

        # 1. Audit server-level security
        issues.extend(self._audit_server_security(config))

        # 2. Audit tool configurations
        issues.extend(self._audit_tool_security(config))

        # 3. Audit authentication and authorization
        issues.extend(self._audit_auth_security(config))

        # 4. Audit file access controls
        issues.extend(self._audit_file_access(config))

        # 5. Check for known MCP attack vectors
        issues.extend(self._check_known_attack_vectors(config))

        # Convert issues to vulnerabilities
        vulnerabilities = self._issues_to_vulnerabilities(issues, config)

        # Generate recommendations
        recommendations = self._generate_recommendations(issues, config)

        # Calculate risk score
        risk_score = self._calculate_risk_score(issues)

        # Count issues by severity
        critical_count = len([i for i in issues if i.severity == SeverityLevel.CRITICAL])
        high_count = len([i for i in issues if i.severity == SeverityLevel.HIGH])
        medium_count = len([i for i in issues if i.severity == SeverityLevel.MEDIUM])
        low_count = len([i for i in issues if i.severity == SeverityLevel.LOW])

        # Determine compliance status
        compliance_status = "compliant" if critical_count == 0 and high_count == 0 else "non_compliant"

        logger.info(
            "MCP security audit complete",
            server=config.server_name,
            total_issues=len(issues),
            critical=critical_count,
            high=high_count,
            risk_score=risk_score
        )

        return MCPSecurityAuditReport(
            server_name=config.server_name,
            total_issues=len(issues),
            critical_issues=critical_count,
            high_issues=high_count,
            medium_issues=medium_count,
            low_issues=low_count,
            issues=issues,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            compliance_status=compliance_status,
            risk_score=risk_score
        )

    def _audit_server_security(self, config: MCPServerConfig) -> List[MCPSecurityIssue]:
        """Audit server-level security configuration"""
        issues = []

        # Check TLS/SSL
        if not config.tls_enabled:
            issues.append(MCPSecurityIssue(
                issue_type="missing_tls",
                severity=SeverityLevel.CRITICAL,
                title="MCP Server Not Using TLS/SSL",
                description=f"MCP server '{config.server_name}' does not have TLS enabled, exposing communications to interception",
                affected_component=config.server_name,
                recommendation="Enable TLS/SSL for all MCP server connections using mTLS",
                detection_method="configuration_analysis"
            ))

        # Check certificate validation
        if config.tls_enabled and not config.certificate_validation:
            issues.append(MCPSecurityIssue(
                issue_type="missing_cert_validation",
                severity=SeverityLevel.HIGH,
                title="MCP Server Certificate Validation Disabled",
                description="TLS certificate validation is disabled, allowing man-in-the-middle attacks",
                affected_component=config.server_name,
                recommendation="Enable certificate validation to prevent MITM attacks",
                detection_method="configuration_analysis"
            ))

        # Check authentication
        if not config.authentication_method:
            issues.append(MCPSecurityIssue(
                issue_type="missing_authentication",
                severity=SeverityLevel.CRITICAL,
                title="No Authentication Configured",
                description="MCP server has no authentication, allowing unauthorized access",
                affected_component=config.server_name,
                recommendation="Implement strong authentication (OAuth 2.0, JWT, or mTLS)",
                detection_method="configuration_analysis"
            ))

        # Check weak authentication
        if config.authentication_method in ['basic_auth', 'api_key']:
            issues.append(MCPSecurityIssue(
                issue_type="weak_authentication",
                severity=SeverityLevel.HIGH,
                title="Weak Authentication Method",
                description=f"Using weak authentication method: {config.authentication_method}",
                affected_component=config.server_name,
                recommendation="Use stronger authentication (mTLS, OAuth 2.0 with JWT)",
                detection_method="configuration_analysis"
            ))

        return issues

    def _audit_tool_security(self, config: MCPServerConfig) -> List[MCPSecurityIssue]:
        """Audit tool-level security configuration"""
        issues = []

        for tool in config.tools:
            # Check high-risk tools without approval
            if tool.tool_name in self.HIGH_RISK_TOOLS and not tool.requires_approval:
                issues.append(MCPSecurityIssue(
                    issue_type="high_risk_tool_no_approval",
                    severity=SeverityLevel.CRITICAL,
                    title=f"High-Risk Tool '{tool.tool_name}' Lacks Approval Requirement",
                    description=f"Tool '{tool.tool_name}' can perform dangerous operations without human approval",
                    affected_component=f"{config.server_name}/{tool.tool_name}",
                    recommendation="Require explicit user approval for high-risk tool operations",
                    detection_method="tool_analysis"
                ))

            # Check missing rate limiting
            if not tool.rate_limit:
                issues.append(MCPSecurityIssue(
                    issue_type="missing_rate_limit",
                    severity=SeverityLevel.MEDIUM,
                    title=f"Tool '{tool.tool_name}' Missing Rate Limiting",
                    description="Tool has no rate limiting, allowing abuse and resource exhaustion",
                    affected_component=f"{config.server_name}/{tool.tool_name}",
                    recommendation="Implement rate limiting to prevent abuse",
                    detection_method="tool_analysis"
                ))

            # Check missing authentication for critical tools
            if tool.risk_level in [MCPToolRiskLevel.CRITICAL, MCPToolRiskLevel.HIGH]:
                if not tool.authentication_required:
                    issues.append(MCPSecurityIssue(
                        issue_type="missing_tool_auth",
                        severity=SeverityLevel.HIGH,
                        title=f"Critical Tool '{tool.tool_name}' Lacks Authentication",
                        description="High-risk tool can be executed without authentication",
                        affected_component=f"{config.server_name}/{tool.tool_name}",
                        recommendation="Require authentication for all high-risk tools",
                        detection_method="tool_analysis"
                    ))

        return issues

    def _audit_auth_security(self, config: MCPServerConfig) -> List[MCPSecurityIssue]:
        """Audit authentication and authorization"""
        issues = []

        # Check for missing agent allowlist
        if not config.allowed_agents:
            issues.append(MCPSecurityIssue(
                issue_type="missing_agent_allowlist",
                severity=SeverityLevel.HIGH,
                title="No Agent Allowlist Configured",
                description="Any agent can connect to this MCP server without restrictions",
                affected_component=config.server_name,
                recommendation="Implement agent allowlist to restrict access to trusted agents only",
                detection_method="authorization_analysis"
            ))

        return issues

    def _audit_file_access(self, config: MCPServerConfig) -> List[MCPSecurityIssue]:
        """Audit file access controls for filesystem tools"""
        issues = []

        filesystem_tools = [t for t in config.tools if 'filesystem' in t.tool_name.lower()]

        for tool in filesystem_tools:
            # Check for missing path restrictions
            if not tool.allowed_paths and not tool.blocked_paths:
                issues.append(MCPSecurityIssue(
                    issue_type="unrestricted_filesystem_access",
                    severity=SeverityLevel.CRITICAL,
                    title=f"Filesystem Tool '{tool.tool_name}' Has Unrestricted Access",
                    description="Tool can access any file on the system, including sensitive files",
                    affected_component=f"{config.server_name}/{tool.tool_name}",
                    recommendation="Implement allowed_paths allowlist to restrict file access",
                    detection_method="file_access_analysis"
                ))

            # Check if sensitive files are not blocked
            if tool.blocked_paths:
                missing_blocks = []
                for sensitive_pattern in self.SENSITIVE_FILE_PATTERNS:
                    if not any(sensitive_pattern in blocked for blocked in tool.blocked_paths):
                        missing_blocks.append(sensitive_pattern)

                if missing_blocks:
                    issues.append(MCPSecurityIssue(
                        issue_type="sensitive_files_not_blocked",
                        severity=SeverityLevel.HIGH,
                        title=f"Sensitive Files Not Blocked for '{tool.tool_name}'",
                        description=f"Sensitive file patterns not blocked: {', '.join(missing_blocks[:5])}",
                        affected_component=f"{config.server_name}/{tool.tool_name}",
                        recommendation="Add sensitive file patterns to blocked_paths",
                        detection_method="file_access_analysis"
                    ))

        return issues

    def _check_known_attack_vectors(self, config: MCPServerConfig) -> List[MCPSecurityIssue]:
        """Check for known MCP attack vectors"""
        issues = []

        mcp_attacks = get_mcp_specific_attacks()

        # Check for malicious MCP server indicators
        if 'localhost' not in config.server_url and 'http://' in config.server_url:
            issues.append(MCPSecurityIssue(
                issue_type="insecure_transport",
                severity=SeverityLevel.HIGH,
                title="MCP Server Using Insecure HTTP",
                description="MCP server URL uses HTTP instead of HTTPS, vulnerable to interception",
                affected_component=config.server_name,
                recommendation="Use HTTPS for all MCP server connections",
                detection_method="url_analysis"
            ))

        # Check for tool chaining risks
        has_read_tool = any('read' in t.tool_name.lower() for t in config.tools)
        has_write_tool = any('write' in t.tool_name.lower() or 'execute' in t.tool_name.lower() for t in config.tools)
        has_network_tool = any('network' in t.tool_name.lower() or 'api' in t.tool_name.lower() for t in config.tools)

        if has_read_tool and has_network_tool:
            issues.append(MCPSecurityIssue(
                issue_type="tool_chaining_risk",
                severity=SeverityLevel.HIGH,
                title="Tool Chaining Risk Detected",
                description="Combination of read + network tools allows data exfiltration via tool chaining",
                affected_component=config.server_name,
                recommendation="Implement tool usage policies to prevent dangerous tool chains",
                detection_method="tool_combination_analysis"
            ))

        return issues

    def _issues_to_vulnerabilities(
        self,
        issues: List[MCPSecurityIssue],
        config: MCPServerConfig
    ) -> List[Vulnerability]:
        """Convert security issues to vulnerability objects"""
        vulnerabilities = []

        for issue in issues:
            # Map severity to CVSS score
            cvss_map = {
                SeverityLevel.CRITICAL: 9.5,
                SeverityLevel.HIGH: 7.5,
                SeverityLevel.MEDIUM: 5.0,
                SeverityLevel.LOW: 2.5
            }

            # Map issue type to CWE and OWASP
            cwe_mapping = {
                'missing_tls': ('CWE-319', 'Cleartext Transmission of Sensitive Information'),
                'missing_authentication': ('CWE-306', 'Missing Authentication for Critical Function'),
                'weak_authentication': ('CWE-287', 'Improper Authentication'),
                'unrestricted_filesystem_access': ('CWE-22', 'Path Traversal'),
                'high_risk_tool_no_approval': ('CWE-732', 'Incorrect Permission Assignment'),
                'missing_rate_limit': ('CWE-770', 'Allocation of Resources Without Limits'),
                'tool_chaining_risk': ('CWE-269', 'Improper Privilege Management')
            }

            cwe_id, cwe_name = cwe_mapping.get(issue.issue_type, ('CWE-710', 'Coding Standards Violation'))

            vuln = Vulnerability(
                title=issue.title,
                description=issue.description,
                severity=issue.severity,
                cvss_score=cvss_map.get(issue.severity, 5.0),
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                owasp_llm_category=OWASPLLMCategory.LLM07_INSECURE_PLUGIN,
                mcp_threat_category=self._map_issue_to_mcp_category(issue.issue_type),
                is_mcp_threat=True,
                attack_vector=f"MCP {issue.issue_type}",
                affected_component=issue.affected_component,
                impact=f"MCP security issue: {issue.description}",
                recommendation=issue.recommendation,
                likelihood="high",
                risk_score=cvss_map.get(issue.severity, 5.0),
                exploitability="easy" if issue.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else "moderate",
                metadata={
                    "detection_method": issue.detection_method,
                    "mcp_server": config.server_name,
                    "issue_type": issue.issue_type
                }
            )

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _map_issue_to_mcp_category(self, issue_type: str) -> MCPThreatCategory:
        """Map issue type to MCP threat category"""
        mapping = {
            'missing_tls': MCPThreatCategory.MCP_AUTH_BYPASS,
            'missing_authentication': MCPThreatCategory.MCP_AUTH_BYPASS,
            'weak_authentication': MCPThreatCategory.MCP_AUTH_BYPASS,
            'unrestricted_filesystem_access': MCPThreatCategory.MCP_TOOL_ABUSE,
            'high_risk_tool_no_approval': MCPThreatCategory.MCP_TOOL_ABUSE,
            'missing_rate_limit': MCPThreatCategory.MCP_TOOL_ABUSE,
            'tool_chaining_risk': MCPThreatCategory.MCP_TOOL_CHAINING,
            'insecure_transport': MCPThreatCategory.MCP_AUTH_BYPASS,
            'sensitive_files_not_blocked': MCPThreatCategory.MCP_DATA_EXFILTRATION
        }
        return mapping.get(issue_type, MCPThreatCategory.MCP_TOOL_ABUSE)

    def _generate_recommendations(
        self,
        issues: List[MCPSecurityIssue],
        config: MCPServerConfig
    ) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []

        # Group issues by type
        issue_types = set(i.issue_type for i in issues)

        for issue_type in issue_types:
            category = self._map_issue_to_mcp_category(issue_type)
            if category in MCP_MITIGATIONS:
                mitigation = MCP_MITIGATIONS[category]
                for control in mitigation.get('controls', []):
                    recommendations.append(
                        f"[{control['effectiveness'].upper()}] {control['control']}: {control['description']}"
                    )

        # Add general recommendations
        if len(issues) > 0:
            recommendations.insert(0, "Immediate Actions Required:")
            recommendations.insert(1, f"- Fix {len([i for i in issues if i.severity == SeverityLevel.CRITICAL])} CRITICAL issues")
            recommendations.insert(2, f"- Address {len([i for i in issues if i.severity == SeverityLevel.HIGH])} HIGH severity issues")

        return list(set(recommendations))  # Remove duplicates

    def _calculate_risk_score(self, issues: List[MCPSecurityIssue]) -> float:
        """Calculate overall risk score (0-10)"""
        if not issues:
            return 0.0

        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5
        }

        total_score = sum(severity_weights.get(issue.severity, 0) for issue in issues)
        # Normalize to 0-10 scale (assume max 5 critical issues = 10.0)
        risk_score = min(10.0, total_score / 5.0)

        return round(risk_score, 2)
