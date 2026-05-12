"""
Threat Modeling Pydantic Models
Comprehensive data structures for agentic threat analysis
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Literal, Any
from enum import Enum
from datetime import datetime
from uuid import UUID, uuid4


class SeverityLevel(str, Enum):
    """CVSS-aligned severity levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Alias for STRIDE agent compatibility
ThreatSeverity = SeverityLevel


class OWASPCategory(str, Enum):
    """OWASP Top 10 2021 categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


class MITRECategory(str, Enum):
    """MITRE ATT&CK tactics"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class OWASPLLMCategory(str, Enum):
    """OWASP LLM Top 10 for AI/ML Security"""
    LLM01_PROMPT_INJECTION = "LLM01:2023 - Prompt Injection"
    LLM02_INSECURE_OUTPUT = "LLM02:2023 - Insecure Output Handling"
    LLM03_SUPPLY_CHAIN = "LLM03:2023 - Supply Chain Vulnerabilities"
    LLM04_DATA_POISONING = "LLM04:2023 - Model Denial of Service"
    LLM05_OUTPUT_HANDLING = "LLM05:2023 - Supply Chain Vulnerabilities"
    LLM06_SENSITIVE_DISCLOSURE = "LLM06:2023 - Sensitive Information Disclosure"
    LLM07_INSECURE_PLUGIN = "LLM07:2023 - Insecure Plugin Design"
    LLM08_EXCESSIVE_AGENCY = "LLM08:2023 - Excessive Agency"
    LLM09_OVERRELIANCE = "LLM09:2023 - Overreliance"
    LLM10_MODEL_THEFT = "LLM10:2023 - Model Theft"


class AgenticThreatCategory(str, Enum):
    """Agentic system-specific threat categories"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAKING = "jailbreaking"
    TOOL_MISUSE = "tool_misuse"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_AGENT_COORDINATION = "multi_agent_coordination_attack"
    GOAL_HIJACKING = "agent_goal_hijacking"
    RECURSIVE_DELEGATION = "recursive_delegation_exploit"
    MCP_EXPLOITATION = "mcp_exploitation"
    AGENT_TO_AGENT_ATTACK = "agent_to_agent_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation_agentic"
    DATA_EXFILTRATION = "data_exfiltration_agentic"
    SUPPLY_CHAIN = "supply_chain_agentic"


class MCPThreatCategory(str, Enum):
    """MCP (Model Context Protocol) specific threats"""
    MALICIOUS_MCP_SERVER = "malicious_mcp_server"
    MCP_TOOL_ABUSE = "mcp_tool_abuse"
    MCP_RESPONSE_POISONING = "mcp_response_poisoning"
    MCP_AUTH_BYPASS = "mcp_authentication_bypass"
    MCP_PARAMETER_INJECTION = "mcp_parameter_injection"
    MCP_TOOL_CHAINING = "mcp_tool_chaining_attack"
    MCP_SUPPLY_CHAIN = "mcp_supply_chain_attack"
    MCP_DATA_EXFILTRATION = "mcp_data_exfiltration"


class Threat(BaseModel):
    """
    Threat identified by STRIDE analysis
    Simplified version of Vulnerability for STRIDE agent compatibility
    """
    title: str
    description: str
    severity: SeverityLevel
    stride_category: Optional[str] = None  # S/T/R/I/D/E
    owasp_category: Optional[OWASPCategory] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    attack_vector: Optional[str] = None
    recommendation: Optional[str] = None
    impact: Optional[str] = None
    likelihood: Optional[Literal["low", "medium", "high"]] = None
    exploitability: Optional[Literal["easy", "moderate", "difficult"]] = None

    # Agentic threat fields
    owasp_llm_category: Optional[OWASPLLMCategory] = None
    agentic_threat_category: Optional[AgenticThreatCategory] = None
    mcp_threat_category: Optional[MCPThreatCategory] = None
    is_agentic_threat: bool = False
    is_mcp_threat: bool = False

    metadata: Optional[Dict] = Field(default_factory=dict)


class ComponentType(str, Enum):
    """System component types"""
    WEB_SERVER = "web_server"
    DATABASE = "database"
    API_ENDPOINT = "api_endpoint"
    AUTHENTICATION = "authentication"
    DATA_STORE = "data_store"
    EXTERNAL_SERVICE = "external_service"
    USER_INPUT = "user_input"
    BUSINESS_LOGIC = "business_logic"
    NETWORK_BOUNDARY = "network_boundary"

    # Agentic component types
    AI_AGENT = "ai_agent"
    LLM_ENDPOINT = "llm_endpoint"
    MCP_SERVER = "mcp_server"
    MCP_CLIENT = "mcp_client"
    TOOL_INTEGRATION = "tool_integration"
    MULTI_AGENT_SYSTEM = "multi_agent_system"
    PROMPT_HANDLER = "prompt_handler"
    CONTEXT_MANAGER = "context_manager"


class AssetInput(BaseModel):
    """Input describing the system/feature to analyze"""
    description: str = Field(..., description="Natural language description of the system/feature")
    component_type: Optional[ComponentType] = None
    programming_languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    external_dependencies: List[str] = Field(default_factory=list)
    compliance_requirements: List[str] = Field(default_factory=list, description="FDA, HIPAA, NIST, etc.")

    # Optional: actual code snippet
    code_snippet: Optional[str] = None

    # Context
    user_roles: List[str] = Field(default_factory=list)
    data_sensitivity: Optional[SeverityLevel] = None
    internet_facing: bool = False


class Vulnerability(BaseModel):
    """Identified vulnerability"""
    vuln_id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)

    # Classification
    cwe_id: str = Field(..., description="CWE ID (e.g., CWE-79)")
    cwe_name: str = Field(..., description="CWE name")
    owasp_category: OWASPCategory
    mitre_tactic: Optional[MITRECategory] = None

    # Agentic classification
    owasp_llm_category: Optional[OWASPLLMCategory] = None
    agentic_threat_category: Optional[AgenticThreatCategory] = None
    mcp_threat_category: Optional[MCPThreatCategory] = None
    is_agentic_threat: bool = False
    is_mcp_threat: bool = False

    # Attack details
    attack_vector: str
    prerequisites: List[str] = Field(default_factory=list)
    impact: str

    # Evidence
    affected_component: str
    vulnerable_code_line: Optional[int] = None
    evidence: List[str] = Field(default_factory=list)

    # Remediation
    recommendation: str
    remediation_steps: List[str] = Field(default_factory=list)
    code_fix_example: Optional[str] = None

    # Risk
    likelihood: Literal["low", "medium", "high"]
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Likelihood × Impact")
    exploitability: Literal["easy", "moderate", "difficult"]

    # Compliance
    compliance_violations: List[str] = Field(default_factory=list)

    # Additional metadata (for CVE enrichment, etc.)
    metadata: Optional[Dict] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """Attack tree path from entry to impact"""
    path_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str

    # Path nodes
    entry_point: str
    intermediate_steps: List[str] = Field(default_factory=list)
    target: str
    impact: str

    # Metrics
    complexity: Literal["low", "medium", "high"]
    probability: float = Field(..., ge=0.0, le=1.0)
    potential_damage: SeverityLevel

    # Vulnerabilities exploited
    vulnerabilities: List[UUID] = Field(default_factory=list, description="Vulnerability IDs in this path")


class ThreatActor(BaseModel):
    """Potential threat actor profile"""
    actor_type: Literal["insider", "external_attacker", "nation_state", "automated_bot", "competitor"]
    skill_level: Literal["novice", "intermediate", "advanced", "expert"]
    motivation: List[str] = Field(default_factory=list)
    resources: Literal["minimal", "moderate", "significant", "extensive"]


class CWEReference(BaseModel):
    """CWE weakness reference"""
    cwe_id: str = Field(..., pattern=r"^CWE-\d+$")
    cwe_name: str
    description: str
    likelihood: Literal["low", "medium", "high"]
    severity: SeverityLevel

    # Related OWASP
    owasp_mapping: Optional[OWASPCategory] = None

    # Affected components
    affected_languages: List[str] = Field(default_factory=list)
    affected_frameworks: List[str] = Field(default_factory=list)

    # MAESTRO principles violated
    maestro_violations: List[str] = Field(default_factory=list, description="MAESTRO security principles violated")

    # Remediation
    mitigation_strategies: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class CodeFix(BaseModel):
    """Suggested code fix for compliance violation"""
    file_path: Optional[str] = None
    vulnerable_code: Optional[str] = None
    fixed_code: str
    explanation: str


class ComplianceCheck(BaseModel):
    """Compliance requirement check"""
    framework: Literal["NIST_AI_RMF", "OWASP_ASVS", "NIST_800_53", "ISO_27001", "GDPR", "HIPAA", "PCI_DSS"]
    control_id: str  # e.g., "SC-8", "ASVS-2.1.1", "AI RMF: MAP-1.1"
    control_name: str
    status: Literal["compliant", "non_compliant", "partial", "not_applicable"]

    # Gap analysis
    finding: str = ""  # LLM-generated explanation of the violation
    evidence: List[str] = Field(default_factory=list)  # References to specific threats/vulns

    # Remediation
    remediation_steps: List[str] = Field(default_factory=list)  # Actionable fixes
    code_fixes: List[CodeFix] = Field(default_factory=list)  # Code-level suggestions
    priority: Literal["critical", "high", "medium", "low"] = "medium"
    estimated_effort: str = ""  # e.g., "2-4 hours", "1 week"


class ThreatModel(BaseModel):
    """Complete threat model output"""
    model_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Input
    asset_description: str
    component_type: Optional[ComponentType] = None

    # Analysis results
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    threat_actors: List[ThreatActor] = Field(default_factory=list)
    cwe_references: List[CWEReference] = Field(default_factory=list)
    compliance_checks: List[ComplianceCheck] = Field(default_factory=list)

    # Top critical issues
    top_vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="Top 5-10 critical vulns")
    critical_paths: List[AttackPath] = Field(default_factory=list, description="Most likely attack paths")

    # Metadata
    analysis_duration_seconds: float
    agent_analyses: Dict[str, str] = Field(default_factory=dict, description="Individual agent outputs")
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    metadata: Optional[Dict] = Field(default_factory=dict, description="Additional metadata (source, files analyzed, etc.)")

    # Graph data for visualization
    threat_graph: Optional[Dict] = Field(None, description="D3.js-compatible graph structure")


class AgentAnalysis(BaseModel):
    """Individual agent analysis output"""
    agent_name: str
    agent_type: Literal["owasp", "attack_tree", "ai_safety", "cwe_analyzer", "compliance", "maestro"]
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    findings: List[str] = Field(default_factory=list)
    vulnerabilities_found: List[Vulnerability] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str

    # MAESTRO principles check
    maestro_analysis: Optional[Dict[str, str]] = Field(None, description="MAESTRO security principles analysis")

    # Formal verification (for symbolic verifier)
    formal_proofs: Optional[List[str]] = None
    z3_constraints: Optional[str] = None

    # Additional metadata for storing agent-specific data (like attack paths)
    analysis_metadata: Optional[Dict[str, Any]] = None
