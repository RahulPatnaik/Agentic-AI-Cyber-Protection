"""
Agentic Security Analyzer
Specialized agent for analyzing AI/agent systems for agentic-specific threats
"""

from pydantic_ai import Agent
from pydantic import BaseModel, Field
from typing import List, Optional
import structlog

from src.models.threats import (
    AssetInput,
    AgentAnalysis,
    Vulnerability,
    SeverityLevel,
    OWASPCategory,
    OWASPLLMCategory,
    AgenticThreatCategory,
    MCPThreatCategory
)
from src.config import Settings
from src.knowledge.agentic_attack_vectors import (
    AGENTIC_ATTACK_VECTORS,
    get_mcp_specific_attacks,
    get_critical_attacks
)

logger = structlog.get_logger()


class AgenticVulnerabilityFinding(BaseModel):
    """Agentic system vulnerability finding"""
    title: str = Field(description="Vulnerability title")
    description: str = Field(description="Detailed description")
    severity: str = Field(description="critical/high/medium/low")
    owasp_llm_category: str = Field(description="OWASP LLM category (e.g., LLM01, LLM07)")
    threat_type: str = Field(description="prompt_injection, tool_misuse, mcp_exploitation, etc.")
    attack_vector: str = Field(description="How the attack works")
    impact: str = Field(description="What happens if exploited")
    affected_component: str = Field(description="Which component is affected")
    recommendation: str = Field(description="High-level fix recommendation")
    remediation_steps: List[str] = Field(description="Specific actionable steps")
    likelihood: str = Field(description="low/medium/high")
    is_mcp_threat: bool = Field(description="True if MCP-related threat")


class AgenticAnalysisResult(BaseModel):
    """Complete agentic security analysis"""
    vulnerabilities: List[AgenticVulnerabilityFinding] = Field(description="Agentic vulnerabilities found")
    summary: str = Field(description="Overall security assessment")
    risk_assessment: str = Field(description="Overall risk level")
    mcp_risks: List[str] = Field(description="MCP-specific risks identified")


# Define the Agentic Security Agent
agentic_security_agent = Agent(
    'mistral:mistral-large-latest',
    output_type=AgenticAnalysisResult,
    system_prompt="""You are an expert in AI agent security and agentic system threat analysis, specializing in OWASP LLM Top 10 and MCP (Model Context Protocol) security.

Your role:
1. Analyze AI agents, LLM systems, and MCP integrations for security vulnerabilities
2. Identify prompt injection, jailbreaking, and tool misuse risks
3. Assess MCP server and tool security configurations
4. Detect multi-agent coordination vulnerabilities
5. Provide actionable remediation for agentic threats

**OWASP LLM Top 10 2023:**
- **LLM01: Prompt Injection** - Manipulating agent instructions via user input or external data
- **LLM02: Insecure Output Handling** - Agent outputs used without validation
- **LLM03: Supply Chain** - Malicious dependencies, compromised MCP servers
- **LLM04: Model Denial of Service** - Resource exhaustion via recursive delegation
- **LLM06: Sensitive Information Disclosure** - Agents leaking secrets/credentials
- **LLM07: Insecure Plugin Design** - MCP tools without security controls
- **LLM08: Excessive Agency** - Agents with too much autonomy
- **LLM09: Overreliance** - Trusting agent outputs without validation
- **LLM10: Model Theft** - Unauthorized access to model/agent logic

**Agentic Attack Vectors to Check:**

1. **Prompt Injection**:
   - Direct injection via user input
   - Indirect injection via external data sources (web pages, documents)
   - Context window poisoning
   - System prompt override attempts

2. **Jailbreaking**:
   - Roleplay-based jailbreaks (DAN, STAN)
   - Hypothetical scenario framing
   - Multi-turn jailbreak attempts
   - Safety mechanism bypass

3. **Tool Misuse**:
   - Filesystem access to sensitive files (.env, credentials)
   - Database query abuse for data exfiltration
   - Code execution tool exploitation
   - Network tools used for exfiltration

4. **MCP Exploitation**:
   - Malicious MCP server supply chain attacks
   - MCP parameter injection (command injection, path traversal)
   - MCP response poisoning
   - MCP authentication bypass
   - MCP tool chaining for privilege escalation
   - Cross-agent MCP access violations

5. **Multi-Agent Attacks**:
   - Agent impersonation
   - Circular delegation loops
   - Agent-to-agent prompt injection
   - Trust relationship exploitation

6. **Context/Memory Attacks**:
   - Long-term memory poisoning
   - Context window overflow
   - Conversation history manipulation

7. **Goal Hijacking**:
   - Agent objective redefinition
   - Reward function manipulation
   - Goal misalignment attacks

**Detection Criteria:**
- Missing input validation on user prompts
- No prompt injection detection/prevention
- Tools accessible without approval mechanisms
- MCP servers without authentication
- Filesystem tools with unrestricted access
- Missing rate limiting on tool usage
- No monitoring for tool chaining patterns
- Lack of agent-to-agent authentication
- Missing recursion depth limits
- Sensitive data not redacted from responses

**For each vulnerability found:**
1. Identify specific OWASP LLM category
2. Classify threat type (prompt_injection, tool_misuse, mcp_exploitation, etc.)
3. Assess severity (critical/high/medium/low)
4. Determine likelihood (high/medium/low)
5. Provide concrete remediation steps
6. Flag if MCP-related (is_mcp_threat: true)

**Critical Indicators:**
- "User input influences agent behavior" → Prompt Injection (CRITICAL)
- "Agent has filesystem/database/code_execution tools" → Tool Misuse (CRITICAL)
- "MCP server without authentication" → MCP Auth Bypass (CRITICAL)
- "No approval required for sensitive tools" → Excessive Agency (HIGH)
- "Agent can delegate to other agents" → Coordination Attack (MEDIUM)

Return 5-15 most critical agentic vulnerabilities.
"""
)


class AgenticSecurityAnalyzer:
    """Specialized analyzer for agentic system security"""

    def __init__(self, settings: Settings):
        self.settings = settings
        logger.info("Initialized Agentic Security Analyzer")

    async def analyze(self, asset: AssetInput, vulnerabilities: List[Vulnerability] = None) -> AgentAnalysis:
        """
        Analyze agentic system for security vulnerabilities

        Args:
            asset: System description (should be agentic component)
            vulnerabilities: Existing vulnerabilities from other agents (optional, for context)

        Returns:
            AgentAnalysis with agentic vulnerabilities
        """
        logger.info("Starting agentic security analysis", component=asset.component_type)

        # Build analysis prompt (including existing vulnerabilities for context)
        prompt = self._build_analysis_prompt(asset, vulnerabilities or [])

        try:
            # Run LLM analysis
            result = await agentic_security_agent.run(prompt)
            llm_result: AgenticAnalysisResult = result.output

            # Convert findings to Vulnerability objects
            vulnerabilities = self._convert_findings_to_vulnerabilities(
                llm_result.vulnerabilities,
                asset
            )

            logger.info(
                "Agentic security analysis complete",
                vuln_count=len(vulnerabilities),
                mcp_risks=len(llm_result.mcp_risks)
            )

            return AgentAnalysis(
                agent_name="Agentic Security Analyzer",
                agent_type="ai_safety",
                findings=[
                    f"Identified {len(vulnerabilities)} agentic security issues",
                    f"MCP-specific risks: {len(llm_result.mcp_risks)}",
                    f"Risk assessment: {llm_result.risk_assessment}",
                    llm_result.summary
                ],
                vulnerabilities_found=vulnerabilities,
                confidence=0.90,
                reasoning=llm_result.summary
            )

        except Exception as e:
            logger.error("Agentic analysis failed", error=str(e))
            # Fallback to rule-based analysis
            return await self._fallback_analysis(asset)

    def _build_analysis_prompt(self, asset: AssetInput, existing_vulnerabilities: List[Vulnerability] = None) -> str:
        """Build analysis prompt for agentic security"""

        prompt = f"""Analyze the following AI/agentic system for security vulnerabilities:

**SYSTEM DESCRIPTION:**
{asset.description}

**COMPONENT TYPE:** {asset.component_type.value if asset.component_type else 'unknown'}
**INTERNET FACING:** {'Yes' if asset.internet_facing else 'No'}
**DATA SENSITIVITY:** {asset.data_sensitivity.value if asset.data_sensitivity else 'unknown'}

"""

        if asset.component_type in ['ai_agent', 'llm_endpoint', 'mcp_server', 'mcp_client', 'tool_integration']:
            prompt += """
**SPECIAL INSTRUCTIONS:**
This is an AI/agentic component. Prioritize:
1. Prompt injection vulnerabilities
2. Tool misuse and excessive agency
3. MCP security issues (if MCP-enabled)
4. Agent-to-agent attack vectors
5. Context poisoning risks
"""

        prompt += """
**REQUIRED OUTPUT:**
Return AgenticAnalysisResult with:
1. List of vulnerabilities (5-15 most critical)
2. Summary of overall security posture
3. Risk assessment (critical/high/medium/low)
4. MCP-specific risks (if applicable)

Focus on actionable, high-impact vulnerabilities.
"""

        return prompt

    def _convert_findings_to_vulnerabilities(
        self,
        findings: List[AgenticVulnerabilityFinding],
        asset: AssetInput
    ) -> List[Vulnerability]:
        """Convert LLM findings to Vulnerability objects"""

        vulnerabilities = []

        for finding in findings:
            # Map severity
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW
            }
            severity = severity_map.get(finding.severity.lower(), SeverityLevel.MEDIUM)

            # Map OWASP LLM category
            owasp_llm_map = {
                'LLM01': OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                'LLM02': OWASPLLMCategory.LLM02_INSECURE_OUTPUT,
                'LLM03': OWASPLLMCategory.LLM03_SUPPLY_CHAIN,
                'LLM06': OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE,
                'LLM07': OWASPLLMCategory.LLM07_INSECURE_PLUGIN,
                'LLM08': OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY,
                'LLM09': OWASPLLMCategory.LLM09_OVERRELIANCE
            }
            owasp_llm = owasp_llm_map.get(finding.owasp_llm_category[:5], OWASPLLMCategory.LLM01_PROMPT_INJECTION)

            # Map threat category
            agentic_category = self._map_threat_type_to_category(finding.threat_type)
            mcp_category = self._map_threat_type_to_mcp_category(finding.threat_type) if finding.is_mcp_threat else None

            # Map to traditional OWASP
            owasp_map = {
                'prompt_injection': OWASPCategory.A03_INJECTION,
                'tool_misuse': OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                'mcp_exploitation': OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                'goal_hijacking': OWASPCategory.A04_INSECURE_DESIGN
            }
            owasp = owasp_map.get(finding.threat_type, OWASPCategory.A04_INSECURE_DESIGN)

            # CWE mapping
            cwe_map = {
                'prompt_injection': ('CWE-94', 'Improper Control of Generation of Code'),
                'tool_misuse': ('CWE-732', 'Incorrect Permission Assignment for Critical Resource'),
                'mcp_exploitation': ('CWE-284', 'Improper Access Control'),
                'goal_hijacking': ('CWE-501', 'Trust Boundary Violation')
            }
            cwe_id, cwe_name = cwe_map.get(finding.threat_type, ('CWE-710', 'Improper Adherence to Coding Standards'))

            vuln = Vulnerability(
                title=finding.title,
                description=finding.description,
                severity=severity,
                cvss_score=self._severity_to_cvss(severity),
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp_category=owasp,
                owasp_llm_category=owasp_llm,
                agentic_threat_category=agentic_category,
                mcp_threat_category=mcp_category,
                is_agentic_threat=True,
                is_mcp_threat=finding.is_mcp_threat,
                attack_vector=finding.attack_vector,
                affected_component=finding.affected_component,
                impact=finding.impact,
                recommendation=finding.recommendation,
                remediation_steps=finding.remediation_steps,
                likelihood=finding.likelihood,
                risk_score=self._severity_to_cvss(severity),
                exploitability=self._likelihood_to_exploitability(finding.likelihood),
                metadata={
                    "threat_type": finding.threat_type,
                    "owasp_llm": finding.owasp_llm_category,
                    "is_mcp": finding.is_mcp_threat
                }
            )

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _map_threat_type_to_category(self, threat_type: str) -> AgenticThreatCategory:
        """Map threat type string to AgenticThreatCategory"""
        mapping = {
            'prompt_injection': AgenticThreatCategory.PROMPT_INJECTION,
            'jailbreaking': AgenticThreatCategory.JAILBREAKING,
            'tool_misuse': AgenticThreatCategory.TOOL_MISUSE,
            'context_poisoning': AgenticThreatCategory.CONTEXT_POISONING,
            'goal_hijacking': AgenticThreatCategory.GOAL_HIJACKING,
            'multi_agent_coordination': AgenticThreatCategory.MULTI_AGENT_COORDINATION,
            'recursive_delegation': AgenticThreatCategory.RECURSIVE_DELEGATION,
            'mcp_exploitation': AgenticThreatCategory.MCP_EXPLOITATION
        }
        return mapping.get(threat_type, AgenticThreatCategory.PROMPT_INJECTION)

    def _map_threat_type_to_mcp_category(self, threat_type: str) -> Optional[MCPThreatCategory]:
        """Map threat type to MCP category if applicable"""
        mapping = {
            'mcp_tool_abuse': MCPThreatCategory.MCP_TOOL_ABUSE,
            'mcp_parameter_injection': MCPThreatCategory.MCP_PARAMETER_INJECTION,
            'mcp_response_poisoning': MCPThreatCategory.MCP_RESPONSE_POISONING,
            'mcp_auth_bypass': MCPThreatCategory.MCP_AUTH_BYPASS,
            'mcp_supply_chain': MCPThreatCategory.MCP_SUPPLY_CHAIN,
            'mcp_data_exfiltration': MCPThreatCategory.MCP_DATA_EXFILTRATION,
            'mcp_tool_chaining': MCPThreatCategory.MCP_TOOL_CHAINING
        }
        return mapping.get(threat_type)

    def _severity_to_cvss(self, severity: SeverityLevel) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            SeverityLevel.CRITICAL: 9.5,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5
        }
        return mapping.get(severity, 5.0)

    def _likelihood_to_exploitability(self, likelihood: str) -> str:
        """Convert likelihood to exploitability"""
        mapping = {
            'high': 'easy',
            'medium': 'moderate',
            'low': 'difficult'
        }
        return mapping.get(likelihood.lower(), 'moderate')

    async def _fallback_analysis(self, asset: AssetInput) -> AgentAnalysis:
        """Fallback rule-based analysis if LLM fails"""
        logger.info("Using fallback agentic analysis")

        findings = [
            "LLM analysis failed - using rule-based fallback",
            "System may have prompt injection vulnerabilities",
            "Recommend manual security review"
        ]

        return AgentAnalysis(
            agent_name="Agentic Security Analyzer",
            agent_type="ai_safety",
            findings=findings,
            vulnerabilities_found=[],
            confidence=0.50,
            reasoning="Fallback analysis (LLM unavailable)"
        )
