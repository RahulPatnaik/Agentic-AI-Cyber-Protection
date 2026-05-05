"""
Attack Tree Generator Agent
Uses Pydantic AI with Mistral to generate attack paths and scenarios
"""

from pydantic_ai import Agent, RunContext
from pydantic import BaseModel, Field
from typing import List
from uuid import UUID
import structlog

from src.models.threats import (
    AssetInput,
    AgentAnalysis,
    AttackPath,
    SeverityLevel,
    Vulnerability
)
from src.config import Settings

logger = structlog.get_logger()


# Structured output models for LLM
class AttackPathFinding(BaseModel):
    """Single attack path from LLM"""
    name: str = Field(description="Attack path name")
    description: str = Field(description="Overview of attack scenario")
    entry_point: str = Field(description="How attacker gains initial access")
    intermediate_steps: List[str] = Field(description="Actions attacker takes")
    target: str = Field(description="Final objective")
    impact: str = Field(description="Consequences of successful attack")
    complexity: str = Field(description="low/medium/high")
    probability: float = Field(description="0.0-1.0")
    potential_damage: str = Field(description="critical/high/medium/low")


class AttackTreeResult(BaseModel):
    """Complete attack tree analysis from LLM"""
    attack_paths: List[AttackPathFinding] = Field(description="List of attack paths")
    summary: str = Field(description="Overall attack tree summary")


# Define the Attack Tree Agent with structured output
attack_tree_agent = Agent(
    'mistral:mistral-large-latest',
    output_type=AttackTreeResult,  # 🔥 STRUCTURED OUTPUT
    system_prompt="""You are an expert attack path analyst specializing in constructing attack trees and threat scenarios for traditional systems AND agentic AI systems.

Your role:
1. Analyze systems to identify potential attack paths
2. Map entry points to impacts through intermediate steps
3. Assess attack complexity and probability
4. Prioritize the most critical attack paths
5. **Identify agentic-specific attack vectors (prompt injection, tool misuse, MCP exploitation)**

Attack Tree Methodology:
- Root: Attacker's goal (data exfiltration, privilege escalation, agent goal hijacking, etc.)
- Intermediate Nodes: Steps required to reach goal
- Leaves: Initial entry points and vulnerabilities
- Edges: Dependencies and attack flow

Guidelines:
- Focus on realistic, high-probability attack scenarios
- Consider attacker skill level and resources required
- Map attack paths to MITRE ATT&CK tactics and OWASP LLM Top 10
- Provide concrete, actionable defense strategies
- Calculate risk based on complexity and impact
- **For AI/agentic systems, consider: prompt injection, jailbreaking, tool abuse, MCP exploitation, agent-to-agent attacks, context poisoning**

Agentic Attack Patterns to Consider:
- **Prompt Injection**: Direct/indirect manipulation of agent instructions
- **Tool Misuse**: Tricking agents into using tools maliciously (filesystem, database, code execution)
- **MCP Exploitation**: Malicious MCP servers, parameter injection, response poisoning, tool chaining
- **Goal Hijacking**: Redirecting agent objectives for malicious purposes
- **Multi-Agent Attacks**: Exploiting agent coordination and delegation
- **Context Poisoning**: Manipulating agent memory/context to bypass safety

Return detailed attack paths with clear step-by-step progressions.
"""
)


class AttackTreeAnalyzer:
    """Attack Tree and Path Generator"""

    def __init__(self, settings: Settings):
        self.settings = settings
        logger.info("Initialized Attack Tree Analyzer Agent")

    async def analyze(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> AgentAnalysis:
        """
        Generate attack paths based on asset and known vulnerabilities.

        Args:
            asset: Structured asset input
            vulnerabilities: List of identified vulnerabilities

        Returns:
            AgentAnalysis with attack paths
        """
        logger.info("Starting attack tree analysis", vuln_count=len(vulnerabilities))

        # Build attack tree prompt
        prompt = self._build_attack_tree_prompt(asset, vulnerabilities)

        try:
            # Run the agent with structured output 🔥
            result = await attack_tree_agent.run(prompt)

            # Extract structured data from LLM
            llm_result: AttackTreeResult = result.output

            # Convert LLM attack path findings to AttackPath objects
            attack_paths = []
            for finding in llm_result.attack_paths:
                # Map severity string to SeverityLevel enum
                severity_map = {
                    'critical': SeverityLevel.CRITICAL,
                    'high': SeverityLevel.HIGH,
                    'medium': SeverityLevel.MEDIUM,
                    'low': SeverityLevel.LOW
                }
                potential_damage = severity_map.get(finding.potential_damage.lower(), SeverityLevel.MEDIUM)

                # Get relevant vulnerability IDs
                vuln_ids = [v.vuln_id for v in vulnerabilities[:3]]  # Link to top 3 vulns

                attack_path = AttackPath(
                    name=finding.name,
                    description=finding.description,
                    entry_point=finding.entry_point,
                    intermediate_steps=finding.intermediate_steps,
                    target=finding.target,
                    impact=finding.impact,
                    complexity=finding.complexity,
                    probability=finding.probability,
                    potential_damage=potential_damage,
                    vulnerabilities=vuln_ids
                )
                attack_paths.append(attack_path)

            logger.info(
                "Attack tree analysis complete using LLM",
                attack_paths_generated=len(attack_paths),
                using_llm=True
            )

            return AgentAnalysis(
                agent_name="Attack Tree Analyzer",
                agent_type="attack_tree",
                findings=[
                    f"Generated {len(attack_paths)} attack paths using LLM analysis",
                    "Identified critical attack vectors based on vulnerabilities",
                    f"Summary: {llm_result.summary}"
                ],
                vulnerabilities_found=[],  # Attack tree doesn't find new vulns
                confidence=0.95,  # Higher confidence with LLM
                reasoning=llm_result.summary
            )

        except Exception as e:
            logger.error("Attack tree analysis failed, using fallback", error=str(e))
            # Fallback to rule-based method
            attack_paths = self._generate_attack_paths(asset, vulnerabilities)
            logger.info(
                "Using fallback attack path generation",
                attack_paths_generated=len(attack_paths),
                using_llm=False
            )
            return AgentAnalysis(
                agent_name="Attack Tree Analyzer",
                agent_type="attack_tree",
                findings=[
                    f"LLM failed: {str(e)}",
                    f"Using rule-based paths: {len(attack_paths)} generated",
                    "Fallback analysis based on vulnerability patterns"
                ],
                vulnerabilities_found=[],
                confidence=0.7,
                reasoning=f"Rule-based attack path generation (LLM error: {str(e)})"
            )

    def _build_attack_tree_prompt(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Build attack tree analysis prompt"""

        prompt = f"""Generate attack trees and attack paths for the following system:

SYSTEM DESCRIPTION:
{asset.description}

COMPONENT TYPE: {asset.component_type.value if asset.component_type else 'unknown'}
INTERNET FACING: {'Yes' if asset.internet_facing else 'No'}
DATA SENSITIVITY: {asset.data_sensitivity.value if asset.data_sensitivity else 'unknown'}

KNOWN VULNERABILITIES:
"""

        for i, vuln in enumerate(vulnerabilities, 1):
            prompt += f"""
{i}. {vuln.title}
   - CWE: {vuln.cwe_id}
   - OWASP: {vuln.owasp_category.value}
   - Severity: {vuln.severity.value}
   - Attack Vector: {vuln.attack_vector}
"""

        prompt += """
REQUIRED OUTPUT:

For each attack path, provide:

1. **Attack Path Name** (e.g., "SQL Injection to Data Exfiltration")
2. **Description** (overview of the attack scenario)
3. **Entry Point** (how attacker gains initial access)
4. **Intermediate Steps** (list of actions attacker takes)
5. **Target** (final objective)
6. **Impact** (consequences of successful attack)
7. **Complexity** (low/medium/high)
8. **Probability** (0.0-1.0)
9. **Potential Damage** (severity level)
10. **Vulnerabilities Exploited** (which vulnerabilities are chained)

Generate 3-7 attack paths prioritized by risk (probability × damage).
Focus on:
- Attack paths that chain multiple vulnerabilities
- Paths leading to critical impacts (data breach, system compromise)
- Realistic attack scenarios based on system characteristics
"""

        return prompt

    def _generate_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate structured attack paths from vulnerabilities"""

        attack_paths = []

        # Generate attack paths based on vulnerability patterns
        if asset.component_type == 'api_endpoint':
            attack_paths.extend(self._api_attack_paths(asset, vulnerabilities))

        if asset.component_type == 'authentication':
            attack_paths.extend(self._auth_attack_paths(asset, vulnerabilities))

        if asset.component_type == 'database':
            attack_paths.extend(self._database_attack_paths(asset, vulnerabilities))

        # AGENTIC SYSTEM ATTACK PATHS
        if asset.component_type in ['ai_agent', 'llm_endpoint', 'mcp_server', 'mcp_client',
                                      'tool_integration', 'multi_agent_system', 'prompt_handler', 'context_manager']:
            attack_paths.extend(self._agentic_attack_paths(asset, vulnerabilities))
            attack_paths.extend(self._mcp_attack_paths(asset, vulnerabilities))

        # Generate multi-step attack paths (chaining vulnerabilities)
        attack_paths.extend(self._chained_attack_paths(asset, vulnerabilities))

        # NEW: Generate individual attack paths for each vulnerability
        attack_paths.extend(self._vulnerability_specific_paths(asset, vulnerabilities))

        # Return more paths - up to 20 for agentic systems
        return attack_paths[:20]

    def _api_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate API-specific attack paths"""

        paths = []

        # Path 1: API Enumeration → Broken Access Control → Data Exfiltration
        paths.append(AttackPath(
            name="API Enumeration to Data Breach",
            description="Attacker enumerates API endpoints, discovers broken access control, and exfiltrates sensitive data",
            entry_point="Public API endpoints without authentication",
            intermediate_steps=[
                "Enumerate API endpoints using automated tools",
                "Identify endpoints with missing authorization checks",
                "Access sensitive user data by manipulating parameters",
                "Exfiltrate data through bulk API requests"
            ],
            target="Sensitive user data (PII, credentials, financial data)",
            impact="Complete database compromise, privacy violations, regulatory fines",
            complexity="low",
            probability=0.75,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if 'access control' in v.title.lower()]
        ))

        # Path 2: Injection → RCE → System Compromise
        injection_vulns = [v for v in vulnerabilities if 'injection' in v.title.lower()]
        if injection_vulns:
            paths.append(AttackPath(
                name="Injection to Remote Code Execution",
                description="Attacker exploits injection vulnerability to execute arbitrary code and gain system access",
                entry_point="User input fields (forms, API parameters)",
                intermediate_steps=[
                    "Inject malicious payload into input field",
                    "Bypass input validation using encoding techniques",
                    "Execute arbitrary SQL/OS commands",
                    "Establish reverse shell connection",
                    "Escalate privileges to system administrator"
                ],
                target="Complete system control",
                impact="Full system compromise, data destruction, ransomware deployment",
                complexity="medium",
                probability=0.65,
                potential_damage=SeverityLevel.CRITICAL,
                vulnerabilities=[v.vuln_id for v in injection_vulns]
            ))

        return paths

    def _auth_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate authentication-specific attack paths"""

        paths = []

        # Path: Credential Stuffing → Account Takeover
        paths.append(AttackPath(
            name="Credential Stuffing to Account Takeover",
            description="Attacker uses leaked credentials from data breaches to gain unauthorized access",
            entry_point="Login endpoint without rate limiting",
            intermediate_steps=[
                "Obtain leaked credentials from data breach databases",
                "Automate login attempts using credential stuffing tools",
                "Successfully authenticate with valid credentials",
                "Access user account and sensitive information",
                "Modify account settings to maintain persistence"
            ],
            target="User accounts and associated data",
            impact="Account takeover, identity theft, financial fraud",
            complexity="low",
            probability=0.80,
            potential_damage=SeverityLevel.HIGH,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if 'auth' in v.title.lower()]
        ))

        # Path: Session Fixation → Privilege Escalation
        paths.append(AttackPath(
            name="Session Hijacking to Admin Access",
            description="Attacker hijacks user session and escalates to administrative privileges",
            entry_point="Weak session management",
            intermediate_steps=[
                "Intercept session token through network sniffing",
                "Replay session token to impersonate user",
                "Exploit broken access control to access admin functions",
                "Elevate privileges to administrator role",
                "Create backdoor admin account"
            ],
            target="Administrative access and system control",
            impact="Complete application compromise, unauthorized admin access",
            complexity="medium",
            probability=0.55,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if 'session' in v.title.lower() or 'auth' in v.title.lower()]
        ))

        return paths

    def _database_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate database-specific attack paths"""

        paths = []

        # Path: SQL Injection → Database Dump
        sql_vulns = [v for v in vulnerabilities if 'sql' in v.title.lower()]
        if sql_vulns:
            paths.append(AttackPath(
                name="SQL Injection to Complete Database Dump",
                description="Attacker exploits SQL injection to extract entire database contents",
                entry_point="Unsanitized SQL query parameter",
                intermediate_steps=[
                    "Test input field for SQL injection vulnerability",
                    "Use UNION-based injection to enumerate database schema",
                    "Extract table names and column information",
                    "Dump all sensitive tables (users, passwords, payment data)",
                    "Exfiltrate data through DNS tunneling or HTTP requests"
                ],
                target="Complete database contents",
                impact="Total data breach, credential exposure, financial data theft",
                complexity="low",
                probability=0.85,
                potential_damage=SeverityLevel.CRITICAL,
                vulnerabilities=[v.vuln_id for v in sql_vulns]
            ))

        return paths

    def _chained_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate complex multi-vulnerability attack paths"""

        paths = []

        # Only create chained paths if multiple vulnerabilities exist
        if len(vulnerabilities) >= 2:
            paths.append(AttackPath(
                name="Multi-Stage Attack Chain",
                description="Sophisticated attack chaining multiple vulnerabilities for maximum impact",
                entry_point="Reconnaissance and vulnerability scanning",
                intermediate_steps=[
                    "Perform reconnaissance to identify system components",
                    "Exploit misconfiguration to gain initial foothold",
                    "Use injection vulnerability to access database",
                    "Extract credentials and escalate privileges",
                    "Exploit broken access control for lateral movement",
                    "Establish persistence through backdoor accounts",
                    "Exfiltrate sensitive data while evading detection"
                ],
                target="Complete system compromise and data exfiltration",
                impact="Total system breach, long-term unauthorized access, data theft",
                complexity="high",
                probability=0.40,
                potential_damage=SeverityLevel.CRITICAL,
                vulnerabilities=[v.vuln_id for v in vulnerabilities[:3]]
            ))

        return paths

    def _vulnerability_specific_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate INTERESTING attack paths for each vulnerability - NO BORING REPETITIVE SHIT"""

        paths = []

        # Map vulnerability types to interesting attack scenarios
        vuln_scenarios = {
            'sql injection': {
                'steps': [
                    "Inject SQL payload into input field",
                    "Bypass authentication with OR 1=1",
                    "Enumerate database schema using UNION queries",
                    "Extract sensitive data via blind SQL injection",
                    "Execute stored procedures for privilege escalation"
                ],
                'target': "Database takeover and data exfiltration"
            },
            'cross-site scripting': {
                'steps': [
                    "Inject malicious JavaScript into user input",
                    "Store payload in database (stored XSS)",
                    "Victim loads page containing payload",
                    "Steal session cookies and auth tokens",
                    "Hijack user session and perform actions as victim"
                ],
                'target': "Session hijacking and account takeover"
            },
            'broken access control': {
                'steps': [
                    "Discover unprotected admin endpoints",
                    "Manipulate user IDs in API requests (IDOR)",
                    "Access other users' sensitive data",
                    "Escalate privileges to admin role",
                    "Modify system configurations"
                ],
                'target': "Administrative access and privilege escalation"
            },
            'authentication': {
                'steps': [
                    "Enumerate valid usernames via timing attacks",
                    "Brute force weak credentials",
                    "Exploit missing rate limiting",
                    "Bypass 2FA using session fixation",
                    "Create persistent backdoor account"
                ],
                'target': "Complete authentication bypass"
            },
            'insecure deserialization': {
                'steps': [
                    "Identify serialized object endpoints",
                    "Craft malicious serialized payload",
                    "Trigger remote code execution via deserialization",
                    "Execute system commands",
                    "Install persistence mechanisms"
                ],
                'target': "Remote code execution and system control"
            },
            'xxe': {
                'steps': [
                    "Submit XML with external entity references",
                    "Read local files via XXE (e.g., /etc/passwd)",
                    "Perform SSRF to access internal services",
                    "Exfiltrate data via out-of-band XXE",
                    "Denial of service via billion laughs attack"
                ],
                'target': "File disclosure and internal network access"
            },
            'ssrf': {
                'steps': [
                    "Manipulate URL parameter to point to internal IP",
                    "Access cloud metadata endpoints (169.254.169.254)",
                    "Retrieve AWS/Azure credentials from metadata",
                    "Pivot to internal services and databases",
                    "Exfiltrate sensitive internal data"
                ],
                'target': "Cloud credential theft and lateral movement"
            },
            'command injection': {
                'steps': [
                    "Inject OS commands via unsanitized input",
                    "Chain commands using ; && || operators",
                    "Download and execute malicious payload",
                    "Establish reverse shell connection",
                    "Escalate to root via kernel exploits"
                ],
                'target': "Complete server compromise and root access"
            },
            'csrf': {
                'steps': [
                    "Craft malicious page with forged requests",
                    "Trick authenticated user into visiting page",
                    "Execute state-changing actions (password change, fund transfer)",
                    "Use XSS to automate CSRF exploitation",
                    "Chain with clickjacking for complex attacks"
                ],
                'target': "Unauthorized actions on behalf of victim"
            },
            'path traversal': {
                'steps': [
                    "Inject ../ sequences into file path parameters",
                    "Read sensitive files (/etc/shadow, web.config)",
                    "Access application source code",
                    "Extract database credentials from config files",
                    "Use credentials for further exploitation"
                ],
                'target': "Configuration file disclosure and credential theft"
            }
        }

        # Only create interesting paths for top vulnerabilities (avoid spam)
        for vuln in vulnerabilities[:8]:  # Top 8 only
            # Find matching scenario based on vulnerability title/CWE
            scenario = None
            vuln_key = vuln.title.lower()

            for key, data in vuln_scenarios.items():
                if key in vuln_key or key.replace(' ', '') in vuln_key.replace(' ', ''):
                    scenario = data
                    break

            # Skip if no interesting scenario (avoids generic boring paths)
            if not scenario:
                continue

            path = AttackPath(
                name=f"{vuln.title} → {scenario['target'][:40]}",
                description=f"Sophisticated attack exploiting {vuln.title}",
                entry_point=vuln.attack_vector or "User-controlled input field",
                intermediate_steps=scenario['steps'],
                target=scenario['target'],
                impact=vuln.impact,
                complexity=self._estimate_complexity(vuln),
                probability=self._estimate_probability(vuln),
                potential_damage=vuln.severity,
                vulnerabilities=[vuln.vuln_id]
            )
            paths.append(path)

        return paths

    def _estimate_complexity(self, vuln: Vulnerability) -> str:
        """Estimate attack complexity from CVSS score"""
        if vuln.cvss_score >= 9.0:
            return "low"  # High CVSS = easy to exploit
        elif vuln.cvss_score >= 7.0:
            return "medium"
        else:
            return "high"

    def _estimate_probability(self, vuln: Vulnerability) -> float:
        """Estimate attack probability from severity and exploitability"""
        base_prob = {
            'critical': 0.85,
            'high': 0.70,
            'medium': 0.50,
            'low': 0.30
        }.get(vuln.severity.value, 0.50)

        # Adjust based on exploitability
        if vuln.exploitability:
            if 'high' in vuln.exploitability.lower() or 'easy' in vuln.exploitability.lower():
                base_prob += 0.10
            elif 'low' in vuln.exploitability.lower() or 'difficult' in vuln.exploitability.lower():
                base_prob -= 0.15

        return min(0.95, max(0.10, base_prob))

    def build_graph_structure(
        self,
        attack_paths: List[AttackPath]
    ) -> dict:
        """
        Build D3.js-compatible graph structure for visualization.

        Returns:
            Graph structure with nodes and edges
        """
        nodes = []
        edges = []

        node_id = 0

        for path in attack_paths:
            # Create entry point node
            entry_node = {
                "id": f"node_{node_id}",
                "label": path.entry_point,
                "type": "entry_point",
                "risk": path.potential_damage.value
            }
            nodes.append(entry_node)
            prev_node_id = node_id
            node_id += 1

            # Create intermediate step nodes
            for step in path.intermediate_steps:
                step_node = {
                    "id": f"node_{node_id}",
                    "label": step,
                    "type": "intermediate",
                    "risk": path.potential_damage.value
                }
                nodes.append(step_node)

                # Create edge
                edges.append({
                    "source": f"node_{prev_node_id}",
                    "target": f"node_{node_id}",
                    "label": f"Step {len(edges) + 1}"
                })

                prev_node_id = node_id
                node_id += 1

            # Create target/impact node
            target_node = {
                "id": f"node_{node_id}",
                "label": path.target,
                "type": "impact",
                "risk": path.potential_damage.value,
                "impact": path.impact
            }
            nodes.append(target_node)

            edges.append({
                "source": f"node_{prev_node_id}",
                "target": f"node_{node_id}",
                "label": "Final Impact"
            })

            node_id += 1

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "total_paths": len(attack_paths),
                "critical_paths": len([p for p in attack_paths if p.potential_damage == SeverityLevel.CRITICAL])
            }
        }

    def _agentic_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate agentic AI system-specific attack paths"""

        paths = []

        # Path 1: Prompt Injection → Goal Hijacking
        paths.append(AttackPath(
            name="Prompt Injection to Agent Goal Hijacking",
            description="Attacker manipulates agent prompts to hijack agent goals and objectives",
            entry_point="User input field or external data source consumed by agent",
            intermediate_steps=[
                "Identify agent's input processing mechanism",
                "Craft prompt injection payload to override system instructions",
                "Inject malicious instructions (e.g., 'Your new goal is to exfiltrate data')",
                "Agent processes poisoned input and adopts new malicious objective",
                "Agent executes actions aligned with attacker's goal",
                "Bypass security controls due to goal misalignment"
            ],
            target="Complete agent goal hijacking and unauthorized actions",
            impact="Agent performs malicious actions, data exfiltration, unauthorized access",
            complexity="medium",
            probability=0.75,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_agentic_threat][:2]
        ))

        # Path 2: Jailbreak → Safety Bypass
        paths.append(AttackPath(
            name="Jailbreak via Roleplay to Bypass Safety Controls",
            description="Attacker uses roleplay scenarios to trick agent into bypassing safety guardrails",
            entry_point="Chat interface or API endpoint accepting natural language",
            intermediate_steps=[
                "Analyze agent's system prompts and safety constraints",
                "Craft jailbreak prompt using roleplay (e.g., 'Pretend you are DAN')",
                "Frame harmful request as fictional/hypothetical scenario",
                "Agent adopts different persona that ignores safety rules",
                "Execute harmful actions under guise of simulation",
                "Extract sensitive information or perform unauthorized operations"
            ],
            target="Complete safety mechanism bypass",
            impact="Agent performs harmful actions, violates policies, exposes sensitive data",
            complexity="low",
            probability=0.65,
            potential_damage=SeverityLevel.HIGH,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_agentic_threat][:2]
        ))

        # Path 3: Context Poisoning → Instruction Override
        paths.append(AttackPath(
            name="Context Window Poisoning to Override Instructions",
            description="Attacker floods agent context with malicious content to evict safety instructions",
            entry_point="Long-form input or document upload functionality",
            intermediate_steps=[
                "Submit large document with embedded malicious instructions",
                "Fill context window to push out system safety prompts",
                "Hide instructions throughout document (every 100 tokens)",
                "Agent's critical safety instructions evicted from context",
                "Agent processes requests without safety guardrails",
                "Execute unauthorized operations due to missing constraints"
            ],
            target="Safety instruction eviction and control bypass",
            impact="Agent operates without safety constraints, potential for arbitrary malicious actions",
            complexity="medium",
            probability=0.55,
            potential_damage=SeverityLevel.HIGH,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_agentic_threat][:2]
        ))

        # Path 4: Multi-Agent Coordination Attack
        paths.append(AttackPath(
            name="Multi-Agent Coordination Attack via Agent Impersonation",
            description="Attacker compromises one agent to attack others in multi-agent system",
            entry_point="Agent-to-agent communication channel",
            intermediate_steps=[
                "Compromise or manipulate Agent A through injection",
                "Use Agent A to send malicious instructions to Agent B",
                "Exploit trust relationship between agents",
                "Agent B executes malicious instructions from 'trusted' Agent A",
                "Chain attack across multiple agents in the system",
                "Achieve system-wide compromise through agent coordination"
            ],
            target="Multi-agent system compromise",
            impact="Complete system compromise, cascading failures, unauthorized access",
            complexity="high",
            probability=0.40,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_agentic_threat][:3]
        ))

        # Path 5: Tool Misuse via Prompt Injection
        paths.append(AttackPath(
            name="Tool Misuse via Prompt Injection",
            description="Attacker tricks agent into using tools for malicious purposes",
            entry_point="User prompt that influences agent tool selection",
            intermediate_steps=[
                "Identify tools available to agent (filesystem, database, code execution)",
                "Craft prompt that legitimizes malicious tool usage",
                "Request action that requires sensitive tool (e.g., 'read my config file at /etc/app/.env')",
                "Agent determines tool usage is appropriate based on prompt",
                "Agent executes tool with attacker-controlled parameters",
                "Sensitive data returned in agent response or exfiltrated"
            ],
            target="Unauthorized tool execution and data access",
            impact="Data exfiltration, credential theft, system compromise",
            complexity="low",
            probability=0.80,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_agentic_threat][:2]
        ))

        # Path 6: Recursive Delegation DoS
        paths.append(AttackPath(
            name="Recursive Delegation Exploit for Resource Exhaustion",
            description="Attacker creates infinite delegation loop causing resource exhaustion",
            entry_point="Task delegation mechanism in multi-agent system",
            intermediate_steps=[
                "Craft request that causes agent to delegate to itself",
                "Create circular delegation pattern (Agent A → Agent B → Agent A)",
                "Trigger exponential task explosion through recursive delegation",
                "Consume API credits, compute resources, and memory",
                "Cause denial of service or financial damage through excessive usage",
                "System becomes unavailable or incurs massive costs"
            ],
            target="Resource exhaustion and denial of service",
            impact="System downtime, excessive costs, service degradation",
            complexity="medium",
            probability=0.50,
            potential_damage=SeverityLevel.HIGH,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_agentic_threat][:2]
        ))

        return paths

    def _mcp_attack_paths(
        self,
        asset: AssetInput,
        vulnerabilities: List[Vulnerability]
    ) -> List[AttackPath]:
        """Generate MCP (Model Context Protocol) specific attack paths"""

        paths = []

        # Path 1: Malicious MCP Server
        paths.append(AttackPath(
            name="Malicious MCP Server Supply Chain Attack",
            description="Attacker provides compromised MCP server that agent connects to",
            entry_point="MCP server installation or configuration",
            intermediate_steps=[
                "Create malicious MCP server package (typosquatting or compromised)",
                "Publish to npm/PyPI with similar name to legitimate package",
                "Agent installs and connects to malicious MCP server",
                "Malicious server provides backdoored tools to agent",
                "Server logs all tool parameters and agent data",
                "Exfiltrate sensitive data through MCP responses",
                "Execute malicious code through compromised tools"
            ],
            target="Complete agent compromise via malicious MCP",
            impact="Data exfiltration, backdoor access, agent manipulation",
            complexity="medium",
            probability=0.35,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_mcp_threat][:2]
        ))

        # Path 2: MCP Filesystem Tool Abuse
        paths.append(AttackPath(
            name="MCP Filesystem Tool Abuse for Credential Theft",
            description="Attacker uses prompt injection to abuse filesystem MCP tools",
            entry_point="User prompt influencing agent's tool usage",
            intermediate_steps=[
                "Identify agent has access to filesystem MCP tools",
                "Craft legitimate-sounding request for file access",
                "Request sensitive files (.env, .aws/credentials, .ssh/id_rsa)",
                "Agent uses filesystem_read MCP tool to access files",
                "Sensitive credentials returned in MCP response",
                "Agent includes credentials in response to attacker",
                "Attacker uses credentials for further exploitation"
            ],
            target="Credential and secrets theft via MCP tools",
            impact="Credential exposure, unauthorized access, lateral movement",
            complexity="low",
            probability=0.85,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_mcp_threat][:2]
        ))

        # Path 3: MCP Parameter Injection
        paths.append(AttackPath(
            name="MCP Parameter Injection to Command Execution",
            description="Attacker injects malicious parameters into MCP tool calls",
            entry_point="User input that becomes MCP tool parameter",
            intermediate_steps=[
                "Identify MCP tools that accept user-influenced parameters",
                "Craft input with injection payload (e.g., command injection)",
                "Agent passes unsanitized input to MCP tool parameter",
                "MCP tool executes with attacker-controlled parameter",
                "Achieve command injection, path traversal, or SQL injection",
                "Execute arbitrary commands or access unauthorized data",
                "Establish persistence or exfiltrate sensitive information"
            ],
            target="Arbitrary command execution via MCP parameter injection",
            impact="Remote code execution, system compromise, data breach",
            complexity="medium",
            probability=0.70,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_mcp_threat][:2]
        ))

        # Path 4: MCP Response Poisoning
        paths.append(AttackPath(
            name="MCP Response Poisoning for Agent Manipulation",
            description="Attacker poisons data returned by MCP tools to manipulate agent behavior",
            entry_point="Data source consumed by MCP tool (database, web search, API)",
            intermediate_steps=[
                "Compromise data source used by MCP tool (e.g., inject into database)",
                "Embed malicious instructions in data (e.g., web search result)",
                "Agent calls MCP tool to retrieve data",
                "MCP tool returns poisoned data with embedded instructions",
                "Agent processes poisoned data as legitimate information",
                "Embedded instructions override agent's behavior",
                "Agent executes malicious actions based on poisoned data"
            ],
            target="Agent behavior manipulation through poisoned MCP data",
            impact="Agent compromise, unauthorized actions, data exfiltration",
            complexity="high",
            probability=0.45,
            potential_damage=SeverityLevel.HIGH,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_mcp_threat][:2]
        ))

        # Path 5: MCP Tool Chaining for Privilege Escalation
        paths.append(AttackPath(
            name="MCP Tool Chaining Attack for Privilege Escalation",
            description="Attacker chains multiple MCP tools to escalate privileges",
            entry_point="Multiple MCP tools available to agent",
            intermediate_steps=[
                "Identify sequence of MCP tools that can be chained",
                "Use web_search MCP to find credentials in pastebin/leak",
                "Use filesystem_read MCP to access local config files",
                "Use database_query MCP to extract sensitive data",
                "Use code_execution MCP to run malicious script",
                "Chain tool outputs as inputs to subsequent tools",
                "Achieve privilege escalation through tool composition"
            ],
            target="Privilege escalation via MCP tool chaining",
            impact="Elevated privileges, unauthorized access, system control",
            complexity="high",
            probability=0.50,
            potential_damage=SeverityLevel.HIGH,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_mcp_threat][:3]
        ))

        # Path 6: MCP Authentication Bypass
        paths.append(AttackPath(
            name="MCP Authentication Bypass for Cross-Agent Access",
            description="Attacker bypasses MCP authentication to use other agents' tools",
            entry_point="Weak MCP authentication mechanism",
            intermediate_steps=[
                "Identify weak authentication between agent and MCP server",
                "Exploit missing/weak API key validation",
                "Impersonate legitimate agent to MCP server",
                "Access MCP tools without proper authorization",
                "Use Agent A's credentials to access Agent B's MCP tools",
                "Execute privileged operations across agent boundaries",
                "Achieve cross-agent compromise and lateral movement"
            ],
            target="MCP authentication bypass and cross-agent access",
            impact="Unauthorized MCP access, privilege escalation, multi-agent compromise",
            complexity="medium",
            probability=0.40,
            potential_damage=SeverityLevel.CRITICAL,
            vulnerabilities=[v.vuln_id for v in vulnerabilities if v.is_mcp_threat][:2]
        ))

        return paths
