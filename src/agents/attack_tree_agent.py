"""
Attack Tree Generator Agent
Uses Pydantic AI with Mistral to generate attack paths and scenarios
"""

from pydantic_ai import Agent, RunContext
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


# Define the Attack Tree Agent
attack_tree_agent = Agent(
    'mistral:mistral-large-latest',
    system_prompt="""You are an expert attack path analyst specializing in constructing attack trees and threat scenarios.

Your role:
1. Analyze systems to identify potential attack paths
2. Map entry points to impacts through intermediate steps
3. Assess attack complexity and probability
4. Prioritize the most critical attack paths

Attack Tree Methodology:
- Root: Attacker's goal (data exfiltration, privilege escalation, etc.)
- Intermediate Nodes: Steps required to reach goal
- Leaves: Initial entry points and vulnerabilities
- Edges: Dependencies and attack flow

Guidelines:
- Focus on realistic, high-probability attack scenarios
- Consider attacker skill level and resources required
- Map attack paths to MITRE ATT&CK tactics
- Provide concrete, actionable defense strategies
- Calculate risk based on complexity and impact

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
            # Run the agent
            result = await attack_tree_agent.run(prompt)
            analysis = result.data

            # Generate structured attack paths
            attack_paths = self._generate_attack_paths(asset, vulnerabilities)

            return AgentAnalysis(
                agent_name="Attack Tree Analyzer",
                agent_type="attack_tree",
                findings=analysis.findings if hasattr(analysis, 'findings') else [
                    f"Generated {len(attack_paths)} attack paths",
                    "Identified critical attack vectors",
                    "Mapped attack progression scenarios"
                ],
                vulnerabilities_found=[],  # Attack tree doesn't find new vulns
                confidence=0.85,
                reasoning=analysis.reasoning if hasattr(analysis, 'reasoning') else "Attack path analysis complete"
            )

        except Exception as e:
            logger.error("Attack tree analysis failed", error=str(e))
            return AgentAnalysis(
                agent_name="Attack Tree Analyzer",
                agent_type="attack_tree",
                findings=[f"Analysis failed: {str(e)}"],
                vulnerabilities_found=[],
                confidence=0.0,
                reasoning="Analysis encountered an error"
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

        # Generate multi-step attack paths (chaining vulnerabilities)
        attack_paths.extend(self._chained_attack_paths(asset, vulnerabilities))

        return attack_paths[:7]  # Return top 7 paths

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
