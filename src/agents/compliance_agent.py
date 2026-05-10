"""
Compliance Agent - LLM-powered compliance mapping and remediation

Maps security findings to compliance frameworks (NIST AI RMF, OWASP ASVS, NIST 800-53, ISO 27001)
and provides actionable remediation guidance.
"""
import logging
from typing import List, Optional
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from src.models.threats import (
    ThreatModel,
    ComplianceCheck,
    CodeFix,
    Vulnerability,
)

logger = logging.getLogger(__name__)


class ComplianceAnalysisResult(BaseModel):
    """Result from compliance analysis"""
    framework: str
    controls: List[ComplianceCheck]
    overall_compliance_score: float  # 0-100%
    executive_summary: str


class ComplianceDeps(BaseModel):
    """Dependencies for compliance agent"""
    framework: str
    threat_model: ThreatModel


# Compliance mapping agent
compliance_agent = Agent(
    'mistral:mistral-large-latest',  # Use same model as other agents
    output_type=ComplianceAnalysisResult,  # 🔥 STRUCTURED OUTPUT
    deps_type=ComplianceDeps,
    system_prompt="""You are an expert security compliance auditor and remediation specialist.

Your role is to:
1. Analyze security vulnerabilities and map them to compliance framework controls
2. Determine compliance status (compliant, non_compliant, partial, not_applicable)
3. Provide detailed gap analysis explaining WHY controls are violated
4. Suggest specific, actionable remediation steps with code examples
5. Prioritize fixes by risk and effort

When analyzing:
- Be SPECIFIC: Don't say "implement encryption" - say "Use TLS 1.3 with AES-256-GCM cipher suites"
- Provide code fixes where applicable with before/after examples
- Reference actual vulnerabilities found as evidence
- Estimate realistic implementation effort
- Use the compliance framework's terminology and control IDs

Frameworks you support:
- NIST AI RMF: AI-specific risk management (prompt injection, data poisoning, model theft)
- OWASP ASVS: Application Security Verification Standard (3 levels)
- NIST 800-53: Federal security controls (AC, IA, SC, SI, etc.)
- ISO 27001: International security management standard
- GDPR: EU data protection (Art. 25, Art. 32, Art. 33)

Output structured JSON matching the ComplianceAnalysisResult model with the following structure:
{
    "framework": "NIST_AI_RMF",
    "controls": [list of ComplianceCheck objects],
    "overall_compliance_score": 0-100,
    "executive_summary": "2-3 sentence summary"
}""",
)


def condense_threat_model(threat_model: ThreatModel) -> str:
    """Condense threat model to key findings for LLM context"""

    # Extract critical and high severity vulnerabilities
    critical_vulns = [v for v in threat_model.vulnerabilities if v.severity == "critical"]
    high_vulns = [v for v in threat_model.vulnerabilities if v.severity == "high"]

    summary_parts = []

    # System description
    summary_parts.append(f"SYSTEM DESCRIPTION:\n{threat_model.asset_description}\n")

    # Critical vulnerabilities
    if critical_vulns:
        summary_parts.append("CRITICAL VULNERABILITIES:")
        for v in critical_vulns[:5]:  # Top 5
            summary_parts.append(f"- {v.title} (CWE-{v.cwe_id}): {v.description}")
            summary_parts.append(f"  Impact: {v.impact}")

    # High vulnerabilities
    if high_vulns:
        summary_parts.append("\nHIGH SEVERITY VULNERABILITIES:")
        for v in high_vulns[:5]:  # Top 5
            summary_parts.append(f"- {v.title} (CWE-{v.cwe_id}): {v.description}")

    # Attack paths
    if threat_model.attack_paths:
        summary_parts.append(f"\nATTACK PATHS: {len(threat_model.attack_paths)} identified")
        for path in threat_model.attack_paths[:3]:  # Top 3
            summary_parts.append(f"- {path.description}")

    # CWE references
    if threat_model.cwe_references:
        cwe_list = ", ".join([f"CWE-{cwe.cwe_id}" for cwe in threat_model.cwe_references[:10]])
        summary_parts.append(f"\nCWE CATEGORIES: {cwe_list}")

    # Existing mitigations
    all_mitigations = set()
    for v in threat_model.vulnerabilities:
        # Safely get mitigation_strategies (some vulnerabilities might not have this field)
        if hasattr(v, 'mitigation_strategies') and v.mitigation_strategies:
            all_mitigations.update(v.mitigation_strategies)

    if all_mitigations:
        summary_parts.append(f"\nEXISTING MITIGATIONS: {len(all_mitigations)} strategies identified")

    return "\n".join(summary_parts)


def get_framework_guidance(framework: str) -> str:
    """Get framework-specific guidance for the LLM"""

    guidance = {
        "NIST_AI_RMF": """
NIST AI Risk Management Framework (2023):
Focus on AI-specific risks:
- MAP: Identify AI system risks (data poisoning, model theft, adversarial examples)
- MEASURE: Assess AI risks quantitatively
- MANAGE: Prioritize and respond to AI risks
- GOVERN: Establish AI governance and accountability

Key areas:
- Prompt injection and jailbreaking
- Training data poisoning
- Model extraction/theft
- Adversarial examples
- Bias and fairness
- Explainability and transparency
- Supply chain risks (model dependencies)
""",
        "OWASP_ASVS": """
OWASP Application Security Verification Standard:
Use format: ASVS-[Chapter].[Section].[Number]

Key chapters:
- ASVS-1: Architecture, Design and Threat Modeling
- ASVS-2: Authentication
- ASVS-3: Session Management
- ASVS-4: Access Control
- ASVS-5: Validation, Sanitization and Encoding
- ASVS-8: Data Protection
- ASVS-9: Communication Security
- ASVS-10: Malicious Code
- ASVS-14: Configuration

Verification levels:
- L1: Basic security (opportunistic attackers)
- L2: Standard security (skilled attackers)
- L3: High security (advanced persistent threats)
""",
        "NIST_800_53": """
NIST 800-53 Rev 5 Security Controls:
Use format: [FAMILY]-[NUMBER]

Key control families:
- AC: Access Control (AC-2, AC-3, AC-6)
- IA: Identification and Authentication (IA-2, IA-5, IA-8)
- SC: System and Communications Protection (SC-8, SC-13, SC-28)
- SI: System and Information Integrity (SI-3, SI-10, SI-16)
- AU: Audit and Accountability (AU-2, AU-3, AU-12)
- CM: Configuration Management (CM-2, CM-6, CM-7)
- RA: Risk Assessment (RA-3, RA-5)
- SA: System and Services Acquisition (SA-11, SA-15)
""",
        "ISO_27001": """
ISO 27001:2022 Annex A Controls:
Use format: A.[Domain].[Number]

Key domains:
- A.5: Organizational controls
- A.6: People controls
- A.7: Physical controls
- A.8: Technological controls
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.8.3: Information access restriction
  - A.8.8: Management of technical vulnerabilities
  - A.8.24: Use of cryptography
  - A.8.25: Secure development lifecycle
""",
        "GDPR": """
GDPR (EU General Data Protection Regulation):
Focus on:
- Art. 25: Data protection by design and by default
- Art. 32: Security of processing (technical and organizational measures)
- Art. 33: Notification of personal data breach
- Art. 35: Data protection impact assessment

Key requirements:
- Pseudonymization and encryption
- Confidentiality, integrity, availability
- Data minimization
- Purpose limitation
- Storage limitation
"""
    }

    return guidance.get(framework, "")


async def analyze_compliance(
    threat_model: ThreatModel,
    frameworks: List[str]
) -> List[ComplianceAnalysisResult]:
    """
    Analyze threat model against compliance frameworks

    Args:
        threat_model: Complete threat model from orchestrator
        frameworks: List of frameworks to check (e.g., ["NIST_AI_RMF", "OWASP_ASVS"])

    Returns:
        List of compliance analysis results, one per framework
    """
    logger.info(f"Starting compliance analysis for frameworks: {frameworks}")

    # Condense threat model to manageable size for LLM
    condensed_findings = condense_threat_model(threat_model)

    compliance_results = []

    for framework in frameworks:
        logger.info(f"Analyzing compliance for {framework}")

        try:
            # Get framework-specific guidance
            framework_guidance = get_framework_guidance(framework)

            # Build prompt
            prompt = f"""Analyze the following security findings against {framework} compliance requirements.

{framework_guidance}

SECURITY FINDINGS:
{condensed_findings}

TASK:
1. Identify 5-10 most relevant controls from {framework}
2. For each control, determine:
   - Control ID and name
   - Compliance status (compliant/non_compliant/partial/not_applicable)
   - Detailed finding explaining the gap
   - Evidence from the security findings
   - Specific remediation steps (be detailed and actionable)
   - Code fixes where applicable (with before/after examples)
   - Priority (critical/high/medium/low)
   - Estimated effort (e.g., "2-4 hours", "1 week")

3. Calculate overall compliance score (percentage of controls that are compliant or partial)
4. Write a 2-3 sentence executive summary

Return the result as structured JSON matching the ComplianceAnalysisResult format.
Focus on the most critical gaps that need immediate attention."""

            # Run compliance agent - returns ComplianceAnalysisResult via structured output
            result = await compliance_agent.run(
                prompt,
                deps=ComplianceDeps(
                    framework=framework,
                    threat_model=threat_model
                )
            )

            # Extract structured result (Pydantic AI returns ComplianceAnalysisResult in .output)
            compliance_result: ComplianceAnalysisResult = result.output
            compliance_results.append(compliance_result)
            logger.info(f"Completed {framework} analysis: {len(compliance_result.controls)} controls mapped")

        except Exception as e:
            logger.error(f"Error analyzing {framework} compliance: {e}")
            # Return empty result on error
            compliance_results.append(ComplianceAnalysisResult(
                framework=framework,
                controls=[],
                overall_compliance_score=0.0,
                executive_summary=f"Error analyzing {framework} compliance: {str(e)}"
            ))

    return compliance_results


def generate_compliance_summary(results: List[ComplianceAnalysisResult]) -> dict:
    """Generate summary statistics across all frameworks"""

    total_controls = sum(len(r.controls) for r in results)
    avg_compliance = sum(r.overall_compliance_score for r in results) / len(results) if results else 0

    # Count by status
    status_counts = {"compliant": 0, "non_compliant": 0, "partial": 0, "not_applicable": 0}
    priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for result in results:
        for control in result.controls:
            status_counts[control.status] += 1
            priority_counts[control.priority] += 1

    return {
        "total_frameworks": len(results),
        "total_controls_checked": total_controls,
        "average_compliance_score": round(avg_compliance, 1),
        "status_breakdown": status_counts,
        "priority_breakdown": priority_counts,
        "frameworks_analyzed": [r.framework for r in results]
    }
