"""
Agent Orchestrator
Coordinates multiple Pydantic AI agents for comprehensive threat modeling
"""

import asyncio
from typing import List, Dict
from datetime import datetime
import time
import structlog
from dotenv import load_dotenv

# Load environment variables before importing agents
load_dotenv()

from src.models.threats import (
    AssetInput,
    ThreatModel,
    AgentAnalysis,
    Vulnerability,
    AttackPath,
    CWEReference,
    ComplianceCheck
)
from src.config import Settings
from src.agents.owasp_agent import OWASPAnalyzer
from src.agents.attack_tree_agent import AttackTreeAnalyzer
from src.agents.cwe_agent import CWEAnalyzer
from src.agents.maestro_agent import MAESTROValidator
from src.agents.dfd_builder_agent import DFDBuilder
from src.agents.threat_generator import AutomatedThreatGenerator
from src.agents.stride_agent import STRIDEAgent
from src.agents.symbolic_verifier import SymbolicVerifier
from src.agents.cve_scanner import CVEScanner
from src.agents.agentic_security_agent import AgenticSecurityAnalyzer
from src.agents.compliance_agent import analyze_compliance, generate_compliance_summary

logger = structlog.get_logger()


class ThreatModelingOrchestrator:
    """
    Orchestrates multiple specialized agents for comprehensive threat modeling.

    Workflow (Enhanced with DFD):
    1. DFD Builder: Create Data Flow Diagram from description
    2. Automated Threat Generator: Generate threats from DFD structure
    3. OWASP Analyzer: Identify OWASP Top 10 vulnerabilities
    4. Attack Tree Analyzer: Generate attack paths from vulnerabilities
    5. CWE Analyzer: Map vulnerabilities to CWE database
    6. MAESTRO Validator: Validate against security principles

    All agents run in parallel where possible for optimal performance.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

        # Initialize all agents
        self.dfd_builder = DFDBuilder(settings)
        self.threat_generator = AutomatedThreatGenerator(settings)
        self.stride_agent = STRIDEAgent(settings)
        self.owasp_analyzer = OWASPAnalyzer(settings)
        self.attack_tree_analyzer = AttackTreeAnalyzer(settings)
        self.cwe_analyzer = CWEAnalyzer(settings)
        self.maestro_validator = MAESTROValidator(settings)
        self.symbolic_verifier = SymbolicVerifier()
        self.cve_scanner = CVEScanner(nvd_api_key=settings.nvd_api_key)
        self.agentic_analyzer = AgenticSecurityAnalyzer(settings)

        logger.info("Initialized Threat Modeling Orchestrator with 10 agents (DFD, STRIDE, OWASP, Attack Tree, CWE, MAESTRO, Symbolic Verifier, CVE Scanner, Agentic Security)")

    async def analyze(self, asset: AssetInput) -> ThreatModel:
        """
        Perform comprehensive threat modeling analysis using multiple agents.

        Args:
            asset: Structured asset input from NLP parser

        Returns:
            Complete ThreatModel with vulnerabilities, attack paths, and recommendations
        """
        start_time = time.time()
        logger.info("Starting multi-agent threat modeling", component=asset.component_type)

        try:
            # Phase 0: Build DFD and generate automated threats (OWASP pytm-style)
            logger.warning("🔷 PHASE 0: Building Data Flow Diagram from system description")
            dfd = await self.dfd_builder.build_dfd(asset)

            logger.info(
                "DFD built successfully",
                processes=len(dfd.processes),
                data_stores=len(dfd.data_stores),
                data_flows=len(dfd.data_flows),
                trust_boundaries=len(dfd.trust_boundaries)
            )

            logger.info("Generating automated threats from DFD structure")
            automated_threats = self.threat_generator.generate_threats(dfd)

            logger.info(
                "Automated threat generation complete",
                threats_generated=len(automated_threats)
            )

            # Generate Mermaid DFD diagram for visualization (will be updated with vulnerabilities later)
            dfd_diagram = None  # Will be generated after we have all vulnerabilities

            # Phase 1: STRIDE Analysis
            logger.warning("🔷 PHASE 1: Running STRIDE threat analysis")
            stride_threats = await self.stride_agent.analyze_system(
                system_description=asset.description,
                components=[{
                    'name': p.name,
                    'type': 'Process',
                    'description': p.description or asset.description
                } for p in dfd.processes] if dfd.processes else None
            )

            logger.info(
                "STRIDE analysis complete",
                stride_threats=len(stride_threats)
            )

            # Phase 2: OWASP Analysis
            logger.warning("🔷 PHASE 2: Running OWASP analysis")
            owasp_analysis = await self.owasp_analyzer.analyze(asset)
            owasp_vulnerabilities = owasp_analysis.vulnerabilities_found

            # Convert STRIDE Threat objects to Vulnerability objects
            stride_vulnerabilities = []
            for threat in stride_threats:
                from src.models.threats import Vulnerability
                from uuid import uuid4
                vuln = Vulnerability(
                    vuln_id=uuid4(),
                    title=threat.title,
                    description=threat.description,
                    severity=threat.severity,
                    cvss_score=8.0 if threat.severity.value == "critical" else 7.0 if threat.severity.value == "high" else 5.0,
                    cwe_id=threat.cwe_id or "CWE-1000",
                    cwe_name=threat.cwe_name or "Unknown Weakness",
                    owasp_category=threat.owasp_category,
                    attack_vector=threat.attack_vector or "Unknown",
                    impact=threat.impact or "Security compromise",
                    affected_component="System Component",
                    recommendation=threat.recommendation or "Implement security controls",
                    likelihood=threat.likelihood or "medium",
                    risk_score=8.0,
                    exploitability=threat.exploitability or "moderate"
                )
                stride_vulnerabilities.append(vuln)

            # Merge automated threats with STRIDE and OWASP analysis results
            vulnerabilities = automated_threats + stride_vulnerabilities + owasp_vulnerabilities

            # Deduplicate based on CWE ID and title
            seen = set()
            unique_vulnerabilities = []
            for vuln in vulnerabilities:
                key = (vuln.cwe_id, vuln.title)
                if key not in seen:
                    seen.add(key)
                    unique_vulnerabilities.append(vuln)

            vulnerabilities = unique_vulnerabilities

            logger.info(
                "OWASP analysis complete",
                owasp_vulnerabilities=len(owasp_vulnerabilities),
                automated_threats=len(automated_threats),
                total_vulnerabilities=len(vulnerabilities),
                confidence=owasp_analysis.confidence
            )

            # Phase 3: Run remaining agents in parallel (Attack Tree, CWE, MAESTRO, Agentic Security, Symbolic Verification)
            logger.warning("🔷 PHASE 3: Running attack tree, CWE, MAESTRO, agentic security, and symbolic verification agents in parallel")

            attack_tree_task = asyncio.create_task(
                self.attack_tree_analyzer.analyze(asset, vulnerabilities)
            )
            cwe_task = asyncio.create_task(
                self.cwe_analyzer.analyze(asset, vulnerabilities)
            )
            maestro_task = asyncio.create_task(
                self.maestro_validator.analyze(asset, vulnerabilities)
            )
            agentic_task = asyncio.create_task(
                self.agentic_analyzer.analyze(asset, vulnerabilities)
            )

            # Symbolic verification - extract security features AND Z3 variables from DFD
            security_features = self.symbolic_verifier.extract_security_features(asset.description)
            z3_variables = self.symbolic_verifier.extract_z3_variables_from_dfd(dfd)  # 🔥 NEW!
            symbolic_task = asyncio.create_task(
                self.symbolic_verifier.verify_system_security_with_dfd(
                    asset.description,
                    security_features,
                    z3_variables  # Pass extracted variables
                )
            )

            # Wait for all agents to complete
            attack_tree_analysis, cwe_analysis, maestro_analysis, agentic_analysis, symbolic_verification = await asyncio.gather(
                attack_tree_task,
                cwe_task,
                maestro_task,
                agentic_task,
                symbolic_task,
                return_exceptions=True
            )

            # Handle any exceptions from parallel execution
            if isinstance(attack_tree_analysis, Exception):
                logger.error("❌ Attack tree analysis failed", error=str(attack_tree_analysis), exc_info=True)
                attack_tree_analysis = AgentAnalysis(
                    agent_name="Attack Tree Analyzer",
                    agent_type="attack_tree",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            if isinstance(cwe_analysis, Exception):
                logger.error("❌ CWE analysis failed", error=str(cwe_analysis), exc_info=True)
                cwe_analysis = AgentAnalysis(
                    agent_name="CWE Analyzer",
                    agent_type="cwe_analyzer",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            if isinstance(maestro_analysis, Exception):
                logger.error("❌ MAESTRO validation failed", error=str(maestro_analysis), exc_info=True)
                maestro_analysis = AgentAnalysis(
                    agent_name="MAESTRO Validator",
                    agent_type="maestro",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            if isinstance(agentic_analysis, Exception):
                logger.error("❌ Agentic security analysis failed", error=str(agentic_analysis), exc_info=True)
                agentic_analysis = AgentAnalysis(
                    agent_name="Agentic Security Analyzer",
                    agent_type="ai_safety",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            if isinstance(symbolic_verification, Exception):
                logger.error("❌ Symbolic verification failed", error=str(symbolic_verification), exc_info=True)
                symbolic_verification = []

            # Merge agentic vulnerabilities into main list
            if agentic_analysis and agentic_analysis.vulnerabilities_found:
                logger.info(f"Adding {len(agentic_analysis.vulnerabilities_found)} agentic-specific vulnerabilities")
                vulnerabilities.extend(agentic_analysis.vulnerabilities_found)

            logger.info("All agent analyses complete")

            # Phase 4: CVE Enrichment (run in parallel for top vulnerabilities)
            logger.warning("🔷 PHASE 4: Enriching vulnerabilities with CVE data from NVD API")
            cve_enrichment_tasks = []
            for vuln in vulnerabilities[:10]:  # Enrich top 10 vulnerabilities
                task = asyncio.create_task(
                    self.cve_scanner.enrich_vulnerability_with_cves(
                        vulnerability_description=vuln.description,
                        cwe_id=vuln.cwe_id
                    )
                )
                cve_enrichment_tasks.append((vuln, task))

            # Wait for CVE enrichment
            for vuln, task in cve_enrichment_tasks:
                try:
                    related_cves = await task
                    if related_cves and not hasattr(vuln, 'related_cves'):
                        # Store related CVEs in vulnerability metadata
                        if not vuln.metadata:
                            vuln.metadata = {}
                        vuln.metadata['related_cves'] = [
                            {"cve_id": cve.cve_id, "cvss_score": cve.cvss_score, "severity": cve.severity}
                            for cve in related_cves
                        ]
                except Exception as e:
                    logger.warning("⚠️ CVE enrichment failed for vulnerability", vuln_title=vuln.title, error=str(e))

            # Use attack paths from the LLM analysis if available
            if attack_tree_analysis and hasattr(attack_tree_analysis, 'analysis_metadata') and attack_tree_analysis.analysis_metadata:
                attack_paths = attack_tree_analysis.analysis_metadata.get('attack_paths', [])
                logger.info(f"Using {len(attack_paths)} LLM-generated attack paths")
            else:
                # Fallback to hardcoded paths only if LLM analysis failed
                logger.warning("No LLM attack paths available, using hardcoded fallback")
                attack_paths = self.attack_tree_analyzer._generate_attack_paths(asset, vulnerabilities)

            # Generate CWE references
            cwe_references = self.cwe_analyzer._generate_cwe_references(asset, vulnerabilities)

            # NOW generate DFD diagram with all vulnerabilities highlighted
            dfd_diagram = self.dfd_builder.generate_mermaid_dfd(dfd, vulnerabilities)

            # Build threat graph for visualization (includes DFD + attack paths)
            attack_tree_graph = self.attack_tree_analyzer.build_graph_structure(attack_paths)

            # Combine DFD diagram with attack tree graph
            threat_graph = {
                "dfd_diagram": dfd_diagram,
                "attack_tree": attack_tree_graph,
                "type": "combined"
            }

            # Debug: Log what we're sending to frontend
            logger.warning(f"📤 Sending to frontend - DFD diagram (first 300 chars):\n{dfd_diagram[:300]}")
            logger.warning(f"📤 DFD diagram length: {len(dfd_diagram)} characters")
            logger.warning(f"📤 Attack paths generated: {len(attack_paths)}")
            logger.warning(f"📤 Attack tree nodes: {len(attack_tree_graph.get('nodes', []))}")

            # Select top 5-10 critical vulnerabilities
            top_vulnerabilities = self._select_top_vulnerabilities(vulnerabilities)

            # Select critical attack paths
            critical_paths = self._select_critical_paths(attack_paths)

            # Calculate overall confidence score
            confidence_score = self._calculate_confidence(
                owasp_analysis,
                attack_tree_analysis,
                cwe_analysis,
                maestro_analysis
            )

            # Build agent analyses summary
            symbolic_summary = f"Verified {len(symbolic_verification)} security properties" if symbolic_verification else "Symbolic verification skipped"
            if symbolic_verification:
                verified_count = sum(1 for r in symbolic_verification if r.verified)
                symbolic_summary += f" ({verified_count}/{len(symbolic_verification)} passed)"

            agent_analyses = {
                "dfd_builder": f"Built DFD with {len(dfd.processes)} processes, {len(dfd.data_stores)} data stores, {len(dfd.data_flows)} data flows, {len(dfd.trust_boundaries)} trust boundaries",
                "threat_generator": f"Generated {len(automated_threats)} automated threats from DFD structure",
                "stride": f"STRIDE analysis identified {len(stride_threats)} threats across 6 categories",
                "owasp": owasp_analysis.reasoning,
                "attack_tree": attack_tree_analysis.reasoning,
                "cwe": cwe_analysis.reasoning,
                "maestro": maestro_analysis.reasoning,
                "symbolic_verifier": symbolic_summary,
                "cve_scanner": f"CVE enrichment added for {sum(1 for v in vulnerabilities if v.metadata and 'related_cves' in v.metadata)} vulnerabilities"
            }

            # Phase 4: Compliance Analysis (if compliance requirements provided)
            compliance_checks = []
            if asset.compliance_requirements:
                logger.warning(f"🔷 PHASE 4: Running compliance analysis for frameworks: {asset.compliance_requirements}")

                # Build initial threat model for compliance agent
                temp_threat_model = ThreatModel(
                    asset_description=asset.description,
                    component_type=asset.component_type,
                    vulnerabilities=vulnerabilities,
                    attack_paths=attack_paths,
                    threat_actors=[],
                    cwe_references=cwe_references,
                    compliance_checks=[],
                    top_vulnerabilities=top_vulnerabilities,
                    critical_paths=critical_paths,
                    analysis_duration_seconds=0,
                    agent_analyses=agent_analyses,
                    confidence_score=confidence_score,
                    threat_graph=threat_graph
                )

                try:
                    # Run compliance analysis
                    compliance_results = await analyze_compliance(
                        temp_threat_model,
                        asset.compliance_requirements
                    )

                    # Flatten all controls from all frameworks
                    for result in compliance_results:
                        compliance_checks.extend(result.controls)

                    # Generate summary
                    compliance_summary = generate_compliance_summary(compliance_results)
                    logger.info(
                        "Compliance analysis complete",
                        frameworks=compliance_summary['frameworks_analyzed'],
                        total_controls=compliance_summary['total_controls_checked'],
                        avg_compliance=compliance_summary['average_compliance_score']
                    )

                    # Add compliance analysis to agent analyses
                    agent_analyses["compliance"] = (
                        f"Analyzed {compliance_summary['total_controls_checked']} controls across "
                        f"{compliance_summary['total_frameworks']} frameworks. "
                        f"Average compliance: {compliance_summary['average_compliance_score']}%. "
                        f"Critical gaps: {compliance_summary['priority_breakdown']['critical']}"
                    )

                except Exception as e:
                    logger.error(f"Error during compliance analysis: {e}")

            # Calculate analysis duration
            duration = time.time() - start_time

            # Build complete threat model
            threat_model = ThreatModel(
                asset_description=asset.description,
                component_type=asset.component_type,
                vulnerabilities=vulnerabilities,
                attack_paths=attack_paths,
                threat_actors=[],  # Can be enhanced with threat actor profiling
                cwe_references=cwe_references,
                compliance_checks=compliance_checks,
                top_vulnerabilities=top_vulnerabilities,
                critical_paths=critical_paths,
                analysis_duration_seconds=duration,
                agent_analyses=agent_analyses,
                confidence_score=confidence_score,
                threat_graph=threat_graph
            )

            logger.warning(
                "✅ Threat modeling complete",
                duration_seconds=round(duration, 2),
                total_vulnerabilities=len(vulnerabilities),
                top_vulnerabilities=len(top_vulnerabilities),
                attack_paths=len(attack_paths),
                compliance_checks=len(compliance_checks),
                confidence=confidence_score
            )

            return threat_model

        except Exception as e:
            logger.error("❌ ❌ ❌ ORCHESTRATION FAILED ❌ ❌ ❌", error=str(e))
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error location: {e.__traceback__.tb_frame.f_code.co_filename}:{e.__traceback__.tb_lineno}")
            import traceback
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            raise

    def _select_top_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Select top 5-10 critical vulnerabilities based on risk score.

        Args:
            vulnerabilities: List of all identified vulnerabilities

        Returns:
            Top 5-10 vulnerabilities sorted by risk score
        """
        # Sort by risk score (descending)
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: (v.risk_score, v.cvss_score),
            reverse=True
        )

        # Return top 10 (or fewer if less than 10 total)
        return sorted_vulns[:10]

    def _select_critical_paths(
        self,
        attack_paths: List[AttackPath]
    ) -> List[AttackPath]:
        """
        Select critical attack paths based on probability and damage.

        Args:
            attack_paths: List of all identified attack paths

        Returns:
            Top 3-5 critical attack paths
        """
        # Calculate risk score: probability × damage severity
        severity_scores = {
            'critical': 10,
            'high': 7,
            'medium': 5,
            'low': 2,
            'none': 0
        }

        def path_risk_score(path: AttackPath) -> float:
            damage_score = severity_scores.get(path.potential_damage.value, 5)
            return path.probability * damage_score

        # Sort by risk score
        sorted_paths = sorted(
            attack_paths,
            key=path_risk_score,
            reverse=True
        )

        return sorted_paths[:5]

    def _calculate_confidence(
        self,
        owasp_analysis: AgentAnalysis,
        attack_tree_analysis: AgentAnalysis,
        cwe_analysis: AgentAnalysis,
        maestro_analysis: AgentAnalysis
    ) -> float:
        """
        Calculate overall confidence score from agent analyses.

        Args:
            owasp_analysis, attack_tree_analysis, cwe_analysis, maestro_analysis: Agent results

        Returns:
            Weighted average confidence score (0.0-1.0)
        """
        # Weight each agent's contribution
        weights = {
            'owasp': 0.35,      # OWASP is most critical
            'attack_tree': 0.25,
            'cwe': 0.25,
            'maestro': 0.15
        }

        weighted_sum = (
            owasp_analysis.confidence * weights['owasp'] +
            attack_tree_analysis.confidence * weights['attack_tree'] +
            cwe_analysis.confidence * weights['cwe'] +
            maestro_analysis.confidence * weights['maestro']
        )

        return round(weighted_sum, 2)

    async def analyze_code_snippet(self, code: str, description: str = "", compliance_requirements: List[str] = None) -> ThreatModel:
        """
        Analyze a code snippet for vulnerabilities.

        Args:
            code: Code snippet to analyze
            description: Optional description of what the code does
            compliance_requirements: Optional list of compliance frameworks to check

        Returns:
            ThreatModel with code-specific vulnerabilities
        """
        logger.info("Analyzing code snippet", code_length=len(code))

        # Create AssetInput for code analysis
        asset = AssetInput(
            description=description or "Code snippet analysis",
            code_snippet=code,
            component_type=None,  # Will be inferred
            programming_languages=[],
            frameworks=[],
            compliance_requirements=compliance_requirements or []
        )

        return await self.analyze(asset)

    async def batch_analyze(self, assets: List[AssetInput]) -> List[ThreatModel]:
        """
        Analyze multiple assets in parallel.

        Args:
            assets: List of assets to analyze

        Returns:
            List of ThreatModels
        """
        logger.info("Starting batch analysis", asset_count=len(assets))

        # Respect max concurrent agents setting
        semaphore = asyncio.Semaphore(self.settings.max_agents_concurrent)

        async def analyze_with_semaphore(asset: AssetInput) -> ThreatModel:
            async with semaphore:
                return await self.analyze(asset)

        # Run analyses in parallel (respecting concurrency limit)
        threat_models = await asyncio.gather(
            *[analyze_with_semaphore(asset) for asset in assets],
            return_exceptions=True
        )

        # Filter out exceptions
        successful_models = [
            model for model in threat_models
            if not isinstance(model, Exception)
        ]

        logger.info(
            "Batch analysis complete",
            total=len(assets),
            successful=len(successful_models),
            failed=len(assets) - len(successful_models)
        )

        return successful_models

    def get_agent_status(self) -> Dict[str, str]:
        """Get status of all agents"""
        return {
            "owasp_analyzer": "ready",
            "attack_tree_analyzer": "ready",
            "cwe_analyzer": "ready",
            "maestro_validator": "ready",
            "status": "operational"
        }
