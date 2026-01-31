"""
Agent Orchestrator
Coordinates multiple Pydantic AI agents for comprehensive threat modeling
"""

import asyncio
from typing import List, Dict
from datetime import datetime
import time
import structlog

from src.models.threats import (
    AssetInput,
    ThreatModel,
    AgentAnalysis,
    Vulnerability,
    AttackPath,
    CWEReference
)
from src.config import Settings
from src.agents.owasp_agent import OWASPAnalyzer
from src.agents.attack_tree_agent import AttackTreeAnalyzer
from src.agents.cwe_agent import CWEAnalyzer
from src.agents.maestro_agent import MAESTROValidator
from src.agents.dfd_builder_agent import DFDBuilder
from src.agents.threat_generator import AutomatedThreatGenerator

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
        self.owasp_analyzer = OWASPAnalyzer(settings)
        self.attack_tree_analyzer = AttackTreeAnalyzer(settings)
        self.cwe_analyzer = CWEAnalyzer(settings)
        self.maestro_validator = MAESTROValidator(settings)

        logger.info("Initialized Threat Modeling Orchestrator with 6 agents (including DFD builder)")

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
            logger.info("Phase 0: Building Data Flow Diagram from system description")
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

            # Generate Mermaid DFD diagram for visualization
            dfd_diagram = self.dfd_builder.generate_mermaid_dfd(dfd)

            # Phase 1: OWASP Analysis
            logger.info("Phase 1: Running OWASP analysis")
            owasp_analysis = await self.owasp_analyzer.analyze(asset)
            owasp_vulnerabilities = owasp_analysis.vulnerabilities_found

            # Merge automated threats with OWASP analysis results
            vulnerabilities = automated_threats + owasp_vulnerabilities

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

            # Phase 2: Run remaining agents in parallel
            logger.info("Phase 2: Running attack tree, CWE, and MAESTRO agents in parallel")

            attack_tree_task = asyncio.create_task(
                self.attack_tree_analyzer.analyze(asset, vulnerabilities)
            )
            cwe_task = asyncio.create_task(
                self.cwe_analyzer.analyze(asset, vulnerabilities)
            )
            maestro_task = asyncio.create_task(
                self.maestro_validator.analyze(asset, vulnerabilities)
            )

            # Wait for all agents to complete
            attack_tree_analysis, cwe_analysis, maestro_analysis = await asyncio.gather(
                attack_tree_task,
                cwe_task,
                maestro_task,
                return_exceptions=True
            )

            # Handle any exceptions from parallel execution
            if isinstance(attack_tree_analysis, Exception):
                logger.error("Attack tree analysis failed", error=str(attack_tree_analysis))
                attack_tree_analysis = AgentAnalysis(
                    agent_name="Attack Tree Analyzer",
                    agent_type="attack_tree",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            if isinstance(cwe_analysis, Exception):
                logger.error("CWE analysis failed", error=str(cwe_analysis))
                cwe_analysis = AgentAnalysis(
                    agent_name="CWE Analyzer",
                    agent_type="cwe_analyzer",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            if isinstance(maestro_analysis, Exception):
                logger.error("MAESTRO validation failed", error=str(maestro_analysis))
                maestro_analysis = AgentAnalysis(
                    agent_name="MAESTRO Validator",
                    agent_type="maestro",
                    findings=["Analysis failed"],
                    vulnerabilities_found=[],
                    confidence=0.0,
                    reasoning="Error occurred"
                )

            logger.info("All agent analyses complete")

            # Generate attack paths
            attack_paths = self.attack_tree_analyzer._generate_attack_paths(asset, vulnerabilities)

            # Generate CWE references
            cwe_references = self.cwe_analyzer._generate_cwe_references(asset, vulnerabilities)

            # Build threat graph for visualization (includes DFD + attack paths)
            attack_tree_graph = self.attack_tree_analyzer.build_graph_structure(attack_paths)

            # Combine DFD diagram with attack tree graph
            threat_graph = {
                "dfd_diagram": dfd_diagram,
                "attack_tree": attack_tree_graph,
                "type": "combined"
            }

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
            agent_analyses = {
                "dfd_builder": f"Built DFD with {len(dfd.processes)} processes, {len(dfd.data_stores)} data stores, {len(dfd.data_flows)} data flows, {len(dfd.trust_boundaries)} trust boundaries",
                "threat_generator": f"Generated {len(automated_threats)} automated threats from DFD structure",
                "owasp": owasp_analysis.reasoning,
                "attack_tree": attack_tree_analysis.reasoning,
                "cwe": cwe_analysis.reasoning,
                "maestro": maestro_analysis.reasoning
            }

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
                compliance_checks=[],  # Can be enhanced with compliance checking
                top_vulnerabilities=top_vulnerabilities,
                critical_paths=critical_paths,
                analysis_duration_seconds=duration,
                agent_analyses=agent_analyses,
                confidence_score=confidence_score,
                threat_graph=threat_graph
            )

            logger.info(
                "Threat modeling complete",
                duration_seconds=duration,
                total_vulnerabilities=len(vulnerabilities),
                top_vulnerabilities=len(top_vulnerabilities),
                attack_paths=len(attack_paths),
                confidence=confidence_score
            )

            return threat_model

        except Exception as e:
            logger.error("Orchestration failed", error=str(e), exc_info=True)
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

    async def analyze_code_snippet(self, code: str, description: str = "") -> ThreatModel:
        """
        Analyze a code snippet for vulnerabilities.

        Args:
            code: Code snippet to analyze
            description: Optional description of what the code does

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
            frameworks=[]
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
