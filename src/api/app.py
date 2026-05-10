"""
FastAPI Application
Main API server for Agentic Threat Modeling System
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
from pathlib import Path
import asyncio
import structlog
from datetime import datetime
import json
import os

from src.config import Settings
from src.parsers.nlp_parser import NLPParser
from src.agents.orchestrator import ThreatModelingOrchestrator
from src.models.threats import ThreatModel, AssetInput
from src.integrations.github_integration import GitHubIntegration
from src.utils.compliance_report_generator import generate_compliance_html_report

# Initialize logger
logger = structlog.get_logger()

# Load settings
settings = Settings()

# Initialize FastAPI app
app = FastAPI(
    title="Agentic Threat Modeling System",
    description="AI-Powered Security Threat Analysis using Pydantic AI, Mistral AI, OWASP Top 10, CWE, and MAESTRO",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for dashboard
dashboard_path = Path(__file__).parent.parent.parent / "dashboard"
if dashboard_path.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")

# Initialize components
nlp_parser = NLPParser(settings)
orchestrator = ThreatModelingOrchestrator(settings)
github_integration = GitHubIntegration()

# In-memory storage (would be database in production)
threat_models_db: dict[UUID, ThreatModel] = {}


# Request/Response Models
class AnalyzeRequest(BaseModel):
    """Request model for threat analysis"""
    description: str = Field(
        ...,
        description="Natural language description of the system/feature/requirement",
        min_length=10,
        max_length=10000
    )
    code_snippet: Optional[str] = Field(
        None,
        description="Optional code snippet to analyze"
    )
    compliance_requirements: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks to check (HIPAA, FDA, NIST, GDPR, etc.)"
    )


class AnalyzeResponse(BaseModel):
    """Response model for threat analysis"""
    model_id: UUID
    status: str
    message: str
    summary: Optional[dict] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    agents_status: dict


# API Endpoints

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint"""
    return {
        "message": "Agentic Threat Modeling System API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health"
    }


@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint.

    Returns system status and agent availability.
    """
    try:
        agent_status = orchestrator.get_agent_status()

        return HealthResponse(
            status="healthy",
            version="1.0.0",
            agents_status=agent_status
        )
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(status_code=503, detail="Service unavailable")


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_threat(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze a system/feature/requirement for security threats.

    This endpoint:
    1. Parses natural language input using Mistral AI
    2. Runs multi-agent threat analysis (OWASP, Attack Tree, CWE, MAESTRO)
    3. Generates interactive threat graph
    4. Identifies top 5-10 critical vulnerabilities with remediation

    Args:
        request: Analysis request with description and optional code snippet

    Returns:
        Analysis response with model ID and summary
    """
    logger.info("Received analysis request", description_length=len(request.description))

    try:
        # Step 1: Parse natural language input
        logger.info("Parsing input with NLP Parser")
        asset = await nlp_parser.parse_description(
            description=request.description,
            code_snippet=request.code_snippet
        )

        # Add compliance requirements
        if request.compliance_requirements:
            asset.compliance_requirements = request.compliance_requirements

        # Step 2: Run multi-agent analysis
        logger.info("Starting multi-agent threat modeling")
        threat_model = await orchestrator.analyze(asset)

        # Store in database
        threat_models_db[threat_model.model_id] = threat_model

        logger.info(
            "Analysis complete",
            model_id=str(threat_model.model_id),
            vulnerabilities=len(threat_model.top_vulnerabilities),
            duration=threat_model.analysis_duration_seconds
        )

        # Build summary response
        summary = {
            "total_vulnerabilities": len(threat_model.vulnerabilities),
            "critical_vulnerabilities": len([
                v for v in threat_model.vulnerabilities
                if v.severity.value == "critical"
            ]),
            "high_vulnerabilities": len([
                v for v in threat_model.vulnerabilities
                if v.severity.value == "high"
            ]),
            "attack_paths": len(threat_model.attack_paths),
            "critical_paths": len(threat_model.critical_paths),
            "confidence_score": threat_model.confidence_score,
            "analysis_duration": threat_model.analysis_duration_seconds,
            "top_vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "cwe_id": v.cwe_id,
                    "owasp_category": v.owasp_category.value,
                    "cvss_score": v.cvss_score,
                    "risk_score": v.risk_score
                }
                for v in threat_model.top_vulnerabilities[:5]  # Top 5 for summary
            ]
        }

        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="complete",
            message=f"Analysis complete. Found {len(threat_model.top_vulnerabilities)} critical vulnerabilities.",
            summary=summary
        )

    except Exception as e:
        logger.error("Analysis failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@app.get("/api/models/{model_id}", response_model=ThreatModel, tags=["Models"])
async def get_threat_model(model_id: UUID):
    """
    Retrieve a complete threat model by ID.

    Args:
        model_id: UUID of the threat model

    Returns:
        Complete ThreatModel with all vulnerabilities, attack paths, and analysis
    """
    logger.info("Retrieving threat model", model_id=str(model_id))

    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    return threat_models_db[model_id]


@app.get("/api/models/{model_id}/vulnerabilities", tags=["Models"])
async def get_vulnerabilities(model_id: UUID, top_only: bool = False):
    """
    Get vulnerabilities for a threat model.

    Args:
        model_id: UUID of the threat model
        top_only: If True, return only top 5-10 critical vulnerabilities

    Returns:
        List of vulnerabilities
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    if top_only:
        return {
            "model_id": str(model_id),
            "vulnerabilities": threat_model.top_vulnerabilities
        }
    else:
        return {
            "model_id": str(model_id),
            "vulnerabilities": threat_model.vulnerabilities
        }


@app.get("/api/models/{model_id}/attack-paths", tags=["Models"])
async def get_attack_paths(model_id: UUID):
    """
    Get attack paths for a threat model.

    Args:
        model_id: UUID of the threat model

    Returns:
        List of attack paths
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    return {
        "model_id": str(model_id),
        "attack_paths": threat_model.attack_paths,
        "critical_paths": threat_model.critical_paths
    }


@app.get("/api/models/{model_id}/compliance-report", response_class=HTMLResponse, tags=["Compliance"])
async def get_compliance_report(model_id: UUID):
    """
    Generate and download a comprehensive compliance report in HTML format.
    Can be printed to PDF from browser.

    Args:
        model_id: UUID of the threat model

    Returns:
        HTML compliance report
    """
    logger.info("Generating compliance report", model_id=str(model_id))

    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    if not threat_model.compliance_checks:
        raise HTTPException(
            status_code=400,
            detail="No compliance analysis performed for this threat model. Please re-run analysis with compliance requirements."
        )

    try:
        # Generate HTML report
        html_content = generate_compliance_html_report(threat_model)
        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error("Error generating compliance report", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate compliance report: {str(e)}"
        )


@app.get("/api/models/{model_id}/graph", tags=["Models"])
async def get_threat_graph(model_id: UUID):
    """
    Get D3.js-compatible threat graph for visualization.

    Args:
        model_id: UUID of the threat model

    Returns:
        Threat graph structure with nodes and edges
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    if not threat_model.threat_graph:
        raise HTTPException(status_code=404, detail="Threat graph not available")

    return threat_model.threat_graph


@app.get("/api/models/{model_id}/cwe", tags=["Models"])
async def get_cwe_references(model_id: UUID):
    """
    Get CWE references for a threat model.

    Args:
        model_id: UUID of the threat model

    Returns:
        List of CWE references with mitigation strategies
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    return {
        "model_id": str(model_id),
        "cwe_references": threat_model.cwe_references
    }


@app.get("/api/models", tags=["Models"])
async def list_threat_models(limit: int = 50, offset: int = 0):
    """
    List all threat models.

    Args:
        limit: Maximum number of models to return
        offset: Offset for pagination

    Returns:
        List of threat model summaries
    """
    models = list(threat_models_db.values())

    # Sort by timestamp (most recent first)
    models.sort(key=lambda m: m.timestamp, reverse=True)

    # Apply pagination
    paginated = models[offset:offset + limit]

    summaries = [
        {
            "model_id": str(model.model_id),
            "timestamp": model.timestamp.isoformat(),
            "component_type": model.component_type.value if model.component_type else None,
            "vulnerabilities_count": len(model.vulnerabilities),
            "critical_count": len([v for v in model.vulnerabilities if v.severity.value == "critical"]),
            "confidence_score": model.confidence_score
        }
        for model in paginated
    ]

    return {
        "total": len(models),
        "limit": limit,
        "offset": offset,
        "models": summaries
    }


@app.delete("/api/models/{model_id}", tags=["Models"])
async def delete_threat_model(model_id: UUID):
    """
    Delete a threat model.

    Args:
        model_id: UUID of the threat model

    Returns:
        Success message
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    del threat_models_db[model_id]
    logger.info("Deleted threat model", model_id=str(model_id))

    return {"message": "Threat model deleted successfully", "model_id": str(model_id)}


@app.post("/api/analyze/code", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_code_snippet(code: str, description: Optional[str] = None):
    """
    Analyze a code snippet for vulnerabilities.

    Args:
        code: Code snippet to analyze
        description: Optional description of what the code does

    Returns:
        Analysis response with vulnerabilities found
    """
    logger.info("Analyzing code snippet", code_length=len(code))

    try:
        threat_model = await orchestrator.analyze_code_snippet(code, description or "")

        threat_models_db[threat_model.model_id] = threat_model

        summary = {
            "total_vulnerabilities": len(threat_model.vulnerabilities),
            "critical_vulnerabilities": len([v for v in threat_model.vulnerabilities if v.severity.value == "critical"]),
            "top_vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "cwe_id": v.cwe_id,
                    "line": v.vulnerable_code_line
                }
                for v in threat_model.top_vulnerabilities[:5]
            ]
        }

        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="complete",
            message=f"Code analysis complete. Found {len(threat_model.top_vulnerabilities)} vulnerabilities.",
            summary=summary
        )

    except Exception as e:
        logger.error("Code analysis failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Code analysis failed: {str(e)}")


# Error Handlers

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"message": "Resource not found", "detail": str(exc)}
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error("Internal server error", error=str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error", "detail": "An unexpected error occurred"}
    )


@app.post("/api/reports/{model_id}/pdf", tags=["Reports"])
async def generate_pdf_report(model_id: UUID):
    """
    Generate a PDF report for a threat model.

    Args:
        model_id: UUID of the threat model

    Returns:
        PDF file download
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    try:
        # Create reports directory if it doesn't exist
        reports_dir = Path(settings.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Generate HTML report content
        html_content = generate_html_report(threat_model)

        # Save as HTML (simple PDF alternative for demo)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_report_{model_id}_{timestamp}.html"
        filepath = reports_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info("PDF report generated", model_id=str(model_id), filepath=str(filepath))

        return FileResponse(
            path=filepath,
            filename=filename,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.error("PDF generation failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


def generate_html_report(threat_model: ThreatModel) -> str:
    """Generate HTML report from threat model"""

    # Build vulnerabilities HTML
    vulns_html = ""
    for i, vuln in enumerate(threat_model.top_vulnerabilities, 1):
        vulns_html += f"""
        <div class="vulnerability {vuln.severity.value}">
            <h3>{i}. {vuln.title}</h3>
            <p class="severity">Severity: <strong>{vuln.severity.value.upper()}</strong></p>
            <p>{vuln.description}</p>
            <div class="meta">
                <p><strong>CWE:</strong> {vuln.cwe_id} - {vuln.cwe_name}</p>
                <p><strong>OWASP:</strong> {vuln.owasp_category.value}</p>
                <p><strong>CVSS Score:</strong> {vuln.cvss_score}/10</p>
                <p><strong>Risk Score:</strong> {vuln.risk_score}/10</p>
                <p><strong>Attack Vector:</strong> {vuln.attack_vector}</p>
            </div>
            <div class="remediation">
                <h4>Remediation:</h4>
                <p>{vuln.recommendation}</p>
            </div>
        </div>
        """

    # Build attack paths HTML
    paths_html = ""
    for i, path in enumerate(threat_model.attack_paths[:5], 1):
        steps_html = " → ".join(path.intermediate_steps)
        paths_html += f"""
        <div class="attack-path">
            <h4>Path {i}: {path.entry_point} → {path.target}</h4>
            <p class="steps">{steps_html}</p>
            <p class="damage"><strong>Potential Damage:</strong> {path.potential_damage}</p>
        </div>
        """

    # Build CWE references HTML
    cwe_html = ""
    for cwe in threat_model.cwe_references[:10]:
        cwe_html += f"""
        <div class="cwe-item">
            <h4>{cwe.cwe_id}: {cwe.cwe_name}</h4>
            <p>{cwe.description}</p>
        </div>
        """

    # Build complete HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Threat Model Report - {threat_model.model_id}</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                margin: 40px;
                background: #f5f5f5;
                color: #333;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 8px;
                margin-bottom: 30px;
            }}
            h1 {{ margin: 0; font-size: 32px; }}
            .meta-info {{ margin-top: 15px; opacity: 0.9; }}
            .section {{
                background: white;
                padding: 25px;
                margin-bottom: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .section h2 {{
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
                margin-top: 0;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 15px;
                margin: 20px 0;
            }}
            .stat-card {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
            }}
            .stat-value {{
                font-size: 36px;
                font-weight: bold;
                margin: 10px 0;
            }}
            .stat-label {{
                font-size: 12px;
                text-transform: uppercase;
                opacity: 0.9;
            }}
            .vulnerability {{
                border-left: 5px solid #ccc;
                padding: 15px;
                margin: 15px 0;
                background: #f9f9f9;
            }}
            .vulnerability.critical {{
                border-left-color: #dc2626;
                background: #fef2f2;
            }}
            .vulnerability.high {{
                border-left-color: #ea580c;
                background: #fff7ed;
            }}
            .vulnerability.medium {{
                border-left-color: #f59e0b;
                background: #fffbeb;
            }}
            .vulnerability h3 {{
                margin-top: 0;
                color: #1f2937;
            }}
            .severity {{
                font-size: 14px;
                color: #6b7280;
            }}
            .meta, .remediation {{
                margin-top: 15px;
                padding: 10px;
                background: white;
                border-radius: 4px;
            }}
            .attack-path {{
                background: #f9fafb;
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
                border: 1px solid #e5e7eb;
            }}
            .steps {{
                font-family: monospace;
                background: white;
                padding: 10px;
                border-radius: 4px;
                margin: 10px 0;
            }}
            .cwe-item {{
                background: #f9fafb;
                padding: 12px;
                margin: 8px 0;
                border-radius: 4px;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                padding: 20px;
                color: #6b7280;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>THREAT MODEL REPORT</h1>
            <div class="meta-info">
                <p><strong>Model ID:</strong> {threat_model.model_id}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p><strong>Component Type:</strong> {threat_model.component_type.value if threat_model.component_type else 'N/A'}</p>
                <p><strong>Confidence Score:</strong> {threat_model.confidence_score * 100:.1f}%</p>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-value">{len(threat_model.vulnerabilities)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-value">{len([v for v in threat_model.vulnerabilities if v.severity.value == 'critical'])}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Attack Paths</div>
                <div class="stat-value">{len(threat_model.attack_paths)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Analysis Duration</div>
                <div class="stat-value">{threat_model.analysis_duration_seconds:.1f}s</div>
            </div>
        </div>

        <div class="section">
            <h2>Top Vulnerabilities</h2>
            {vulns_html if vulns_html else '<p>No vulnerabilities found.</p>'}
        </div>

        <div class="section">
            <h2>Attack Paths</h2>
            {paths_html if paths_html else '<p>No attack paths identified.</p>'}
        </div>

        <div class="section">
            <h2>CWE References</h2>
            {cwe_html if cwe_html else '<p>No CWE references available.</p>'}
        </div>

        <div class="footer">
            <p>Generated with Agentic Threat Modeling System</p>
            <p>Powered by Pydantic AI • Mistral AI • OWASP Top 10 • CWE Database</p>
            <p>TECHGIUM Security Operations</p>
        </div>
    </body>
    </html>
    """

    return html


# GitHub Integration Endpoints

class GitHubIssueRequest(BaseModel):
    """Request to create GitHub issue from vulnerability"""
    repo_owner: str = Field(..., description="GitHub repository owner")
    repo_name: str = Field(..., description="GitHub repository name")
    vulnerability_title: str = Field(..., description="Vulnerability title to create issue from")


class GitHubPRCommentRequest(BaseModel):
    """Request to comment on GitHub PR"""
    repo_owner: str = Field(..., description="GitHub repository owner")
    repo_name: str = Field(..., description="GitHub repository name")
    pr_number: int = Field(..., description="Pull request number")
    model_id: UUID = Field(..., description="Threat model ID to comment about")


@app.post("/api/github/create-issue/{model_id}", tags=["GitHub"])
async def create_github_issue(
    model_id: UUID,
    request: GitHubIssueRequest
):
    """
    Create a GitHub issue from a vulnerability

    Args:
        model_id: Threat model ID
        request: GitHub issue creation request

    Returns:
        Issue URL if successful
    """
    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    # Find the vulnerability by title
    vulnerability = None
    for vuln in threat_model.vulnerabilities:
        if vuln.title == request.vulnerability_title:
            vulnerability = vuln
            break

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    try:
        issue_url = await github_integration.create_issue_from_vulnerability(
            repo_owner=request.repo_owner,
            repo_name=request.repo_name,
            vulnerability=vulnerability
        )

        if issue_url:
            return {
                "success": True,
                "issue_url": issue_url,
                "message": "GitHub issue created successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create GitHub issue")

    except Exception as e:
        logger.error("GitHub issue creation failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/comment-pr", tags=["GitHub"])
async def comment_on_github_pr(request: GitHubPRCommentRequest):
    """
    Add threat analysis comment to a GitHub Pull Request

    Args:
        request: PR comment request

    Returns:
        Success status
    """
    if request.model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[request.model_id]

    try:
        success = await github_integration.comment_on_pr(
            repo_owner=request.repo_owner,
            repo_name=request.repo_name,
            pr_number=request.pr_number,
            threat_model=threat_model
        )

        if success:
            return {
                "success": True,
                "message": f"Comment added to PR #{request.pr_number}"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to comment on PR")

    except Exception as e:
        logger.error("GitHub PR comment failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/workflow", tags=["GitHub"])
async def get_github_actions_workflow():
    """
    Get GitHub Actions workflow YAML for automated threat modeling

    Returns:
        GitHub Actions workflow YAML content
    """
    workflow_yaml = github_integration.generate_github_actions_workflow()

    return {
        "filename": ".github/workflows/threat-modeling.yml",
        "content": workflow_yaml,
        "instructions": """
1. Create a `.github/workflows/` directory in your repository
2. Save the workflow content as `threat-modeling.yml`
3. Add repository secrets:
   - MISTRAL_API_KEY: Your Mistral API key
   - NVD_API_KEY: Your NVD API key
4. The workflow will run on every pull request
"""
    }


class LocalFileAnalyzeRequest(BaseModel):
    """Request model for local file/directory analysis"""
    file_path: str = Field(
        ...,
        description="Absolute or relative path to file or directory to analyze"
    )
    description: Optional[str] = Field(
        None,
        description="Optional description of what the file/code does"
    )
    recursive: bool = Field(
        default=False,
        description="If path is a directory, analyze all files recursively"
    )
    compliance_requirements: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks to check (NIST_AI_RMF, OWASP_ASVS, NIST_800_53, etc.)"
    )


class GitHubFixPRRequest(BaseModel):
    """Request to create PR with automated fixes"""
    repo_owner: str = Field(..., description="GitHub repository owner")
    repo_name: str = Field(..., description="GitHub repository name")
    base_branch: str = Field(default="main", description="Base branch to create PR against")


@app.post("/api/analyze/local-file", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_local_file(request: LocalFileAnalyzeRequest):
    """
    Analyze local file(s) on the file system for security vulnerabilities.

    This endpoint can analyze:
    - Single files (.py, .js, .ts, .java, .go, .cpp, etc.)
    - Entire directories (with recursive option)

    Args:
        request: Local file analysis request with file path

    Returns:
        Analysis response with vulnerabilities found in the file(s)
    """
    logger.info("Analyzing local file(s)", file_path=request.file_path)

    try:
        # Resolve the file path
        file_path = Path(request.file_path)

        # Security check: ensure the path exists
        if not file_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"File or directory not found: {request.file_path}"
            )

        files_to_analyze = []

        # Check if it's a file or directory
        if file_path.is_file():
            files_to_analyze.append(file_path)
        elif file_path.is_dir():
            if request.recursive:
                # Recursively find all code files
                code_extensions = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go',
                                 '.cpp', '.c', '.h', '.hpp', '.rs', '.rb', '.php',
                                 '.cs', '.swift', '.kt', '.scala', '.sql', '.sh', '.yaml', '.yml'}
                for ext in code_extensions:
                    files_to_analyze.extend(file_path.rglob(f'*{ext}'))
            else:
                # Only immediate children
                code_extensions = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go',
                                 '.cpp', '.c', '.h', '.hpp', '.rs', '.rb', '.php',
                                 '.cs', '.swift', '.kt', '.scala', '.sql', '.sh', '.yaml', '.yml'}
                for item in file_path.iterdir():
                    if item.is_file() and item.suffix in code_extensions:
                        files_to_analyze.append(item)

        if not files_to_analyze:
            raise HTTPException(
                status_code=400,
                detail="No code files found to analyze"
            )

        logger.info(f"Found {len(files_to_analyze)} file(s) to analyze")

        # Read file contents
        combined_code = ""
        file_summaries = []

        for file in files_to_analyze[:20]:  # Limit to 20 files to avoid overwhelming the system
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    combined_code += f"\n\n# File: {file.name}\n{content}\n"
                    file_summaries.append({
                        "filename": file.name,
                        "path": str(file),
                        "size": len(content),
                        "lines": len(content.splitlines())
                    })
            except Exception as e:
                logger.warning(f"Could not read file {file}: {e}")
                continue

        if not combined_code:
            raise HTTPException(
                status_code=400,
                detail="Could not read any file contents"
            )

        # Build description
        description = request.description or f"Security analysis of local file(s): {', '.join([f.name for f in files_to_analyze[:5]])}"

        # Analyze using the orchestrator with compliance requirements
        threat_model = await orchestrator.analyze_code_snippet(
            combined_code,
            description,
            compliance_requirements=request.compliance_requirements
        )

        # Add file information to the threat model metadata
        threat_model.metadata = {
            "source": "local_filesystem",
            "files_analyzed": file_summaries,
            "total_files": len(files_to_analyze),
            "base_path": str(file_path)
        }

        # Store in database
        threat_models_db[threat_model.model_id] = threat_model

        logger.info(
            "Local file analysis complete",
            model_id=str(threat_model.model_id),
            files_count=len(files_to_analyze),
            vulnerabilities=len(threat_model.vulnerabilities)
        )

        # Build summary response
        summary = {
            "files_analyzed": len(files_to_analyze),
            "base_path": str(file_path),
            "total_vulnerabilities": len(threat_model.vulnerabilities),
            "critical_vulnerabilities": len([
                v for v in threat_model.vulnerabilities if v.severity.value == "critical"
            ]),
            "high_vulnerabilities": len([
                v for v in threat_model.vulnerabilities if v.severity.value == "high"
            ]),
            "top_vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "cwe_id": v.cwe_id,
                    "file": v.vulnerable_code_line,
                    "risk_score": v.risk_score
                }
                for v in threat_model.top_vulnerabilities[:5]
            ]
        }

        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="complete",
            message=f"Local file analysis complete. Analyzed {len(files_to_analyze)} file(s) and found {len(threat_model.top_vulnerabilities)} vulnerabilities.",
            summary=summary
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Local file analysis failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Local file analysis failed: {str(e)}"
        )


@app.post("/api/github/create-fix-pr/{model_id}", tags=["GitHub"])
async def create_fix_pr(
    model_id: UUID,
    request: GitHubFixPRRequest
):
    """
    Create a Pull Request with automated security fixes

    Args:
        model_id: UUID of the threat model
        request: GitHub PR creation request with repo details

    Returns:
        PR URL and details
    """
    logger.info("Creating fix PR", model_id=str(model_id), repo=f"{request.repo_owner}/{request.repo_name}")

    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    if not threat_model.top_vulnerabilities:
        raise HTTPException(status_code=400, detail="No vulnerabilities found to fix")

    try:
        pr_url = await github_integration.create_fix_pr(
            repo_owner=request.repo_owner,
            repo_name=request.repo_name,
            vulnerabilities=threat_model.top_vulnerabilities,
            base_branch=request.base_branch
        )

        if pr_url:
            return {
                "success": True,
                "pr_url": pr_url,
                "message": f"Security fix PR created successfully with {len(threat_model.top_vulnerabilities[:5])} vulnerability fixes",
                "fixes_count": min(5, len(threat_model.top_vulnerabilities))
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create fix PR")

    except Exception as e:
        logger.error("Fix PR creation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create fix PR: {str(e)}")


# Startup/Shutdown Events

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting Agentic Threat Modeling System")
    logger.info("Mistral API configured", api_key_set=bool(settings.mistral_api_key))
    logger.info("GitHub integration configured", github_token_set=bool(github_integration.github_token))
    logger.info("Agents initialized", agent_count=9)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Agentic Threat Modeling System")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )
