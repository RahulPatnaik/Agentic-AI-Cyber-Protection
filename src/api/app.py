"""
FastAPI Application
Main API server for Agentic Threat Modeling System
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
from pathlib import Path
import asyncio
import structlog

from src.config import Settings
from src.parsers.nlp_parser import NLPParser
from src.agents.orchestrator import ThreatModelingOrchestrator
from src.models.threats import ThreatModel, AssetInput

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


# Startup/Shutdown Events

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting Agentic Threat Modeling System")
    logger.info("Mistral API configured", api_key_set=bool(settings.mistral_api_key))
    logger.info("Agents initialized", agent_count=4)


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
