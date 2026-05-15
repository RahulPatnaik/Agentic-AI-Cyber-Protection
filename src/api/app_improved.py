"""
Improved FastAPI application with tree-sitter chunking integration.
Key changes:
1. Replaces naive string concatenation with tree-sitter chunking
2. Uses ChromaDB for vector storage and retrieval
3. Integrates improved NLP parser with instructor
4. Uses PyGithub for better GitHub integration
"""

import os
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, HTTPException, BackgroundTasks, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
import structlog

# Import the core modules
from src.agents.orchestrator import ThreatModelingOrchestrator
from src.config import Settings
from src.models.threats import AssetInput, ThreatModel

# Import the new improved modules
from src.utils.local_ingestion import ingest_local_files, CodeChunker
from src.parsers.nlp_parser_cerebras import CerebrasFastParser as ImprovedNLPParser  # Use Cerebras
from src.integrations.github_integration_improved import ImprovedGitHubIntegration
from src.integrations.github_integration import GitHubIntegration  # For issue creation
from src.api.mcp_replay_router import router as mcp_replay_router
from src.parsers.dfd_upload_parser import parse_uploaded_dfd

# Initialize logging
logger = structlog.get_logger()

# Initialize settings
settings = Settings()

# Initialize GitHub integration for issue creation
github_integration = GitHubIntegration()

# Initialize FastAPI app
app = FastAPI(
    title="Agentic Threat Modeling API - Improved",
    description="Advanced AI-powered threat modeling with tree-sitter code chunking",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for dashboard
dashboard_path = Path(__file__).parent.parent.parent / "dashboard"
if dashboard_path.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")
    logger.info(f"Dashboard mounted from {dashboard_path}")
else:
    logger.warning(f"Dashboard directory not found at {dashboard_path}")

# Mount MCP attack-replay router (powers /dashboard/mcp_replay.html)
app.include_router(mcp_replay_router)

# In-memory storage for threat models
threat_models_db: Dict[UUID, ThreatModel] = {}


class LocalFileAnalyzeRequest(BaseModel):
    """Request model for local file analysis with improved chunking"""
    file_path: str = Field(..., description="Path to file or directory to analyze")
    recursive: bool = Field(True, description="If directory, analyze recursively")
    max_files: int = Field(100, description="Maximum number of files to analyze")
    use_vector_search: bool = Field(True, description="Use vector similarity for context retrieval")
    compliance_requirements: Optional[List[str]] = Field(
        default_factory=list,
        description="Compliance frameworks to check (e.g., 'GDPR', 'HIPAA', 'PCI-DSS', 'NIST AI RMF')"
    )


class GitHubAnalyzeRequest(BaseModel):
    """Request model for GitHub repository analysis"""
    repo_owner: str = Field(..., description="Repository owner (username or org)")
    repo_name: str = Field(..., description="Repository name")
    branch: str = Field("main", description="Branch to analyze")
    pr_number: Optional[int] = Field(None, description="PR number for focused analysis")
    compliance_requirements: Optional[List[str]] = Field(
        default_factory=list,
        description="Compliance frameworks to check (e.g., 'GDPR', 'HIPAA', 'PCI-DSS', 'NIST AI RMF')"
    )


class AnalyzeResponse(BaseModel):
    """Response model for analysis endpoints"""
    model_id: UUID
    status: str
    message: str
    summary: Optional[Dict[str, Any]] = None
    chunks_processed: Optional[int] = None
    collection_id: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with improved status"""
    return """
    <html>
        <head>
            <title>Agentic Threat Modeling API v2.0</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }
                .container {
                    background: white;
                    border-radius: 10px;
                    padding: 30px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }
                h1 {
                    color: #333;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 10px;
                }
                .badge {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                    margin-left: 10px;
                }
                .badge-new {
                    background: #10b981;
                    color: white;
                }
                .badge-improved {
                    background: #3b82f6;
                    color: white;
                }
                .improvements {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }
                .improvement-card {
                    background: #f3f4f6;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #667eea;
                }
                .improvement-card h3 {
                    margin-top: 0;
                    color: #4c51bf;
                }
                .endpoints {
                    background: #fef3c7;
                    border: 1px solid #fbbf24;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 20px 0;
                }
                .endpoint {
                    background: white;
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                }
                .method {
                    display: inline-block;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-weight: bold;
                    margin-right: 10px;
                }
                .post { background: #10b981; color: white; }
                .get { background: #3b82f6; color: white; }
                a {
                    color: #4c51bf;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
                .status {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 10px;
                    background: #10b981;
                    color: white;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                .status-dot {
                    width: 10px;
                    height: 10px;
                    background: white;
                    border-radius: 50%;
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="status">
                    <div class="status-dot"></div>
                    <strong>System Status: IMPROVED & OPERATIONAL</strong>
                </div>

                <h1>Agentic Threat Modeling API <span class="badge badge-improved">v2.0</span></h1>

                <h2>🚀 Key Improvements</h2>
                <div class="improvements">
                    <div class="improvement-card">
                        <h3>🌳 Tree-Sitter Chunking</h3>
                        <p>Semantic code parsing that scales to 100+ files without concatenation issues</p>
                    </div>
                    <div class="improvement-card">
                        <h3>🔍 ChromaDB Vector Storage</h3>
                        <p>Intelligent retrieval with vector similarity search for security-relevant code</p>
                    </div>
                    <div class="improvement-card">
                        <h3>📝 Instructor NLP</h3>
                        <p>Guaranteed structured output from Mistral AI - no more JSON parsing errors</p>
                    </div>
                    <div class="improvement-card">
                        <h3>🐙 PyGithub Integration</h3>
                        <p>Robust GitHub API with automatic rate limiting and pagination</p>
                    </div>
                </div>

                <h2>📚 Documentation</h2>
                <ul>
                    <li>📖 <a href="/docs">Interactive API Documentation (Swagger UI)</a></li>
                    <li>📋 <a href="/redoc">Alternative Documentation (ReDoc)</a></li>
                </ul>

                <h2>🔥 Enhanced Endpoints</h2>
                <div class="endpoints">
                    <div class="endpoint">
                        <span class="method post">POST</span>
                        <strong>/api/analyze/local-file-v2</strong>
                        <span class="badge badge-new">NEW</span>
                        <br>
                        <small>Analyze local files/directories with tree-sitter chunking</small>
                    </div>
                    <div class="endpoint">
                        <span class="method post">POST</span>
                        <strong>/api/analyze/github-v2</strong>
                        <span class="badge badge-new">NEW</span>
                        <br>
                        <small>Analyze GitHub repositories with PyGithub integration</small>
                    </div>
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <strong>/api/search/chunks</strong>
                        <span class="badge badge-new">NEW</span>
                        <br>
                        <small>Search code chunks using vector similarity</small>
                    </div>
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <strong>/api/models/{model_id}</strong>
                        <br>
                        <small>Retrieve complete threat model analysis</small>
                    </div>
                </div>

                <h2>✅ What's Fixed</h2>
                <ul>
                    <li>✅ <strong>Scalability:</strong> No more crashes with large codebases (was limited to ~5 files)</li>
                    <li>✅ <strong>JSON Parsing:</strong> Instructor ensures valid structured output every time</li>
                    <li>✅ <strong>GitHub Rate Limits:</strong> PyGithub handles rate limiting automatically</li>
                    <li>✅ <strong>File Processing:</strong> Now processes JSON, YAML config files too</li>
                </ul>

                <p style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; text-align: center;">
                    Powered by Tree-Sitter, ChromaDB, Instructor, and PyGithub
                </p>
            </div>
        </body>
    </html>
    """


@app.post("/api/analyze/local-file-v2", response_model=AnalyzeResponse, tags=["Analysis V2"])
async def analyze_local_file_v2(request: LocalFileAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Improved local file analysis with tree-sitter chunking and vector storage.

    This endpoint:
    - Chunks code using tree-sitter for semantic understanding
    - Stores chunks in ChromaDB for vector similarity search
    - Analyzes with context-aware retrieval
    - Scales to large codebases (100+ files)

    Args:
        request: Local file analysis request
        background_tasks: FastAPI background task runner

    Returns:
        Analysis response with model ID and chunking info
    """
    logger.info("Starting improved local file analysis", file_path=request.file_path)

    try:
        # Resolve the file path
        file_path = Path(request.file_path)

        if not file_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"File or directory not found: {request.file_path}"
            )

        # Determine what to analyze
        paths_to_analyze = []

        if file_path.is_file():
            paths_to_analyze = [str(file_path)]
            logger.info(f"Analyzing single file: {file_path}")
        elif file_path.is_dir():
            # Pass the directory itself, let ingest_directory handle the traversal
            paths_to_analyze = [str(file_path)]
            logger.info(f"Analyzing directory: {file_path} (recursive={request.recursive})")

        # Step 1: Ingest and chunk files using tree-sitter
        # The ingest function will handle directory traversal internally
        chunks, collection_id = ingest_local_files(paths_to_analyze)

        if not chunks:
            raise HTTPException(
                status_code=400,
                detail="No code chunks could be created from the specified path"
            )

        logger.info(f"Created {len(chunks)} code chunks, stored in collection: {collection_id}")

        # Step 2: Parse chunks into AssetInput using improved NLP parser
        nlp_parser = ImprovedNLPParser(settings)
        asset_input = await nlp_parser.parse_code_chunks(chunks)

        # Step 3: If vector search is enabled, use ChromaDB for context retrieval
        if request.use_vector_search and chunks:
            # Sample: retrieve relevant chunks for security analysis
            chunker = CodeChunker()
            security_keywords = [
                "authentication", "authorization", "password", "token", "api key",
                "sql injection", "xss", "csrf", "encryption", "vulnerable"
            ]

            relevant_chunks = []
            for keyword in security_keywords:
                search_results = chunker.search_chunks(keyword, n_results=5)
                relevant_chunks.extend(search_results)

            # Add relevant context to asset input
            if relevant_chunks:
                context_summary = "\n\nSecurity-relevant code sections found:\n"
                for chunk in relevant_chunks[:10]:  # Top 10 most relevant
                    meta = chunk['metadata']
                    context_summary += f"- {meta['type']} {meta['name']} in {meta['file_path']} (lines {meta['start_line']}-{meta['end_line']})\n"

                asset_input.description += context_summary

        # Step 3.5: Merge compliance requirements from request
        if request.compliance_requirements:
            # Add user-specified compliance requirements to what was auto-detected
            existing = set(asset_input.compliance_requirements or [])
            existing.update(request.compliance_requirements)
            asset_input.compliance_requirements = list(existing)
            logger.info(f"Compliance requirements: {asset_input.compliance_requirements}")

        # Step 4: Run threat modeling with Orchestrator
        orchestrator = ThreatModelingOrchestrator(settings)
        threat_model = await orchestrator.analyze(asset_input)

        # Store the model
        threat_models_db[threat_model.model_id] = threat_model

        # Count unique files in chunks
        unique_files = len(set(chunk.get('file_path', '') for chunk in chunks))

        # Build summary
        summary = {
            "files_analyzed": unique_files,
            "chunks_created": len(chunks),
            "collection_id": collection_id,
            "total_vulnerabilities": len(threat_model.vulnerabilities),
            "critical_vulnerabilities": len(threat_model.top_vulnerabilities),
            "confidence_score": threat_model.confidence_score,
            "top_vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id
                }
                for v in threat_model.top_vulnerabilities[:5]
            ]
        }

        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="complete",
            message=f"Analysis complete. Processed {len(chunks)} code chunks from {unique_files} files.",
            summary=summary,
            chunks_processed=len(chunks),
            collection_id=collection_id
        )

    except Exception as e:
        logger.error("Improved analysis failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/api/analyze/github-v2", response_model=AnalyzeResponse, tags=["Analysis V2"])
async def analyze_github_v2(request: GitHubAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Improved GitHub repository analysis with PyGithub and tree-sitter chunking.

    This endpoint:
    - Uses PyGithub for robust API interaction
    - Handles rate limiting automatically
    - Chunks repository code with tree-sitter
    - Can analyze PRs for focused threat assessment

    Args:
        request: GitHub analysis request
        background_tasks: FastAPI background task runner

    Returns:
        Analysis response with repository analysis results
    """
    logger.info(
        "Starting improved GitHub analysis",
        repo=f"{request.repo_owner}/{request.repo_name}",
        branch=request.branch
    )

    try:
        # Initialize GitHub integration
        github_integration = ImprovedGitHubIntegration()

        if request.pr_number:
            # Focused PR analysis
            logger.info(f"Analyzing PR #{request.pr_number}")

            # Get changed files in PR
            pr_files = await github_integration.get_pr_files(
                request.repo_owner,
                request.repo_name,
                request.pr_number
            )

            # Create temporary context from patches
            combined_patches = "\n\n".join([
                f"File: {f['filename']}\nChanges: +{f['additions']} -{f['deletions']}\n{f.get('patch', '')}"
                for f in pr_files if f.get('patch')
            ])

            # Parse with NLP
            nlp_parser = ImprovedNLPParser(settings)
            asset_input = await nlp_parser.parse_description(
                f"Pull Request #{request.pr_number} changes in {request.repo_owner}/{request.repo_name}",
                combined_patches
            )

        else:
            # Full repository analysis
            chunks, collection_id = await github_integration.fetch_repository_code(
                request.repo_owner,
                request.repo_name,
                request.branch
            )

            if not chunks:
                raise HTTPException(
                    status_code=404,
                    detail=f"No code files found or repository not accessible"
                )

            logger.info(f"Fetched and chunked {len(chunks)} code segments from repository")

            # Parse chunks into AssetInput
            nlp_parser = ImprovedNLPParser(settings)
            asset_input = await nlp_parser.parse_code_chunks(chunks)

            # Merge compliance requirements from request
            if request.compliance_requirements:
                existing = set(asset_input.compliance_requirements or [])
                existing.update(request.compliance_requirements)
                asset_input.compliance_requirements = list(existing)
                logger.info(f"Compliance requirements for GitHub analysis: {asset_input.compliance_requirements}")

        # Run threat modeling
        orchestrator = ThreatModelingOrchestrator(settings)
        threat_model = await orchestrator.analyze(asset_input)

        # Store the model
        threat_models_db[threat_model.model_id] = threat_model

        # If analyzing a PR, add comment with results
        if request.pr_number:
            background_tasks.add_task(
                github_integration.comment_on_pr,
                request.repo_owner,
                request.repo_name,
                request.pr_number,
                threat_model
            )

        # Build summary
        summary = {
            "repository": f"{request.repo_owner}/{request.repo_name}",
            "branch": request.branch,
            "pr_number": request.pr_number,
            "total_vulnerabilities": len(threat_model.vulnerabilities),
            "critical_vulnerabilities": len(threat_model.top_vulnerabilities),
            "confidence_score": threat_model.confidence_score,
            "top_vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id
                }
                for v in threat_model.top_vulnerabilities[:5]
            ]
        }

        chunks_count = len(chunks) if not request.pr_number else len(pr_files)

        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="complete",
            message=f"GitHub analysis complete. {'PR comment added.' if request.pr_number else ''}",
            summary=summary,
            chunks_processed=chunks_count
        )

    except Exception as e:
        logger.error("GitHub analysis failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"GitHub analysis failed: {str(e)}"
        )


@app.get("/api/models/{model_id}", response_model=ThreatModel, tags=["Models"])
async def get_threat_model(model_id: UUID):
    """
    Retrieve a complete threat model by ID.

    Args:
        model_id: UUID of the threat model

    Returns:
        Complete ThreatModel with all analysis results
    """
    logger.info("Retrieving threat model", model_id=str(model_id))

    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    return threat_models_db[model_id]


@app.get("/api/search/chunks", tags=["Search"])
async def search_code_chunks(
    query: str,
    collection_id: Optional[str] = None,
    limit: int = 10
):
    """
    Search code chunks using vector similarity.

    Args:
        query: Search query
        collection_id: Optional collection to search in
        limit: Number of results to return

    Returns:
        List of relevant code chunks
    """
    try:
        chunker = CodeChunker()
        results = chunker.search_chunks(query, n_results=limit)

        return {
            "query": query,
            "results": results,
            "count": len(results)
        }

    except Exception as e:
        logger.error("Search failed", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )


# ============================================
# BACKWARD COMPATIBILITY - Original endpoints using IMPROVED logic
# ============================================

class AnalyzeRequest(BaseModel):
    """Original request model for backward compatibility"""
    description: str = Field(..., description="Natural language description of the system/feature")
    code_snippet: Optional[str] = Field(None, description="Optional code snippet to analyze")
    compliance_requirements: Optional[List[str]] = Field(default_factory=list)


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_threat(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Original analyze endpoint - NOW USES IMPROVED CHUNKING!
    Maintains backward compatibility while using tree-sitter chunking.
    """
    logger.info("Original /api/analyze endpoint called - using improved logic")

    # Use improved NLP parser
    nlp_parser = ImprovedNLPParser(settings)
    asset_input = await nlp_parser.parse_description(request.description, request.code_snippet)

    # Merge compliance requirements (don't overwrite parser's detection)
    if request.compliance_requirements:
        # Add user's requirements to what parser detected
        existing = set(asset_input.compliance_requirements or [])
        existing.update(request.compliance_requirements)
        asset_input.compliance_requirements = list(existing)

    # Run analysis with improved orchestrator
    orchestrator = ThreatModelingOrchestrator(settings)
    threat_model = await orchestrator.analyze(asset_input)

    threat_models_db[threat_model.model_id] = threat_model

    summary = {
        "total_vulnerabilities": len(threat_model.vulnerabilities),
        "critical_vulnerabilities": len(threat_model.top_vulnerabilities),
        "confidence_score": threat_model.confidence_score,
        "top_vulnerabilities": [
            {
                "title": v.title,
                "severity": v.severity.value,
                "cvss_score": v.cvss_score,
                "cwe_id": v.cwe_id
            }
            for v in threat_model.top_vulnerabilities[:5]
        ]
    }

    return AnalyzeResponse(
        model_id=threat_model.model_id,
        status="complete",
        message=f"Analysis complete (using improved engine). Found {len(threat_model.top_vulnerabilities)} critical vulnerabilities.",
        summary=summary
    )


@app.post("/api/analyze/local-file", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_local_file(request: LocalFileAnalyzeRequest):
    """
    Original local file endpoint - NOW USES IMPROVED TREE-SITTER CHUNKING!
    Redirects to the v2 endpoint internally for backward compatibility.
    """
    logger.info("Original /api/analyze/local-file called - using improved v2 logic")

    # Just call the v2 endpoint with the same request
    background_tasks = BackgroundTasks()
    return await analyze_local_file_v2(request, background_tasks)


class CodeAnalyzeRequest(BaseModel):
    """Request model for code snippet analysis"""
    code: str = Field(..., description="Code snippet to analyze")


@app.post("/api/analyze/code", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_code_snippet(request: CodeAnalyzeRequest):
    """
    Original code analysis endpoint - NOW USES IMPROVED PARSING!
    """
    logger.info("Original /api/analyze/code called - using improved logic")

    # Create temporary file for tree-sitter parsing
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(request.code)
        tmp_path = tmp.name

    try:
        # Use tree-sitter chunking
        chunks, collection_id = ingest_local_files([tmp_path])

        # Parse with improved NLP
        nlp_parser = ImprovedNLPParser(settings)
        asset_input = await nlp_parser.parse_code_chunks(chunks) if chunks else await nlp_parser.parse_description("Code snippet analysis", request.code)

        # Run analysis
        orchestrator = ThreatModelingOrchestrator(settings)
        threat_model = await orchestrator.analyze(asset_input)

        threat_models_db[threat_model.model_id] = threat_model

        summary = {
            "chunks_created": len(chunks),
            "total_vulnerabilities": len(threat_model.vulnerabilities),
            "critical_vulnerabilities": len(threat_model.top_vulnerabilities),
            "top_vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id
                }
                for v in threat_model.top_vulnerabilities[:5]
            ]
        }

        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="complete",
            message="Code analysis complete using improved chunking.",
            summary=summary,
            chunks_processed=len(chunks)
        )
    finally:
        import os
        os.unlink(tmp_path)


@app.get("/api/models/{model_id}/compliance-report", response_class=HTMLResponse, tags=["Compliance"])
async def get_compliance_report(model_id: UUID):
    """
    Generate compliance report in HTML format.
    """
    logger.info("Generating compliance report", model_id=str(model_id))

    if model_id not in threat_models_db:
        raise HTTPException(status_code=404, detail="Threat model not found")

    threat_model = threat_models_db[model_id]

    if not threat_model.compliance_checks:
        raise HTTPException(
            status_code=400,
            detail="No compliance analysis performed. Re-run with compliance requirements."
        )

    try:
        from src.utils.compliance_report_generator import generate_compliance_html_report
        html_content = generate_compliance_html_report(threat_model)
        return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error("Error generating compliance report", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


# GitHub Integration Endpoints

class GitHubIssueRequest(BaseModel):
    """Request to create GitHub issue from vulnerability"""
    repo_owner: str = Field(..., description="GitHub repository owner")
    repo_name: str = Field(..., description="GitHub repository name")
    vulnerability_title: str = Field(..., description="Vulnerability title to create issue from")


class GitHubFixPRRequest(BaseModel):
    """Request to create PR with automated fixes"""
    repo_owner: str = Field(..., description="GitHub repository owner")
    repo_name: str = Field(..., description="GitHub repository name")
    base_branch: str = Field(default="main", description="Base branch to create PR against")


class DFDUploadRequest(BaseModel):
    """Request to upload custom DFD with optional code"""
    format: str = Field(..., description="Format: plantuml, mermaid, json, auto")
    content: str = Field(..., description="DFD content in specified format")
    description: str = Field(..., description="System description for context")
    code_snippet: Optional[str] = Field(None, description="Code to analyze with tree-sitter chunking")
    compliance_requirements: List[str] = Field(default=[], description="List of compliance frameworks")


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
    # Debug logging
    print(f"\n=== GitHub Issue Creation Debug ===")
    print(f"Requested model_id: {model_id}")
    print(f"Models in database: {list(str(k) for k in threat_models_db.keys())}")
    print(f"Repository: {request.repo_owner}/{request.repo_name}")
    print(f"Vulnerability title: {request.vulnerability_title}")
    print(f"Model exists: {model_id in threat_models_db}")
    print("===================================\n")

    if model_id not in threat_models_db:
        raise HTTPException(
            status_code=404,
            detail=f"Threat model {model_id} not found. Available models: {list(str(k) for k in threat_models_db.keys())}"
        )

    threat_model = threat_models_db[model_id]

    # Find the vulnerability by title
    vulnerability = None
    for vuln in threat_model.vulnerabilities:
        if vuln.title == request.vulnerability_title:
            vulnerability = vuln
            break

    if not vulnerability:
        available_vulns = [v.title for v in threat_model.vulnerabilities]
        raise HTTPException(
            status_code=404,
            detail=f"Vulnerability '{request.vulnerability_title}' not found. Available: {available_vulns}"
        )

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
            raise HTTPException(
                status_code=500,
                detail="GitHub API returned no issue URL - check permissions and token"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"GitHub API error: {str(e)}"
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


@app.post("/api/dfd/upload", response_model=AnalyzeResponse, tags=["DFD"])
async def upload_custom_dfd(request: DFDUploadRequest):
    """
    Upload a custom DFD and run threat analysis on it.
    Supports PlantUML, Mermaid, and JSON formats.
    """
    logger.info(f"DFD upload request received, format: {request.format}")

    try:
        # Parse the uploaded DFD based on format
        if request.format == "plantuml":
            # Parse PlantUML syntax
            components = []
            flows = []
            for line in request.content.split('\n'):
                if '->' in line or '-->' in line:
                    # Extract flow: source -> dest : label
                    parts = line.split('->')
                    if len(parts) == 2:
                        source = parts[0].strip().split()[-1]
                        dest_parts = parts[1].split(':')
                        dest = dest_parts[0].strip().split()[0]
                        label = dest_parts[1].strip() if len(dest_parts) > 1 else "data"
                        flows.append(f"{source} sends {label} to {dest}")
                        if source not in components:
                            components.append(source)
                        if dest not in components:
                            components.append(dest)

        elif request.format == "mermaid":
            # Parse Mermaid syntax
            components = []
            flows = []
            for line in request.content.split('\n'):
                if '-->' in line or '==>' in line:
                    # Extract: A --> B or A -->|label| B
                    parts = line.split('-->' if '-->' in line else '==>')
                    if len(parts) == 2:
                        source = parts[0].strip().split('[')[-1].replace(']', '')
                        dest_parts = parts[1].split('|')
                        if len(dest_parts) == 3:  # Has label
                            label = dest_parts[1]
                            dest = dest_parts[2].strip().split('[')[0]
                        else:
                            label = "data"
                            dest = parts[1].strip().split('[')[0]
                        flows.append(f"{source} sends {label} to {dest}")
                        if source not in components:
                            components.append(source)
                        if dest not in components:
                            components.append(dest)

        elif request.format == "json":
            # Parse JSON format
            import json
            dfd_data = json.loads(request.content)
            components = [node['name'] for node in dfd_data.get('nodes', [])]
            flows = [f"{edge['from']} sends {edge.get('protocol', 'data')} to {edge['to']}"
                    for edge in dfd_data.get('edges', [])]

        else:  # Auto-detect
            if request.content.strip().startswith('@startuml'):
                return await upload_custom_dfd(DFDUploadRequest(
                    format="plantuml",
                    content=request.content,
                    description=request.description,
                    code_snippet=request.code_snippet,
                    compliance_requirements=request.compliance_requirements
                ))
            elif 'graph' in request.content and '-->' in request.content:
                return await upload_custom_dfd(DFDUploadRequest(
                    format="mermaid",
                    content=request.content,
                    description=request.description,
                    code_snippet=request.code_snippet,
                    compliance_requirements=request.compliance_requirements
                ))
            elif request.content.strip().startswith('{'):
                return await upload_custom_dfd(DFDUploadRequest(
                    format="json",
                    content=request.content,
                    description=request.description,
                    code_snippet=request.code_snippet,
                    compliance_requirements=request.compliance_requirements
                ))
            else:
                # Default fallback - treat as description
                components = ["User Interface", "Backend API", "Database"]
                flows = ["User sends requests to Backend", "Backend queries Database"]

        # Check if code snippet is provided for tree-sitter chunking
        chunks = []
        if request.code_snippet:
            # Check if it's a GitHub URL (be more flexible with detection)
            import re
            code_stripped = request.code_snippet.strip()
            logger.info(f"Checking if code snippet is GitHub URL: '{code_stripped[:100]}...'")

            # More flexible regex - handles trailing slashes, .git, paths, etc.
            github_match = re.search(r'github\.com/([^/\s]+)/([^/\s]+)', code_stripped)

            # Also check if it just contains github.com
            is_github_url = 'github.com' in code_stripped.lower()

            if github_match and is_github_url:
                # It's a GitHub URL - fetch the actual code!
                logger.info("GitHub URL detected in code snippet, fetching repository code")
                owner, repo_name = github_match.groups()
                # Clean up repo name - remove .git, trailing slashes, and any path after repo
                repo_name = repo_name.replace('.git', '').split('/')[0].split('?')[0].split('#')[0]
                logger.info(f"Parsed GitHub URL - Owner: {owner}, Repo: {repo_name}")

                # Use GitHub integration to fetch and chunk
                from src.integrations.github_integration_improved import ImprovedGitHubIntegration
                github = ImprovedGitHubIntegration()

                try:
                    chunks, collection_id = await github.fetch_repository_code(owner, repo_name, "main")
                    logger.info(f"Successfully fetched {len(chunks)} chunks from GitHub repository {owner}/{repo_name}")

                    # Log chunk breakdown
                    chunk_types = {}
                    for chunk in chunks:
                        chunk_type = chunk.get('type', 'unknown')
                        chunk_types[chunk_type] = chunk_types.get(chunk_type, 0) + 1
                    logger.info(f"GitHub chunks breakdown: {chunk_types}")

                except Exception as e:
                    logger.error(f"Failed to fetch GitHub repo {owner}/{repo_name}: {e}")
                    # Don't fall back to treating URL as code - that's meaningless
                    chunks = []
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to fetch GitHub repository: {str(e)}. Please check the URL and ensure the repository is public."
                    )

            else:  # Not a GitHub URL or failed to parse as one
                # Check if it looks like a GitHub URL but couldn't be parsed
                if is_github_url and not github_match:
                    logger.warning(f"Looks like GitHub URL but couldn't parse: '{code_stripped[:100]}'")
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid GitHub URL format. Expected: https://github.com/owner/repo"
                    )

                # It's actual code - chunk it
                logger.info("Code snippet provided, performing tree-sitter chunking")

                # Use the ACTUAL working CodeChunker that has tree-sitter!
                from src.utils.local_ingestion import CodeChunker
                import tempfile
                import os

                # Create a temp file for the code (CodeChunker needs a file)
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                    tmp.write(request.code_snippet)
                    tmp_path = tmp.name

                try:
                    # Use the real tree-sitter chunker
                    chunker = CodeChunker()
                    chunks = chunker.chunk_file(tmp_path)
                    logger.info(f"Tree-sitter chunking complete: {len(chunks)} semantic chunks created")

                    # Log chunk details
                    chunk_types = {}
                    for chunk in chunks:
                        chunk_type = chunk.get('type', 'unknown')
                        chunk_types[chunk_type] = chunk_types.get(chunk_type, 0) + 1
                    logger.info(f"Chunk breakdown: {chunk_types}")

                finally:
                    # Clean up temp file
                    os.unlink(tmp_path)

        # If we have chunks (from either GitHub or code snippet), parse them
        if chunks:
            # Parse chunks with NLP parser
            from src.parsers.nlp_parser_cerebras import ImprovedNLPParser
            nlp_parser = ImprovedNLPParser(Settings())
            asset = await nlp_parser.parse_code_chunks(chunks)

            # Update the asset description to include DFD info
            # Note: AssetInput doesn't have components/interactions fields, so we embed in description
            dfd_info = f"\nDFD Components: {', '.join(components)}\n"
            dfd_info += f"DFD Flows: {'; '.join(flows[:5])}"  # First 5 flows
            asset.description = (request.description or f"Custom DFD with {len(components)} components") + dfd_info

            # Merge compliance requirements
            existing = set(asset.compliance_requirements or [])
            existing.update(request.compliance_requirements)
            asset.compliance_requirements = list(existing)

            logger.info(f"Merged custom DFD with code analysis: {len(components)} components, {len(chunks)} tree-sitter chunks")

        else:
            # No code snippet, use only the custom DFD
            asset = AssetInput(
                description=request.description or f"Custom DFD with {len(components)} components",
                component_type="business_logic",  # Valid enum value
                data_sensitivity="high",
                deployment_environment="cloud",
                frameworks=components[:3],  # Use first 3 as frameworks
                components=components,
                interactions=flows,
                compliance_requirements=request.compliance_requirements
            )

        # ------------------------------------------------------------------
        # Convert the upload into a REAL DataFlowDiagram so the orchestrator
        # uses the user's diagram instead of asking the LLM to rebuild one
        # from the description. Resolve "auto" to a concrete format first.
        # ------------------------------------------------------------------
        concrete_fmt = request.format
        if concrete_fmt == "auto" or concrete_fmt not in {"mermaid", "plantuml", "json"}:
            stripped = request.content.strip()
            if stripped.startswith("@startuml"):
                concrete_fmt = "plantuml"
            elif "graph" in stripped and ("-->" in stripped or "==>" in stripped):
                concrete_fmt = "mermaid"
            elif stripped.startswith("{"):
                concrete_fmt = "json"
            else:
                concrete_fmt = None  # couldn't tell -- fall through to LLM build

        prebuilt_dfd = None
        if concrete_fmt:
            try:
                prebuilt_dfd = parse_uploaded_dfd(
                    concrete_fmt,
                    request.content,
                    diagram_name=request.description[:80] or "Uploaded DFD",
                )
                logger.info(
                    "Uploaded DFD parsed into pydantic model",
                    format=concrete_fmt,
                    entities=len(prebuilt_dfd.external_entities),
                    processes=len(prebuilt_dfd.processes),
                    stores=len(prebuilt_dfd.data_stores),
                    flows=len(prebuilt_dfd.data_flows),
                )
            except Exception as parse_err:
                # Don't abort the whole run; just fall back to LLM-built DFD.
                logger.warning(
                    "Could not parse uploaded DFD; falling back to LLM DFDBuilder",
                    error=str(parse_err),
                )
                prebuilt_dfd = None

        # Run threat analysis (use the user's DFD if we managed to build one)
        orchestrator = ThreatModelingOrchestrator(Settings())

        # Store original diagram if uploaded (to avoid regeneration bugs)
        original_diagram = None
        if concrete_fmt == "mermaid" and prebuilt_dfd:
            original_diagram = request.content

        threat_model = await orchestrator.analyze(
            asset,
            prebuilt_dfd=prebuilt_dfd,
            original_diagram=original_diagram
        )

        # Store in database
        threat_models_db[threat_model.model_id] = threat_model

        # Track chunks processed
        chunks_processed = len(chunks) if request.code_snippet else 0

        logger.info(
            "Custom DFD analysis complete",
            model_id=str(threat_model.model_id),
            components=len(components),
            flows=len(flows),
            chunks_processed=chunks_processed,
            vulnerabilities=len(threat_model.vulnerabilities)
        )

        # Build analysis message
        message_parts = [f"Custom DFD analyzed successfully with {len(components)} components"]
        if chunks_processed > 0:
            message_parts.append(f"and {chunks_processed} tree-sitter chunks")

        # Return summary
        return AnalyzeResponse(
            model_id=threat_model.model_id,
            status="completed",
            message=" ".join(message_parts),
            summary={
                "vulnerabilities": len(threat_model.vulnerabilities),
                "critical": sum(1 for v in threat_model.vulnerabilities if v.severity.value == "critical"),
                "high": sum(1 for v in threat_model.vulnerabilities if v.severity.value == "high"),
                "components": components,
                "data_flows": flows[:10],  # First 10 flows
                "chunks_processed": chunks_processed
            },
            chunks_processed=chunks_processed
        )

    except Exception as e:
        logger.error(f"DFD upload analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "improvements": [
            "tree-sitter chunking",
            "ChromaDB vector storage",
            "instructor NLP parsing",
            "PyGithub integration"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)