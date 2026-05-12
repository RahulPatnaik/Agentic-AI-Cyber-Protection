# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agentic Threat Modeling System — an AI-powered security threat analysis tool built for the TECHGIUM Hackathon. Takes natural language descriptions of systems/features and produces comprehensive threat models with vulnerabilities, attack paths, and remediation recommendations.

**Tech Stack:** Python 3.12+, FastAPI, Pydantic AI, Mistral AI (mistral-large-latest), PostgreSQL, ChromaDB, Z3 solver, D3.js

## Commands

```bash
# Setup
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then add MISTRAL_API_KEY

# Run the server (serves API + dashboard)
python main.py
# API: http://localhost:8000/docs
# Dashboard: http://localhost:8000/dashboard

# Tests
pytest tests/
pytest tests/test_vulnerability_detection.py  # single test file
python tests/run_all_tests.py                 # alternative test runner
```

## Architecture

### Analysis Pipeline (Orchestrator)

The system runs a phased multi-agent pipeline, coordinated by `ThreatModelingOrchestrator` in `src/agents/orchestrator.py`:

1. **Phase 0 — DFD Construction:** `DFDBuilder` creates a Data Flow Diagram from the description, then `AutomatedThreatGenerator` generates threats from the DFD structure
2. **Phase 1 — STRIDE Analysis:** `STRIDEAgent` categorizes threats across 6 STRIDE dimensions
3. **Phase 2 — OWASP Analysis:** `OWASPAnalyzer` identifies OWASP Top 10 vulnerabilities; results are merged and deduplicated with Phase 0+1
4. **Phase 3 — Parallel agents:** `AttackTreeAnalyzer`, `CWEAnalyzer`, `MAESTROValidator`, and `SymbolicVerifier` (Z3) run concurrently via `asyncio.gather`
5. **Phase 4 — CVE Enrichment:** `CVEScanner` enriches top 10 vulnerabilities with NVD data

Failed agents are caught individually and produce fallback `AgentAnalysis` objects — the pipeline continues even if individual agents fail.

### Key Data Flow

```
User input (natural language/code)
  → NLPParser (Mistral AI) → AssetInput
  → Orchestrator → 9 agents → ThreatModel
  → FastAPI response / Dashboard visualization
```

### Core Models (`src/models/`)

- `threats.py`: All Pydantic models — `AssetInput`, `Vulnerability`, `AttackPath`, `ThreatModel`, `AgentAnalysis`, `CWEReference`, enums (`SeverityLevel`, `OWASPCategory`, `MITRECategory`, `ComponentType`)
- `dfd_components.py`: DFD models — `DataFlowDiagram`, `Process`, `DataStore`, `DataFlow`, `ExternalEntity`, `TrustBoundary` with security validation methods

### Agents (`src/agents/`)

Each agent takes a `Settings` instance in its constructor. LLM-backed agents use Mistral AI via Pydantic AI. The `SymbolicVerifier` uses Z3 solver (no LLM). All analysis methods are async.

| Agent | Purpose |
|---|---|
| `dfd_builder_agent.py` | Builds DFD from system description |
| `threat_generator.py` | Generates threats from DFD structure (rule-based) |
| `stride_agent.py` | STRIDE categorization |
| `owasp_agent.py` | OWASP Top 10 mapping |
| `attack_tree_agent.py` | Attack path generation + D3.js graph structure |
| `cwe_agent.py` | CWE database mapping |
| `maestro_agent.py` | MAESTRO security principles validation |
| `symbolic_verifier.py` | Z3 SMT formal verification of security properties |
| `cve_scanner.py` | NVD API CVE enrichment |

### API Layer (`src/api/app.py`)

FastAPI app with in-memory storage (`threat_models_db` dict). Key endpoints:
- `POST /api/analyze` — main analysis endpoint (NLP parse → orchestrate → return)
- `GET /api/models/{id}` — retrieve threat model
- `GET /api/models/{id}/graph` — D3.js graph data (combined DFD + attack tree)
- `POST /api/reports/{id}/pdf` — generates HTML report (despite endpoint name)
- GitHub integration endpoints for issue creation and PR comments

### Frontend (`dashboard/`)

Static HTML/CSS/JS served by FastAPI's `StaticFiles`. Uses D3.js for attack path visualization and Mermaid for DFD rendering.

## Configuration

All config via environment variables, loaded through `pydantic-settings` in `src/config.py`. Key vars:
- `MISTRAL_API_KEY` — required for AI-powered parsing (falls back to keyword-based without it)
- `NVD_API_KEY` — for CVE enrichment
- `GITHUB_TOKEN` — for GitHub integration
- `DATABASE_URL` — PostgreSQL connection (schema in `database_schema.sql`)
- `MAX_AGENTS_CONCURRENT` — concurrency limit for batch analysis (default: 5)

## Important Patterns

- The `NLPParser` has a keyword-based fallback when no Mistral API key is set — the system still works without LLM access
- Vulnerability deduplication uses `(cwe_id, title)` as composite key
- The `ThreatModel.threat_graph` dict contains both `dfd_diagram` (Mermaid string) and `attack_tree` (D3.js node/edge structure)
- `main.py` adds the project root to `sys.path` and loads `.env` before any imports
- The `.gitignore` excludes all `*.md` files (including this one) from being pushed
