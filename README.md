# Agentic Threat Modeling System

**AI-Powered Security Threat Analysis** using Pydantic AI, Mistral AI, OWASP Top 10, CWE, and MAESTRO Principles

---

## Overview

This system takes natural language descriptions of features, client requirements, or codebases and automatically generates comprehensive threat models with:

- **Top 5-10 Critical Vulnerabilities** with CWE mappings
- **Attack Path Visualization** (D3.js interactive graphs)
- **OWASP Top 10 Classification**
- **MAESTRO Security Principles Analysis**
- **Automated Remediation Recommendations**
- **Compliance Checks** (HIPAA, FDA, NIST, GDPR)

---

## Architecture

```
INPUT LAYER
└─ Natural Language Description → Mistral AI Parser → Structured AssetInput

AGENTIC ANALYSIS LAYER (Pydantic AI)
├─ Agent Orchestrator
├─ OWASP Analyzer Agent
├─ Attack Tree Agent
├─ AI Safety Agent
├─ CWE Analyzer Agent
├─ Compliance Agent (HIPAA/FDA/NIST)
└─ MAESTRO Principles Agent

DATA LAYER
├─ PostgreSQL (threat models)
├─ ChromaDB (vector store for threat intelligence)
└─ CWE Database Integration

OUTPUT LAYER
├─ Interactive D3.js Threat Graph
├─ PDF Threat Reports
└─ Top 5-10 Critical Vulnerabilities with Fixes
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- Mistral AI API Key ([Get one here](https://console.mistral.ai/))

### Installation

```bash
# Clone/navigate to project
cd "Agentic-Threat-Modeling"

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your MISTRAL_API_KEY
```

### Run the System

```bash
# Start the API server
python main.py

# Access the dashboard
# http://localhost:8000/dashboard
```

---

## Usage

### Input Format

Provide natural language descriptions like:

**Example 1: Feature Description**
```
"A user authentication system using JWT tokens. Users can login with email/password,
and the system issues access tokens with 1-hour expiration. Implements password hashing
with bcrypt and stores user credentials in PostgreSQL database."
```

**Example 2: Client Requirement**
```
"We need a file upload feature where users can upload medical documents (PDF, DOCX).
The files should be scanned for viruses and stored in AWS S3. The system must be
HIPAA compliant and support role-based access control."
```

**Example 3: Code Snippet**
```python
def process_user_input(user_data):
    query = f"SELECT * FROM users WHERE username='{user_data['username']}'"
    result = db.execute(query)
    return result
```

### Output Format

The system returns:

1. **Top 5-10 Critical Vulnerabilities**
   - CWE ID and name
   - OWASP Top 10 category
   - CVSS severity score
   - Attack vector description
   - Code-level remediation steps

2. **Attack Tree Visualization**
   - Interactive D3.js graph showing attack paths
   - Entry points → Intermediate steps → Impact
   - Risk scores and likelihood ratings

3. **MAESTRO Analysis**
   - Security principles violated
   - Recommendations for improvement

4. **Compliance Report**
   - HIPAA/FDA/NIST requirement checks
   - Non-compliance findings
   - Remediation steps

---

## API Endpoints

### POST /api/analyze
Analyze a system description for threats

**Request:**
```json
{
  "description": "User authentication system with JWT...",
  "code_snippet": "optional code here",
  "compliance_requirements": ["HIPAA", "NIST"]
}
```

**Response:**
```json
{
  "model_id": "uuid",
  "top_vulnerabilities": [
    {
      "title": "SQL Injection",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021-Injection",
      "severity": "critical",
      "cvss_score": 9.8,
      "recommendation": "Use parameterized queries...",
      "code_fix_example": "query = 'SELECT * FROM users WHERE username=?'"
    }
  ],
  "attack_paths": [...],
  "threat_graph": {...}
}
```

### GET /api/models/{model_id}
Retrieve a previously generated threat model

### POST /api/reports/{model_id}/pdf
Generate PDF report for a threat model

---

## Key Features

### 1. Multi-Agent Analysis

Each specialized agent focuses on specific security aspects:

- **OWASP Agent**: Identifies OWASP Top 10 vulnerabilities
- **CWE Agent**: Maps weaknesses to CWE database
- **Attack Tree Agent**: Constructs attack paths and scenarios
- **AI Safety Agent**: Analyzes AI-specific security risks
- **Compliance Agent**: Checks regulatory requirements
- **MAESTRO Agent**: Validates security design principles

### 2. CWE Integration

- 900+ Common Weakness Enumerations
- Automated CWE-to-OWASP mapping
- Language-specific vulnerability patterns
- Framework-specific security issues

### 3. MAESTRO Principles

Validates against MAESTRO security principles:
- **M**inimize attack surface
- **E**stablish secure defaults
- **A**uthentication & authorization
- **S**eparation of duties
- **T**rust but verify
- **R**esilience and recovery
- **O**bservability and monitoring

### 4. Attack Graph Visualization

Interactive D3.js graphs showing:
- Threat actor capabilities
- Entry points and attack vectors
- Privilege escalation paths
- Data exfiltration routes
- Impact scenarios

---

## Technology Stack

- **AI Framework**: Pydantic AI v0.0.14+
- **LLM**: Mistral AI (mistral-large-latest)
- **Web Framework**: FastAPI
- **Database**: PostgreSQL + ChromaDB
- **Frontend**: React.js + D3.js
- **Report Generation**: ReportLab (PDF)
- **Security Standards**: OWASP Top 10 2021, CWE, MITRE ATT&CK

---

## Project Structure

```
Agentic-Threat-Modeling/
├── src/
│   ├── agents/              # Pydantic AI agents
│   │   ├── owasp_agent.py
│   │   ├── attack_tree_agent.py
│   │   ├── cwe_agent.py
│   │   ├── maestro_agent.py
│   │   └── orchestrator.py
│   ├── models/              # Pydantic models
│   │   └── threats.py
│   ├── parsers/             # NLP parser
│   │   └── nlp_parser.py
│   ├── analyzers/           # Analysis engines
│   ├── database/            # Database models
│   ├── api/                 # FastAPI endpoints
│   └── tools/               # Utility tools
├── frontend/                # React + D3.js dashboard
├── data/                    # CWE data, threat intel
├── reports/                 # Generated PDF reports
├── tests/                   # Test suite
├── requirements.txt
├── .env.example
└── README.md
```

---

## Development

### Running Tests

```bash
pytest tests/
```

### Adding New Agents

1. Create agent in `src/agents/`
2. Register with orchestrator
3. Define analysis logic using Pydantic AI
4. Return `AgentAnalysis` model

Example:
```python
from pydantic_ai import Agent
from src.models.threats import AgentAnalysis, Vulnerability

owasp_agent = Agent(
    'mistral-large-latest',
    system_prompt="You are an OWASP security expert..."
)

async def analyze_owasp(asset: AssetInput) -> AgentAnalysis:
    result = await owasp_agent.run(asset.description)
    return AgentAnalysis(
        agent_name="OWASP Analyzer",
        agent_type="owasp",
        findings=[...],
        vulnerabilities_found=[...],
        confidence=0.9,
        reasoning=result.data
    )
```

---

## Roadmap

- [x] Natural Language Parser with Mistral AI
- [x] Pydantic Models for Threats
- [ ] OWASP Analyzer Agent
- [ ] CWE Database Integration
- [ ] Attack Tree Generator
- [ ] D3.js Interactive Threat Graph
- [ ] PDF Report Generation
- [ ] Compliance Checking Engine
- [ ] MAESTRO Principles Validator
- [ ] Continuous CVE Monitoring (hourly checks)
- [ ] Symbolic Verification (Z3 solver)

---

## License

MIT License

---

## Acknowledgments

- **Pydantic AI** - Agent framework
- **Mistral AI** - LLM for threat analysis
- **OWASP** - Security standards
- **CWE/MITRE** - Vulnerability databases

---

**Built for TECHGIUM Hackathon - Agentic AI for Automated Threat Modeling**
