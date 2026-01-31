# Getting Started with Agentic Threat Modeling System

This guide will help you set up and run the Agentic Threat Modeling System in minutes.

## Prerequisites

- **Python 3.11+** (Python 3.12 recommended)
- **Mistral AI API Key** ([Get one here - FREE tier available](https://console.mistral.ai/))

## Quick Setup (5 minutes)

### 1. Navigate to Project Directory

```bash
cd "/home/rahul/Desktop/TECHGIUM/Agentic-Threat-Modeling"
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3.12 -m venv venv

# Activate it
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This will install:
- Pydantic AI (agent framework)
- Mistral AI SDK
- FastAPI (web framework)
- All other required packages

### 4. Configure Mistral API Key

**Option A: Edit .env file** (Recommended)

```bash
nano .env  # Or use any text editor
```

Add your Mistral API key:
```
MISTRAL_API_KEY=your_mistral_api_key_here
```

**Option B: Set environment variable**

```bash
export MISTRAL_API_KEY='your_mistral_api_key_here'
```

**Get Mistral API Key:**
1. Go to https://console.mistral.ai/
2. Sign up (FREE tier available)
3. Navigate to API Keys section
4. Create new API key
5. Copy and paste into .env file

### 5. Run the System

```bash
python main.py
```

You should see:

```
================================================================================
🛡️  AGENTIC THREAT MODELING SYSTEM
================================================================================
AI-Powered Security Threat Analysis
Built with: Pydantic AI + Mistral AI + OWASP Top 10 + CWE + MAESTRO
--------------------------------------------------------------------------------
API Server: http://0.0.0.0:8000
API Docs: http://0.0.0.0:8000/docs
Dashboard: http://0.0.0.0:8000/dashboard
--------------------------------------------------------------------------------
Agents:
  ✓ OWASP Analyzer (OWASP Top 10 2021)
  ✓ Attack Tree Generator (Attack Paths)
  ✓ CWE Analyzer (Common Weakness Enumeration)
  ✓ MAESTRO Validator (Security Principles)
================================================================================
```

### 6. Open the Dashboard

Open your browser and navigate to:

```
http://localhost:8000/dashboard
```

You should see the threat modeling dashboard!

## Using the System

### Method 1: Web Dashboard

1. Open http://localhost:8000/dashboard
2. Enter a system description in natural language
3. Optionally add code snippet
4. Click "Analyze Threats"
5. View results with:
   - Top 5-10 critical vulnerabilities
   - Attack path visualization
   - CWE mappings
   - MAESTRO validation
   - Remediation recommendations

### Method 2: API Directly

**Analyze a system:**

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "description": "A user authentication system using JWT tokens. Users can login with email/password, and the system issues access tokens with 1-hour expiration.",
    "compliance_requirements": ["HIPAA", "NIST"]
  }'
```

**Get threat model:**

```bash
curl http://localhost:8000/api/models/{model_id}
```

### Method 3: Interactive API Docs

Visit http://localhost:8000/docs for interactive Swagger UI

## Example Analysis

Try this example to see the system in action:

**Input:**
```
A file upload feature where users can upload medical documents (PDF, DOCX).
The files are stored in AWS S3 without validation. The system must be
HIPAA compliant.
```

**Expected Output:**
- Unrestricted File Upload (CWE-434)
- Missing Input Validation (CWE-20)
- Insufficient Access Control (CWE-285)
- HIPAA compliance violations
- Attack paths showing exploitation scenarios
- Detailed remediation steps

## Common Issues

### Issue: "No Mistral API key configured"

**Solution:** Add your API key to .env file:
```bash
MISTRAL_API_KEY=your_key_here
```

### Issue: "ModuleNotFoundError"

**Solution:** Ensure virtual environment is activated and dependencies are installed:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: "Port 8000 already in use"

**Solution:** Change port in .env file:
```bash
API_PORT=8001
```

### Issue: "Permission denied on port 80/443"

**Solution:** Use port 8000 or run with sudo (not recommended)

## Architecture Overview

```
User Input (Natural Language)
        ↓
    NLP Parser (Mistral AI)
        ↓
    Structured AssetInput
        ↓
┌───────────────────────────────┐
│   Agent Orchestrator          │
└───────────────────────────────┘
        ↓
┌───────────────────────────────────────────────────┐
│  Multi-Agent Analysis (Parallel Execution)        │
├───────────────────────────────────────────────────┤
│  1. OWASP Analyzer    → Vulnerabilities           │
│  2. Attack Tree Agent → Attack Paths              │
│  3. CWE Analyzer      → CWE Mappings              │
│  4. MAESTRO Validator → Security Principles       │
└───────────────────────────────────────────────────┘
        ↓
    Complete Threat Model
        ↓
┌───────────────────────────────┐
│  Output Layer                 │
├───────────────────────────────┤
│  • Interactive Dashboard      │
│  • D3.js Threat Graph         │
│  • Top 5-10 Vulnerabilities   │
│  • Remediation Steps          │
│  • PDF Reports (planned)      │
└───────────────────────────────┘
```

## Key Features

✅ **Natural Language Processing** - Describe your system in plain English
✅ **Multi-Agent Analysis** - 4 specialized AI agents working in parallel
✅ **OWASP Top 10 2021** - Industry-standard vulnerability classification
✅ **CWE Mappings** - 900+ software weakness enumerations
✅ **MAESTRO Principles** - Security design principle validation
✅ **Attack Path Visualization** - Interactive D3.js graphs
✅ **Detailed Remediation** - Code examples and step-by-step fixes
✅ **Compliance Checking** - HIPAA, FDA, NIST, GDPR support

## Next Steps

1. **Try the examples** in the dashboard
2. **Analyze your own code** by pasting code snippets
3. **Explore the API** at http://localhost:8000/docs
4. **Review the codebase** in src/ directory
5. **Extend the system** by adding new agents

## System Requirements

- **CPU:** 2+ cores recommended
- **RAM:** 4GB minimum, 8GB recommended
- **Disk:** 500MB for dependencies
- **Network:** Internet connection for Mistral AI API calls

## Performance

- **Analysis Time:** 10-30 seconds per system
- **Concurrency:** Up to 5 agents in parallel (configurable)
- **Throughput:** ~2-6 analyses per minute
- **Mistral API Cost:** ~$0.01-0.05 per analysis (FREE tier available)

## Support

- **Documentation:** README.md in root directory
- **API Reference:** http://localhost:8000/docs
- **GitHub Issues:** Report bugs and request features
- **TECHGIUM Hackathon:** Built for agentic AI security challenge

## License

MIT License - See LICENSE file for details

---

**Built with ❤️ for TECHGIUM Hackathon**

**Technologies:**
- Pydantic AI v0.0.14+
- Mistral AI (mistral-large-latest)
- FastAPI
- D3.js
- OWASP Top 10 2021
- CWE Database
- MAESTRO Security Principles
