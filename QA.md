# QA.md — Comprehensive Q&A Preparation for TECHgium Final Presentation

**Project:** AI-Enabled Agile Automated Threat Modeling
**Team:** Rahul Patnaik, Noel S Mathew | Mentor: Dr. Sudarshan B G
**PID:** TG0915025 | RV College of Engineering, Bangalore

---

## CATEGORY 1: CORE CONCEPT & PROBLEM STATEMENT

### Q1. What problem are you solving, and why does it matter?

**Answer:** Traditional threat modeling is a manual, time-intensive process that takes security experts hours to days per system. With 28,821 CVEs published in 2023 alone (a 14.9% year-over-year increase), manual approaches cannot keep pace. Modern systems — especially medical devices — use wireless communication, AI models, cloud connectivity, and embedded firmware, broadening attack surfaces beyond what manual review can cover.

Our system automates the entire threat modeling pipeline: a developer or security engineer types a natural language description of their system (or pastes code), and within 15-30 seconds, they receive a complete threat model with a Data Flow Diagram, STRIDE categorization, OWASP Top 10 mapping, CWE references, attack paths, MAESTRO validation, formal verification results, and CVE enrichment — all from 9 specialized AI agents running in parallel.

This enables "shift-left" security — catching vulnerabilities at design time rather than in production.

---

### Q2. How is this different from existing threat modeling tools like Microsoft Threat Modeling Tool or OWASP Threat Dragon?

**Answer:** The key differences are:

| Aspect | Traditional Tools | Our System |
|--------|------------------|------------|
| Input | Manual diagram creation (drag & drop DFD) | Natural language + optional code |
| Analysis | Human expert reviews the diagram | 9 AI agents analyze automatically |
| Speed | Hours to days | 15-30 seconds |
| Coverage | Depends on analyst expertise | Systematic: STRIDE + OWASP + CWE + MAESTRO + CVE + Z3 |
| Attack Paths | Not generated | Multi-step attack paths auto-generated |
| Output | Static report | Interactive dashboard + DFD visualization + D3.js attack graphs |
| Formal Verification | None | Z3 SMT solver verifies security properties mathematically |

We also support code snippet analysis — the tool can scan actual code for vulnerabilities, not just architectural descriptions. Traditional tools like OWASP Threat Dragon and Microsoft TMT require manual DFD construction. Our DFD Builder agent creates this automatically from text.

---

### Q3. Who is the target user for this system?

**Answer:**
1. **DevSecOps teams** — integrate into CI/CD pipelines via GitHub Actions (we generate the workflow YAML)
2. **Security engineers** — rapid threat model generation for design reviews
3. **Developers** — paste code and get immediate vulnerability feedback
4. **Compliance officers** — automated HIPAA/NIST/GDPR/FDA gap analysis
5. **Penetration testers** — attack path identification before manual testing

The GitHub integration can automatically create issues from vulnerabilities, comment on PRs with threat analysis results, and create fix PRs — making security a first-class CI/CD concern.

---

### Q4. What is the challenge statement you're addressing?

**Answer:** The LTTS TECHgium challenge is: *"Develop an autonomous security framework that can continuously analyse any device data integrity, identify vulnerabilities in real time, and propose regulatory-compliant strategies."*

We address all three requirements:
1. **Continuous analysis** — GitHub Actions integration for automated threat modeling on every PR
2. **Real-time vulnerability identification** — 15-30 second analysis with CVE enrichment from NVD
3. **Regulatory-compliant strategies** — Built-in HIPAA, FDA, NIST, GDPR compliance checking with remediation steps

---

## CATEGORY 2: ARCHITECTURE & DESIGN

### Q5. Explain your multi-agent architecture. Why 9 agents instead of one monolithic model?

**Answer:** Our architecture follows the "agent specialization" principle — each agent is an expert in one security domain. The orchestrator coordinates them in a phased pipeline:

**Phase 0 — DFD Construction:**
- `DFDBuilder` — creates Data Flow Diagram with processes, data stores, flows, trust boundaries
- `AutomatedThreatGenerator` — rule-based threat generation from DFD structure (mimics OWASP pytm)

**Phase 1 — STRIDE Analysis:**
- `STRIDEAgent` — categorizes threats across 6 STRIDE dimensions (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)

**Phase 2 — OWASP Analysis:**
- `OWASPAnalyzer` — maps vulnerabilities to OWASP Top 10 2021 categories

**Phase 3 — Parallel Deep Analysis (asyncio.gather):**
- `AttackTreeAnalyzer` — generates multi-step attack paths
- `CWEAnalyzer` — maps to 900+ CWE weaknesses
- `MAESTROValidator` — validates against MAESTRO security principles
- `SymbolicVerifier` — Z3 SMT formal verification

**Phase 4 — Enrichment:**
- `CVEScanner` — enriches top 10 vulnerabilities with NVD data

**Why this matters:** A single LLM call would miss domain-specific nuances. Our approach:
- Gives each agent a focused system prompt optimized for its domain
- Enables parallel execution (Phase 3 runs 4 agents concurrently)
- Provides fault tolerance — if one agent fails, others continue (each failure produces a fallback `AgentAnalysis`)
- Produces structured, deduplicated output (we dedup on `(cwe_id, title)` composite key)

---

### Q6. Walk us through the data flow — from user input to final output.

**Answer:**
```
User types description + optional code
  |
  v
NLPParser (Mistral AI, mistral-large-latest)
  - Extracts: component_type, languages, frameworks, dependencies, compliance needs
  - Falls back to keyword-based parsing if no API key
  |
  v
AssetInput (Pydantic model with structured fields)
  |
  v
ThreatModelingOrchestrator.analyze()
  - Phase 0: DFD Builder -> DataFlowDiagram -> AutomatedThreatGenerator -> Vulnerability[]
  - Phase 1: STRIDE Agent -> Threat[] (converted to Vulnerability[])
  - Phase 2: OWASP Agent -> AgentAnalysis with vulnerabilities
  - Merge + deduplicate all vulnerabilities
  - Phase 3: Parallel (Attack Tree + CWE + MAESTRO + Z3 Symbolic) via asyncio.gather
  - Phase 4: CVE enrichment via NVD API for top 10 vulns
  |
  v
ThreatModel (Pydantic model with everything)
  - vulnerabilities, attack_paths, cwe_references, threat_graph (Mermaid DFD + D3.js attack tree)
  - top_vulnerabilities (top 10 by risk_score), critical_paths (top 5 by probability * damage)
  - agent_analyses (summary from each of 9 agents), confidence_score (weighted average)
  |
  v
FastAPI response -> Dashboard visualization / PDF report / GitHub PR comment
```

---

### Q7. What is the Perception-Reasoning-Synthesis layer architecture mentioned in your proposal?

**Answer:**

**Perception Layer (Input Understanding):**
- The NLP Parser uses Mistral AI (mistral-large-latest) with RAG principles to convert unstructured text into structured `AssetInput`
- It automatically detects component types, languages, frameworks, compliance needs
- Includes STRIDE/MITRE/OWASP classification at the input stage

**Reasoning Layer (Multi-Agent Analysis):**
- The DFD Builder creates a system architecture model (knowledge graph)
- 9 agents reason about different security dimensions simultaneously
- The Z3 symbolic verifier provides formal mathematical proofs
- Attack paths simulate multi-stage exploits through the system

**Synthesis Layer (Actionable Output):**
- Aggregates findings from all agents with deduplication
- Generates counter strategies and compliance mappings
- Produces visual DFD diagrams (Mermaid), interactive attack graphs (D3.js), HTML reports
- Creates GitHub issues, PR comments, and fix PRs automatically

---

### Q8. What is the role of the Data Flow Diagram (DFD) in your system, and how is it generated?

**Answer:** The DFD is the structural foundation of our threat analysis, based on OWASP pytm methodology. It identifies:
- **External Entities** (users, external APIs) with trust levels
- **Processes** (application services) with security property flags (sanitizesInput, implementsAuthentication, etc.)
- **Data Stores** (databases, caches) with encryption and access control status
- **Data Flows** (connections between components) with protocol, encryption, authentication method
- **Trust Boundaries** (network zones) with firewall/WAF/IDS status

The `DFDBuilder` agent creates this from the natural language description using heuristic keyword analysis (e.g., detecting "PostgreSQL" creates a database DataStore, "JWT" sets authentication method). The `AutomatedThreatGenerator` then walks the DFD structure and applies rule-based checks:
- Process without `sanitizesInput`? → Injection vulnerability (CWE-89)
- DataStore with `stores_pii` but not `isEncrypted`? → Cryptographic failure (CWE-311)
- DataFlow with `carries_credentials` but not `isEncrypted`? → Cleartext transmission (CWE-319)
- Data crossing trust boundaries without encryption? → Boundary violation

This is how OWASP pytm works — but we do it from natural language, not from Python code defining the DFD manually.

---

### Q9. How does the Z3 symbolic verifier work? What does "formal verification" mean here?

**Answer:** The Z3 SMT (Satisfiability Modulo Theories) solver is a mathematical theorem prover from Microsoft Research. Unlike LLMs which are probabilistic, Z3 provides mathematically provable guarantees.

Our `SymbolicVerifier` uses Z3 for three verification types:

1. **Access Control Verification:**
   - Creates boolean variables for each resource: `protected_resource_X = True/False`
   - Adds constraints based on role-to-resource mappings
   - Asks Z3: "Is it satisfiable that ALL resources are protected?"
   - If SAT: all resources have access control (proven)
   - If UNSAT: some resources are unprotected, and Z3 identifies which ones

2. **Data Flow Integrity (Taint Analysis):**
   - Models data sources (tainted), sanitizers (clean), and sinks (must be clean)
   - Z3 proves whether tainted data can reach sinks without sanitization
   - If sanitizers exist and SAT: data flow is safe (proven)
   - If no sanitizers and SAT: tainted data reaches sinks (vulnerability proven)

3. **Authentication Invariants:**
   - Verifies: `authentication ∧ session_management ∧ token_validation`
   - Returns which specific components are missing

This is not AI hallucination — it's a mathematical proof. When Z3 says a property holds or fails, it's provably correct.

---

### Q10. Why did you choose Pydantic AI and Mistral AI specifically?

**Answer:**

**Pydantic AI:**
- Provides structured output from LLMs — agents return validated Pydantic models, not raw text
- Type safety with runtime validation (CVSS scores between 0-10, severity enums, etc.)
- Agent orchestration with system prompts, tool use, and dependency injection
- Works with multiple LLM backends (swappable to OpenAI, Anthropic, etc.)

**Mistral AI (mistral-large-latest):**
- Strong security domain knowledge — competitive with GPT-4 for code analysis and vulnerability identification
- Cost-effective: ~$0.01-0.05 per analysis (free tier available for POC)
- Fast inference with low latency
- Good at structured JSON output (critical for our NLP parser)

However, our architecture is LLM-agnostic. The `primary_llm` setting in `config.py` and the agent model strings can be swapped to use OpenAI, Anthropic, or local models — this addresses the "single LLM dependency" weakness in our SWOT.

---

## CATEGORY 3: TECHNICAL DEEP DIVE

### Q11. How does the NLP Parser handle ambiguous or vague user input?

**Answer:** Two-tier parsing strategy:

**Tier 1 — LLM-powered (Mistral AI):**
- Sends description to Mistral with a structured JSON extraction prompt
- Parses the response, stripping markdown formatting if present
- Falls back to Tier 2 if JSON parsing fails

**Tier 2 — Keyword-based fallback:**
- Detects component types: "api" → API_ENDPOINT, "database" → DATABASE, "auth" → AUTHENTICATION
- Detects languages: "python", "javascript", "java"
- Detects frameworks: "django", "flask", "react"
- Detects compliance: "hipaa", "nist", "gdpr"
- Assesses data sensitivity: "patient", "health", "ssn" → CRITICAL
- Detects internet exposure: "internet", "public", "external" → internet_facing=True

**Even with minimal input like "A web application"**, the system generates generic but relevant threats because the DFD Builder creates a default architecture (external entity + process + trust boundary), and the STRIDE/OWASP agents still analyze each STRIDE category.

Test 19 in our test suite validates this: minimal input still produces vulnerabilities.

---

### Q12. How do you handle false positives and ensure accuracy?

**Answer:** Multiple mechanisms:

1. **Multi-agent consensus** — vulnerabilities found by multiple agents (automated generator + STRIDE + OWASP) reinforce each other; deduplication on `(cwe_id, title)` prevents duplicates

2. **Confidence scoring** — weighted average from 4 agent analyses:
   - OWASP: 35% weight (most critical domain)
   - Attack Tree: 25%
   - CWE: 25%
   - MAESTRO: 15%
   - The resulting confidence score (mean 0.75 in tests) gives users a reliability signal

3. **Risk scoring** — each vulnerability has `likelihood × impact = risk_score` (0-10), allowing users to focus on high-confidence, high-risk findings

4. **Z3 formal verification** — cannot produce false positives by definition (mathematical proof)

5. **DFD-based rule checking** — the `AutomatedThreatGenerator` checks concrete structural properties (is encryption enabled? is authentication implemented?), which are deterministic, not probabilistic

**Current metrics from our test suite:**
- 85% success rate (17/20 tests pass)
- 156 vulnerabilities identified across test cases
- 75 classified as critical, 81 as high
- Failures primarily from labeling inconsistencies (e.g., vulnerability title doesn't match expected pattern), not missed detections

---

### Q13. How does the vulnerability deduplication work?

**Answer:** After Phase 2, we merge three vulnerability sources:
1. `automated_threats` — from DFD rule-based analysis
2. `stride_vulnerabilities` — converted from STRIDE `Threat` objects to `Vulnerability` objects
3. `owasp_vulnerabilities` — from OWASP analyzer agent

Deduplication uses a set-based approach:
```python
seen = set()
unique_vulnerabilities = []
for vuln in vulnerabilities:
    key = (vuln.cwe_id, vuln.title)
    if key not in seen:
        seen.add(key)
        unique_vulnerabilities.append(vuln)
```

This means two vulnerabilities with the same CWE-ID AND title are considered duplicates. Different CWE IDs for similar issues (e.g., CWE-89 SQL Injection from DFD analysis AND CWE-79 XSS from STRIDE) are kept as separate findings because they represent distinct weakness classes.

---

### Q14. How does the CVE Scanner work? Is it real-time?

**Answer:** The `CVEScanner` integrates with the NVD (National Vulnerability Database) REST API v2.0:

1. **Enrichment flow:** For the top 10 vulnerabilities, it concurrently queries NVD by CWE-ID or keyword
2. **Rate limiting:** Respects NVD's limits (0.6s between requests; 50 req/30s with API key)
3. **Caching:** 24-hour TTL cache to avoid redundant API calls
4. **CVSS parsing:** Supports CVSS v3.1, v3.0, and v2.0 score extraction
5. **Fallback:** When no NVD API key is configured, returns curated demo CVE data for common patterns (JWT, SQL injection, XSS, auth bypass)

The results are stored in `vulnerability.metadata['related_cves']`, linking each vulnerability to real-world CVEs with their CVSS scores.

For production, the `CVE_CHECK_INTERVAL_HOURS=1` config would enable hourly monitoring — this is the "continuous monitoring" aspect of the challenge statement.

---

### Q15. How does the attack path generation work?

**Answer:** The `AttackTreeAnalyzer` generates multi-step attack paths:

1. Takes the list of identified vulnerabilities + the original asset description
2. For each critical vulnerability, constructs an attack scenario with:
   - **Entry point** — how the attacker gains initial access
   - **Intermediate steps** — privilege escalation, lateral movement
   - **Target** — final objective (data exfiltration, system compromise)
   - **Probability** (0-1) and **potential damage** (severity level)
3. Builds a D3.js-compatible graph structure with nodes and edges

The orchestrator selects top 5 critical paths using: `path_risk_score = probability × damage_severity_score`

Severity scores: critical=10, high=7, medium=5, low=2, none=0

The threat graph sent to the frontend contains both the Mermaid DFD diagram and the D3.js attack tree — combined visualization showing architecture + exploit paths.

---

### Q16. What are MAESTRO principles and how do you validate them?

**Answer:** MAESTRO is a security design principle framework:

- **M**inimize attack surface — reduce exposed interfaces
- **A**uthentication & authorization — verify identity and permissions
- **E**stablish secure defaults — secure out of the box
- **S**eparation of duties — no single point of compromise
- **T**rust but verify — validate all inputs regardless of source
- **R**esilience and recovery — survive and recover from attacks
- **O**bservability and monitoring — detect and respond to incidents

The `MAESTROValidator` agent analyzes each principle against the system description and identified vulnerabilities. If a vulnerability maps to a MAESTRO principle violation, it's flagged. For example:
- Missing input validation → violates "Trust but verify"
- No logging → violates "Observability and monitoring"
- Single database with no backup → violates "Resilience and recovery"

---

### Q17. How does the GitHub integration work?

**Answer:** Four integration points:

1. **GitHub Issues from vulnerabilities** — `POST /api/github/create-issue/{model_id}` creates a formatted issue with severity, CWE, OWASP category, impact, attack vector, and remediation
2. **PR comments** — `POST /api/github/comment-pr` posts a full threat analysis summary as a PR comment with severity distribution, top vulnerabilities, and attack paths
3. **Security Fix PRs** — `POST /api/github/create-fix-pr/{model_id}` creates a branch, generates a SECURITY_FIXES.md with detailed fix instructions for each vulnerability, and opens a PR
4. **GitHub Actions workflow** — `GET /api/github/workflow` returns a ready-to-use YAML workflow that runs threat analysis on every PR

This is the DevSecOps integration story — automated security in the development pipeline.

---

## CATEGORY 4: TESTING & RESULTS

### Q18. What were your testing results? How did you achieve 85% accuracy?

**Answer:** We conducted 20 end-to-end tests across 8 categories:

| Test Category | Tests | What We Validated |
|--------------|-------|-------------------|
| SQL Injection Detection | 2 | Detects string concatenation; recognizes parameterized queries as safer |
| XSS Detection | 2 | Detects unencoded output; recognizes html.escape() as safe |
| Authentication Vulnerabilities | 2 | Detects missing auth on PII endpoints; detects IDOR |
| Cryptographic Failures | 2 | Detects unencrypted PII; detects MD5 password hashing |
| Security Misconfiguration | 2 | Detects debug mode; detects default credentials |
| DFD Generation | 2 | Verifies component identification; verifies data flow detection |
| Attack Path Prediction | 2 | Verifies path generation; verifies multi-step chaining |
| MAESTRO + Compliance + Performance + Edge Cases | 6 | MAESTRO validation; HIPAA gaps; analysis speed (<30s); confidence scoring; minimal input; complex system |

**Results:**
- 17/20 tests passed (85% success rate)
- 156 total vulnerabilities identified across successful test cases
- 75 critical, 81 high severity
- 7-8 actionable findings per analysis on average
- Mean confidence score: 0.75
- 3 failures were labeling inconsistencies, not missed detections

---

### Q19. What happens when an agent fails? Show me the fault tolerance.

**Answer:** The orchestrator wraps Phase 3 agents in `asyncio.gather(return_exceptions=True)`:

```python
attack_tree_analysis, cwe_analysis, maestro_analysis, symbolic_verification = await asyncio.gather(
    attack_tree_task, cwe_task, maestro_task, symbolic_task,
    return_exceptions=True
)
```

If any returns an exception, it's caught and replaced with a fallback:
```python
if isinstance(attack_tree_analysis, Exception):
    attack_tree_analysis = AgentAnalysis(
        agent_name="Attack Tree Analyzer",
        agent_type="attack_tree",
        findings=["Analysis failed"],
        vulnerabilities_found=[],
        confidence=0.0,
        reasoning="Error occurred"
    )
```

The confidence score naturally drops (0.0 contribution from failed agent), signaling reduced reliability. But the pipeline continues — Phase 4 (CVE enrichment) and final threat model assembly still execute. The system remained operational despite partial agent failures in our testing.

---

### Q20. How fast is the analysis? What about scalability?

**Answer:**
- **Single analysis:** 15-30 seconds end-to-end (Test 17 validates <30s)
- **DFD building:** 3-5 seconds
- **STRIDE + OWASP:** 5-10 seconds
- **Parallel agents (Phase 3):** 5-10 seconds
- **CVE enrichment:** 2-5 seconds

**Scalability mechanisms:**
1. `asyncio.gather` for parallel agent execution (Phase 3 runs 4 agents concurrently)
2. `asyncio.Semaphore(MAX_AGENTS_CONCURRENT=5)` for batch analysis rate limiting
3. CVE cache with 24-hour TTL avoids redundant NVD API calls
4. FastAPI async framework handles concurrent HTTP requests natively
5. In-memory storage (dict) — production would use PostgreSQL with the provided schema

For the MVP roadmap (Month 6), we planned Kubernetes deployment with horizontal scaling.

---

## CATEGORY 5: SWOT, CHALLENGES & LIMITATIONS

### Q21. What are the weaknesses and how would you address them?

**Answer:**

**Weakness 1: Limited production-grade infrastructure**
- Currently uses in-memory storage (Python dict)
- **Fix:** PostgreSQL schema is already designed (`database_schema.sql`), ChromaDB for vector storage. Month 1 MVP plan includes DB + vector store integration.

**Weakness 2: Single LLM dependency (Mistral AI)**
- If Mistral API is down or rate-limited, LLM-backed agents fail
- **Fix:** Architecture supports swapping LLM via config (`primary_llm` setting). Month 2-3 MVP plan includes multi-LLM support. The keyword-based NLP fallback and the rule-based threat generator already work without LLM.

**Weakness 3: AI hallucination and false positives**
- LLM agents can generate plausible but incorrect vulnerability descriptions
- **Fix:** Z3 formal verification provides mathematical guarantees (no hallucination). Rule-based threat generator checks concrete structural properties. Multi-agent consensus reduces single-agent errors. Confidence scoring signals reliability.

---

### Q22. How do you handle the AI hallucination problem specifically?

**Answer:** Four-layer defense:

1. **Structured output** — Pydantic models enforce valid CVSS scores (0-10), valid severity enums, valid OWASP categories. Invalid data is rejected at the model level.

2. **Rule-based grounding** — The `AutomatedThreatGenerator` produces deterministic results from DFD structure. If a process has `sanitizesInput=False`, that's a fact, not a hallucination.

3. **Z3 formal verification** — Mathematical proofs cannot hallucinate. When Z3 says access control is violated, it provides the exact counterexample.

4. **Confidence scoring** — Users see a confidence score (0-1) for each analysis. Low confidence signals potential unreliability.

We acknowledge this is still a challenge — it's listed as a "Threat" in our SWOT. Future work includes a feedback loop where users confirm/reject findings to improve accuracy (Month 2-3 MVP plan).

---

### Q23. What are the opportunities for enterprise deployment?

**Answer:**

1. **Enterprise SOC automation** — integrate into Security Operations Centers for automated threat assessment of new system designs
2. **DevSecOps pipeline integration** — GitHub Actions workflow already built; extend to GitLab CI, Jenkins, Azure DevOps
3. **Regulatory compliance automation** — HIPAA, GDPR, FDA, NIST, PCI-DSS compliance gap analysis at design time (not just post-deployment)
4. **SaaS platform** — multi-tenant threat modeling service for consulting firms and enterprise security teams
5. **Medical device security** — directly addresses LTTS's domain: medical devices with AI, IoT, and cloud connectivity need continuous threat assessment

---

### Q24. What competitors exist and how do you differentiate?

**Answer:**

| Tool | Limitations | Our Advantage |
|------|-------------|---------------|
| Microsoft Threat Modeling Tool | Manual DFD creation, Windows-only | Automated DFD from text, web-based, cross-platform |
| OWASP Threat Dragon | Manual DFD, basic threat mapping | Multi-agent AI analysis, attack path prediction |
| OWASP pytm | Requires writing Python code to define DFD | Natural language input, no coding needed |
| IriusRisk | Commercial, expensive, manual workflow | AI-powered, fast, includes formal verification |
| GitHub Dependabot / Snyk | Dependency scanning only | Full threat modeling: architecture + code + compliance |

**Unique differentiators:**
1. Natural language → complete threat model (no manual diagramming)
2. Z3 SMT formal verification (no other tool has this)
3. 9 specialized agents vs. single-tool approach
4. Combined DFD + attack path visualization
5. GitHub integration with automated fix PRs

---

## CATEGORY 6: COST, BUSINESS & FUTURE

### Q25. What are the costs? POC vs MVP?

**Answer:**

**POC Cost: ~Rs.35K/year**
- LLM API usage: Rs.15K
- GPU/Inference: Rs.10K
- Cloud hosting: Rs.6K
- Storage & misc: Rs.4K

**MVP Cost: ~Rs.12.4 Lakh/year**
- Infrastructure: Rs.4.2L (34%)
- Development team: Rs.3.5L (28%)
- LLM & embeddings: Rs.2.6L (21%)
- Licenses & tools: Rs.0.85L (7%)
- Operations: Rs.0.65L (5%)
- Security & compliance: Rs.0.62L (5%)

The cost-per-analysis at POC level is Rs.0.75-3.75 ($0.01-0.05) — making it feasible even at free tier.

---

### Q26. What is the POC to MVP roadmap?

**Answer:**

**Month 1 — Production Foundation:** DB + vector store, auth & RBAC, security hardening, multi-tenancy
**Month 2-3 — Reliability & Quality:** Formal verification improvement, multi-LLM support, feedback loop, comprehensive test suite
**Month 4-5 — Enterprise Features:** CI/CD integration, compliance reporting, PDF reports, team collaboration
**Month 6 — Scaling & Deployment:** Kubernetes, horizontal scaling, monitoring (Prometheus/Grafana), beta pilot

**Key Deliverables:** Production-ready SaaS platform with multi-tenant support, automated compliance reporting, enterprise security validation.

**Expected Impact:** Reduce manual threat-modeling time from hours to seconds while improving coverage and consistency for DevSecOps teams.

---

### Q27. How would you monetize this? What's the business model?

**Answer:**
1. **Freemium SaaS** — free tier (5 analyses/month), Pro tier (unlimited + GitHub integration + compliance), Enterprise tier (multi-tenant + on-premise + custom agents)
2. **API-as-a-Service** — per-analysis pricing for integration into third-party security platforms
3. **Enterprise licensing** — on-premise deployment for regulated industries (healthcare, finance)
4. **Consulting** — custom threat model templates for specific industry verticals

---

## CATEGORY 7: DEMO-SPECIFIC QUESTIONS

### Q28. Can you analyze a medical device scenario right now?

**Answer:** Yes. Example input:
> "A wireless insulin pump with Bluetooth connectivity to a mobile app. The app communicates with a cloud backend via REST API. Patient glucose readings, insulin dosage history, and pump calibration data are stored in AWS DynamoDB. Firmware updates are pushed over-the-air. The mobile app uses OAuth 2.0 for authentication."

The system would identify:
- Unencrypted Bluetooth communication (CWE-319)
- OTA firmware update without signature verification (CWE-494)
- Missing rate limiting on API (CWE-799)
- Insufficient access control on patient data (CWE-285)
- HIPAA compliance gaps for healthcare data
- Attack paths: Bluetooth interception → dosage manipulation

---

### Q29. What if the Mistral API is down during the demo?

**Answer:** The system has comprehensive fallbacks:
1. **NLP Parser** falls back to keyword-based parsing (Tier 2)
2. **DFD Builder** uses heuristic `_create_smart_dfd()` (doesn't need LLM)
3. **Threat Generator** is entirely rule-based (no LLM)
4. **STRIDE Agent** has `_fallback_analysis()` generating default threats per category
5. **Symbolic Verifier** uses Z3 (no LLM dependency)
6. **CVE Scanner** uses curated fallback CVE data

The system would still produce meaningful threat models — just with less nuanced descriptions.

---

### Q30. Show us the code — where does the "magic" happen?

**Answer:** Three critical code paths:

1. **`src/agents/orchestrator.py:65-350`** — The `analyze()` method orchestrates the entire 5-phase pipeline. Key line: `asyncio.gather(attack_tree_task, cwe_task, maestro_task, symbolic_task, return_exceptions=True)` — this is where parallel execution happens.

2. **`src/agents/threat_generator.py:40-59`** — `generate_threats()` walks the DFD structure and produces deterministic, rule-based vulnerabilities. No AI uncertainty.

3. **`src/agents/symbolic_verifier.py:56-149`** — `verify_access_control()` creates Z3 boolean constraints and proves whether all resources have access control. This is formal verification — mathematically provable results.

---

## CATEGORY 8: FEEDBACK FROM PREVIOUS ROUNDS & IMPROVEMENTS

### Q31. What feedback did you incorporate from previous rounds?

**Answer:** Four key improvements:

1. **Shift from reactive to proactive** — We transitioned from monitoring-based detection to design-time analysis. DFD generation enables early architecture assessment before any code is written.

2. **MAESTRO security integration** — Added as a validation layer to align findings with established security design principles, producing structured compliance insights.

3. **Automated attack vector prediction** — Multi-agent system now simulates multi-stage attacks, generates realistic attack paths (not isolated issues), and improves risk prioritization.

4. **Modern framework adoption** — Implemented AI-native stack (FastAPI, async orchestration, Pydantic AI), modular design for scalability, and DevSecOps integration with GitHub.

---

### Q32. What would you do differently if you started over?

**Answer:**
1. Start with the PostgreSQL database from day 1 instead of in-memory storage
2. Use structured output mode in Pydantic AI agents from the beginning (parsing LLM responses is fragile)
3. Add a RAG pipeline with a CWE knowledge base in ChromaDB for more precise vulnerability descriptions
4. Build a feedback loop earlier — letting users confirm/reject findings improves accuracy over time
5. Support multiple LLMs from the start to avoid platform lock-in

---

## CATEGORY 9: RAPID-FIRE / TRICKY QUESTIONS

### Q33. "Your system uses AI — how can we trust its output for security-critical decisions?"

**Answer:** We never claim to replace security experts. The system is an accelerator: it produces a first draft in 30 seconds that a security engineer would take hours to create manually. The Z3 formal verification provides mathematical guarantees for properties it checks. The confidence score signals reliability. And the structured output (CWE IDs, OWASP categories, CVSS scores) is verifiable against industry databases. Think of it as an AI co-pilot for security, not an autonomous decision-maker.

---

### Q34. "What if an attacker feeds adversarial input to trick your system?"

**Answer:** The NLP Parser uses Mistral AI with a constrained JSON output schema — adversarial input would be parsed into the fixed `AssetInput` structure. The Pydantic model validation rejects invalid values (e.g., CVSS > 10, invalid enum values). Additionally, the rule-based threat generator and Z3 verifier are not susceptible to adversarial NLP attacks since they operate on structural properties, not language.

---

### Q35. "Why not just use ChatGPT for threat modeling?"

**Answer:** ChatGPT gives you a freeform essay. We give you:
- Structured data (JSON API response with typed Pydantic models)
- Visual DFD with vulnerability overlay
- Interactive attack path graphs
- Formal verification proofs
- Direct GitHub integration (auto-create issues, comment on PRs)
- Consistent output format every time
- Multi-agent analysis from 9 specialized perspectives simultaneously
- CVE enrichment from real NVD data

A ChatGPT conversation is disposable. Our system produces an API-consumable, version-trackable, CI/CD-integrable threat model.

---

### Q36. "Your POC uses in-memory storage — isn't that a toy?"

**Answer:** Correct — the in-memory dict is a POC choice for demo speed. But:
- The PostgreSQL schema is already designed and complete (`database_schema.sql` — 7 tables, indexes, views, triggers)
- ChromaDB path is configured for vector storage
- SQLAlchemy and asyncpg are in requirements.txt
- The MVP Month 1 plan specifically addresses this

The architecture separates concerns cleanly — swapping in-memory for PostgreSQL requires changing the storage layer in `app.py`, not the analysis pipeline.

---

### Q37. "How does this apply specifically to LTTS's domain — medical devices and embedded systems?"

**Answer:** Medical devices are uniquely vulnerable because they combine:
- Wireless communication (Bluetooth, WiFi, Zigbee) — we detect unencrypted protocols
- Cloud connectivity (REST APIs, MQTT) — we check authentication and encryption
- AI/ML models — our AI Safety agent analyzes AI-specific risks
- Regulatory requirements (FDA, HIPAA) — built-in compliance checking
- Embedded firmware — we can analyze firmware update mechanisms for integrity

Example: A Bluetooth-connected insulin pump → our DFD Builder creates external entity (mobile app), process (pump controller), data store (cloud DB), data flows (BLE, REST), trust boundaries. The threat generator identifies BLE interception, missing firmware signing, and HIPAA violations — all automatically.

LTTS's challenge is specifically about "wireless communication, AI models, cloud connectivity, and embedded firmware" — our system addresses each of these.

---

### Q38. "What if there are 1000 microservices? Does your system scale?"

**Answer:** Current POC handles single-system analysis. For microservice architectures:
1. The `batch_analyze()` method in the orchestrator processes multiple assets in parallel with `asyncio.Semaphore(MAX_AGENTS_CONCURRENT=5)` to respect rate limits
2. Each microservice can be analyzed independently — vulnerability aggregation happens at the API level
3. The DFD Builder can model complex architectures (Test 20 validates a system with 5 backend services, 3 databases, message queue, 3 external APIs)

For true 1000-service scale, the MVP roadmap includes Kubernetes horizontal scaling (Month 6) with dedicated worker pods per analysis.

---

### Q39. "Why FastAPI over Flask or Django?"

**Answer:**
- **Async-native** — all our agents are async (Pydantic AI, aiohttp for NVD). FastAPI's ASGI architecture supports this natively without monkey-patching
- **Automatic OpenAPI docs** — Swagger UI at `/docs` for free
- **Pydantic integration** — request/response validation with the same Pydantic models used throughout the codebase
- **Performance** — 3-5x faster than Flask for async workloads
- **Type hints** — full type checking for API endpoints

---

### Q40. "What's the single most impressive technical achievement in this project?"

**Answer:** The 5-phase orchestration pipeline that runs 9 agents with fault tolerance in 15-30 seconds. Specifically: Phase 3 running 4 agents (Attack Tree, CWE, MAESTRO, Z3) concurrently via `asyncio.gather` with individual exception handling — if any agent crashes, the pipeline continues and the confidence score adjusts accordingly. Combined with the Z3 formal verification (which provides mathematical guarantees, not AI guesses), this creates a system that is both fast and provably correct for the properties it verifies.

---

## CATEGORY 10: DATA PRIVACY & SECURITY OF THE TOOL ITSELF

### Q41. When users submit code for analysis, the code gets sent to Mistral's API. Free-tier APIs can potentially expose or retain that code. How do you control access and protect submitted code?

**Answer:** This is a critical and valid concern. Let's break it down honestly:

**What happens today in our POC:**

The user's code snippet is embedded directly into the LLM prompt in two places:
1. `NLPParser._build_parsing_prompt()` — sends the full code snippet to Mistral for structured extraction
2. `OWASPAnalyzer` — sends the code again for vulnerability analysis

This means the raw source code leaves the user's machine and reaches Mistral's API servers. On a free-tier or standard API plan, this is a genuine data exposure risk.

**Mitigation strategies (some implemented, some for MVP):**

**1. LLM Provider Data Policies (what exists today):**
- **Mistral AI's API** (which we use): Mistral's commercial API does NOT use API-submitted data for training. Their terms state that data submitted through the API is not used to improve their models. This is distinct from their free chat interface.
- **Anthropic (Claude API):** Explicitly states API data is not used for training. Offers a 30-day retention policy with opt-out.
- **OpenAI API:** As of 2024, API data is NOT used for training by default. Enterprise tier offers zero-retention.
- **Azure OpenAI:** Data stays within your Azure tenant. Microsoft does not access it. This is the gold standard for enterprise.
- **AWS Bedrock:** Models run within your VPC. Data never leaves your AWS account.
- **Self-hosted models (Ollama, vLLM, llama.cpp):** Code never leaves your infrastructure. Zero external exposure.

**2. Architectural mitigations we can implement:**

| Strategy | Description | Effort |
|----------|-------------|--------|
| **Code abstraction** | Strip the code before sending to LLM — send only an abstract representation (AST, function signatures, data flow patterns) instead of raw source | Medium |
| **Local-first analysis** | Run the DFD Builder and Threat Generator (rule-based, no LLM) locally. Only send the *description* to the LLM, never the code | Low — partially already works |
| **Self-hosted LLM** | Deploy Mistral-7B or Llama-3 locally via Ollama. All inference stays on-premise | Medium — architecture already supports swapping LLM |
| **Tokenization / redaction** | Before sending code to the API, automatically redact sensitive strings (API keys, passwords, connection strings, variable names) and replace with placeholders | Medium |
| **Enterprise LLM tiers** | Use Azure OpenAI or AWS Bedrock where data stays in your cloud tenant with contractual guarantees | Low — config change |

**3. What we'd implement in the MVP (Month 2-3):**

- **Hybrid analysis mode:** The rule-based agents (DFD Builder, Threat Generator, Z3 Verifier, CVE Scanner) already run without sending code to any LLM. We'd add a "privacy mode" toggle that restricts LLM usage to *only* the natural language description — never the code. The code would be analyzed locally using AST parsing (Python `ast` module), regex pattern matching for vulnerability signatures (e.g., `f"SELECT * FROM` for SQL injection), and Z3 symbolic verification. This would sacrifice some analysis depth but guarantee zero code exposure.

- **Multi-LLM support with self-hosted option:** Our `primary_llm` config setting already exists. Adding Ollama as a backend (local Mistral-7B) means code analysis happens entirely on the user's machine. No API calls, no exposure.

**Bottom line for judges:** We acknowledge this risk openly. In the POC, code IS sent to Mistral's API, which does not use API data for training. For production, the architecture supports self-hosted LLMs and a privacy mode that keeps code local — the modular agent design makes this a configuration change, not a rewrite.

---

### Q42. Is there anything that ensures the system itself isn't malicious? How does the Z3 Solver help with integrity/trust guarantees?

**Answer:** This question has two dimensions: (a) how do we ensure our *tool's outputs* are trustworthy and not harmful, and (b) how does Z3 specifically provide integrity guarantees.

**Part A: Ensuring the tool's outputs are non-malicious and trustworthy**

There are several layers that prevent the system from producing malicious or fabricated results:

**1. Deterministic rule-based grounding:**
The `AutomatedThreatGenerator` (Phase 0) produces vulnerabilities from pure logic — it walks the DFD structure and checks concrete boolean properties:
```
if not process.sanitizesInput → Injection vulnerability
if store.stores_pii and not store.isEncrypted → Cryptographic failure
if flow.carries_credentials and not flow.isEncrypted → Cleartext transmission
```
These checks are deterministic. You can read the code in `threat_generator.py` and verify exactly what conditions produce what output. There is no LLM involved — no possibility of hallucination or manipulation.

**2. Pydantic model validation (structural integrity):**
Every vulnerability must pass Pydantic model validation before it enters the output:
- `cvss_score: float = Field(ge=0.0, le=10.0)` — cannot fabricate a score of 15
- `severity: SeverityLevel` — must be one of: none, low, medium, high, critical
- `owasp_category: OWASPCategory` — must be a valid OWASP Top 10 2021 category
- `cwe_id: str = Field(pattern=r"^CWE-\d+$")` on CWEReference — must be valid CWE format
- `probability: float = Field(ge=0.0, le=1.0)` on AttackPath

If an LLM agent hallucinates a CWE-ID that doesn't match the pattern, or a CVSS score outside 0-10, Pydantic rejects it at runtime. The output is structurally guaranteed to be valid.

**3. Multi-agent consensus:**
A single agent could be wrong. But when the DFD-based threat generator, STRIDE agent, AND OWASP agent all independently identify "SQL Injection / CWE-89" for the same system, the finding has multi-source corroboration. Our deduplication on `(cwe_id, title)` ensures we count it once, but the fact that multiple agents agree increases confidence.

**4. CVE enrichment from authoritative sources:**
When we say a vulnerability maps to CVE-2024-1234 with CVSS 9.8, that data comes from NIST's National Vulnerability Database — an authoritative, government-maintained source. We don't fabricate CVE data; we query it from NVD or use curated fallback data with real CWE mappings.

**Part B: How Z3 specifically provides integrity guarantees**

The Z3 SMT Solver is the highest-integrity component in our system. Here's why it's fundamentally different from AI:

**Z3 is not AI. It is a theorem prover.**

When Z3 says a property holds, it has *mathematically proven* it. When it says a property is violated, it provides a *concrete counterexample*. There is no probability, no confidence score, no hallucination possible.

**Concrete example — Access Control Verification:**

```python
# Z3 creates boolean variables for each resource
resource_protected = {
    "patient_records": z3.Bool('protected_patient_records'),
    "admin_panel": z3.Bool('protected_admin_panel'),
    "api_keys": z3.Bool('protected_api_keys')
}

# Adds constraints based on actual role-to-resource mappings
# If "admin_panel" has no role assigned → constraint: protected_admin_panel == False
# Then asks: "Can ALL resources be protected simultaneously?"

result = solver.check()
# If UNSAT → mathematically proven that not all resources are protected
# Z3 identifies exactly WHICH resources are unprotected
```

The Z3 result is not "we think access control might be incomplete." It's: "It is mathematically impossible for all resources to be protected given the current policy configuration. Specifically, `admin_panel` and `api_keys` have no access control."

**Three properties Z3 verifies in our system:**

| Property | What Z3 Proves | Guarantee Level |
|----------|---------------|-----------------|
| **Access Control Coverage** | Every resource has at least one authorized role | Mathematical proof (SAT/UNSAT) |
| **Data Flow Integrity (Taint Analysis)** | Untrusted data cannot reach sensitive sinks without sanitization | Mathematical proof with counterexample |
| **Authentication Invariants** | Authentication ∧ Session Management ∧ Token Validation all present | Logical conjunction verification |

**Why this matters for trust:**

If a judge asks "how do I know your tool isn't lying about a vulnerability?" — the answer for Z3-verified properties is: "The same way you know 2+2=4. Z3 is a mathematical theorem prover used in production by Microsoft for verifying Windows drivers, by AWS for verifying IAM policies (Zelkova), and by CompCert for verifying C compilers. When Z3 says a property is violated, it provides the specific counterexample that proves the violation. This is not AI opinion — it is mathematical fact."

**For the LLM-based agents (STRIDE, OWASP, MAESTRO):**
These ARE probabilistic and CAN hallucinate. That's why:
- We use them in conjunction with Z3, not instead of it
- The confidence score (weighted average, mean 0.75) signals reliability
- The rule-based threat generator provides a deterministic baseline
- Pydantic validation rejects structurally invalid output
- Multi-agent consensus reduces single-agent errors

**The overall trust model is: Z3 provides mathematical guarantees, rule-based agents provide deterministic checks, and LLM agents provide breadth of coverage with explicit confidence signaling.** No single layer is trusted alone.

---

*Last updated: March 2026 | Prepared for TECHgium 9th Edition Final Presentation*
