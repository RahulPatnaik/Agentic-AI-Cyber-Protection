# PRESENTATION SCRIPT — TECHgium 9th Edition Final Round

**Project:** AI-Enabled Agile Automated Threat Modeling
**PID:** TG0915025 | Team: Rahul Patnaik, Noel S Mathew | Mentor: Dr. Sudarshan B G
**Institution:** RV College of Engineering, Bangalore

**Time Allocation:**
- 8 minutes content + 2 minutes conclusion = 10 minutes presentation
- 5 minutes demo (integrated within presentation)
- 5 minutes Q&A

---

## SLIDE 1: TITLE SLIDE [0:00 - 0:15] (15 seconds)

**Speaker:** [Rahul]

**Say:**
> "Good morning / afternoon, judges and mentors. We are Team TG0915025 from RV College of Engineering. I'm Rahul Patnaik, with me is Noel S Mathew, and our project mentor is Dr. Sudarshan B G. Today we're presenting our AI-Enabled Agile Automated Threat Modeling system."

**Action:** Title slide is already displayed. Stand confident. Make eye contact.

---

## SLIDE 2: CHALLENGE STATEMENT [0:15 - 1:00] (45 seconds)

**Speaker:** [Rahul]

**Say:**
> "Let's begin with the challenge. Modern medical devices rely on wireless communication, AI models, cloud connectivity, and embedded firmware — each expanding the attack surface. Look at this graph: in 2023 alone, 28,821 CVEs were published — a 14.9% increase from the previous year. The trend is accelerating.
>
> Traditional security assessments are manual, static, and cannot keep pace with this volume. A skilled security engineer takes 2-4 hours per system for a basic threat model. For organizations managing hundreds of systems, this is simply not scalable.
>
> The challenge is clear: develop an autonomous security framework that can continuously analyze any device's data integrity, identify vulnerabilities in real time, and propose regulatory-compliant strategies. That's exactly what we built."

**Action:** Point to the CVE graph when mentioning the numbers. Emphasize "2-4 hours" vs what you'll show later.

---

## SLIDE 3: CONCEPT / PROPOSED SOLUTION [1:00 - 2:15] (75 seconds)

**Speaker:** [Noel]

**Say:**
> "Our solution operates in three layers — Perception, Reasoning, and Synthesis.
>
> **Perception Layer:** A user types a natural language description of their system — or pastes actual code. Our NLP Parser, powered by Mistral AI, transforms this unstructured input into a structured asset model with component types, frameworks, compliance requirements, and data sensitivity classification.
>
> **Reasoning Layer:** This is where the multi-agent intelligence happens. Nine specialized AI agents work in a coordinated pipeline. The DFD Builder automatically generates a Data Flow Diagram — identifying processes, data stores, data flows, and trust boundaries. From this structure, the Automated Threat Generator applies rule-based checks, similar to OWASP pytm. Then STRIDE, OWASP, Attack Tree, CWE, and MAESTRO agents analyze simultaneously using asyncio parallel execution. Our Z3 SMT Symbolic Verifier provides formal mathematical proofs of security properties — this is not AI guessing, it's theorem proving. And the CVE Scanner enriches findings with real data from the National Vulnerability Database.
>
> **Synthesis Layer:** Everything is aggregated, deduplicated, risk-scored, and presented as an interactive dashboard with DFD visualizations, D3.js attack graphs, and actionable remediation steps. One-click export to HTML reports, or direct GitHub integration to create issues and fix PRs.
>
> The entire pipeline runs in 15 to 30 seconds."

**Action:** Point to the architecture diagram as you describe each layer. Trace the flow from input to output.

---

## SLIDE 4: FEEDBACK FROM PREVIOUS ROUNDS [2:15 - 2:55] (40 seconds)

**Speaker:** [Rahul]

**Say:**
> "We took the feedback from previous rounds seriously and made four significant changes.
>
> First, we shifted from reactive detection to proactive threat modeling. Instead of monitoring running systems, we now analyze at design time — enabling 'shift-left' security during development.
>
> Second, we integrated MAESTRO security principles as a validation layer, aligning all findings with established best practices.
>
> Third, we implemented automated attack vector prediction. Our multi-agent system now simulates multi-stage attacks, generating realistic attack paths — not isolated findings.
>
> Fourth, we adopted a modern AI-native tech stack — FastAPI, async orchestration, Pydantic AI — with modular design for scalability and DevSecOps pipeline integration."

**Action:** Briefly touch on each of the 4 points. Keep it punchy — don't elaborate too much here.

---

## SLIDE 5: SWOT ANALYSIS [2:55 - 3:25] (30 seconds)

**Speaker:** [Noel]

**Say:**
> "Quickly on our SWOT: Our strengths are the multi-agent architecture with specialized expertise and proactive pre-deployment threat prediction.
>
> We acknowledge weaknesses — the POC uses in-memory storage, and we currently depend on a single LLM provider. Both are addressed in our MVP roadmap.
>
> The opportunity is enterprise SOC automation and regulatory compliance automation for HIPAA, GDPR, FDA, and NIST — massive markets that currently rely on manual processes.
>
> The key threat is AI hallucination causing false positive fatigue. We mitigate this with Z3 formal verification, rule-based DFD analysis, and multi-agent consensus."

**Action:** Don't linger here. It's a quick acknowledgment of maturity. Move on.

---

## SLIDE 6: IMPLEMENTATION 1/2 [3:25 - 4:15] (50 seconds)

**Speaker:** [Rahul]

**Say:**
> "Let me walk you through the implementation pipeline.
>
> Input — a description or code — goes to the NLP Parser powered by Mistral AI. This produces a structured AssetInput with component type, languages, frameworks, and compliance requirements.
>
> The Agent Orchestrator then runs a 5-phase pipeline. Phase 0: DFD Builder creates the architecture diagram and the Threat Generator produces rule-based vulnerabilities from the structure. Phase 1: STRIDE categorization across 6 threat dimensions. Phase 2: OWASP Top 10 analysis — then we merge and deduplicate all vulnerabilities using CWE-ID and title as composite keys.
>
> Phase 3 is where parallel execution shines — Attack Tree, CWE Mapper, MAESTRO Validator, and Z3 Symbolic Verifier run simultaneously using Python asyncio. If any agent fails, the pipeline continues — each failure produces a fallback analysis and the confidence score adjusts accordingly.
>
> Phase 4: CVE enrichment from the NVD API for the top 10 vulnerabilities, with rate limiting and 24-hour caching.
>
> The output: prioritized vulnerabilities, attack paths, interactive graph, and compliance report."

**Action:** Trace the pipeline diagram left to right as you speak. Emphasize "parallel execution" and "fault tolerance."

---

## SLIDE 7: IMPLEMENTATION 2/2 — TECH STACK [4:15 - 4:35] (20 seconds)

**Speaker:** [Noel]

**Say:**
> "Our technology stack: Pydantic AI for agent orchestration and structured LLM output. Mistral AI for NLP parsing and vulnerability reasoning. FastAPI with Uvicorn for the async REST API. Pydantic for data validation — every vulnerability model has validated CVSS scores, severity enums, and OWASP categories. D3.js and NetworkX for visualization. And OWASP, CWE, and MAESTRO as our security classification standards."

**Action:** Quick walkthrough of the table. Don't read every row — highlight the key choices.

---

## SLIDE 8 + 9: TESTING RESULTS [4:35 - 5:25] (50 seconds)

**Speaker:** [Rahul]

**Say:**
> "We built a comprehensive test suite with 20 end-to-end tests across 8 vulnerability categories: SQL injection, XSS, authentication failures, cryptographic failures, security misconfiguration, DFD generation accuracy, attack path prediction, and MAESTRO validation.
>
> Our evaluation approach was end-to-end pipeline testing: natural language input goes through the complete pipeline — NLP parsing, DFD generation, all 9 agents — and we validate the output against expected vulnerability types.
>
> Results: 85% success rate — 17 out of 20 tests passed. The system identified 156 vulnerabilities across test cases. 75 were classified as critical, 81 as high severity. Each system description yielded 7 to 8 actionable findings on average. Mean confidence score: 0.75.
>
> Importantly, the 3 failures were labeling inconsistencies — the vulnerability was detected but the title didn't match our pattern. The system remained operational despite partial agent or API failures during testing."

**Action:** Point to the test flow diagram. Emphasize "85% success rate" and "156 vulnerabilities" as concrete metrics.

---

## *** LIVE DEMO *** [5:25 - 10:00] (4.5 minutes)

**Speaker:** [Noel operates, Rahul narrates]

### Demo Setup (already running before presentation)
- Server running at http://localhost:8000
- Browser open at http://localhost:8000/dashboard

---

### Demo Part 1: JWT Authentication System [5:25 - 7:30] (2 min 5 sec)

**[Rahul says:]**
> "Let me show you the system in action. We have our dashboard ready. Let's analyze a real-world scenario: a JWT-based authentication API."

**[Noel types in "TARGET SYSTEM DESCRIPTION":]**
```
A user authentication API built with Node.js and Express. Users register with email/password, which are stored in MongoDB. Upon login, the system generates JWT tokens with 24-hour expiration. The API has endpoints for user registration, login, password reset, and profile updates. Password reset sends a reset link via email with a temporary token.
```

**[Noel types in "CODE INTEL":]**
```javascript
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await db.collection('users').findOne({ email: email });
    if (!user || user.password !== password) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
        { userId: user._id, email: user.email },
        'secret-key-12345',
        { expiresIn: '24h' }
    );
    res.json({ token: token, userId: user._id });
});
```

**[Noel selects PCI-DSS and GDPR compliance checkboxes, clicks "INITIATE THREAT ANALYSIS"]**

**[Rahul says while waiting:]**
> "Watch the progress indicators — 9 agents are now working in parallel. The DFD Builder is mapping the architecture, STRIDE is categorizing threats across 6 dimensions, OWASP and CWE are classifying vulnerabilities, and the Z3 verifier is running formal proofs."

**[Results appear — Rahul narrates:]**

> "Results are in. Let's walk through what the system found.
>
> First, the stats — [read the numbers: total vulnerabilities, critical, high, attack paths].
>
> Here's the automatically generated Data Flow Diagram. Notice it identified the User as an untrusted external entity, the Auth API as a process, MongoDB as the data store, and the trust boundary between internet and internal network. Data flows show HTTP for user requests and SQL for database queries — with security annotations.
>
> Now the attack path visualization — see how the system chains vulnerabilities: hardcoded JWT secret key allows token forgery, which leads to account takeover, which provides access to all user data.
>
> Top vulnerabilities: the hardcoded JWT secret 'secret-key-12345' — CWE-798 — plaintext password comparison — CWE-257 — weak password reset token using Math.random — CWE-330. Each has OWASP category, CVSS score, risk rating, and specific code fix examples.
>
> This analysis would take a security engineer 2-3 hours manually. We did it in [read the actual time from the dashboard] seconds."

---

### Demo Part 2: Quick Second Analysis [7:30 - 8:45] (1 min 15 sec)

**[Rahul says:]**
> "Let's do one more — a file upload service. This is common in medical device portals for uploading patient documents."

**[Noel clicks "NEW ANALYSIS" and types:]**
```
A file upload service for a healthcare portal. Users upload medical documents (PDF, DOCX, DICOM). Files are stored in /uploads directory on the server with no file type validation. The system accepts any file type, generates a random filename, and stores the path in PostgreSQL. Files are served directly via URL. The service must be HIPAA compliant.
```

**[Noel selects HIPAA compliance, clicks "INITIATE THREAT ANALYSIS"]**

**[Rahul says while waiting:]**
> "Notice we mentioned HIPAA compliance — the system will now also check regulatory requirements."

**[Results appear — Rahul quickly narrates:]**
> "As expected: unrestricted file upload — CWE-434, path traversal — CWE-22, potential remote code execution, missing authentication on the upload endpoint, and HIPAA compliance violations for unencrypted medical records. The system provides specific remediation: implement file type whitelisting, store files outside web root, scan for malware, encrypt at rest for HIPAA.
>
> Two complete threat models, each in under 30 seconds."

---

### Demo Part 3: Quick GitHub Integration Showcase [8:45 - 9:15] (30 seconds)

**[Rahul says:]**
> "One more thing — our GitHub integration. From any vulnerability, you can create a GitHub issue with one click. For teams using pull requests, the system can automatically comment on PRs with the full threat analysis, or create a fix PR with a SECURITY_FIXES.md detailing every remediation step. We also generate a GitHub Actions workflow YAML for automated threat modeling on every pull request — true DevSecOps integration."

**[Noel shows the API docs at /docs briefly, showing the GitHub endpoints]**

---

## SLIDE 11: POC TO MVP ROADMAP [9:15 - 9:35] (20 seconds)

**Speaker:** [Rahul]

**Say:**
> "Our 6-month roadmap to MVP: Month 1 — production foundation with PostgreSQL, authentication, and multi-tenancy. Months 2-3 — reliability with multi-LLM support, feedback loops, and expanded test suite. Months 4-5 — enterprise features including CI/CD, compliance reporting, and team collaboration. Month 6 — Kubernetes deployment with horizontal scaling and a beta pilot."

---

## SLIDE 12: COST [9:35 - 9:45] (10 seconds)

**Speaker:** [Noel]

**Say:**
> "POC cost is approximately 35 thousand rupees per year. MVP scales to 12.4 lakh per year, with infrastructure and development as the major components. Per-analysis cost is under 4 rupees at POC level."

---

## SLIDE 13: RESULT & CONCLUSION [9:45 - 10:00] (15 seconds)

**Speaker:** [Rahul]

**Say:**
> "To conclude: We achieved 85% detection accuracy across diverse security scenarios. Our system identifies critical vulnerabilities and generates realistic attack paths from natural language descriptions in under 30 seconds. It provides unified coverage across OWASP, CWE, CVSS, STRIDE, and MAESTRO standards — something no existing tool offers.
>
> The advantages over existing tools: natural language input eliminates manual diagramming, Z3 formal verification provides mathematical guarantees, and the fully automated pipeline from DFD generation through remediation makes security accessible to every developer, not just security experts.
>
> Thank you. We're ready for questions."

**Action:** Confident closing. Make eye contact with the judges.

---

## Q&A PREPARATION [10:00 - 15:00] (5 minutes)

### Priority Questions to Prepare For (most likely to be asked):

**Tier 1 — Almost Certain:**
1. "How do you handle false positives?" → See QA.md Q12, Q22
2. "How is this different from ChatGPT for security?" → See QA.md Q35
3. "What about AI hallucination?" → See QA.md Q22
4. "How does the Z3 verification work?" → See QA.md Q9
5. "What happens when the API is down?" → See QA.md Q29

**Tier 2 — Likely:**
6. "How does this apply to medical devices?" → See QA.md Q37
7. "How do you ensure scalability?" → See QA.md Q20, Q38
8. "What are your weaknesses?" → See QA.md Q21
9. "Why 9 agents instead of one?" → See QA.md Q5
10. "Can we trust AI for security-critical decisions?" → See QA.md Q33

**Tier 3 — Possible Curveballs:**
11. "What if an attacker feeds adversarial input?" → See QA.md Q34
12. "Your POC uses in-memory storage — isn't that a toy?" → See QA.md Q36
13. "What competitors exist?" → See QA.md Q24
14. "What would you do differently?" → See QA.md Q32
15. "What's the single most impressive achievement?" → See QA.md Q40

### Q&A Strategy:
- **Rahul** handles: Architecture, orchestrator pipeline, Z3 verification, testing results, business questions
- **Noel** handles: Tech stack choices, GitHub integration, demo questions, cost, implementation details
- If you don't know an answer: "That's an excellent point — our current POC doesn't address that, but our MVP roadmap includes [X] in Month [Y]."
- Keep answers to 30-45 seconds max. Be direct. Lead with the answer, then explain.

---

## TIMING SUMMARY

| Section | Time | Duration | Cumulative |
|---------|------|----------|------------|
| Title | 0:00 | 0:15 | 0:15 |
| Challenge Statement | 0:15 | 0:45 | 1:00 |
| Concept / Solution | 1:00 | 1:15 | 2:15 |
| Feedback from Rounds | 2:15 | 0:40 | 2:55 |
| SWOT | 2:55 | 0:30 | 3:25 |
| Implementation 1/2 | 3:25 | 0:50 | 4:15 |
| Implementation 2/2 | 4:15 | 0:20 | 4:35 |
| Testing Results | 4:35 | 0:50 | 5:25 |
| **LIVE DEMO** | 5:25 | 3:50 | 9:15 |
| Roadmap | 9:15 | 0:20 | 9:35 |
| Cost | 9:35 | 0:10 | 9:45 |
| Conclusion | 9:45 | 0:15 | 10:00 |
| **Q&A** | 10:00 | 5:00 | 15:00 |

---

## PRE-PRESENTATION CHECKLIST

- [ ] Server running: `python main.py` (start 10 min before slot)
- [ ] Browser open at `http://localhost:8000/dashboard`
- [ ] Demo scenarios pre-typed in a text file for quick copy-paste
- [ ] Backup: screenshots of results in case of API failure
- [ ] Slides loaded and tested on projector
- [ ] Both team members know their speaking parts
- [ ] QA.md reviewed — both members know all 40 answers
- [ ] Water available for dry throat
- [ ] Laptop fully charged / plugged in

---

*Good luck, team. You built something impressive. Now show them.*
