/**
 * TACTICAL THREAT MODELING OPS - JavaScript
 */

// API Configuration
const API_BASE_URL = window.location.origin;

// GitHub supported languages/file extensions for code analysis
const SUPPORTED_CODE_EXTENSIONS = [
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h', '.hpp',
    '.go', '.rs', '.rb', '.php', '.cs', '.swift', '.kt', '.scala', '.sql',
    '.sh', '.bash', '.yml', '.yaml', '.json', '.xml', '.html', '.css'
];

// Initialize Mermaid
mermaid.initialize({
    startOnLoad: true,
    theme: 'dark',
    themeVariables: {
        primaryColor: '#1a1f2e',
        primaryTextColor: '#e5e7eb',
        primaryBorderColor: '#fb923c',
        lineColor: '#06b6d4',
        secondaryColor: '#0d1117',
        tertiaryColor: '#2a3441',
        fontSize: '14px',
        fontFamily: 'JetBrains Mono, IBM Plex Mono, monospace'
    },
    flowchart: {
        htmlLabels: true,
        curve: 'basis',
        padding: 20
    }
});

// State
let currentModelId = null;
let currentThreatModel = null;

// DOM Elements
const analyzeForm = document.getElementById('analyzeForm');
const analyzeBtn = document.getElementById('analyzeBtn');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultsSection = document.getElementById('resultsSection');
const newAnalysisBtn = document.getElementById('newAnalysisBtn');
const exportPdfBtn = document.getElementById('exportPdfBtn');

// Event Listeners
analyzeForm.addEventListener('submit', handleAnalyzeSubmit);
newAnalysisBtn.addEventListener('click', handleNewAnalysis);
exportPdfBtn.addEventListener('click', handleExportPdf);

// Compliance button event listener (added after results are shown)
function attachComplianceButtonListener() {
    const downloadComplianceBtn = document.getElementById('downloadComplianceBtn');
    if (downloadComplianceBtn && !downloadComplianceBtn.dataset.listenerAttached) {
        downloadComplianceBtn.addEventListener('click', handleDownloadComplianceReport);
        downloadComplianceBtn.dataset.listenerAttached = 'true';
        console.log('Compliance button listener attached');
    }
}

/**
 * Handle form submission
 */
async function handleAnalyzeSubmit(e) {
    e.preventDefault();

    // Get form data
    const description = document.getElementById('description').value.trim();
    const codeSnippet = document.getElementById('codeSnippet').value.trim();
    const complianceCheckboxes = document.querySelectorAll('input[name="compliance"]:checked');
    const compliance = Array.from(complianceCheckboxes).map(cb => cb.value);

    if (!description) {
        alert('ALERT: PROVIDE SYSTEM DESCRIPTION');
        return;
    }

    // Show loading
    analyzeBtn.disabled = true;
    loadingIndicator.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    // Start progress simulation
    simulateProgress();

    try {
        // Call API
        const response = await fetch(`${API_BASE_URL}/api/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                description: description,
                code_snippet: codeSnippet || null,
                compliance_requirements: compliance
            })
        });

        if (!response.ok) {
            throw new Error(`API ERROR: ${response.status}`);
        }

        const result = await response.json();
        currentModelId = result.model_id;

        // Fetch complete threat model
        const modelResponse = await fetch(`${API_BASE_URL}/api/models/${currentModelId}`);
        if (!modelResponse.ok) {
            throw new Error(`FAILED TO FETCH THREAT MODEL: ${modelResponse.status}`);
        }

        currentThreatModel = await modelResponse.json();

        // Display results
        displayResults(currentThreatModel);

    } catch (error) {
        console.error('ANALYSIS FAILED:', error);
        alert(`ANALYSIS FAILED: ${error.message}`);
    } finally {
        loadingIndicator.classList.add('hidden');
        analyzeBtn.disabled = false;
    }
}

/**
 * Display analysis results
 */
function displayResults(threatModel) {
    // Update stats
    const criticalVulns = threatModel.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highVulns = threatModel.vulnerabilities.filter(v => v.severity === 'high').length;

    document.getElementById('criticalCount').textContent = criticalVulns;
    document.getElementById('highCount').textContent = highVulns;
    document.getElementById('attackPathsCount').textContent = threatModel.attack_paths.length;
    document.getElementById('confidenceScore').textContent = Math.round(threatModel.confidence_score * 100) + '%';

    // Display vulnerabilities
    displayVulnerabilities(threatModel.top_vulnerabilities);

    // Display DFD diagram if available
    if (threatModel.threat_graph && threatModel.threat_graph.dfd_diagram) {
        displayDFDDiagram(threatModel.threat_graph.dfd_diagram);
    }

    // Display Mermaid threat graph (attack paths)
    displayMermaidGraph(threatModel.attack_paths);

    // Display CWE mappings
    displayCWEMappings(threatModel.cwe_references);

    // Display Agentic AI Threats
    displayAgenticThreats(threatModel.vulnerabilities);

    // Display MAESTRO validation
    if (threatModel.agent_analyses && threatModel.agent_analyses.maestro) {
        displayMAESTROValidation(threatModel.agent_analyses.maestro);
    }

    // Show results section
    resultsSection.classList.remove('hidden');

    // Attach compliance button listener now that results are visible
    attachComplianceButtonListener();

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Display DFD (Data Flow Diagram)
 */
function displayDFDDiagram(dfdMermaidCode) {
    if (!dfdMermaidCode || dfdMermaidCode.trim() === '') {
        document.getElementById('dfdGraph').textContent = 'graph TD\n    A[NO DFD DATA AVAILABLE]';
        mermaid.init(undefined, document.getElementById('dfdGraph'));
        return;
    }

    // Update the mermaid element with DFD code
    const dfdElement = document.getElementById('dfdGraph');
    dfdElement.textContent = dfdMermaidCode;
    dfdElement.removeAttribute('data-processed');

    // Re-render Mermaid
    mermaid.init(undefined, dfdElement);
}

/**
 * Display Mermaid.js threat graph
 */
function displayMermaidGraph(attackPaths) {
    if (!attackPaths || attackPaths.length === 0) {
        document.getElementById('threatGraph').textContent = 'graph TD\n    A[NO ATTACK PATHS IDENTIFIED]';
        mermaid.init(undefined, document.getElementById('threatGraph'));
        return;
    }

    // Build Mermaid flowchart syntax - show ALL attack paths
    let mermaidCode = 'graph TD\n';
    let nodeCounter = 0;
    const nodeMap = new Map();

    // Show all attack paths (removed slice limit)
    attackPaths.forEach((path, pathIndex) => {
        // Entry point
        const entryId = `N${nodeCounter++}`;
        nodeMap.set(`${pathIndex}_entry`, entryId);
        mermaidCode += `    ${entryId}["[ENTRY] ${path.entry_point}"]\n`;

        // Intermediate steps
        let prevId = entryId;
        path.intermediate_steps.forEach((step, stepIndex) => {
            const stepId = `N${nodeCounter++}`;
            nodeMap.set(`${pathIndex}_${stepIndex}`, stepId);
            mermaidCode += `    ${stepId}["${step}"]\n`;
            mermaidCode += `    ${prevId} --> ${stepId}\n`;
            prevId = stepId;
        });

        // Target/Impact
        const targetId = `N${nodeCounter++}`;
        nodeMap.set(`${pathIndex}_target`, targetId);
        const severity = path.potential_damage || 'critical';
        const icon = severity === 'critical' ? '[!]' : '[!]';
        mermaidCode += `    ${targetId}["${icon} ${path.target}"]\n`;
        mermaidCode += `    ${prevId} --> ${targetId}\n`;

        // Style based on severity
        const colorClass = severity === 'critical' ? 'critical' : 'high';
        mermaidCode += `    style ${targetId} fill:#ff4444,stroke:#ff4444,stroke-width:3px\n`;
    });

    // Update the mermaid element
    const mermaidElement = document.getElementById('threatGraph');
    mermaidElement.textContent = mermaidCode;
    mermaidElement.removeAttribute('data-processed');

    // Re-render Mermaid
    mermaid.init(undefined, mermaidElement);
}

/**
 * Display vulnerabilities list
 */
function displayVulnerabilities(vulnerabilities) {
    // Store for filtering
    allVulnerabilities = vulnerabilities;

    // Initial display (no filters)
    displayFilteredVulnerabilities(vulnerabilities);

    // Show filter stats
    const statsEl = document.getElementById('filterStats');
    if (statsEl) {
        statsEl.textContent = `› SHOWING ${vulnerabilities.length} VULNERABILITIES`;
    }
}

// Keep old function for compatibility but redirect to filtered version
function displayVulnerabilitiesOld(vulnerabilities) {
    const container = document.getElementById('vulnerabilitiesList');
    container.innerHTML = '';

    if (vulnerabilities.length === 0) {
        container.innerHTML = '<div class="empty-state">NO CRITICAL VULNERABILITIES FOUND</div>';
        return;
    }

    vulnerabilities.forEach((vuln, index) => {
        const vulnDiv = document.createElement('div');
        vulnDiv.className = `vuln-card severity-${vuln.severity}`;

        vulnDiv.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-title">${index + 1}. ${vuln.title}</div>
                <div class="vuln-severity">${vuln.severity.toUpperCase()}</div>
            </div>
            <div class="vuln-description">${vuln.description}</div>
            <div class="vuln-meta">
                <div class="meta-item">
                    <div class="meta-label">CWE</div>
                    <div class="meta-value">${vuln.cwe_id} - ${vuln.cwe_name}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">OWASP</div>
                    <div class="meta-value">${vuln.owasp_category}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">CVSS SCORE</div>
                    <div class="meta-value">${vuln.cvss_score}/10</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">RISK SCORE</div>
                    <div class="meta-value">${vuln.risk_score}/10</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">EXPLOITABILITY</div>
                    <div class="meta-value">${vuln.exploitability || 'N/A'}</div>
                </div>
            </div>
            <div class="vuln-meta">
                <div class="meta-item" style="grid-column: 1 / -1;">
                    <div class="meta-label">ATTACK VECTOR</div>
                    <div class="meta-value">${vuln.attack_vector}</div>
                </div>
            </div>
            <div class="vuln-remediation">
                <h4>REMEDIATION</h4>
                <p>${vuln.recommendation}</p>
                ${vuln.remediation_steps && vuln.remediation_steps.length > 0 ? `
                    <ul class="remediation-steps">
                        ${vuln.remediation_steps.map(step => `<li>${step}</li>`).join('')}
                    </ul>
                ` : ''}
                ${vuln.code_fix_example ? `
                    <div class="code-fix">
                        <strong>CODE FIX EXAMPLE:</strong>
                        <pre>${escapeHtml(vuln.code_fix_example)}</pre>
                    </div>
                ` : ''}
            </div>
        `;

        container.appendChild(vulnDiv);
    });
}

/**
 * Display CWE mappings
 */
function displayCWEMappings(cweReferences) {
    const container = document.getElementById('cweList');
    container.innerHTML = '';

    if (!cweReferences || cweReferences.length === 0) {
        container.innerHTML = '<div class="empty-state">NO CWE MAPPINGS AVAILABLE</div>';
        return;
    }

    cweReferences.slice(0, 10).forEach(cwe => {
        const cweDiv = document.createElement('div');
        cweDiv.className = 'cwe-card';

        cweDiv.innerHTML = `
            <div class="cwe-header">${cwe.cwe_id}: ${cwe.cwe_name}</div>
            <div class="cwe-description">${cwe.description}</div>
            ${cwe.mitigation_strategies && cwe.mitigation_strategies.length > 0 ? `
                <div class="cwe-mitigations">
                    <h5>MITIGATION STRATEGIES:</h5>
                    <ul>
                        ${cwe.mitigation_strategies.map(strategy => `<li>${strategy}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        `;

        container.appendChild(cweDiv);
    });
}

/**
 * Display Agentic AI Threats
 */
function displayAgenticThreats(vulnerabilities) {
    const container = document.getElementById('agenticThreats');
    container.innerHTML = '';

    if (!vulnerabilities || vulnerabilities.length === 0) {
        container.innerHTML = '<div class="empty-state">NO VULNERABILITIES AVAILABLE</div>';
        return;
    }

    // Filter for agentic-specific threats
    const agenticVulns = vulnerabilities.filter(v =>
        v.is_agentic_threat ||
        v.is_mcp_threat ||
        v.owasp_llm_category ||
        v.agentic_threat_category ||
        v.mcp_threat_category
    );

    if (agenticVulns.length === 0) {
        container.innerHTML = '<div class="empty-state">NO AGENTIC AI THREATS DETECTED</div>';
        return;
    }

    // Count by category
    const stats = {
        total: agenticVulns.length,
        prompt_injection: agenticVulns.filter(v =>
            v.agentic_threat_category === 'prompt_injection' ||
            v.owasp_llm_category?.includes('Prompt Injection')
        ).length,
        tool_misuse: agenticVulns.filter(v =>
            v.agentic_threat_category === 'tool_misuse' ||
            v.mcp_threat_category?.includes('tool_abuse')
        ).length,
        mcp_threats: agenticVulns.filter(v => v.is_mcp_threat).length,
        jailbreaking: agenticVulns.filter(v => v.agentic_threat_category === 'jailbreaking').length
    };

    // Display stats
    container.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 8px; padding: 15px; text-align: center;">
                <div style="font-size: 32px; font-weight: bold; color: #ef4444;">${stats.total}</div>
                <div style="font-size: 12px; color: var(--text-secondary); margin-top: 5px;">TOTAL AGENTIC THREATS</div>
            </div>
            <div style="background: rgba(249, 115, 22, 0.1); border: 1px solid #f97316; border-radius: 8px; padding: 15px; text-align: center;">
                <div style="font-size: 32px; font-weight: bold; color: #f97316;">${stats.prompt_injection}</div>
                <div style="font-size: 12px; color: var(--text-secondary); margin-top: 5px;">PROMPT INJECTION</div>
            </div>
            <div style="background: rgba(234, 179, 8, 0.1); border: 1px solid #eab308; border-radius: 8px; padding: 15px; text-align: center;">
                <div style="font-size: 32px; font-weight: bold; color: #eab308;">${stats.tool_misuse}</div>
                <div style="font-size: 12px; color: var(--text-secondary); margin-top: 5px;">TOOL MISUSE</div>
            </div>
            <div style="background: rgba(168, 85, 247, 0.1); border: 1px solid #a855f7; border-radius: 8px; padding: 15px; text-align: center;">
                <div style="font-size: 32px; font-weight: bold; color: #a855f7;">${stats.mcp_threats}</div>
                <div style="font-size: 12px; color: var(--text-secondary); margin-top: 5px;">MCP THREATS</div>
            </div>
        </div>
        <div style="margin-top: 20px;">
            <h4 style="color: var(--cyan); margin-bottom: 15px; font-size: 14px;">AGENTIC VULNERABILITIES DETECTED:</h4>
            <div id="agenticVulnsList"></div>
        </div>
    `;

    const vulnsList = document.getElementById('agenticVulnsList');

    agenticVulns.forEach((vuln, index) => {
        const vulnDiv = document.createElement('div');
        vulnDiv.style.cssText = `
            background: rgba(0,0,0,0.3);
            border-left: 4px solid ${vuln.severity === 'critical' ? '#dc2626' : vuln.severity === 'high' ? '#ea580c' : '#f59e0b'};
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
        `;

        // Build category badges
        let badges = '';
        if (vuln.owasp_llm_category) {
            badges += `<span style="background: rgba(239, 68, 68, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 11px; margin-right: 8px;">OWASP LLM: ${vuln.owasp_llm_category}</span>`;
        }
        if (vuln.agentic_threat_category) {
            badges += `<span style="background: rgba(249, 115, 22, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 11px; margin-right: 8px;">AGENTIC: ${vuln.agentic_threat_category}</span>`;
        }
        if (vuln.mcp_threat_category) {
            badges += `<span style="background: rgba(168, 85, 247, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 11px; margin-right: 8px;">MCP: ${vuln.mcp_threat_category}</span>`;
        }

        vulnDiv.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                <h4 style="margin: 0; color: var(--text-primary); flex: 1;">${index + 1}. ${escapeHtml(vuln.title)}</h4>
                <span style="background: ${vuln.severity === 'critical' ? '#dc2626' : vuln.severity === 'high' ? '#ea580c' : '#f59e0b'}; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; white-space: nowrap;">${vuln.severity}</span>
            </div>
            <div style="margin-bottom: 10px;">
                ${badges}
            </div>
            <p style="color: var(--text-secondary); font-size: 14px; margin: 10px 0;">${escapeHtml(vuln.description)}</p>
            <div style="margin-top: 10px; padding: 10px; background: rgba(6, 182, 212, 0.1); border-radius: 4px;">
                <strong style="color: var(--cyan);">Attack Vector:</strong>
                <p style="color: var(--text-secondary); font-size: 13px; margin: 5px 0;">${escapeHtml(vuln.attack_vector)}</p>
            </div>
            <div style="margin-top: 10px; padding: 10px; background: rgba(34, 197, 94, 0.1); border-radius: 4px;">
                <strong style="color: #22c55e;">Recommendation:</strong>
                <p style="color: var(--text-secondary); font-size: 13px; margin: 5px 0;">${escapeHtml(vuln.recommendation)}</p>
            </div>
        `;

        vulnsList.appendChild(vulnDiv);
    });
}

/**
 * Display MAESTRO validation
 */
function displayMAESTROValidation(maestroAnalysis) {
    const container = document.getElementById('maestroValidation');
    container.innerHTML = '';

    if (!maestroAnalysis) {
        container.innerHTML = '<div class="empty-state">MAESTRO VALIDATION NOT AVAILABLE</div>';
        return;
    }

    // MAESTRO principles
    const principles = [
        { key: 'M', name: 'MINIMIZE ATTACK SURFACE' },
        { key: 'A', name: 'AUTHENTICATION & AUTHORIZATION' },
        { key: 'E', name: 'ESTABLISH SECURE DEFAULTS' },
        { key: 'S', name: 'SEPARATION OF DUTIES' },
        { key: 'T', name: 'TRUST BUT VERIFY' },
        { key: 'R', name: 'RESILIENCE AND RECOVERY' },
        { key: 'O', name: 'OBSERVABILITY AND MONITORING' }
    ];

    principles.forEach(principle => {
        const maestroDiv = document.createElement('div');

        // Determine status based on keywords
        let status = 'compliant';
        const analysisText = typeof maestroAnalysis === 'string' ? maestroAnalysis : JSON.stringify(maestroAnalysis);

        if (analysisText.includes('NON-COMPLIANT') || analysisText.includes('non-compliant')) {
            status = 'non-compliant';
        } else if (analysisText.includes('PARTIAL') || analysisText.includes('partial')) {
            status = 'partial';
        }

        maestroDiv.className = `maestro-card ${status}`;

        const statusIcon = status === 'compliant' ? '[OK]' : status === 'non-compliant' ? '[X]' : '[!]';
        const statusText = status === 'compliant' ? 'COMPLIANT' : status === 'non-compliant' ? 'NON-COMPLIANT' : 'PARTIAL COMPLIANCE';

        maestroDiv.innerHTML = `
            <div class="maestro-principle">${statusIcon} ${principle.key} - ${principle.name}</div>
            <div class="maestro-status">${statusText}</div>
        `;

        container.appendChild(maestroDiv);
    });
}

/**
 * Handle new analysis button
 */
function handleNewAnalysis() {
    document.getElementById('description').value = '';
    document.getElementById('codeSnippet').value = '';
    document.querySelectorAll('input[name="compliance"]').forEach(cb => cb.checked = false);

    resultsSection.classList.add('hidden');
    currentModelId = null;
    currentThreatModel = null;

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/**
 * Handle export PDF button
 */
async function handleExportPdf() {
    if (!currentModelId) {
        alert('NO THREAT MODEL TO EXPORT');
        return;
    }

    try {
        exportPdfBtn.disabled = true;
        exportPdfBtn.textContent = 'GENERATING REPORT...';

        const response = await fetch(`${API_BASE_URL}/api/reports/${currentModelId}/pdf`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`REPORT GENERATION FAILED: ${response.status}`);
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat-report-${currentModelId}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        alert('REPORT EXPORTED SUCCESSFULLY');

    } catch (error) {
        console.error('Report export failed:', error);
        alert(`REPORT EXPORT FAILED: ${error.message}`);
    } finally {
        exportPdfBtn.disabled = false;
        exportPdfBtn.innerHTML = '<span class="button-bracket">&gt;</span> EXPORT REPORT';
    }
}

/**
 * Escape HTML for safe display
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Progress Bar Simulation
 */
function simulateProgress() {
    // Match actual backend phases from orchestrator.py
    const phases = [
        { progress: 15, phase: 'PHASE 0: Building Data Flow Diagram...', agent: 'dfd', time: 3000 },
        { progress: 30, phase: 'PHASE 1: Running STRIDE Threat Analysis...', agent: 'stride', time: 8000 },
        { progress: 50, phase: 'PHASE 2: Running OWASP Top 10 Analysis...', agent: 'owasp', time: 15000 },
        { progress: 65, phase: 'PHASE 3: Attack Tree Analysis (parallel)...', agent: 'attack', time: 20000 },
        { progress: 72, phase: 'PHASE 3: CWE Classification (parallel)...', agent: 'cwe', time: 21000 },
        { progress: 80, phase: 'PHASE 3: MAESTRO Validation (parallel)...', agent: 'maestro', time: 22000 },
        { progress: 87, phase: 'PHASE 3: Z3 Symbolic Verification (parallel)...', agent: 'z3', time: 23000 },
        { progress: 95, phase: 'PHASE 4: CVE Enrichment from NVD API...', agent: 'cve', time: 28000 },
    ];

    phases.forEach(({ progress, phase, agent, time }) => {
        setTimeout(() => {
            updateProgress(progress, phase, agent);
        }, time);
    });
}

function updateProgress(percent, phase, agent) {
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const currentPhase = document.getElementById('currentPhase');

    if (progressBar) progressBar.style.width = percent + '%';
    if (progressText) progressText.textContent = percent + '%';
    if (currentPhase) currentPhase.textContent = phase;

    // Update agent status
    if (agent) {
        const agentEl = document.getElementById('agent-' + agent);
        if (agentEl) {
            agentEl.innerHTML = `[OK] ${agentEl.textContent.split(':')[0].replace('[WAIT]', '').trim()}: COMPLETE`;
            agentEl.style.color = '#10b981';
        }
    }
}

/**
 * GitHub Integration Functions
 */

async function handleCreateGitHubIssues() {
    if (!currentModelId || !currentThreatModel) {
        alert('NO ANALYSIS AVAILABLE. RUN THREAT ANALYSIS FIRST.');
        return;
    }

    const repoOwner = prompt('ENTER GITHUB USERNAME:');
    const repoName = prompt('ENTER REPOSITORY NAME:');

    if (!repoOwner || !repoName) {
        return;
    }

    try {
        // Get critical vulnerabilities
        const criticalVulns = currentThreatModel.top_vulnerabilities.filter(
            v => v.severity === 'critical' || v.severity === 'high'
        );

        if (criticalVulns.length === 0) {
            alert('NO CRITICAL/HIGH VULNERABILITIES FOUND TO CREATE ISSUES.');
            return;
        }

        const createIssue = confirm(`CREATE ${criticalVulns.length} GITHUB ISSUES FOR CRITICAL/HIGH VULNERABILITIES?`);
        if (!createIssue) return;

        let successCount = 0;
        let issueUrls = [];

        for (const vuln of criticalVulns) {
            try {
                const response = await fetch(`${API_BASE_URL}/api/github/create-issue/${currentModelId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        repo_owner: repoOwner,
                        repo_name: repoName,
                        vulnerability_id: vuln.vuln_id
                    })
                });

                const result = await response.json();

                if (result.success) {
                    successCount++;
                    issueUrls.push(result.issue_url);
                }
            } catch (error) {
                console.error('Failed to create issue:', error);
            }
        }

        alert(`✅ SUCCESS: CREATED ${successCount}/${criticalVulns.length} GITHUB ISSUES`);

        // Open first issue
        if (issueUrls.length > 0) {
            const openIssues = confirm('OPEN GITHUB ISSUES IN BROWSER?');
            if (openIssues) {
                issueUrls.forEach(url => window.open(url, '_blank'));
            }
        }

    } catch (error) {
        console.error('GitHub integration error:', error);
        alert(`❌ GITHUB INTEGRATION FAILED: ${error.message}\n\nMAKE SURE GITHUB_TOKEN IS SET IN .ENV FILE`);
    }
}

async function handleCommentOnPR() {
    if (!currentModelId || !currentThreatModel) {
        alert('NO ANALYSIS AVAILABLE. RUN THREAT ANALYSIS FIRST.');
        return;
    }

    const repoOwner = prompt('ENTER GITHUB USERNAME:');
    const repoName = prompt('ENTER REPOSITORY NAME:');
    const prNumber = prompt('ENTER PR NUMBER:');

    if (!repoOwner || !repoName || !prNumber) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/github/comment-pr`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                repo_owner: repoOwner,
                repo_name: repoName,
                pr_number: parseInt(prNumber),
                model_id: currentModelId
            })
        });

        const result = await response.json();

        if (result.success) {
            alert(`✅ SUCCESS: ${result.message}`);

            const openPR = confirm('OPEN PULL REQUEST IN BROWSER?');
            if (openPR) {
                window.open(`https://github.com/${repoOwner}/${repoName}/pull/${prNumber}`, '_blank');
            }
        } else {
            throw new Error('Failed to comment on PR');
        }

    } catch (error) {
        console.error('GitHub PR comment error:', error);
        alert(`❌ GITHUB PR COMMENT FAILED: ${error.message}\n\nMAKE SURE GITHUB_TOKEN IS SET IN .ENV FILE`);
    }
}

async function handleDownloadWorkflow() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/github/workflow`);
        const data = await response.json();

        // Create blob and download
        const blob = new Blob([data.content], { type: 'text/yaml' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat-modeling.yml';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        alert(`✅ WORKFLOW DOWNLOADED SUCCESSFULLY\n\n${data.instructions}`);

    } catch (error) {
        console.error('Workflow download error:', error);
        alert(`❌ WORKFLOW DOWNLOAD FAILED: ${error.message}`);
    }
}

/**
 * Vulnerability Search and Filter
 */
let allVulnerabilities = [];

function filterVulnerabilities() {
    const searchTerm = document.getElementById('vulnSearch')?.value.toLowerCase() || '';
    const severityFilter = document.getElementById('severityFilter')?.value || 'all';
    const owaspFilter = document.getElementById('owaspFilter')?.value || 'all';

    const filtered = allVulnerabilities.filter(vuln => {
        // Search filter
        const matchesSearch = !searchTerm ||
            vuln.title.toLowerCase().includes(searchTerm) ||
            vuln.description.toLowerCase().includes(searchTerm) ||
            vuln.cwe_id.toLowerCase().includes(searchTerm) ||
            vuln.cwe_name.toLowerCase().includes(searchTerm);

        // Severity filter
        const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter;

        // OWASP filter
        const matchesOWASP = owaspFilter === 'all' ||
            (vuln.owasp_category && vuln.owasp_category.startsWith(owaspFilter));

        return matchesSearch && matchesSeverity && matchesOWASP;
    });

    // Update stats
    const statsEl = document.getElementById('filterStats');
    if (statsEl) {
        statsEl.textContent = `› SHOWING ${filtered.length} OF ${allVulnerabilities.length} VULNERABILITIES`;
    }

    // Re-render vulnerabilities
    displayFilteredVulnerabilities(filtered);
}

function displayFilteredVulnerabilities(vulns) {
    const listEl = document.getElementById('vulnerabilitiesList');
    if (!listEl) return;

    if (vulns.length === 0) {
        listEl.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-secondary);">[!] NO VULNERABILITIES MATCH YOUR FILTERS</div>';
        return;
    }

    listEl.innerHTML = vulns.map((vuln, index) => {
        const severityClass = vuln.severity || 'medium';
        const severityColor = {
            critical: '#dc2626',
            high: '#ea580c',
            medium: '#f59e0b',
            low: '#10b981'
        }[severityClass] || '#f59e0b';

        return `
            <div class="vuln-item" style="border-left: 4px solid ${severityColor}; margin-bottom: 15px; padding: 15px; background: rgba(0,0,0,0.2); border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                        <h4 style="margin: 0 0 10px 0; color: var(--text-primary);">${index + 1}. ${escapeHtml(vuln.title)}</h4>
                        <div style="display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap;">
                            <span class="tag" style="background: ${severityColor}; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;">${vuln.severity}</span>
                            <span class="tag" style="background: rgba(6, 182, 212, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 11px;">${vuln.cwe_id}</span>
                            <span class="tag" style="background: rgba(251, 146, 60, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 11px;">CVSS: ${vuln.cvss_score}/10</span>
                            ${vuln.owasp_category ? `<span class="tag" style="background: rgba(168, 85, 247, 0.3); padding: 4px 12px; border-radius: 4px; font-size: 11px;">${vuln.owasp_category}</span>` : ''}
                        </div>
                        <p style="color: var(--text-secondary); font-size: 14px; margin: 10px 0;">${escapeHtml(vuln.description)}</p>
                        <div style="margin-top: 10px;">
                            <strong style="color: var(--cyan);">Recommendation:</strong>
                            <p style="color: var(--text-secondary); font-size: 13px; margin: 5px 0;">${escapeHtml(vuln.recommendation)}</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function clearFilters() {
    document.getElementById('vulnSearch').value = '';
    document.getElementById('severityFilter').value = 'all';
    document.getElementById('owaspFilter').value = 'all';
    filterVulnerabilities();
}

/**
 * Analyze Local Files/Directory
 */
async function analyzeLocalFiles() {
    const filePath = document.getElementById('localFilePath').value.trim();
    const recursive = document.getElementById('recursiveAnalysis').checked;
    const localAnalyzeBtn = document.getElementById('localAnalyzeBtn');

    if (!filePath) {
        alert('[!] PLEASE ENTER A FILE OR DIRECTORY PATH');
        return;
    }

    // Show loading
    localAnalyzeBtn.disabled = true;
    localAnalyzeBtn.textContent = 'ANALYZING...';
    loadingIndicator.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    // Start progress simulation
    simulateProgress();

    try {
        const description = document.getElementById('description').value.trim() ||
            `Security analysis of local files at: ${filePath}`;

        // Get compliance requirements
        const complianceCheckboxes = document.querySelectorAll('input[name="compliance"]:checked');
        const compliance = Array.from(complianceCheckboxes).map(cb => cb.value);

        // Call local file analysis API
        const response = await fetch(`${API_BASE_URL}/api/analyze/local-file`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                file_path: filePath,
                description: description,
                recursive: recursive,
                compliance_requirements: compliance
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || `API ERROR: ${response.status}`);
        }

        const result = await response.json();
        currentModelId = result.model_id;

        // Fetch complete threat model
        const modelResponse = await fetch(`${API_BASE_URL}/api/models/${currentModelId}`);
        if (!modelResponse.ok) {
            throw new Error(`FAILED TO FETCH THREAT MODEL: ${modelResponse.status}`);
        }

        currentThreatModel = await modelResponse.json();

        // Display results
        displayResults(currentThreatModel);

        alert(`[OK] LOCAL FILE ANALYSIS COMPLETE\n\nFILES ANALYZED: ${result.summary.files_analyzed}\nVULNERABILITIES: ${result.summary.total_vulnerabilities}`);

    } catch (error) {
        console.error('Local file analysis failed:', error);
        alert(`[X] LOCAL FILE ANALYSIS FAILED\n\n${error.message}\n\nMAKE SURE:\n- Path exists and is accessible\n- Path contains code files\n- Backend server is running`);
    } finally {
        loadingIndicator.classList.add('hidden');
        localAnalyzeBtn.disabled = false;
        localAnalyzeBtn.textContent = 'ANALYZE';
    }
}

/**
 * Fetch GitHub Repository Code
 */
async function fetchGitHubRepo() {
    const repoUrl = document.getElementById('githubRepoUrl').value.trim();

    if (!repoUrl) {
        alert('[!] PLEASE ENTER A GITHUB REPOSITORY URL');
        return;
    }

    // Parse GitHub URL (supports https://github.com/owner/repo or github.com/owner/repo)
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\?#]+)/);
    if (!match) {
        alert('[X] INVALID GITHUB URL\n\nEXPECTED FORMAT:\nhttps://github.com/username/repository');
        return;
    }

    const [, owner, repo] = match;
    const repoName = repo.replace('.git', '');

    try {
        // Show loading indicator
        const codeSnippet = document.getElementById('codeSnippet');
        codeSnippet.value = '[WAIT] FETCHING REPOSITORY CODE FROM GITHUB...\n\nREPO: ' + owner + '/' + repoName;

        // Fetch repository tree
        const treeResponse = await fetch(`https://api.github.com/repos/${owner}/${repoName}/git/trees/main?recursive=1`);

        if (!treeResponse.ok) {
            // Try 'master' branch if 'main' fails
            const masterResponse = await fetch(`https://api.github.com/repos/${owner}/${repoName}/git/trees/master?recursive=1`);
            if (!masterResponse.ok) {
                throw new Error('Repository not found or not accessible');
            }
            var treeData = await masterResponse.json();
        } else {
            var treeData = await treeResponse.json();
        }

        // Filter for code files only
        const codeFiles = treeData.tree.filter(item => {
            return item.type === 'blob' &&
                   SUPPORTED_CODE_EXTENSIONS.some(ext => item.path.endsWith(ext)) &&
                   !item.path.includes('node_modules') &&
                   !item.path.includes('__pycache__') &&
                   !item.path.includes('.min.') &&
                   !item.path.includes('dist/') &&
                   !item.path.includes('build/');
        }).slice(0, 20); // Limit to 20 files to avoid overwhelming the analysis

        if (codeFiles.length === 0) {
            alert('[!] NO SUPPORTED CODE FILES FOUND\n\nSUPPORTED: Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby, PHP, C#, Swift, Kotlin, SQL, and more');
            codeSnippet.value = '';
            return;
        }

        // Fetch content of each file
        let combinedCode = `/// GITHUB REPOSITORY: ${owner}/${repoName}\n`;
        combinedCode += `/// FILES ANALYZED: ${codeFiles.length}\n`;
        combinedCode += `/// ========================================\n\n`;

        for (const file of codeFiles) {
            try {
                const fileResponse = await fetch(`https://api.github.com/repos/${owner}/${repoName}/contents/${file.path}`);
                const fileData = await fileResponse.json();

                if (fileData.content) {
                    const content = atob(fileData.content); // Decode base64
                    combinedCode += `\n/// FILE: ${file.path}\n`;
                    combinedCode += `/// ========================================\n`;
                    combinedCode += content + '\n\n';
                }
            } catch (e) {
                console.error('Failed to fetch file:', file.path, e);
            }
        }

        codeSnippet.value = combinedCode;
        alert(`[OK] SUCCESS: FETCHED ${codeFiles.length} CODE FILES FROM ${owner}/${repoName}\n\nREADY FOR ANALYSIS`);

    } catch (error) {
        console.error('GitHub fetch error:', error);
        alert(`[X] FAILED TO FETCH REPOSITORY\n\nERROR: ${error.message}\n\nMAKE SURE:\n- Repository is public\n- URL is correct\n- Repository exists`);
        document.getElementById('codeSnippet').value = '';
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('> TACTICAL THREAT MODELING OPS: INITIALIZED');
    console.log('> AGENTS: READY');
    console.log('> MISTRAL API: LINKED');
    console.log('> SYSTEM STATUS: OPERATIONAL');

    // Add GitHub integration event listeners
    const createGitHubIssuesBtn = document.getElementById('createGitHubIssuesBtn');
    const commentOnPRBtn = document.getElementById('commentOnPRBtn');
    const downloadWorkflowBtn = document.getElementById('downloadWorkflowBtn');

    if (createGitHubIssuesBtn) {
        createGitHubIssuesBtn.addEventListener('click', handleCreateGitHubIssues);
    }
    if (commentOnPRBtn) {
        commentOnPRBtn.addEventListener('click', handleCommentOnPR);
    }
    if (downloadWorkflowBtn) {
        downloadWorkflowBtn.addEventListener('click', handleDownloadWorkflow);
    }

    // Add NEW Create Fix PR button listener
    const createFixPRBtn = document.getElementById('createFixPRBtn');
    console.log('>>> CREATE FIX PR BUTTON:', createFixPRBtn);
    if (createFixPRBtn) {
        createFixPRBtn.addEventListener('click', handleCreateFixPR);
        console.log('>>> CREATE FIX PR LISTENER ATTACHED');
    } else {
        console.error('>>> CREATE FIX PR BUTTON NOT FOUND!');
    }

    // Modal event listeners
    const modalCancelBtn = document.getElementById('modalCancelBtn');
    const modalOverlay = document.querySelector('.modal-overlay');
    if (modalCancelBtn) {
        modalCancelBtn.addEventListener('click', closeModal);
    }
    if (modalOverlay) {
        modalOverlay.addEventListener('click', closeModal);
    }
});

// ============================================
// MODAL FUNCTIONS
// ============================================

let modalResolve = null;
let modalReject = null;

function showModal(title, fields) {
    return new Promise((resolve, reject) => {
        modalResolve = resolve;
        modalReject = reject;

        const modal = document.getElementById('customModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalPRNumberField = document.getElementById('modalPRNumberField');
        const modalBaseBranchField = document.getElementById('modalBaseBranchField');
        const confirmBtn = document.getElementById('modalConfirmBtn');

        modalTitle.textContent = title;

        // Reset fields
        document.getElementById('modalGithubUsername').value = '';
        document.getElementById('modalRepoName').value = '';
        document.getElementById('modalPRNumber').value = '';
        document.getElementById('modalBaseBranch').value = 'main';

        // Show/hide fields based on configuration
        modalPRNumberField.style.display = fields.includes('prNumber') ? 'block' : 'none';
        modalBaseBranchField.style.display = fields.includes('baseBranch') ? 'block' : 'none';

        // Remove old listener and add new one
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
        newConfirmBtn.addEventListener('click', handleModalConfirm);

        modal.style.display = 'flex';
    });
}

function closeModal() {
    const modal = document.getElementById('customModal');
    modal.style.display = 'none';
    if (modalReject) {
        modalReject('cancelled');
        modalReject = null;
        modalResolve = null;
    }
}

function handleModalConfirm() {
    const username = document.getElementById('modalGithubUsername').value.trim();
    const repoName = document.getElementById('modalRepoName').value.trim();
    const prNumber = document.getElementById('modalPRNumber').value.trim();
    const baseBranch = document.getElementById('modalBaseBranch').value.trim() || 'main';

    if (!username || !repoName) {
        alert('[!] GITHUB USERNAME AND REPOSITORY NAME ARE REQUIRED');
        return;
    }

    const data = { username, repoName, prNumber, baseBranch };

    if (modalResolve) {
        modalResolve(data);
        modalResolve = null;
        modalReject = null;
    }

    closeModal();
}

// ============================================
// GITHUB INTEGRATION HANDLERS
// ============================================

async function handleCreateGitHubIssues() {
    if (!currentModelId) {
        alert('[!] NO ANALYSIS RESULTS AVAILABLE\n\nRUN A THREAT ANALYSIS FIRST');
        return;
    }

    try {
        const data = await showModal('CREATE GITHUB ISSUES', []);

        // Create issues
        console.log(`Creating GitHub issues for ${data.username}/${data.repoName}...`);

        // Show success message
        alert(`[OK] CREATING GITHUB ISSUES\n\nREPO: ${data.username}/${data.repoName}\n\nProcessing ${currentThreatModel.top_vulnerabilities.length} vulnerabilities...`);

        // Call API for each vulnerability
        let created = 0;
        for (const vuln of currentThreatModel.top_vulnerabilities) {
            try {
                const response = await fetch(`${API_BASE_URL}/api/github/create-issue/${currentModelId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        repo_owner: data.username,
                        repo_name: data.repoName,
                        vulnerability_title: vuln.title
                    })
                });

                if (response.ok) {
                    created++;
                }
            } catch (err) {
                console.error('Failed to create issue:', err);
            }
        }

        alert(`[OK] SUCCESS\n\nCREATED ${created}/${currentThreatModel.top_vulnerabilities.length} GITHUB ISSUES\n\nVIEW AT: https://github.com/${data.username}/${data.repoName}/issues`);

    } catch (err) {
        if (err !== 'cancelled') {
            console.error('Failed to create issues:', err);
        }
    }
}

async function handleCommentOnPR() {
    if (!currentModelId) {
        alert('⚠️ NO ANALYSIS RESULTS AVAILABLE\n\nRUN A THREAT ANALYSIS FIRST');
        return;
    }

    try {
        const data = await showModal('COMMENT ON PULL REQUEST', ['prNumber']);

        if (!data.prNumber) {
            alert('⚠️ PR NUMBER IS REQUIRED');
            return;
        }

        console.log(`Commenting on PR #${data.prNumber} in ${data.username}/${data.repoName}...`);

        const response = await fetch(`${API_BASE_URL}/api/github/comment-pr`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                repo_owner: data.username,
                repo_name: data.repoName,
                pr_number: parseInt(data.prNumber),
                model_id: currentModelId
            })
        });

        if (response.ok) {
            alert(`[OK] SUCCESS\n\nCOMMENT POSTED ON PR #${data.prNumber}\n\nVIEW AT: https://github.com/${data.username}/${data.repoName}/pull/${data.prNumber}`);
        } else {
            throw new Error('Failed to post comment');
        }

    } catch (err) {
        if (err !== 'cancelled') {
            alert('[X] FAILED TO POST COMMENT\n\n' + err.message);
        }
    }
}

async function handleCreateFixPR() {
    console.log('>>> HANDLE CREATE FIX PR CALLED');
    console.log('>>> Current Model ID:', currentModelId);
    console.log('>>> Current Threat Model:', currentThreatModel);

    if (!currentModelId) {
        alert('[!] NO ANALYSIS RESULTS AVAILABLE\n\nRUN A THREAT ANALYSIS FIRST');
        return;
    }

    try {
        const data = await showModal('CREATE SECURITY FIX PR', ['baseBranch']);

        console.log(`Creating fix PR for ${data.username}/${data.repoName}...`);

        const response = await fetch(`${API_BASE_URL}/api/github/create-fix-pr/${currentModelId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                repo_owner: data.username,
                repo_name: data.repoName,
                base_branch: data.baseBranch
            })
        });

        const result = await response.json();

        if (response.ok && result.success) {
            alert(`[OK] SUCCESS\n\nSECURITY FIX PR CREATED!\n\nFIXES: ${result.fixes_count} vulnerabilities\n\nVIEW PR: ${result.pr_url}`);

            // Optionally open PR in new tab
            if (confirm('OPEN PR IN BROWSER?')) {
                window.open(result.pr_url, '_blank');
            }
        } else {
            throw new Error(result.detail || 'Failed to create PR');
        }

    } catch (err) {
        if (err !== 'cancelled') {
            alert('[X] FAILED TO CREATE FIX PR\n\n' + err.message);
        }
    }
}

async function handleDownloadWorkflow() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/github/workflow`);
        const data = await response.json();

        // Create blob and download
        const blob = new Blob([data.content], { type: 'text/yaml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = data.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        alert('[OK] WORKFLOW DOWNLOADED\n\nFILE: ' + data.filename + '\n\nFOLLOW INSTRUCTIONS:\n' + data.instructions);

    } catch (err) {
        alert('[X] FAILED TO DOWNLOAD WORKFLOW\n\n' + err.message);
    }
}

/**
 * Handle download compliance report
 */
async function handleDownloadComplianceReport() {
    console.log('>>> Compliance button clicked!');
    console.log('>>> Current Model ID:', currentModelId);
    console.log('>>> Current Threat Model:', currentThreatModel);

    if (!currentModelId) {
        alert('[!] NO ANALYSIS RESULTS AVAILABLE\n\nRUN A THREAT ANALYSIS WITH COMPLIANCE REQUIREMENTS FIRST');
        return;
    }

    if (!currentThreatModel || !currentThreatModel.compliance_checks || currentThreatModel.compliance_checks.length === 0) {
        alert('[!] NO COMPLIANCE ANALYSIS AVAILABLE\n\nPlease re-run analysis with compliance requirements selected (NIST AI RMF, OWASP ASVS, etc.)');
        return;
    }

    try {
        console.log(`Downloading compliance report for model ${currentModelId}...`);

        // Open compliance report in new window (HTML format)
        const reportUrl = `${API_BASE_URL}/api/models/${currentModelId}/compliance-report`;
        window.open(reportUrl, '_blank');

        alert('[OK] COMPLIANCE REPORT OPENED\n\nYou can print to PDF from your browser (Ctrl+P or Cmd+P)');

    } catch (err) {
        alert('[X] FAILED TO GENERATE COMPLIANCE REPORT\n\n' + err.message);
    }
}
