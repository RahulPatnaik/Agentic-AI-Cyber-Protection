/**
 * TACTICAL THREAT MODELING OPS - JavaScript
 */

// API Configuration
const API_BASE_URL = window.location.origin;

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

    // Display MAESTRO validation
    if (threatModel.agent_analyses && threatModel.agent_analyses.maestro) {
        displayMAESTROValidation(threatModel.agent_analyses.maestro);
    }

    // Show results section
    resultsSection.classList.remove('hidden');

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

    // Build Mermaid flowchart syntax
    let mermaidCode = 'graph TD\n';
    let nodeCounter = 0;
    const nodeMap = new Map();

    attackPaths.slice(0, 3).forEach((path, pathIndex) => {
        // Entry point
        const entryId = `N${nodeCounter++}`;
        nodeMap.set(`${pathIndex}_entry`, entryId);
        mermaidCode += `    ${entryId}["🔓 ${path.entry_point}"]\n`;

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
        const icon = severity === 'critical' ? '💀' : '⚠️';
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
                <h4>🛡️ REMEDIATION</h4>
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

        const statusIcon = status === 'compliant' ? '✓' : status === 'non-compliant' ? '✗' : '⚠';
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

    alert('PDF EXPORT: FEATURE COMING SOON');

    // Future implementation:
    // try {
    //     const response = await fetch(`${API_BASE_URL}/api/reports/${currentModelId}/pdf`, {
    //         method: 'POST'
    //     });
    //     if (!response.ok) throw new Error('PDF GENERATION FAILED');
    //     const blob = await response.blob();
    //     const url = window.URL.createObjectURL(blob);
    //     const a = document.createElement('a');
    //     a.href = url;
    //     a.download = `threat-model-${currentModelId}.pdf`;
    //     document.body.appendChild(a);
    //     a.click();
    //     window.URL.revokeObjectURL(url);
    //     document.body.removeChild(a);
    // } catch (error) {
    //     console.error('PDF export failed:', error);
    //     alert('PDF EXPORT FAILED');
    // }
}

/**
 * Escape HTML for safe display
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('> TACTICAL THREAT MODELING OPS: INITIALIZED');
    console.log('> AGENTS: READY');
    console.log('> MISTRAL API: LINKED');
    console.log('> SYSTEM STATUS: OPERATIONAL');
});
