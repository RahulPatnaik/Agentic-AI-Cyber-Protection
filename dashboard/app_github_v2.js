/**
 * GitHub Repository Analysis v2 - Uses improved backend with PyGithub + Tree-sitter
 */

// Function for just fetching and displaying code (RETRIEVE button)
async function fetchGitHubCodeOnly() {
    const repoUrl = document.getElementById('githubRepoUrl').value.trim();

    if (!repoUrl) {
        alert('[!] PLEASE ENTER A GITHUB REPOSITORY URL');
        return;
    }

    // Parse GitHub URL
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\?#]+)/);
    if (!match) {
        alert('[X] INVALID GITHUB URL\n\nEXPECTED FORMAT:\nhttps://github.com/username/repository');
        return;
    }

    const [, owner, repoName] = match;
    const repo = repoName.replace('.git', '');

    // Just show in code snippet that we have the URL ready
    document.getElementById('codeSnippet').value =
        `[READY] GitHub Repository: ${owner}/${repo}\n\n` +
        `Click INITIATE THREAT ANALYSIS to run full analysis with tree-sitter chunking.\n\n` +
        `The analysis will:\n` +
        `• Fetch all code files from the repository\n` +
        `• Perform semantic chunking using tree-sitter\n` +
        `• Identify vulnerabilities and security issues\n` +
        `• Generate comprehensive threat model`;

    console.log(`[✓] GitHub URL ready for analysis: ${owner}/${repo}`);
}

// Full analysis function (called internally, not by button)
async function analyzeGitHubRepository() {
    const repoUrl = document.getElementById('githubRepoUrl').value.trim();

    if (!repoUrl) {
        alert('[!] PLEASE ENTER A GITHUB REPOSITORY URL');
        return;
    }

    // Parse GitHub URL
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\?#]+)/);
    if (!match) {
        alert('[X] INVALID GITHUB URL\n\nEXPECTED FORMAT:\nhttps://github.com/username/repository');
        return;
    }

    const [, owner, repoName] = match;
    const repo = repoName.replace('.git', '');

    // Get compliance requirements
    const complianceCheckboxes = document.querySelectorAll('input[name="compliance"]:checked');
    const compliance = Array.from(complianceCheckboxes).map(cb => cb.value);

    // Get loading indicator and results section
    const loadingIndicator = document.getElementById('loadingIndicator');
    const resultsSection = document.getElementById('resultsSection');

    // Show loading
    loadingIndicator.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    document.getElementById('codeSnippet').value = `[ANALYZING] GitHub Repository: ${owner}/${repo}\n\nUsing improved PyGithub + Tree-sitter analysis...`;

    // Start progress simulation
    simulateProgress();

    try {
        // Call the improved GitHub v2 endpoint
        const response = await fetch(`${API_BASE_URL}/api/analyze/github-v2`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                repo_owner: owner,
                repo_name: repo,
                branch: 'main',  // Could add branch selector in UI
                compliance_requirements: compliance
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'GitHub analysis failed');
        }

        const result = await response.json();

        // Store model ID globally (both window and local variable)
        window.currentModelId = result.model_id;
        currentModelId = result.model_id;

        // Log success
        console.log('[✓] GitHub repository analyzed:', result);

        // Update UI with summary
        if (result.summary) {
            document.getElementById('codeSnippet').value =
                `[SUCCESS] Analyzed ${result.summary.files_analyzed || 0} files\n` +
                `Chunks created: ${result.summary.chunks_created || 0}\n` +
                `Vulnerabilities found: ${result.summary.total_vulnerabilities || 0}\n\n` +
                `Repository: ${owner}/${repo}`;
        }

        // Fetch complete threat model
        const modelResponse = await fetch(`${API_BASE_URL}/api/models/${window.currentModelId}`);
        if (!modelResponse.ok) {
            throw new Error('Failed to fetch threat model results');
        }

        const threatModel = await modelResponse.json();
        window.currentThreatModel = threatModel;

        // Display results using the existing displayResults function
        displayResults(threatModel);

        // Hide loading indicator after success
        loadingIndicator.classList.add('hidden');

    } catch (error) {
        console.error('[X] GitHub analysis error:', error);
        alert(`[ERROR] GITHUB ANALYSIS FAILED\n\n${error.message}`);
        loadingIndicator.classList.add('hidden');
    }
}

/**
 * Updated fetch button to use v2 endpoint
 */
function fetchGitHubRepo() {
    // This now triggers the full analysis, not just fetching
    analyzeGitHubRepository();
}

// Export for use in main app.js
window.analyzeGitHubRepository = analyzeGitHubRepository;
window.fetchGitHubCodeOnly = fetchGitHubCodeOnly;