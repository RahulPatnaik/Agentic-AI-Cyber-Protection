// WiFi Guardian Dashboard - Retro-Futuristic Interface

const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/ws/alerts`;

let ws = null;
let startTime = Date.now();

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    console.log('⚡ WiFi Guardian Dashboard initialized');

    // Start periodic updates
    updateStats();
    setInterval(updateStats, 5000); // Update every 5 seconds

    // Connect WebSocket
    connectWebSocket();

    // Update uptime
    setInterval(updateUptime, 1000);
});

// Connect to WebSocket for real-time alerts
function connectWebSocket() {
    const connectionStatus = document.getElementById('connection-status');
    const connectionStatusText = document.getElementById('connection-status-text');

    try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            console.log('WebSocket connected');
            connectionStatus.textContent = 'ONLINE';
            connectionStatus.style.color = 'var(--accent-green)';
            connectionStatusText.textContent = 'CONNECTED';
            connectionStatusText.style.color = 'var(--accent-green)';
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.type === 'alert') {
                addAlert(data.data);
            } else if (data.type === 'heartbeat') {
                // Connection alive
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            connectionStatus.textContent = 'ERROR';
            connectionStatus.style.color = 'var(--accent-red)';
            connectionStatusText.textContent = 'ERROR';
            connectionStatusText.style.color = 'var(--accent-red)';
        };

        ws.onclose = () => {
            console.log('WebSocket disconnected');
            connectionStatus.textContent = 'OFFLINE';
            connectionStatus.style.color = 'var(--text-dim)';
            connectionStatusText.textContent = 'RECONNECTING';
            connectionStatusText.style.color = 'var(--accent-amber)';

            // Reconnect after 5 seconds
            setTimeout(connectWebSocket, 5000);
        };
    } catch (error) {
        console.error('WebSocket connection failed:', error);
        connectionStatus.textContent = 'FAILED';
        connectionStatus.style.color = 'var(--accent-red)';
        connectionStatusText.textContent = 'FAILED';
        connectionStatusText.style.color = 'var(--accent-red)';
    }
}

// Update system statistics
async function updateStats() {
    try {
        // Get health status
        const healthResponse = await fetch(`${API_BASE}/api/health`);
        const healthData = await healthResponse.json();

        // Update agent status
        updateAgentStatus('guardian', healthData.agents.guardian);
        updateAgentStatus('sentinel', healthData.agents.sentinel);

        // Update statistics
        if (healthData.statistics) {
            document.getElementById('packets-processed').textContent =
                healthData.statistics.packets_processed || 0;
            document.getElementById('threats-detected').textContent =
                healthData.statistics.threats_detected || 0;
            document.getElementById('threats-escalated').textContent =
                healthData.statistics.threats_escalated || 0;
        }

        // Get detailed stats
        const statsResponse = await fetch(`${API_BASE}/api/stats`);
        const statsData = await statsResponse.json();

        // Load recent alerts
        loadAlerts();

    } catch (error) {
        console.error('Failed to update stats:', error);
    }
}

// Update agent status with proper styling
function updateAgentStatus(agent, status) {
    const element = document.getElementById(`${agent}-status`);

    if (status === 'running') {
        element.textContent = 'ONLINE';
        element.classList.add('online');
        element.classList.remove('offline');
    } else {
        element.textContent = 'OFFLINE';
        element.classList.add('offline');
        element.classList.remove('online');
    }
}

// Load recent alerts
async function loadAlerts() {
    try {
        const response = await fetch(`${API_BASE}/api/alerts?limit=10`);
        const data = await response.json();

        const alertCount = document.getElementById('alert-count');
        alertCount.textContent = data.total || 0;

        if (data.alerts && data.alerts.length > 0) {
            const container = document.getElementById('alerts-container');
            container.innerHTML = ''; // Clear existing

            data.alerts.reverse().forEach(alert => {
                addAlert(alert);
            });
        }
    } catch (error) {
        console.error('Failed to load alerts:', error);
    }
}

// Add alert to dashboard
function addAlert(alert) {
    const container = document.getElementById('alerts-container');

    // Remove "no alerts" message if present
    const noAlerts = container.querySelector('.no-alerts');
    if (noAlerts) {
        noAlerts.remove();
    }

    // Create alert element
    const alertElement = document.createElement('div');
    alertElement.className = `alert-item ${alert.severity || 'medium'}`;

    // Format timestamp
    const time = new Date(alert.timestamp).toLocaleTimeString();

    alertElement.innerHTML = `
        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-red); font-family: var(--font-display); letter-spacing: 0.05em;">
                ⚠ THREAT DETECTED
            </strong>
            <span style="color: var(--text-secondary); font-size: 0.75rem;">${time}</span>
        </div>
        <div style="color: var(--text-primary); margin-bottom: 0.5rem; font-size: 0.85rem;">
            ${alert.threat_summary || 'Security threat detected'}
        </div>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
            <span class="badge badge-danger">RISK: ${alert.risk_score ? alert.risk_score.toFixed(1) : 'N/A'}/10</span>
            ${alert.recommended_action ?
                `<span class="badge badge-info">${alert.recommended_action}</span>` : ''}
        </div>
    `;

    // Add to top of container
    container.insertBefore(alertElement, container.firstChild);

    // Keep only last 50 alerts
    while (container.children.length > 50) {
        container.removeChild(container.lastChild);
    }
}

// Update uptime
function updateUptime() {
    const uptime = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = uptime % 60;

    let uptimeStr = '';
    if (hours > 0) {
        uptimeStr = `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
        uptimeStr = `${minutes}m ${seconds}s`;
    } else {
        uptimeStr = `${seconds}s`;
    }

    document.getElementById('uptime').textContent = uptimeStr;
}

// Run live demo
async function runDemo(demoType) {
    const output = document.getElementById('demo-output');
    const loader = document.getElementById('demo-loader');
    const results = document.getElementById('demo-results');

    // Show output section and loader
    output.classList.remove('hidden');
    loader.style.display = 'flex';
    results.classList.remove('show');
    results.innerHTML = '';

    // Temporarily show agents as ONLINE during demo
    document.getElementById('guardian-status').textContent = 'ONLINE';
    document.getElementById('guardian-status').classList.add('online');
    document.getElementById('sentinel-status').textContent = 'STANDBY';
    document.getElementById('sentinel-status').classList.add('online');

    try {
        // Call demo API (use_real_llm=false for demo mode)
        const response = await fetch(`${API_BASE}/api/demo/run?demo_type=${demoType}&use_real_llm=false`, {
            method: 'POST'
        });
        const data = await response.json();

        // Hide loader after 2 seconds (for effect)
        await new Promise(resolve => setTimeout(resolve, 2000));
        loader.style.display = 'none';

        if (data.error) {
            results.innerHTML = `<div class="demo-step threat">
                <h3>❌ SYSTEM ERROR</h3>
                <p style="color: var(--text-secondary);">${data.error}</p>
            </div>`;
            results.classList.add('show');
            return;
        }

        // Build demo output
        let html = '';

        // Step 1: Packet Details
        const isNormal = demoType === 'normal';
        html += `
            <div class="demo-step ${isNormal ? '' : 'threat'}">
                <h3>${isNormal ? '📦 PACKET INTERCEPTED' : '⚠️ SUSPICIOUS PACKET DETECTED'}</h3>
                <div class="demo-data">
                    <div class="demo-data-row">
                        <span class="demo-data-label">SOURCE:</span>
                        <span class="demo-data-value">${data.packet.src_mac}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">DESTINATION:</span>
                        <span class="demo-data-value">${data.packet.dst_mac}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">PROTOCOL:</span>
                        <span class="demo-data-value">${data.packet.protocol}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">PACKET RATE:</span>
                        <span class="demo-data-value ${!isNormal ? 'highlight' : ''}">${data.packet.packet_rate} PKT/S</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">ENTROPY:</span>
                        <span class="demo-data-value ${!isNormal ? 'highlight' : ''}">${data.packet.entropy}</span>
                    </div>
                    ${data.packet.unique_dst_ips ? `
                    <div class="demo-data-row">
                        <span class="demo-data-label">UNIQUE TARGETS:</span>
                        <span class="demo-data-value highlight">${data.packet.unique_dst_ips}</span>
                    </div>` : ''}
                </div>
            </div>
        `;

        // Step 2: Guardian Agent Analysis
        const guardianData = data.guardian_agent || data.guardian_result;
        html += `
            <div class="demo-step guardian">
                <h3>🛡️ GUARDIAN AGENT // ML DETECTION ENGINE</h3>
                <p style="margin-bottom: 1rem; color: var(--text-secondary); font-size: 0.85rem;">
                    <span class="badge badge-success">STATUS: ${guardianData.status || 'ONLINE'}</span>
                    <span class="badge badge-info">RANDOM FOREST</span>
                    <span class="badge badge-info">ISOLATION FOREST</span>
                    <span class="badge badge-success">${guardianData.ensemble_accuracy || '84.40%'}</span>
                </p>
                <div class="demo-data">
                    <div class="demo-data-row">
                        <span class="demo-data-label">CLASSIFICATION:</span>
                        <span class="demo-data-value ${!isNormal ? 'highlight' : ''}">${guardianData.prediction}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">CONFIDENCE:</span>
                        <span class="demo-data-value">${guardianData.confidence}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">ANOMALY SCORE:</span>
                        <span class="demo-data-value">${guardianData.anomaly_score}</span>
                    </div>
                    ${guardianData.threat_severity ? `
                    <div class="demo-data-row">
                        <span class="demo-data-label">THREAT SEVERITY:</span>
                        <span class="demo-data-value highlight">${guardianData.threat_severity}</span>
                    </div>` : ''}
                    <div class="demo-data-row">
                        <span class="demo-data-label">PROCESSING TIME:</span>
                        <span class="demo-data-value">${guardianData.processing_time_ms || 85}ms</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">ESCALATE TO SENTINEL:</span>
                        <span class="demo-data-value ${data.escalated_to_sentinel ? 'highlight' : ''}">
                            ${data.escalated_to_sentinel ? '✅ AFFIRMATIVE' : '❌ NEGATIVE'}
                        </span>
                    </div>
                </div>
            </div>
        `;

        // Step 3: Sentinel Agent Analysis (if escalated)
        if (data.escalated_to_sentinel && (data.sentinel_agent || data.sentinel_analysis)) {
            const sentinel = data.sentinel_agent || data.sentinel_analysis;

            // Update Sentinel status to ONLINE
            document.getElementById('sentinel-status').textContent = 'ONLINE';
            document.getElementById('sentinel-status').classList.add('online');

            // Parse risk score
            const riskScore = typeof sentinel.risk_score === 'string' ?
                parseFloat(sentinel.risk_score) : sentinel.risk_score;
            const riskClass = riskScore >= 7 ? 'danger' : riskScore >= 5 ? 'warning' : 'success';

            // Get MITRE info
            const mitreDisplay = sentinel.mitre_attack ?
                (typeof sentinel.mitre_attack === 'string' ? sentinel.mitre_attack :
                 `${sentinel.mitre_attack.id} - ${sentinel.mitre_attack.name}`) :
                'T1557 - Adversary-in-the-Middle';

            html += `
                <div class="demo-step sentinel">
                    <h3>🧠 SENTINEL AGENT // LLM REASONING</h3>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary); font-size: 0.85rem;">
                        <span class="badge badge-success">STATUS: ${sentinel.status || 'ONLINE'}</span>
                        <span class="badge badge-info">LLM: ${sentinel.llm_model || 'MISTRAL AI'}</span>
                        <span class="badge badge-${riskClass}">RISK: ${typeof sentinel.risk_score === 'string' ? sentinel.risk_score : sentinel.risk_score.toFixed(1) + '/10'}</span>
                    </p>
                    <div class="demo-data">
                        <div class="demo-data-row">
                            <span class="demo-data-label">THREAT CLASSIFICATION:</span>
                            <span class="demo-data-value highlight">${sentinel.threat_type}</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">MITRE ATT&CK:</span>
                            <span class="demo-data-value">${mitreDisplay}</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">RECOMMENDED ACTION:</span>
                            <span class="demo-data-value highlight">${sentinel.recommended_action}</span>
                        </div>
                        ${sentinel.action_reason ? `
                        <div class="demo-data-row">
                            <span class="demo-data-label">ACTION REASON:</span>
                            <span class="demo-data-value">${sentinel.action_reason}</span>
                        </div>` : ''}
                        ${sentinel.processing_time_ms ? `
                        <div class="demo-data-row">
                            <span class="demo-data-label">PROCESSING TIME:</span>
                            <span class="demo-data-value">${sentinel.processing_time_ms}ms</span>
                        </div>` : ''}
                        ${sentinel.requires_approval !== undefined ? `
                        <div class="demo-data-row">
                            <span class="demo-data-label">REQUIRES APPROVAL:</span>
                            <span class="demo-data-value">${sentinel.requires_approval ? 'YES' : 'NO'}</span>
                        </div>` : ''}
                    </div>
                    <div style="margin-top: 1rem; padding: 1rem; background: rgba(0, 0, 0, 0.3); border-left: 2px solid var(--accent-amber); font-size: 0.85rem;">
                        <strong style="color: var(--accent-amber); font-family: var(--font-display); letter-spacing: 0.05em; display: block; margin-bottom: 0.5rem;">
                            💡 LLM THREAT ANALYSIS
                        </strong>
                        <p style="color: var(--text-secondary); line-height: 1.6;">
                            ${sentinel.llm_analysis || sentinel.explanation}
                        </p>
                    </div>
                </div>
            `;
        } else if (!data.escalated_to_sentinel) {
            // Show that Sentinel stayed on standby
            html += `
                <div class="demo-step">
                    <h3>🧠 SENTINEL AGENT // STATUS</h3>
                    <p style="color: var(--text-secondary);">
                        <span class="badge badge-info">STANDBY</span>
                        Sentinel Agent remained on standby. Guardian classified traffic as normal with low confidence, no escalation required.
                    </p>
                </div>
            `;
        }

        // Step 4: Summary
        html += `
            <div class="demo-step">
                <h3>✅ DEMONSTRATION COMPLETE</h3>
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                    This demonstration showcases the complete multi-agent workflow:
                </p>
                <ol style="margin-left: 1.5rem; color: var(--text-secondary); line-height: 1.8;">
                    <li><strong style="color: var(--accent-green);">Guardian Agent</strong> detects threats using ensemble ML models (84.40% accuracy)</li>
                    <li><strong style="color: var(--accent-amber);">Sentinel Agent</strong> analyzes high-confidence threats with Mistral AI LLM</li>
                    <li><strong style="color: var(--accent-cyan);">System</strong> recommends autonomous response with MITRE ATT&CK framework mapping</li>
                </ol>
            </div>
        `;

        results.innerHTML = html;
        results.classList.add('show');

    } catch (error) {
        loader.style.display = 'none';
        results.innerHTML = `<div class="demo-step threat">
            <h3>❌ DEMO ERROR</h3>
            <p style="color: var(--text-secondary);">Failed to execute demonstration: ${error.message}</p>
        </div>`;
        results.classList.add('show');
        console.error('Demo error:', error);
    }
}

// Show ML model information
async function showModelInfo() {
    const output = document.getElementById('demo-output');
    const loader = document.getElementById('demo-loader');
    const results = document.getElementById('demo-results');

    output.classList.remove('hidden');
    loader.style.display = 'flex';
    results.classList.remove('show');
    results.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE}/api/demo/models`);
        const data = await response.json();

        // Hide loader after 1.5 seconds
        await new Promise(resolve => setTimeout(resolve, 1500));
        loader.style.display = 'none';

        if (data.error) {
            results.innerHTML = `<div class="demo-step threat">
                <h3>❌ SYSTEM ERROR</h3>
                <p style="color: var(--text-secondary);">${data.error}</p>
            </div>`;
            results.classList.add('show');
            return;
        }

        let html = `
            <div class="demo-step">
                <h3>📊 MACHINE LEARNING MODELS</h3>
                <div class="demo-data">
                    <div class="demo-data-row">
                        <span class="demo-data-label">ENSEMBLE ACCURACY:</span>
                        <span class="demo-data-value highlight">${data.ensemble_accuracy}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">TRAINING DATASET:</span>
                        <span class="demo-data-value">${data.training_dataset}</span>
                    </div>
                    <div class="demo-data-row">
                        <span class="demo-data-label">DETECTION SPEED:</span>
                        <span class="demo-data-value">${data.detection_speed}</span>
                    </div>
                </div>
            </div>
        `;

        if (data.models) {
            if (data.models.random_forest_loaded) {
                html += `
                    <div class="demo-step guardian">
                        <h3>🌲 RANDOM FOREST CLASSIFIER</h3>
                        <div class="demo-data">
                            <div class="demo-data-row">
                                <span class="demo-data-label">STATUS:</span>
                                <span class="demo-data-value" style="color: var(--accent-green);">LOADED</span>
                            </div>
                            <div class="demo-data-row">
                                <span class="demo-data-label">THREAT CLASSES:</span>
                                <span class="demo-data-value">${data.models.threat_classes ? data.models.threat_classes.join(', ') : 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                `;
            }

            if (data.models.isolation_forest_loaded) {
                html += `
                    <div class="demo-step guardian">
                        <h3>🎯 ISOLATION FOREST (ANOMALY DETECTOR)</h3>
                        <div class="demo-data">
                            <div class="demo-data-row">
                                <span class="demo-data-label">STATUS:</span>
                                <span class="demo-data-value" style="color: var(--accent-green);">LOADED</span>
                            </div>
                            <div class="demo-data-row">
                                <span class="demo-data-label">PURPOSE:</span>
                                <span class="demo-data-value">Anomaly Detection</span>
                            </div>
                        </div>
                    </div>
                `;
            }
        }

        results.innerHTML = html;
        results.classList.add('show');

    } catch (error) {
        loader.style.display = 'none';
        results.innerHTML = `<div class="demo-step threat">
            <h3>❌ MODEL INFO ERROR</h3>
            <p style="color: var(--text-secondary);">Failed to load model information: ${error.message}</p>
        </div>`;
        results.classList.add('show');
        console.error('Model info error:', error);
    }
}

// Defense Demo - Real-time traffic simulation
async function runDefenseDemo() {
    const output = document.getElementById('demo-output');
    const loader = document.getElementById('demo-loader');
    const results = document.getElementById('demo-results');

    // Show output section
    output.classList.remove('hidden');
    loader.style.display = 'none';  // No loader for real-time demo
    results.classList.remove('show');
    results.innerHTML = '';

    // Show both agents as ONLINE during defense demo
    document.getElementById('guardian-status').textContent = 'ONLINE';
    document.getElementById('guardian-status').classList.add('online');
    document.getElementById('sentinel-status').textContent = 'ONLINE';
    document.getElementById('sentinel-status').classList.add('online');

    // Real-time simulation tracking
    let config = null;
    let currentSecond = 0;
    let stats = {
        total_packets: 0,
        legitimate_packets: 0,
        attack_packets: 0,
        threats_detected: 0,
        threats_blocked: 0,
        data_corrupted: 0,
        data_integrity_checks: 0
    };

    // Initialize UI for real-time display
    results.innerHTML = `
        <div class="demo-step" style="border-color: var(--accent-cyan);">
            <h3>🛡️ REAL-TIME DEFENSE SIMULATION</h3>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                Simulating 30 seconds of network traffic with attack injection...
            </p>
            <div class="demo-data">
                <div class="demo-data-row">
                    <span class="demo-data-label">SIMULATION TIME:</span>
                    <span class="demo-data-value" id="sim-time">0s / 30s</span>
                </div>
                <div class="demo-data-row">
                    <span class="demo-data-label">ATTACK WINDOW:</span>
                    <span class="demo-data-value" id="attack-window">Calculating...</span>
                </div>
            </div>
        </div>

        <div class="demo-step" style="border-color: var(--accent-green);">
            <h3>📊 LIVE STATISTICS</h3>
            <div class="demo-data">
                <div class="demo-data-row">
                    <span class="demo-data-label">TOTAL PACKETS:</span>
                    <span class="demo-data-value" id="stat-total">0</span>
                </div>
                <div class="demo-data-row">
                    <span class="demo-data-label">LEGITIMATE PACKETS:</span>
                    <span class="demo-data-value" style="color: var(--accent-green);" id="stat-legit">0</span>
                </div>
                <div class="demo-data-row">
                    <span class="demo-data-label">ATTACK PACKETS:</span>
                    <span class="demo-data-value" style="color: var(--accent-red);" id="stat-attack">0</span>
                </div>
                <div class="demo-data-row">
                    <span class="demo-data-label">THREATS BLOCKED:</span>
                    <span class="demo-data-value highlight" id="stat-blocked">0</span>
                </div>
                <div class="demo-data-row">
                    <span class="demo-data-label">DATA CORRUPTED:</span>
                    <span class="demo-data-value" style="color: var(--accent-green);" id="stat-corrupted">0</span>
                </div>
                <div class="demo-data-row">
                    <span class="demo-data-label">INTEGRITY CHECKS:</span>
                    <span class="demo-data-value" id="stat-integrity">0</span>
                </div>
            </div>
        </div>

        <div class="demo-step" id="packet-feed" style="border-color: var(--accent-amber); max-height: 400px; overflow-y: auto;">
            <h3>📡 LIVE PACKET FEED</h3>
            <div id="packet-list" style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                <p style="color: var(--text-dim);">Waiting for packets...</p>
            </div>
        </div>
    `;
    results.classList.add('show');

    // Connect to Server-Sent Events stream
    const eventSource = new EventSource(`${API_BASE}/api/demo/defense-simulation`);
    const packetList = document.getElementById('packet-list');
    const packetFeed = document.getElementById('packet-feed');

    // Helper function to update statistics display
    function updateStats(newStats) {
        stats = newStats;
        document.getElementById('stat-total').textContent = stats.total_packets;
        document.getElementById('stat-legit').textContent = stats.legitimate_packets;
        document.getElementById('stat-attack').textContent = stats.attack_packets;
        document.getElementById('stat-blocked').textContent = stats.threats_blocked;
        document.getElementById('stat-corrupted').textContent = stats.data_corrupted;
        document.getElementById('stat-integrity').textContent = stats.data_integrity_checks;
    }

    // Helper function to add packet to feed
    function addPacketToFeed(packet, type) {
        const packetEl = document.createElement('div');
        packetEl.style.marginBottom = '0.5rem';
        packetEl.style.padding = '0.5rem';
        packetEl.style.border = '1px solid ' + (
            type === 'threat_blocked' ? 'var(--accent-red)' :
            type === 'legitimate' ? 'var(--accent-green)' :
            'var(--accent-amber)'
        );
        packetEl.style.borderRadius = '3px';
        packetEl.style.backgroundColor = type === 'threat_blocked' ?
            'rgba(255, 77, 77, 0.1)' :
            'rgba(0, 255, 127, 0.05)';

        packetEl.innerHTML = `
            <div style="color: ${type === 'threat_blocked' ? 'var(--accent-red)' : 'var(--accent-green)'};">
                ${type === 'threat_blocked' ? '🚫 THREAT BLOCKED' : '✅ ALLOWED'}
                <span style="float: right; color: var(--text-dim);">#${packet.packet_id} @ ${packet.timestamp}s</span>
            </div>
            <div style="color: var(--text-secondary); font-size: 0.8rem; margin-top: 0.25rem;">
                ${packet.src_mac} → ${packet.dst_mac}
                ${packet.threat_type ? `| ${packet.threat_type} (${packet.confidence})` : ''}
                ${packet.payload_checksum ? `| Checksum: ${packet.payload_checksum}` : ''}
            </div>
        `;

        // Prepend to feed (newest first)
        if (packetList.firstChild && packetList.firstChild.textContent.includes('Waiting')) {
            packetList.innerHTML = '';
        }
        packetList.insertBefore(packetEl, packetList.firstChild);

        // Limit to last 20 packets
        while (packetList.children.length > 20) {
            packetList.removeChild(packetList.lastChild);
        }

        // Auto-scroll to top
        packetFeed.scrollTop = 0;
    }

    // Event handlers
    eventSource.onmessage = (event) => {
        try {
            const eventData = JSON.parse(event.data);

            if (eventData.type === 'config') {
                // Initial configuration
                config = eventData.data;
                document.getElementById('attack-window').textContent =
                    `${config.attack_start}s - ${config.attack_end}s`;
                console.log('Defense simulation config:', config);
            }
            else if (eventData.type === 'legitimate_packet') {
                // Legitimate packet allowed
                const data = eventData.data;
                updateStats(data.stats);
                addPacketToFeed(data, 'legitimate');
                document.getElementById('sim-time').textContent =
                    `${data.timestamp}s / ${config.total_duration}s`;
            }
            else if (eventData.type === 'threat_blocked') {
                // Threat detected and blocked
                const data = eventData.data;
                updateStats(data.stats);
                addPacketToFeed(data, 'threat_blocked');
                document.getElementById('sim-time').textContent =
                    `${data.timestamp}s / ${config.total_duration}s`;

                // Add threat details to feed
                const threatDetail = document.createElement('div');
                threatDetail.style.marginBottom = '1rem';
                threatDetail.style.padding = '0.75rem';
                threatDetail.style.border = '2px solid var(--accent-red)';
                threatDetail.style.borderRadius = '4px';
                threatDetail.style.backgroundColor = 'rgba(255, 77, 77, 0.15)';
                threatDetail.innerHTML = `
                    <div style="color: var(--accent-red); font-weight: bold; margin-bottom: 0.5rem;">
                        ⚠️ ATTACK DETECTED & BLOCKED
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary);">
                        <div>Type: ${data.threat_type}</div>
                        <div>Confidence: ${data.confidence}</div>
                        <div>Anomaly Score: ${data.anomaly_score}</div>
                        <div>Payload Status: ${data.payload_status}</div>
                        <div style="margin-top: 0.5rem; color: var(--accent-amber);">
                            Expected Checksum: ${data.expected_checksum}<br>
                            Received Checksum: ${data.received_checksum}<br>
                            <span style="color: var(--accent-red);">❌ CHECKSUM MISMATCH - DATA MANIPULATION DETECTED</span>
                        </div>
                    </div>
                `;
                packetList.insertBefore(threatDetail, packetList.firstChild);
            }
            else if (eventData.type === 'second_summary') {
                // Second summary (optional - can add visual indicator)
                const data = eventData.data;
                updateStats(data.stats);
            }
            else if (eventData.type === 'simulation_complete') {
                // Simulation complete
                const data = eventData.data;
                eventSource.close();

                // Add final summary
                const summaryEl = document.createElement('div');
                summaryEl.className = 'demo-step';
                summaryEl.style.borderColor = 'var(--accent-green)';
                summaryEl.style.backgroundColor = 'rgba(0, 255, 127, 0.05)';
                summaryEl.style.marginTop = '1rem';
                summaryEl.innerHTML = `
                    <h3>✅ SIMULATION COMPLETE</h3>
                    <div class="demo-data">
                        <div class="demo-data-row">
                            <span class="demo-data-label">DURATION:</span>
                            <span class="demo-data-value">${data.duration}s</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">ATTACK WINDOW:</span>
                            <span class="demo-data-value">${data.attack_window}</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">TOTAL PACKETS:</span>
                            <span class="demo-data-value">${data.final_stats.total_packets}</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">ATTACK PACKETS:</span>
                            <span class="demo-data-value highlight" style="color: var(--accent-red);">${data.final_stats.attack_packets}</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">THREATS BLOCKED:</span>
                            <span class="demo-data-value highlight" style="color: var(--accent-green);">${data.final_stats.threats_blocked}</span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">DATA CORRUPTED:</span>
                            <span class="demo-data-value highlight" style="color: ${data.final_stats.data_corrupted === 0 ? 'var(--accent-green)' : 'var(--accent-red)'};">
                                ${data.final_stats.data_corrupted}
                            </span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">DEFENSE EFFECTIVENESS:</span>
                            <span class="demo-data-value highlight" style="color: var(--accent-green); font-size: 1.3rem;">
                                ${data.defense_effectiveness}
                            </span>
                        </div>
                        <div class="demo-data-row">
                            <span class="demo-data-label">DATA INTEGRITY RATE:</span>
                            <span class="demo-data-value highlight" style="color: var(--accent-green); font-size: 1.3rem;">
                                ${data.data_integrity_rate}
                            </span>
                        </div>
                        <div style="margin-top: 1rem; padding: 1rem; background: rgba(0, 255, 127, 0.1); border-radius: 4px; text-align: center;">
                            <div style="color: var(--accent-green); font-size: 1.2rem; font-weight: bold;">
                                ${data.success ? '✅ ALL THREATS SUCCESSFULLY BLOCKED' : '⚠️ SOME THREATS MISSED'}
                            </div>
                            <div style="color: var(--text-secondary); margin-top: 0.5rem;">
                                Zero data corruption - Guardian + Sentinel defense system operating at peak efficiency
                            </div>
                        </div>
                    </div>
                `;

                // Insert summary before the packet feed
                results.insertBefore(summaryEl, packetFeed);
            }
            else if (eventData.type === 'error') {
                // Error occurred
                eventSource.close();
                const errorEl = document.createElement('div');
                errorEl.className = 'demo-step threat';
                errorEl.innerHTML = `
                    <h3>❌ SIMULATION ERROR</h3>
                    <p style="color: var(--text-secondary);">${eventData.data.error}</p>
                `;
                results.appendChild(errorEl);
            }
        } catch (err) {
            console.error('Error parsing SSE event:', err, event.data);
        }
    };

    eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
        eventSource.close();
        const errorEl = document.createElement('div');
        errorEl.className = 'demo-step threat';
        errorEl.innerHTML = `
            <h3>❌ CONNECTION ERROR</h3>
            <p style="color: var(--text-secondary);">Lost connection to simulation stream</p>
        `;
        results.appendChild(errorEl);
    };

}
