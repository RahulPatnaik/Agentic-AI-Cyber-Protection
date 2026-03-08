-- Threat Modeling System Database Schema
-- PostgreSQL 13+

-- Threat Models Table
CREATE TABLE IF NOT EXISTS threat_models (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    component_type VARCHAR(100),
    description TEXT,
    confidence_score FLOAT,
    analysis_duration_seconds FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    threat_model_id UUID REFERENCES threat_models(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    cwe_id VARCHAR(20),
    cwe_name VARCHAR(500),
    owasp_category VARCHAR(100),
    cvss_score FLOAT,
    risk_score FLOAT,
    attack_vector TEXT,
    exploitability VARCHAR(50),
    recommendation TEXT,
    vulnerable_code_line INTEGER,
    code_fix_example TEXT,
    stride_category VARCHAR(10),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Attack Paths Table
CREATE TABLE IF NOT EXISTS attack_paths (
    id SERIAL PRIMARY KEY,
    threat_model_id UUID REFERENCES threat_models(id) ON DELETE CASCADE,
    entry_point VARCHAR(500),
    target VARCHAR(500),
    potential_damage VARCHAR(100),
    likelihood VARCHAR(50),
    intermediate_steps JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- CWE References Table
CREATE TABLE IF NOT EXISTS cwe_references (
    id SERIAL PRIMARY KEY,
    threat_model_id UUID REFERENCES threat_models(id) ON DELETE CASCADE,
    cwe_id VARCHAR(20) NOT NULL,
    cwe_name VARCHAR(500),
    description TEXT,
    mitigation_strategies JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Agent Analyses Table
CREATE TABLE IF NOT EXISTS agent_analyses (
    id SERIAL PRIMARY KEY,
    threat_model_id UUID REFERENCES threat_models(id) ON DELETE CASCADE,
    agent_name VARCHAR(100) NOT NULL,
    analysis_data JSONB,
    execution_time_seconds FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Data Flow Diagram Components Table
CREATE TABLE IF NOT EXISTS dfd_components (
    id SERIAL PRIMARY KEY,
    threat_model_id UUID REFERENCES threat_models(id) ON DELETE CASCADE,
    component_type VARCHAR(50) NOT NULL, -- process, data_store, external_entity, data_flow
    name VARCHAR(500),
    description TEXT,
    trust_level VARCHAR(50),
    attributes JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- CVE Cache Table (for NVD lookups)
CREATE TABLE IF NOT EXISTS cve_cache (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    cvss_score FLOAT,
    severity VARCHAR(50),
    published_date DATE,
    cwe_ids JSONB,
    affected_products JSONB,
    references JSONB,
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX idx_threat_models_timestamp ON threat_models(timestamp DESC);
CREATE INDEX idx_vulnerabilities_threat_model ON vulnerabilities(threat_model_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cwe ON vulnerabilities(cwe_id);
CREATE INDEX idx_attack_paths_threat_model ON attack_paths(threat_model_id);
CREATE INDEX idx_cwe_references_threat_model ON cwe_references(threat_model_id);
CREATE INDEX idx_cwe_references_cwe_id ON cwe_references(cwe_id);
CREATE INDEX idx_agent_analyses_threat_model ON agent_analyses(threat_model_id);
CREATE INDEX idx_dfd_components_threat_model ON dfd_components(threat_model_id);
CREATE INDEX idx_cve_cache_cve_id ON cve_cache(cve_id);
CREATE INDEX idx_cve_cache_expires ON cve_cache(expires_at);

-- Updated timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_threat_models_updated_at
    BEFORE UPDATE ON threat_models
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- View for threat model summary
CREATE OR REPLACE VIEW threat_model_summary AS
SELECT
    tm.id,
    tm.timestamp,
    tm.component_type,
    tm.confidence_score,
    COUNT(DISTINCT v.id) as total_vulnerabilities,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'critical') as critical_vulnerabilities,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'high') as high_vulnerabilities,
    COUNT(DISTINCT ap.id) as attack_paths_count,
    AVG(v.cvss_score) as avg_cvss_score
FROM threat_models tm
LEFT JOIN vulnerabilities v ON tm.id = v.threat_model_id
LEFT JOIN attack_paths ap ON tm.id = ap.threat_model_id
GROUP BY tm.id, tm.timestamp, tm.component_type, tm.confidence_score;

COMMENT ON TABLE threat_models IS 'Main threat modeling analysis records';
COMMENT ON TABLE vulnerabilities IS 'Identified security vulnerabilities';
COMMENT ON TABLE attack_paths IS 'Attack path sequences from entry to target';
COMMENT ON TABLE cwe_references IS 'CWE weakness references with mitigations';
COMMENT ON TABLE agent_analyses IS 'Individual agent analysis results';
COMMENT ON TABLE dfd_components IS 'Data Flow Diagram components';
COMMENT ON TABLE cve_cache IS 'Cached CVE data from NVD API';
